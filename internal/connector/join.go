package connector

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/frame"
	"ssheep.xyz/internal/netx"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
)

// Enrolled is one flock this machine may relay for.
type Enrolled struct {
	Name       string
	RosterPath string
	NodePath   string
}

// Start brings up a relay for the flocks this machine is in, and returns without
// blocking.
//
// It is what a sheep calls when it wants to help. One relay, one port, several
// flocks: the relay already keeps flocks apart, so being reachable for three of
// them costs what being reachable for one costs. Whether anybody can actually
// reach it is not this machine's problem to solve — see Announce.
func Start(flocks []Enrolled, port int, public bool) (*Server, error) {
	if len(flocks) == 0 {
		return nil, errors.New("relay: this machine is not in any flock")
	}
	paths := make([]string, 0, len(flocks))
	for _, f := range flocks {
		if err := checkEnrolled(f); err != nil {
			return nil, err
		}
		paths = append(paths, f.RosterPath)
	}

	srv, err := New(Config{
		RosterPaths: paths,
		// One certificate for the whole machine: every flock is reached at the
		// same address, so they share one fingerprint.
		CertPath:   filepath.Join(flock.Dir(), "connector.crt"),
		KeyPath:    filepath.Join(flock.Dir(), "connector.key"),
		Public:     public,
		MaxFlocks:  100,
		MaxConns:   2000,
		MaxMembers: 1000,
	})
	if err != nil {
		return nil, err
	}

	ln, err := srv.Listen(fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("relay: %v", err)
		}
	}()
	return srv, nil
}

// Announce keeps offering this machine as a relay, for as long as it is up.
//
// It offers every address the machine might be reachable at and lets the master
// decide, which is the whole trick: an address that does not answer is simply not
// added, so the machine never has to work out whether it is reachable. addrs
// overrides that guess when the operator knows better.
func Announce(flocks []Enrolled, pin string, addrs []string, port int) {
	for _, f := range flocks {
		go announceForever(f, pin, addrs, port)
	}
}

// Join runs this machine as a dedicated relay, and blocks.
//
// This is the `ssheep connector` path: a machine whose whole job is relaying,
// usually because it is the one with a public address.
func Join(flocks []Enrolled, addr string, port int, public bool) error {
	srv, err := Start(flocks, port, public)
	if err != nil {
		return err
	}
	fmt.Printf("\n📡  relay running on :%d\n", port)
	fmt.Printf("    fingerprint %s\n", srv.Pin())
	for _, f := range flocks {
		fmt.Printf("    serving flock %q\n", f.Name)
	}
	var addrs []string
	if addr != "" {
		addrs = []string{addr}
	}
	Announce(flocks, srv.Pin(), addrs, port)
	select {}
}

// checkEnrolled makes sure the machine really is in this flock, and is allowed to
// relay for it, before it starts advertising itself as one.
func checkEnrolled(f Enrolled) error {
	sr, err := flock.LoadSignedRoster(f.RosterPath)
	if err != nil {
		return err
	}
	roster, err := sr.Verify()
	if err != nil {
		return err
	}
	key, err := flock.LoadKeyFile(f.NodePath)
	if err != nil {
		return err
	}
	m := roster.Find(flock.NodeID(key.SignPub()))
	if m == nil {
		return fmt.Errorf("relay: this machine is not in flock %q", f.Name)
	}
	if !m.MayRelay() {
		return fmt.Errorf("relay: this machine may not relay for flock %q", f.Name)
	}
	return nil
}

// announceForever keeps one flock's registration fresh for as long as this relay
// is up.
func announceForever(f Enrolled, pin string, addrs []string, port int) {
	delay := 5 * time.Second
	for {
		if err := announce(f, pin, addrs, port); err != nil {
			log.Printf("relay: flock %s: %v", f.Name, err)
			if delay < 2*time.Minute {
				delay *= 2
			}
		} else {
			delay = 5 * time.Second
		}
		time.Sleep(delay)
	}
}

// announce holds one connection open to a relay of this flock, offering this
// machine and keeping the offer fresh.
//
// It stays connected rather than knocking once: that way the flock sees the relay
// as online while it is up, and roster changes reach it without waiting for the
// next announcement.
func announce(f Enrolled, pin string, addrs []string, port int) error {
	sr, err := flock.LoadSignedRoster(f.RosterPath)
	if err != nil {
		return err
	}
	roster, err := sr.Verify()
	if err != nil {
		return err
	}
	key, err := flock.LoadKeyFile(f.NodePath)
	if err != nil {
		return err
	}
	id := flock.NodeID(key.SignPub())
	who := peer.Identity{Flock: roster.ID(), NodeID: id, Key: key.SignKey(), Roster: sr}

	var lastErr error
	for _, c := range roster.Connectors {
		conn, ready, err := peer.DialReady(c.Addr, c.Pin, who, 10*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("relay %s: %w", c.Addr, err)
			continue
		}

		mine := candidateAddrs(addrs, &ready, port)
		if len(mine) == 0 {
			conn.Close()
			lastErr = errors.New("no address to offer; pass --addr")
			continue
		}
		if contains(mine, c.Addr) {
			// That is us. Nothing to announce to ourselves.
			conn.Close()
			continue
		}

		offered := 0
		for _, myAddr := range mine {
			if err := sendOffer(conn, key, roster, id, myAddr, pin); err != nil {
				lastErr = err
				break
			}
			if _, err := peer.Read(conn); err != nil { // the acknowledgement
				lastErr = err
				break
			}
			offered++
			log.Printf("relay: flock %s: %s knows this machine is at %s", f.Name, c.Addr, myAddr)
		}
		if offered == 0 {
			conn.Close()
			continue
		}

		next := time.Now().Add(5 * time.Minute)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			env, err := peer.Read(conn)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					if time.Now().After(next) {
						for _, myAddr := range mine {
							if err := sendOffer(conn, key, roster, id, myAddr, pin); err != nil {
								conn.Close()
								return err
							}
							if _, err := peer.Read(conn); err != nil {
								conn.Close()
								return err
							}
						}
						next = time.Now().Add(5 * time.Minute)
					}
					continue
				}
				conn.Close()
				return err
			}
			switch env.Type {
			case proto.TypeRoster:
				adoptRoster(env, f.RosterPath, roster)
			case proto.TypeError:
				var e proto.ErrMsg
				_ = env.Decode(&e)
				log.Printf("relay: flock %s: %s: %s", f.Name, c.Addr, e.Message)
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no other relay to announce to yet")
	}
	return lastErr
}

// candidateAddrs is every address this machine might be reachable at, or the
// operator's override when they know better. See netx.CandidateAddrs.
func candidateAddrs(override []string, ready *proto.Ready, port int) []string {
	if len(override) > 0 {
		return override
	}
	youAre := ""
	if ready != nil {
		youAre = ready.YouAre
	}
	return netx.CandidateAddrs(youAre, port)
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func sendOffer(conn *frame.Conn, key *flock.KeyFile, roster flock.Roster, id, addr, pin string) error {
	o := proto.Offer{
		ID:   id,
		Addr: addr,
		Pin:  pin,
		At:   time.Now().UTC(),
		Sig:  ed25519.Sign(key.SignKey(), proto.OfferMessage(roster.ID(), id, addr, pin)),
	}
	return peer.Send(conn, proto.Wrap(proto.TypeOffer, o))
}

// adoptRoster takes on a newer roster, so a relay that has been up for weeks
// still knows the flock in front of it.
func adoptRoster(env *proto.Envelope, rosterPath string, current flock.Roster) {
	var sr flock.SignedRoster
	if err := json.Unmarshal(env.Body, &sr); err != nil {
		return
	}
	r, err := sr.Verify()
	if err != nil {
		log.Printf("relay: ignoring a roster that does not verify: %v", err)
		return
	}
	if !bytes.Equal(r.FlockKey, current.FlockKey) || r.Version <= current.Version {
		return
	}
	if err := sr.Save(rosterPath); err != nil {
		log.Printf("relay: could not save the roster: %v", err)
		return
	}
	log.Printf("relay: roster is now at version %d", r.Version)
}

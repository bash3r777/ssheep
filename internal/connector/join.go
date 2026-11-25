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
	"strconv"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/frame"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
)

// Enrolled is one flock this machine is a connector for.
type Enrolled struct {
	Name       string
	RosterPath string
	NodePath   string
}

// Join runs this machine as a connector for every flock it is enrolled in.
//
// One relay, one port, several flocks. The relay already keeps flocks apart, so
// being reachable for three of them costs what being reachable for one costs.
// Each flock is announced separately, because each has its own connectors and
// its own roster.
//
// The address is worked out the honest way: this machine asks a flock what it
// looks like from outside, and offers itself at that address on its listening
// port. Behind a NAT with no port forwarding that guess is wrong, the master
// will say so, and then --addr is there to be told the truth.
func Join(flocks []Enrolled, addr string, port int, public bool) error {
	if len(flocks) == 0 {
		return errors.New("connector: this machine is not a connector for any flock")
	}
	paths := make([]string, 0, len(flocks))
	names := make([]string, 0, len(flocks))
	for _, f := range flocks {
		if err := checkEnrolled(f); err != nil {
			return err
		}
		paths = append(paths, f.RosterPath)
		names = append(names, f.Name)
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
		return err
	}

	listen := fmt.Sprintf(":%d", port)
	ln, err := srv.Listen(listen)
	if err != nil {
		return err
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("connector: %v", err)
		}
	}()

	fmt.Printf("\n📡  relay running on %s\n", listen)
	fmt.Printf("    fingerprint %s\n", srv.Pin())
	for _, n := range names {
		fmt.Printf("    serving flock %q\n", n)
	}

	for _, f := range flocks {
		go announceForever(f, srv.Pin(), addr, port)
	}
	select {}
}

// checkEnrolled makes sure the machine really is a connector for this flock,
// before it starts advertising itself as one.
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
		return fmt.Errorf("connector: this machine is not in flock %q", f.Name)
	}
	if m.Role != flock.RoleConnector {
		return fmt.Errorf("connector: this machine is a %s in flock %q, not a connector\n  mint a connector ticket with: ssheep master %q", m.Role, f.Name, f.Name)
	}
	return nil
}

// announceForever keeps one flock's registration fresh for as long as this relay
// is up.
func announceForever(f Enrolled, pin, addrOverride string, port int) {
	delay := 5 * time.Second
	for {
		if err := announce(f, pin, addrOverride, port); err != nil {
			log.Printf("connector: flock %s: %v", f.Name, err)
			if delay < 2*time.Minute {
				delay *= 2
			}
		} else {
			delay = 5 * time.Second
		}
		time.Sleep(delay)
	}
}

// announce holds one connection open to a connector of this flock, offering this
// relay and keeping the offer fresh.
//
// It stays connected rather than knocking once: that way the flock sees the
// connector as online while its relay is up, and roster changes reach it without
// waiting for the next announcement.
func announce(f Enrolled, pin, addrOverride string, port int) error {
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
			lastErr = fmt.Errorf("connector %s: %w", c.Addr, err)
			continue
		}

		myAddr := addrOverride
		if myAddr == "" {
			if ready.YouAre == "" {
				conn.Close()
				lastErr = errors.New("the connector did not say what address it sees us at; pass --addr")
				continue
			}
			host, _, err := net.SplitHostPort(ready.YouAre)
			if err != nil {
				conn.Close()
				lastErr = fmt.Errorf("could not work out this machine's address from %q: %w", ready.YouAre, err)
				continue
			}
			myAddr = net.JoinHostPort(host, strconv.Itoa(port))
		}
		if c.Addr == myAddr {
			// That is us. Nothing to announce to ourselves.
			conn.Close()
			continue
		}

		if err := sendOffer(conn, key, roster, id, myAddr, pin); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		if _, err := peer.Read(conn); err != nil { // the acknowledgement
			conn.Close()
			lastErr = err
			continue
		}
		log.Printf("connector: flock %s: %s knows this relay is at %s", f.Name, c.Addr, myAddr)

		next := time.Now().Add(5 * time.Minute)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			env, err := peer.Read(conn)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					if time.Now().After(next) {
						if err := sendOffer(conn, key, roster, id, myAddr, pin); err != nil {
							conn.Close()
							return err
						}
						if _, err := peer.Read(conn); err != nil {
							conn.Close()
							return err
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
				log.Printf("connector: flock %s: %s: %s", f.Name, c.Addr, e.Message)
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no other connector to announce to yet")
	}
	return lastErr
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
		log.Printf("connector: ignoring a roster that does not verify: %v", err)
		return
	}
	if !bytes.Equal(r.FlockKey, current.FlockKey) || r.Version <= current.Version {
		return
	}
	if err := sr.Save(rosterPath); err != nil {
		log.Printf("connector: could not save the roster: %v", err)
		return
	}
	log.Printf("connector: roster is now at version %d", r.Version)
}

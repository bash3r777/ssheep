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

// Join runs this machine as a connector for its flock.
//
// Two things happen at once. A relay starts serving, and this machine sits in the
// flock as a member so that it can tell the other connectors where it is. That
// second part is what removes the last manual step of setting up: nobody has to
// carry an address or a fingerprint to the master by hand.
//
// The address is worked out the honest way: this machine asks the flock what it
// looks like from outside, and offers itself at that address plus its listening
// port. If it sits behind a NAT with no port forwarding, the master will try it,
// fail, and say so — and then --addr is there to be told the truth.
func Join(rosterPath, nodeKeyPath, addr string, port int, public bool) error {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	roster, err := sr.Verify()
	if err != nil {
		return err
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return err
	}
	id := flock.NodeID(key.SignPub())
	m := roster.Find(id)
	if m == nil {
		return errors.New("connector: this machine is not in the roster")
	}
	if m.Role != flock.RoleConnector {
		return fmt.Errorf("connector: this machine is enrolled as a %s, not a connector\n  mint a connector ticket with: ssheep master --invite", m.Role)
	}

	dir := filepath.Dir(rosterPath)
	srv, err := New(Config{
		RosterPath: rosterPath,
		CertPath:   filepath.Join(dir, "connector.crt"),
		KeyPath:    filepath.Join(dir, "connector.key"),
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
	fmt.Printf("    telling the rest of the flock about itself\n")

	go announceForever(rosterPath, nodeKeyPath, srv.Pin(), addr, port)

	select {}
}

// announceForever keeps this relay registered for as long as it is up.
func announceForever(rosterPath, nodeKeyPath, pin, addrOverride string, port int) {
	delay := 5 * time.Second
	for {
		if err := announce(rosterPath, nodeKeyPath, pin, addrOverride, port); err != nil {
			log.Printf("connector: %v", err)
			if delay < 2*time.Minute {
				delay *= 2
			}
		} else {
			delay = 5 * time.Second
		}
		time.Sleep(delay)
	}
}

// announce holds one connection open to a connector of the flock, offering this
// relay and keeping the offer fresh.
//
// It stays connected rather than knocking once. That way the flock sees the
// connector as online while its relay is up, and roster changes reach it without
// waiting for the next announcement.
func announce(rosterPath, nodeKeyPath, pin, addrOverride string, port int) error {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	roster, err := sr.Verify()
	if err != nil {
		return err
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
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
		log.Printf("connector: %s knows this relay is at %s", c.Addr, myAddr)

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
				adoptRoster(env, rosterPath, roster)
			case proto.TypeError:
				var e proto.ErrMsg
				_ = env.Decode(&e)
				log.Printf("connector: %s: %s", c.Addr, e.Message)
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

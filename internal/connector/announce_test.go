package connector

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/frame"
	"sshepard.com/internal/peer"
	"sshepard.com/internal/proto"
)

// A machine that has been connected for weeks only ever learns about a change if
// the relay tells it. Without this, adding a connector to the flock does nothing
// until every machine happens to restart.
func TestAdoptingANewerRosterTellsConnectedPeers(t *testing.T) {
	s := newServer(t, Config{Public: true})
	authority, member := key(t), key(t)

	st, _, err := s.adopt(signed(t, authority, member, "alpha", 1))
	if err != nil {
		t.Fatal(err)
	}

	// A peer connected over a real socket pair, so nothing blocks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSide.Close()
	serverSide := <-accepted
	defer serverSide.Close()

	st.addPeer(&session{
		id:   flock.NodeID(member.SignPub()),
		name: "a-machine",
		conn: frame.New(serverSide),
	})

	// A newer roster arrives.
	if _, _, err := s.adopt(signed(t, authority, member, "alpha", 2)); err != nil {
		t.Fatal(err)
	}

	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	env, err := peer.Read(frame.New(clientSide))
	if err != nil {
		t.Fatalf("the relay kept the new roster to itself: %v", err)
	}
	if env.Type != proto.TypeRoster {
		t.Fatalf("the relay sent %q, want %q", env.Type, proto.TypeRoster)
	}
	var sr flock.SignedRoster
	if err := json.Unmarshal(env.Body, &sr); err != nil {
		t.Fatal(err)
	}
	r, err := sr.Verify()
	if err != nil {
		t.Fatalf("the roster it sent does not verify: %v", err)
	}
	if r.Version != 2 {
		t.Fatalf("it sent version %d, want 2", r.Version)
	}
}

// An older roster must not be announced: a machine that still lists a revoked
// member would be told to put it back.
func TestAnOlderRosterIsNotAnnounced(t *testing.T) {
	s := newServer(t, Config{Public: true})
	authority, member := key(t), key(t)

	if _, _, err := s.adopt(signed(t, authority, member, "alpha", 5)); err != nil {
		t.Fatal(err)
	}
	st, _, err := s.adopt(signed(t, authority, member, "alpha", 5))
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSide.Close()
	serverSide := <-accepted
	defer serverSide.Close()
	st.addPeer(&session{id: "x", name: "x", conn: frame.New(serverSide)})

	if _, changed, err := s.adopt(signed(t, authority, member, "alpha", 4)); err != nil {
		t.Fatal(err)
	} else if changed {
		t.Fatal("an older roster was adopted")
	}

	_ = clientSide.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := peer.Read(frame.New(clientSide)); err == nil {
		t.Fatal("the relay announced a roster that should have been ignored")
	}
}

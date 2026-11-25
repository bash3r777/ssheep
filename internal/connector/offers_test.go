package connector

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
)

// signedAs builds a roster for one machine holding a given role.
func signedAs(t *testing.T, authority, member *flock.KeyFile, name string, role string) *flock.SignedRoster {
	t.Helper()
	kex, err := member.KexPub()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := flock.Roster{
		Version:  1,
		Name:     name,
		FlockKey: authority.SignPub(),
		Members: []flock.Member{{
			ID:      flock.NodeID(member.SignPub()),
			Name:    "a-machine",
			Role:    role,
			SignKey: member.SignPub(),
			KexKey:  kex,
			Added:   now,
		}},
		IssuedAt: now,
	}
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

// The whole point of an offer: a machine with no fixed address tells the flock
// where it is, and the flock's connector passes that on. Without this the setup
// needs somebody to copy an address and a fingerprint to the master by hand.
func TestARelayKeepsAnOfferAndServesIt(t *testing.T) {
	s, addr := start(t, Config{Public: true})
	authority, member := key(t), key(t)
	sr := signedAs(t, authority, member, "alpha", flock.RoleConnector)
	r, err := sr.Open()
	if err != nil {
		t.Fatal(err)
	}
	who := peer.Identity{
		Flock:  r.ID(),
		NodeID: flock.NodeID(member.SignPub()),
		Key:    member.SignKey(),
		Roster: sr,
	}

	conn, ready, err := peer.DialReady(addr, s.Pin(), who, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if ready.YouAre == "" {
		t.Fatal("the relay did not say what address it sees us at; a connector could not work out what to offer")
	}

	const pin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const mine = "somewhere.test:7000"
	o := proto.Offer{
		ID:   who.NodeID,
		Addr: mine,
		Pin:  pin,
		At:   time.Now().UTC(),
		Sig:  ed25519.Sign(member.SignKey(), proto.OfferMessage(r.ID(), who.NodeID, mine, pin)),
	}
	if err := peer.Send(conn, proto.Wrap(proto.TypeOffer, o)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(conn); err != nil { // the acknowledgement
		t.Fatal(err)
	}

	if err := peer.Send(conn, proto.Wrap(proto.TypeList, nil)); err != nil {
		t.Fatal(err)
	}
	env, err := peer.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	var reply proto.ListReply
	if err := env.Decode(&reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Offers) != 1 {
		t.Fatalf("the relay is serving %d offers, want 1", len(reply.Offers))
	}
	got := reply.Offers[0]
	if got.Addr != mine || got.Pin != pin || got.ID != who.NodeID {
		t.Fatalf("the offer came back changed: %+v", got)
	}
	if len(got.Sig) == 0 {
		t.Fatal("the relay dropped the signature, which is the only thing that makes an offer believable")
	}
}

// An offer claiming to come from somebody else must not be filed.
func TestARelayRefusesAnOfferInSomeoneElsesName(t *testing.T) {
	s, addr := start(t, Config{Public: true})
	authority, member := key(t), key(t)
	sr := signedAs(t, authority, member, "alpha", flock.RoleConnector)
	r, err := sr.Open()
	if err != nil {
		t.Fatal(err)
	}
	who := peer.Identity{Flock: r.ID(), NodeID: flock.NodeID(member.SignPub()), Key: member.SignKey(), Roster: sr}
	conn, _, err := peer.DialReady(addr, s.Pin(), who, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	o := proto.Offer{ID: "someone-else", Addr: "x.test:7000", Pin: strings.Repeat("b", 64), At: time.Now()}
	if err := peer.Send(conn, proto.Wrap(proto.TypeOffer, o)); err != nil {
		t.Fatal(err)
	}
	env, err := peer.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != proto.TypeError {
		t.Fatalf("the relay answered %q, want an error", env.Type)
	}
}

// An offer has to look like an address and a fingerprint, or the master will
// waste a dial on it.
func TestARelayRefusesAMalformedOffer(t *testing.T) {
	s, addr := start(t, Config{Public: true})
	authority, member := key(t), key(t)
	sr := signedAs(t, authority, member, "alpha", flock.RoleConnector)
	r, err := sr.Open()
	if err != nil {
		t.Fatal(err)
	}
	id := flock.NodeID(member.SignPub())
	who := peer.Identity{Flock: r.ID(), NodeID: id, Key: member.SignKey(), Roster: sr}

	for _, bad := range []proto.Offer{
		{ID: id, Addr: "no-port", Pin: strings.Repeat("c", 64)},
		{ID: id, Addr: "x.test:7000", Pin: "too-short"},
	} {
		conn, _, err := peer.DialReady(addr, s.Pin(), who, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.Send(conn, proto.Wrap(proto.TypeOffer, bad)); err != nil {
			t.Fatal(err)
		}
		env, err := peer.Read(conn)
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		if env.Type != proto.TypeError {
			t.Fatalf("the relay accepted %+v, want it refused", bad)
		}
	}
}

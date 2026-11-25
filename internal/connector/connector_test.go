package connector

import (
	"bytes"
	"testing"
	"time"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/peer"
)

func newServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg.CertPath = dir + "/connector.crt"
	cfg.KeyPath = dir + "/connector.key"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signed builds a roster for one flock at a given version.
func signed(t *testing.T, authority, member *flock.KeyFile, name string, version uint64) *flock.SignedRoster {
	t.Helper()
	kex, err := member.KexPub()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := flock.Roster{
		Version:  version,
		Name:     name,
		FlockKey: authority.SignPub(),
		Members: []flock.Member{{
			ID:      flock.NodeID(member.SignPub()),
			Name:    "a-machine",
			Role:    flock.RoleSheep,
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

func key(t *testing.T) *flock.KeyFile {
	t.Helper()
	k, err := flock.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// start runs a relay on an ephemeral port and returns its address.
func start(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	s := newServer(t, cfg)
	ln, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	return s, ln.Addr().String()
}

// The whole point of a public relay: a flock it has never heard of can walk up
// and prove it belongs there, with nobody having registered it first.
func TestARelayLearnsAFlockItHasNeverSeen(t *testing.T) {
	s, addr := start(t, Config{Public: true})

	authority, member := key(t), key(t)
	sr := signed(t, authority, member, "alpha", 1)
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

	conn, err := peer.Dial(addr, s.Pin(), who, 5*time.Second)
	if err != nil {
		t.Fatalf("a relay refused a flock that proved itself: %v", err)
	}
	defer conn.Close()

	s.mu.Lock()
	st := s.flocks[r.ID()]
	s.mu.Unlock()
	if st == nil {
		t.Fatal("the relay accepted the flock but did not keep it")
	}
	if st.version() != 1 {
		t.Fatalf("the relay holds version %d, want 1", st.version())
	}
}

// A private relay serves only what it was given, and says so.
func TestAPrivateRelayRefusesAStranger(t *testing.T) {
	s, addr := start(t, Config{})

	authority, member := key(t), key(t)
	sr := signed(t, authority, member, "alpha", 1)
	r, err := sr.Open()
	if err != nil {
		t.Fatal(err)
	}
	who := peer.Identity{Flock: r.ID(), NodeID: flock.NodeID(member.SignPub()), Key: member.SignKey(), Roster: sr}

	if _, err := peer.Dial(addr, s.Pin(), who, 5*time.Second); err == nil {
		t.Fatal("a private relay enrolled a flock it was never given")
	}
}

// A machine that is not in the roster it presents must not get in, even though
// the roster itself is genuine.
func TestARelayRefusesProofFromOutsideTheRoster(t *testing.T) {
	s, addr := start(t, Config{Public: true})

	authority, member := key(t), key(t)
	sr := signed(t, authority, member, "alpha", 1)
	r, err := sr.Open()
	if err != nil {
		t.Fatal(err)
	}
	// An impostor with the right roster, claiming to be a machine in it.
	impostor := key(t)
	who := peer.Identity{
		Flock:  r.ID(),
		NodeID: flock.NodeID(member.SignPub()), // claims to be the real member
		Key:    impostor.SignKey(),             // but holds a different key
		Roster: sr,
	}
	if _, err := peer.Dial(addr, s.Pin(), who, 5*time.Second); err == nil {
		t.Fatal("a machine proved an identity it does not hold")
	}
}

// A relay refuses an older roster than the one it holds. Without that, a machine
// that has been revoked could simply replay the roster that still listed it.
func TestRosterVersionNeverGoesBackwards(t *testing.T) {
	s := newServer(t, Config{})
	authority, member := key(t), key(t)

	v2 := signed(t, authority, member, "f", 2)
	v3 := signed(t, authority, member, "f", 3)

	st, changed, err := s.adopt(v2)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || st.version() != 2 {
		t.Fatalf("adopting version 2 gave changed=%v version=%d", changed, st.version())
	}

	if _, changed, err = s.adopt(v3); err != nil {
		t.Fatal(err)
	}
	if !changed || st.version() != 3 {
		t.Fatalf("adopting version 3 gave changed=%v version=%d", changed, st.version())
	}

	if _, changed, err = s.adopt(v2); err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("an older roster was accepted")
	}
	if st.version() != 3 {
		t.Fatalf("the roster version went backwards to %d", st.version())
	}
}

// Peers are held per flock, so a node id can only ever resolve inside its own
// flock. This is what stops one flock routing into another on a shared relay.
func TestFlocksCannotReachEachOther(t *testing.T) {
	s := newServer(t, Config{})

	sta, _, err := s.adopt(signed(t, key(t), key(t), "alpha", 1))
	if err != nil {
		t.Fatal(err)
	}
	stb, _, err := s.adopt(signed(t, key(t), key(t), "beta", 1))
	if err != nil {
		t.Fatal(err)
	}
	if sta == stb || sta.id == stb.id {
		t.Fatal("two different flocks share a relay slot")
	}

	sta.addPeer(&session{id: "a-machine", name: "a-machine"})
	if sta.peer("a-machine") == nil {
		t.Fatal("a peer was not registered in its own flock")
	}
	if stb.peer("a-machine") != nil {
		t.Fatal("a peer is visible from another flock")
	}
}

func TestAdoptRefusesATamperedRoster(t *testing.T) {
	s := newServer(t, Config{})
	sr := signed(t, key(t), key(t), "f", 1)
	sr.Roster = bytes.Replace(sr.Roster, []byte(`"f"`), []byte(`"g"`), 1)
	if _, _, err := s.adopt(sr); err == nil {
		t.Fatal("a tampered roster was adopted")
	}
}

// The roster's id has to follow its key. Otherwise a stranger could present a
// roster for a flock they cannot sign for.
func TestAdoptRefusesARosterThatClaimsAnotherFlock(t *testing.T) {
	s := newServer(t, Config{})
	sr := signed(t, key(t), key(t), "f", 1)

	// A roster signed by a different key is simply a different flock, and it
	// gets its own slot rather than displacing anything.
	other, _, err := s.adopt(signed(t, key(t), key(t), "f", 1))
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := s.adopt(sr)
	if err != nil {
		t.Fatal(err)
	}
	if first.id == other.id {
		t.Fatal("a roster signed by a different key took over an existing flock")
	}
}

func TestMaxFlocksIsEnforced(t *testing.T) {
	s := newServer(t, Config{MaxFlocks: 1})
	if _, _, err := s.adopt(signed(t, key(t), key(t), "first", 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.adopt(signed(t, key(t), key(t), "second", 1)); err == nil {
		t.Fatal("a second flock was accepted despite --max-flocks 1")
	}
}

func TestMaxMembersIsEnforced(t *testing.T) {
	s := newServer(t, Config{MaxMembers: 1})
	authority, member := key(t), key(t)
	sr := signed(t, authority, member, "f", 1)
	if _, _, err := s.adopt(sr); err != nil {
		t.Fatal(err)
	}

	// The same flock, grown to two members.
	r, err := sr.Open()
	if err != nil {
		t.Fatal(err)
	}
	extra := key(t)
	kex, err := extra.KexPub()
	if err != nil {
		t.Fatal(err)
	}
	r.Members = append(r.Members, flock.Member{
		ID:      flock.NodeID(extra.SignPub()),
		Name:    "b",
		Role:    flock.RoleSheep,
		SignKey: extra.SignPub(),
		KexKey:  kex,
		Added:   time.Now().UTC().Truncate(time.Second),
	})
	r.Version = 2
	grown, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.adopt(grown); err == nil {
		t.Fatal("a two-member roster was accepted despite --max-members 1")
	}
}

package flock

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testRoster(t *testing.T) (Roster, *KeyFile) {
	t.Helper()
	authority, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	machine, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kex, err := machine.KexPub()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return Roster{
		Version:  1,
		Name:     "test",
		FlockKey: authority.SignPub(),
		Members: []Member{{
			ID:      NodeID(machine.SignPub()),
			Name:    "a-sheep",
			Role:    RoleSheep,
			SignKey: machine.SignPub(),
			KexKey:  kex,
			Added:   now,
		}},
		IssuedAt: now,
	}, authority
}

// The roster is written pretty-printed but signed compact, so a round trip
// through disk must still verify. This is the bug that would silently lock
// everyone out of the flock.
func TestRosterSurvivesDisk(t *testing.T) {
	r, authority := testRoster(t)
	sr, err := SignRoster(r, authority.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sr.Verify(); err != nil {
		t.Fatalf("verify before save: %v", err)
	}

	path := filepath.Join(t.TempDir(), "roster.json")
	if err := sr.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("\n")) {
		t.Fatal("roster file is not readable formatting")
	}

	loaded, err := LoadSignedRoster(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.Verify()
	if err != nil {
		t.Fatalf("verify after save: %v", err)
	}
	if got.Name != "test" {
		t.Fatalf("name = %q", got.Name)
	}
	if len(got.Members) != 1 {
		t.Fatalf("members = %+v", got.Members)
	}
	if got.Members[0].Name != "a-sheep" {
		t.Fatalf("member name = %q", got.Members[0].Name)
	}
	if string(got.FlockKey) != string(r.FlockKey) {
		t.Fatal("flock key changed")
	}
}

func TestTamperedRosterIsRejected(t *testing.T) {
	r, authority := testRoster(t)
	sr, err := SignRoster(r, authority.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	sr.Roster = bytes.Replace(sr.Roster, []byte(`"test"`), []byte(`"evil"`), 1)
	if _, err := sr.Verify(); err == nil {
		t.Fatal("a tampered roster verified")
	}
}

func TestTamperedMemberNameIsRejected(t *testing.T) {
	r, authority := testRoster(t)
	sr, err := SignRoster(r, authority.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	sr.Roster = bytes.Replace(sr.Roster, []byte(`"a-sheep"`), []byte(`"b-sheep"`), 1)
	if _, err := sr.Verify(); err == nil {
		t.Fatal("a tampered roster verified")
	}
}

func TestWrongAuthorityIsRejected(t *testing.T) {
	r, _ := testRoster(t)
	impostor, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	sr, err := SignRoster(r, impostor.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sr.Verify(); err == nil {
		t.Fatal("a roster signed by the wrong key verified")
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	k, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.key.json")
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.SignPub()) != string(k.SignPub()) {
		t.Fatal("signing key changed")
	}
	kp, err := got.KexPub()
	if err != nil {
		t.Fatal(err)
	}
	orig, err := k.KexPub()
	if err != nil {
		t.Fatal(err)
	}
	if string(kp) != string(orig) {
		t.Fatal("kex key changed")
	}
	if err := k.Save(path); err == nil {
		t.Fatal("Save overwrote an existing key file")
	}
}

func TestNodeIDIsStableAndShort(t *testing.T) {
	k, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	id := NodeID(k.SignPub())
	if len(id) != 16 {
		t.Fatalf("id = %q (%d chars), want 16", id, len(id))
	}
	if id != NodeID(k.SignPub()) {
		t.Fatal("NodeID is not stable")
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			t.Fatalf("id %q has an unfriendly character %q", id, c)
		}
	}
}

// A relay tells one flock from another by an id derived from the flock key. If
// that id could be chosen rather than derived, a stranger could claim a flock
// they cannot sign for.
func TestFlockIDIsDerivedFromTheKey(t *testing.T) {
	a, _ := testRoster(t)
	b, _ := testRoster(t)

	if a.ID() != a.ID() {
		t.Fatal("a flock's id is not stable")
	}
	if a.ID() == b.ID() {
		t.Fatal("two different flocks share an id")
	}
	if a.ID() != FlockID(a.FlockKey) {
		t.Fatal("Roster.ID does not agree with FlockID")
	}
	if len(a.ID()) != 13 {
		t.Fatalf("flock id = %q (%d chars), want 13", a.ID(), len(a.ID()))
	}

	// The id must follow the key, not the name: two flocks called the same
	// thing are still different flocks.
	c := b
	c.Name = a.Name
	if c.ID() == a.ID() {
		t.Fatal("the id follows the name rather than the key")
	}
}

func TestRosterRemove(t *testing.T) {
	r, _ := testRoster(t)
	if !r.Remove("a-sheep") {
		t.Fatal("Remove reported nothing removed")
	}
	if len(r.Members) != 0 {
		t.Fatalf("members left: %+v", r.Members)
	}
	if r.Remove("a-sheep") {
		t.Fatal("Remove reported a second removal")
	}
}

func TestConnectorsKeepTheirPreferenceOrder(t *testing.T) {
	var r Roster
	r.UpsertConnector(Connector{Addr: "first:7000", Pin: "aaa"})
	r.UpsertConnector(Connector{Addr: "second:7000", Pin: "bbb"})
	r.UpsertConnector(Connector{Addr: "third:7000", Pin: "ccc"})

	got, err := r.ConnectorsFor("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"first:7000", "second:7000", "third:7000"}
	for i, c := range got {
		if c.Addr != want[i] {
			t.Fatalf("position %d = %q, want %q: the order is the preference order", i, c.Addr, want[i])
		}
	}

	// Updating an existing connector in place must not move it to the end.
	r.UpsertConnector(Connector{Addr: "first:7000", Pin: "changed"})
	got, _ = r.ConnectorsFor("")
	if got[0].Addr != "first:7000" || got[0].Pin != "changed" {
		t.Fatalf("re-registering a connector moved or failed to update it: %+v", got[0])
	}
	if len(r.Connectors) != 3 {
		t.Fatalf("re-registering added a duplicate: %d connectors", len(r.Connectors))
	}
}

func TestConnectorsSelection(t *testing.T) {
	var r Roster
	r.UpsertConnector(Connector{Addr: "a:7000", Pin: "aaa"})
	r.UpsertConnector(Connector{Addr: "b:7000", Pin: "bbb"})

	one, err := r.ConnectorsFor("b:7000")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Addr != "b:7000" {
		t.Fatalf("explicit selection returned %+v", one)
	}
	if _, err := r.ConnectorsFor("nope:7000"); err == nil {
		t.Fatal("an unknown connector address was accepted")
	}

	var none Roster
	if _, err := none.ConnectorsFor(""); err == nil {
		t.Fatal("a flock with no connectors was accepted")
	}
}

func TestRemoveConnector(t *testing.T) {
	var r Roster
	r.UpsertConnector(Connector{Addr: "a:7000", Pin: "aaa"})
	r.UpsertConnector(Connector{Addr: "b:7000", Pin: "bbb"})

	if !r.RemoveConnector("a:7000") {
		t.Fatal("RemoveConnector reported nothing removed")
	}
	if len(r.Connectors) != 1 || r.Connectors[0].Addr != "b:7000" {
		t.Fatalf("connectors after removal: %+v", r.Connectors)
	}
	if r.RemoveConnector("a:7000") {
		t.Fatal("RemoveConnector reported a second removal")
	}
}

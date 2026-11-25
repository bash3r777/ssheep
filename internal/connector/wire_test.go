package connector

import (
	"encoding/json"
	"testing"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/proto"
)

// The relay can only believe an offered roster if the signature survives the
// trip. The roster travels inside the authentication message; sending the bare
// roster without its signature made every offered flock fail with "flock: empty
// roster", which is a confusing way to say "you sent half the document".
func TestOfferedRosterKeepsItsSignature(t *testing.T) {
	authority, member := key(t), key(t)
	sr := signed(t, authority, member, "alpha", 1)

	// Exactly what peer.Dial puts on the wire.
	offered, err := json.Marshal(sr)
	if err != nil {
		t.Fatal(err)
	}
	env := proto.Wrap(proto.TypeAuth, proto.Auth{
		Flock:  "f",
		ID:     "n",
		Sig:    []byte{1, 2, 3},
		Roster: offered,
	})

	// Exactly what a relay does with it.
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back proto.Envelope
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	var a proto.Auth
	if err := back.Decode(&a); err != nil {
		t.Fatal(err)
	}
	var got flock.SignedRoster
	if err := json.Unmarshal(a.Roster, &got); err != nil {
		t.Fatal(err)
	}

	r, err := got.Verify()
	if err != nil {
		t.Fatalf("an offered roster did not survive the wire: %v", err)
	}
	if r.Name != "alpha" {
		t.Fatalf("name = %q, want alpha", r.Name)
	}
	if len(r.Members) != 1 {
		t.Fatalf("members = %+v", r.Members)
	}
}

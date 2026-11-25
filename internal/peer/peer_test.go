package peer

import (
	"bytes"
	"encoding/json"
	"testing"

	"ssheep.xyz/internal/proto"
)

// The connector routes with the envelope's target and reports failures with it,
// so it must always be set. A regression here made run wait out the full
// handshake timeout instead of saying which machine was unreachable.
func TestRouteToSetsTheTargetOnTheEnvelope(t *testing.T) {
	env := RouteTo("abc123", json.RawMessage(`{"k":"kex1"}`))
	if env.To != "abc123" {
		t.Fatalf("envelope To = %q, want abc123", env.To)
	}
	if env.Type != proto.TypeRoute {
		t.Fatalf("envelope type = %q", env.Type)
	}
	var rt proto.Route
	if err := env.Decode(&rt); err != nil {
		t.Fatal(err)
	}
	if rt.To != "abc123" {
		t.Fatalf("route To = %q, want abc123", rt.To)
	}
	if string(rt.Payload) != `{"k":"kex1"}` {
		t.Fatalf("payload = %s", rt.Payload)
	}
}

func TestAuthMessageBindsFlockIdentityAndNonce(t *testing.T) {
	nonce := []byte("0123456789abcdef")
	base := AuthMessage("flock-1", "node-a", nonce)

	cases := map[string][]byte{
		"another machine":   AuthMessage("flock-1", "node-b", nonce),
		"another flock":     AuthMessage("flock-2", "node-a", nonce),
		"another challenge": AuthMessage("flock-1", "node-a", []byte("fedcba9876543210")),
	}
	for what, got := range cases {
		if bytes.Equal(base, got) {
			t.Fatalf("%s produced the same authentication message", what)
		}
	}
	if uint(len(base)) < uint(len(proto.AuthContext)+len(nonce)) {
		t.Fatalf("authentication message is too short: %d", len(base))
	}
}

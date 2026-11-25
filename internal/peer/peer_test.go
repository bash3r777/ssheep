package peer

import (
	"encoding/json"
	"testing"

	"sshepard.com/internal/proto"
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

func TestAuthMessageBindsIdentityAndNonce(t *testing.T) {
	nonce := []byte("0123456789abcdef")
	a := AuthMessage("node-a", nonce)
	b := AuthMessage("node-b", nonce)
	if string(a) == string(b) {
		t.Fatal("two different machines produce the same authentication message")
	}
	c := AuthMessage("node-a", []byte("fedcba9876543210"))
	if string(a) == string(c) {
		t.Fatal("the nonce is not part of the authentication message")
	}
	if len(a) < len(proto.AuthContext)+len(nonce) {
		t.Fatalf("authentication message is too short: %d", len(a))
	}
}

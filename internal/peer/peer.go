// Package peer is the client side of the connector protocol: connect, prove
// identity, and — if the connector has never met this flock — hand over the
// roster that proves who may join it.
package peer

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/frame"
	"sshepard.com/internal/netx"
	"sshepard.com/internal/proto"
)

// Identity is who this machine is, as far as a connector is concerned.
type Identity struct {
	Flock  string // the flock's id, derived from the flock key
	NodeID string
	Key    ed25519.PrivateKey

	// Roster is offered to a relay that has never seen this flock. Because it
	// is signed by the flock key, the relay can check it while trusting
	// nothing in advance — which is what lets an open relay work without a
	// registration authority.
	Roster *flock.SignedRoster
}

// Dial connects, proves this machine's identity, and hands over the flock if the
// connector does not know it yet.
func Dial(addr, pin string, who Identity, timeout time.Duration) (*frame.Conn, error) {
	nc, err := netx.DialPinned(addr, pin, timeout)
	if err != nil {
		return nil, err
	}
	f := frame.New(nc)
	fail := func(err error) (*frame.Conn, error) {
		nc.Close()
		return nil, err
	}

	env, err := Read(f)
	if err != nil {
		return fail(err)
	}
	if env.Type != proto.TypeChallenge {
		return fail(fmt.Errorf("peer: expected a challenge, got %q", env.Type))
	}
	var ch proto.Challenge
	if err := env.Decode(&ch); err != nil {
		return fail(err)
	}

	sig := ed25519.Sign(who.Key, AuthMessage(who.Flock, who.NodeID, ch.Nonce))
	auth := proto.Auth{Flock: who.Flock, ID: who.NodeID, Sig: sig}
	if who.Roster != nil {
		// The roster rides along so a relay can learn a flock it has never met
		// and refresh one it has. It is sent on every connection, which is
		// chattier than it needs to be for very large flocks: the relay could
		// say "I already know, and mine is newer" and save the round trip. Worth
		// doing when flocks are big; not worth the extra protocol for now.
		offered, err := json.Marshal(who.Roster)
		if err != nil {
			return fail(err)
		}
		auth.Roster = offered
	}
	if err := Send(f, proto.Wrap(proto.TypeAuth, auth)); err != nil {
		return fail(err)
	}

	env, err = Read(f)
	if err != nil {
		return fail(err)
	}
	if env.Type != proto.TypeReady {
		var e proto.ErrMsg
		_ = env.Decode(&e)
		if e.Message == "" {
			e.Message = env.Type
		}
		return fail(fmt.Errorf("peer: connector refused: %s", e.Message))
	}
	return f, nil
}

// AuthMessage is what a machine signs to prove it holds its private key.
func AuthMessage(flockID, nodeID string, nonce []byte) []byte {
	return append([]byte(proto.AuthContext+flockID+"|"+nodeID+"|"), nonce...)
}

// Send writes one envelope.
func Send(f *frame.Conn, env *proto.Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return f.Write(b)
}

// Read reads the next envelope.
func Read(f *frame.Conn) (*proto.Envelope, error) {
	b, err := f.Read()
	if err != nil {
		return nil, err
	}
	var env proto.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// RouteTo wraps a payload for delivery to one member.
//
// The target is set both in the envelope and in the body: the connector needs
// it to route, and it uses the envelope copy to say *which* machine failed when
// a delivery cannot be made, so the sender learns immediately instead of waiting
// for a timeout.
func RouteTo(to string, payload json.RawMessage) *proto.Envelope {
	env := proto.Wrap(proto.TypeRoute, proto.Route{To: to, Payload: payload})
	env.To = to
	return env
}

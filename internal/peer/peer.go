// Package peer is the client side of the connector protocol: connect, prove
// identity, then send and receive frames.
package peer

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"sshepard.com/internal/frame"
	"sshepard.com/internal/netx"
	"sshepard.com/internal/proto"
)

// Dial connects to a connector, proves this machine's identity and returns an
// authenticated, framed connection.
func Dial(addr, pin, id string, priv ed25519.PrivateKey, timeout time.Duration) (*frame.Conn, error) {
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
	sig := ed25519.Sign(priv, AuthMessage(id, ch.Nonce))
	if err := Send(f, proto.Wrap(proto.TypeAuth, proto.Auth{ID: id, Sig: sig})); err != nil {
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

// AuthMessage is what a machine signs to prove it holds its private key. The
// context prefix stops a signature made for one purpose being replayed as another.
func AuthMessage(id string, nonce []byte) []byte {
	return append([]byte(proto.AuthContext+id+"|"), nonce...)
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

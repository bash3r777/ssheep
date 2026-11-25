// Package proto is the small protocol spoken between a machine and a connector.
//
// The connector only ever reads routing information: who is asking, who they
// want to reach, and the opaque payload in between. It never sees plaintext.
package proto

import "encoding/json"

// Envelope types.
const (
	TypeChallenge  = "challenge"  // connector -> peer: prove you own your key
	TypeAuth       = "auth"       // peer -> connector: signed challenge
	TypeReady      = "ready"      // connector -> peer: you are in
	TypeList       = "list"       // peer -> connector: who is there?
	TypeListReply  = "listreply"  // connector -> peer: the flock, with presence
	TypeRoute      = "route"      // peer -> connector: deliver this to someone
	TypeData       = "data"       // connector -> peer: someone sent you this
	TypeRoster     = "roster"     // connector -> peer: the current signed roster
	TypeRosterPush = "rosterpush" // shepherd -> connector: adopt this roster
	TypeError      = "error"
)

// AuthContext prefixes every authentication signature so a signature made for
// one purpose can never be replayed as another.
const AuthContext = "sshepard-auth|"

// Envelope is the only thing a connector parses.
type Envelope struct {
	Type string          `json:"t"`
	From string          `json:"f,omitempty"`
	To   string          `json:"to,omitempty"`
	Body json.RawMessage `json:"b,omitempty"`
}

// Wrap builds an envelope. It panics only on a programming error.
func Wrap(t string, body any) *Envelope {
	var raw json.RawMessage
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			panic("proto: " + err.Error())
		}
		raw = b
	}
	return &Envelope{Type: t, Body: raw}
}

// Decode reads the envelope body into v.
func (e *Envelope) Decode(v any) error {
	if len(e.Body) == 0 {
		return json.Unmarshal([]byte("{}"), v)
	}
	return json.Unmarshal(e.Body, v)
}

// Challenge asks a peer to prove it holds its private key.
type Challenge struct {
	Nonce []byte `json:"nonce"`
}

// Auth is the signed answer to a challenge.
type Auth struct {
	ID  string `json:"id"`
	Sig []byte `json:"sig"`
}

// Ready acknowledges a successful join.
type Ready struct {
	Version uint64 `json:"version"`
}

// MemberStatus is one flock member as seen by the connector.
type MemberStatus struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Online bool   `json:"online"`
}

// ListReply is the answer to a list request.
type ListReply struct {
	Version uint64         `json:"version"`
	Members []MemberStatus `json:"members"`
}

// Route is a request to deliver an opaque payload to a member.
type Route struct {
	To      string          `json:"to"`
	Payload json.RawMessage `json:"payload"`
}

// Data is a payload delivered from another member.
type Data struct {
	From    string          `json:"from"`
	Payload json.RawMessage `json:"payload"`
}

// ErrMsg reports a protocol-level failure.
type ErrMsg struct {
	Message string `json:"message"`
}

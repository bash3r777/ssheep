// Package proto is the small protocol spoken between a machine and a connector.
//
// The connector only ever reads routing information: who is asking, who they
// want to reach, and the opaque payload in between. It never sees plaintext.
package proto

import (
	"encoding/json"
	"time"
)

// Envelope types.
const (
	TypeChallenge = "challenge" // connector -> peer: prove you own your key
	TypeAuth      = "auth"      // peer -> connector: signed challenge, plus the roster
	TypeReady     = "ready"     // connector -> peer: you are in
	TypeList      = "list"      // peer -> connector: who is there?
	TypeListReply = "listreply" // connector -> peer: the flock, with presence and offers
	TypeRoute     = "route"     // peer -> connector: deliver this to someone
	TypeData      = "data"      // connector -> peer: someone sent you this
	TypeRoster    = "roster"    // connector -> peer: the current signed roster
	TypeOffer     = "offer"     // peer -> connector: I can serve as a connector
	TypeError     = "error"
)

// AuthContext prefixes the authentication signature, so a signature made for one
// purpose can never be replayed as another.
const AuthContext = "ssheep-auth|"

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

// Auth is the signed answer to a challenge. Flock says which flock this machine
// belongs to, so one relay can serve many.
//
// It carries the roster too. That is what lets a relay learn a flock it has
// never met, and refresh one it has: the roster is signed by the flock key, so
// the relay can believe it while trusting nothing in advance.
type Auth struct {
	Flock  string          `json:"flock"`
	ID     string          `json:"id"`
	Sig    []byte          `json:"sig"`
	Roster json.RawMessage `json:"roster,omitempty"`
}

// Ready acknowledges a successful join. YouAre is the address the connector sees
// the peer at, which is how a machine behind a NAT learns what it looks like from
// outside.
type Ready struct {
	Version uint64 `json:"version"`
	YouAre  string `json:"you_are,omitempty"`
}

// Offer is a machine volunteering to be a relay for its flock.
//
// It is what makes the setup one command: the master cannot know a connector's
// address in advance, so the connector says so itself, through whatever
// connector the flock already has. Any member can send one; only a member the
// roster lists as a connector is believed.
//
// Sig covers the whole offer, so the connector in the middle cannot rewrite the
// address and point the flock at itself.
type Offer struct {
	ID   string    `json:"id"`   // the member making the offer
	Name string    `json:"name"` // its name, for reporting
	Addr string    `json:"addr"` // host:port, as the machine believes it is reachable
	Pin  string    `json:"pin"`  // fingerprint of its relay certificate
	At   time.Time `json:"at"`
	Sig  []byte    `json:"sig,omitempty"`
}

// OfferMessage is what a machine signs to prove an offer is really its own.
func OfferMessage(flockID, nodeID, addr, pin string) []byte {
	return []byte("ssheep-offer|" + flockID + "|" + nodeID + "|" + addr + "|" + pin)
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
	Flock   string         `json:"flock,omitempty"`
	Name    string         `json:"name,omitempty"`
	Members []MemberStatus `json:"members"`
	Offers  []Offer        `json:"offers,omitempty"`
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

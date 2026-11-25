// Package tunnel builds the end-to-end encrypted session between a master and
// a sheep.
//
// The connector forwards every byte of this, and understands none of it. Two
// ephemeral keys are exchanged, each signed by the sender's permanent key, and
// the signatures are checked against the roster. That gives an authenticated
// session with forward secrecy, using nothing outside the standard library.
package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Wire kinds. Everything inside a route/data payload is one of these.
const (
	KindKex1 = "kex1" // initiator -> responder
	KindKex2 = "kex2" // responder -> initiator
	KindEnc  = "enc"  // an encrypted message in either direction
)

// Plaintext message kinds, which the connector never sees.
const (
	KindExec = "exec" // master -> sheep: run this
	KindOut  = "out"  // sheep -> master: standard output
	KindErr  = "err"  // sheep -> master: standard error
	KindExit = "exit" // sheep -> master: finished
)

// Wire is the tunnel's on-the-wire message.
type Wire struct {
	Kind string `json:"k"`
	Eph  []byte `json:"eph,omitempty"`
	Sig  []byte `json:"sig,omitempty"`
	CT   []byte `json:"ct,omitempty"`
}

// Msg is a plaintext message travelling inside the encrypted session.
type Msg struct {
	Kind string   `json:"k"`              // exec, out, err, exit
	Argv []string `json:"argv,omitempty"` // exec: the command
	Data []byte   `json:"d,omitempty"`    // out/err: output bytes
	Code int      `json:"c,omitempty"`    // exit: status code
	Err  string   `json:"e,omitempty"`    // exit: error, if the command could not run
}

// Pending is the state an initiator keeps between kex1 and kex2.
type Pending struct {
	eph            *ecdh.PrivateKey
	ephPub         []byte
	initID, respID string
}

// Session is an established encrypted session.
type Session struct {
	seal, open   cipher.AEAD
	sendN, recvN uint64
	mu           sync.Mutex
}

func transcript(context string, parts ...[]byte) []byte {
	out := []byte(context)
	for _, p := range parts {
		out = append(out, 0)
		out = append(out, p...)
	}
	return out
}

func sig1(initID, respID string, ephPub []byte) []byte {
	return transcript("ssheep-kex1", []byte(initID), []byte(respID), ephPub)
}

func sig2(initID, respID string, ephInit, ephResp []byte) []byte {
	return transcript("ssheep-kex2", []byte(initID), []byte(respID), ephInit, ephResp)
}

// Initiate starts a session to respID.
func Initiate(priv ed25519.PrivateKey, initID, respID string) (*Wire, *Pending, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := eph.PublicKey().Bytes()
	w := &Wire{Kind: KindKex1, Eph: pub, Sig: ed25519.Sign(priv, sig1(initID, respID, pub))}
	return w, &Pending{eph: eph, ephPub: pub, initID: initID, respID: respID}, nil
}

// Complete finishes the handshake from the initiator's side.
func (p *Pending) Complete(respKey ed25519.PublicKey, w *Wire) (*Session, error) {
	if w.Kind != KindKex2 {
		return nil, fmt.Errorf("tunnel: expected %s, got %q", KindKex2, w.Kind)
	}
	if !ed25519.Verify(respKey, sig2(p.initID, p.respID, p.ephPub, w.Eph), w.Sig) {
		return nil, errors.New("tunnel: responder's signature does not verify")
	}
	peer, err := ecdh.X25519().NewPublicKey(w.Eph)
	if err != nil {
		return nil, err
	}
	secret, err := p.eph.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return newSession(secret, p.initID, p.respID, true)
}

// Respond answers a kex1 and returns the kex2 to send back plus the session.
func Respond(priv ed25519.PrivateKey, myID, peerID string, peerKey ed25519.PublicKey, w *Wire) (*Wire, *Session, error) {
	if w.Kind != KindKex1 {
		return nil, nil, fmt.Errorf("tunnel: expected %s, got %q", KindKex1, w.Kind)
	}
	if !ed25519.Verify(peerKey, sig1(peerID, myID, w.Eph), w.Sig) {
		return nil, nil, errors.New("tunnel: initiator's signature does not verify")
	}
	peerEph, err := ecdh.X25519().NewPublicKey(w.Eph)
	if err != nil {
		return nil, nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := eph.ECDH(peerEph)
	if err != nil {
		return nil, nil, err
	}
	sess, err := newSession(secret, peerID, myID, false)
	if err != nil {
		return nil, nil, err
	}
	pub := eph.PublicKey().Bytes()
	out := &Wire{Kind: KindKex2, Eph: pub, Sig: ed25519.Sign(priv, sig2(peerID, myID, w.Eph, pub))}
	return out, sess, nil
}

func newSession(secret []byte, initID, respID string, initiator bool) (*Session, error) {
	okm := hkdf(secret, []byte(initID+"|"+respID), []byte("ssheep-v1"), 64)
	sendKey, recvKey := okm[:32], okm[32:]
	if !initiator {
		sendKey, recvKey = recvKey, sendKey
	}
	sc, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, err
	}
	rc, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, err
	}
	seal, err := cipher.NewGCM(sc)
	if err != nil {
		return nil, err
	}
	open, err := cipher.NewGCM(rc)
	if err != nil {
		return nil, err
	}
	return &Session{seal: seal, open: open}, nil
}

// Seal encrypts a message, returning nonce||ciphertext.
func (s *Session) Seal(plain []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nonce := make([]byte, s.seal.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.sendN)
	s.sendN++
	return append(nonce, s.seal.Seal(nil, nonce, plain, nil)...), nil
}

// Open decrypts a message produced by the peer's Seal.
func (s *Session) Open(ct []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.open.NonceSize()
	if len(ct) < n {
		return nil, errors.New("tunnel: short ciphertext")
	}
	nonce := ct[:n]
	if got := binary.BigEndian.Uint64(nonce[len(nonce)-8:]); got != s.recvN {
		return nil, fmt.Errorf("tunnel: frame %d arrived out of order (expected %d)", got, s.recvN)
	}
	plain, err := s.open.Open(nil, nonce, ct[n:], nil)
	if err != nil {
		return nil, err
	}
	s.recvN++
	return plain, nil
}

// MarshalMsg encodes a plaintext message for encryption.
func MarshalMsg(m *Msg) ([]byte, error) { return json.Marshal(m) }

// ParseMsg decodes a plaintext message that has been decrypted.
func ParseMsg(b []byte, m *Msg) error { return json.Unmarshal(b, m) }

// MarshalWire encodes a tunnel message for transport inside a route payload.
func MarshalWire(w *Wire) (json.RawMessage, error) { return json.Marshal(w) }

// ParseWire decodes a tunnel message from a route payload.
func ParseWire(raw json.RawMessage) (*Wire, error) {
	var w Wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

// hkdf is HKDF-SHA256, written out so the package stays dependency-free.
func hkdf(ikm, salt, info []byte, n int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)

	var out, block []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(block)
		h.Write(info)
		h.Write([]byte{i})
		block = h.Sum(nil)
		out = append(out, block...)
	}
	return out[:n]
}

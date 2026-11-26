// Package invite is the single-use ticket that lets a machine into the flock.
//
// An invite carries the new machine's key pair, a current copy of the roster,
// and nothing else. Private keys only ever travel inside an invite the operator
// hands over deliberately; they are never sent to a server.
package invite

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"ssheep.xyz/internal/flock"
)

// Version is bumped when the invite layout changes.
const Version = 1

// Invite is everything a new machine needs to join.
type Invite struct {
	Version  int                `json:"version"`
	Roster   flock.SignedRoster `json:"roster"`
	NodeID   string             `json:"node_id"`
	Name     string             `json:"name"`
	Role     string             `json:"role"`
	SignSeed []byte             `json:"sign_seed"`
	KexSeed  []byte             `json:"kex_seed"`

	// Flock is the flock's authority key, and it rides along only on a master
	// ticket.
	//
	// A master is the machine allowed to change the flock, and the only thing
	// that lets it is this key. So a master ticket is the authority to add and
	// remove machines, handed to whoever holds it. That is the whole point of a
	// second master — and the reason to mint as few as you can bear.
	Flock *flock.KeyFile `json:"flock,omitempty"`
}

// Key returns the identity for this invite.
func (i *Invite) Key() *flock.KeyFile {
	return &flock.KeyFile{SignSeed: i.SignSeed, KexSeed: i.KexSeed}
}

// Validate checks that the embedded roster verifies and that the invite's key
// matches the member it claims to be.
func (i *Invite) Validate() (flock.Roster, error) {
	r, err := i.Roster.Verify()
	if err != nil {
		return r, err
	}
	if i.Version != Version {
		return r, fmt.Errorf("invite: unsupported version %d", i.Version)
	}
	m := r.Find(i.NodeID)
	if m == nil {
		return r, errors.New("invite: this machine is not in the roster")
	}
	if string(m.SignKey) != string(i.Key().SignPub()) {
		return r, errors.New("invite: the key does not match the roster entry")
	}
	if i.Role == flock.RoleMaster {
		if i.Flock == nil {
			return r, errors.New("invite: a master ticket must carry the flock key")
		}
		if !bytes.Equal(i.Flock.SignPub(), r.FlockKey) {
			return r, errors.New("invite: the flock key does not match the roster")
		}
	}
	return r, nil
}

// Encode produces the compact, pasteable form.
func Encode(inv *Invite) (string, error) {
	b, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// Decode parses the compact form.
func Decode(s string) (*Invite, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invite: not a valid invite blob: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("invite: not a valid invite blob: %w", err)
	}
	defer zr.Close()
	b, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	var inv Invite
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// Resolve accepts either a path to an invite file or an encoded blob.
func Resolve(s string) (*Invite, error) {
	if b, err := os.ReadFile(s); err == nil {
		var inv Invite
		if err := json.Unmarshal(b, &inv); err != nil {
			return nil, fmt.Errorf("invite: %s: %w", s, err)
		}
		return &inv, nil
	}
	return Decode(s)
}

// Install unpacks an invite onto this machine. It refuses to overwrite an
// existing identity, so running it twice cannot silently re-key a machine.
//
// It is the same job for every role: write the key pair the invite carries, and
// the signed roster that goes with it. Which command the machine then runs
// decides what it does.
func Install(rosterPath, nodeKeyPath, source string) error {
	if _, err := os.Stat(nodeKeyPath); err == nil {
		return fmt.Errorf("invite: %s already exists; this machine is already enrolled", nodeKeyPath)
	}
	in, err := Resolve(source)
	if err != nil {
		return err
	}
	if _, err := in.Validate(); err != nil {
		return err
	}
	if err := in.Key().Save(nodeKeyPath); err != nil {
		return err
	}
	return in.Roster.Save(rosterPath)
}

// Save writes the human-readable form of an invite, readable only by its owner.
func Save(path string, inv *Invite) error {
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

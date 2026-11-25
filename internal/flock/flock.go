// Package flock defines the flock roster, node identity and the signing rules
// everything else depends on.
//
// The roster is the whole configuration. It is public, it is small, and it is
// signed by the flock key. Nothing secret is ever distributed with it.
package flock

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Roles a member can hold.
const (
	RoleSheep  = "sheep"
	RoleMaster = "master"
)

// Connector is a reachable address book and relay.
type Connector struct {
	Addr string `json:"addr"` // host:port
	Pin  string `json:"pin"`  // sha256 hex of the connector's TLS certificate
}

// Member is one machine in the flock.
type Member struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Role    string    `json:"role"`
	SignKey []byte    `json:"sign_key"` // ed25519 public key
	KexKey  []byte    `json:"kex_key"`  // x25519 public key
	Added   time.Time `json:"added"`
}

// Roster is the flock: public membership plus where to find the connectors.
type Roster struct {
	Version    uint64      `json:"version"`
	Name       string      `json:"name"`
	FlockKey   []byte      `json:"flock_key"` // ed25519 public key of the authority
	Members    []Member    `json:"members"`
	Connectors []Connector `json:"connectors,omitempty"`
	IssuedAt   time.Time   `json:"issued_at"`
}

// SignedRoster carries the roster's exact bytes alongside its signature, so
// verification never depends on how a JSON encoder orders or formats fields.
type SignedRoster struct {
	Roster json.RawMessage `json:"roster"`
	Sig    []byte          `json:"sig"`
}

// NodeID derives a short, stable, human-readable id from a public key.
func NodeID(pub []byte) string {
	sum := sha256.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	return strings.ToLower(enc)
}

// FlockID derives a short, stable id from the flock's public key.
//
// A relay that serves strangers needs to tell one flock from another, and it
// must be able to do that without being told anything it has to trust. Deriving
// the id from the key means a flock cannot claim an id it does not own: the
// only way to be flock X is to be able to sign as flock X.
func FlockID(pub []byte) string {
	sum := sha256.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:8])
	return strings.ToLower(enc)
}

// ID is this flock's identifier.
func (r Roster) ID() string { return FlockID(r.FlockKey) }

// SignRoster signs a roster with the flock key.
func SignRoster(r Roster, priv ed25519.PrivateKey) (*SignedRoster, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return &SignedRoster{Roster: b, Sig: ed25519.Sign(priv, b)}, nil
}

// Open decodes the roster without checking the signature.
func (sr *SignedRoster) Open() (Roster, error) {
	var r Roster
	if len(sr.Roster) == 0 {
		return r, errors.New("flock: empty roster")
	}
	err := json.Unmarshal(sr.Roster, &r)
	return r, err
}

// canonical returns the roster in the exact form that gets signed.
//
// The signature covers compact JSON. Files are written pretty-printed so the
// roster stays readable and diffable in git, so verification compacts the bytes
// again before checking. Compacting is lossless: it only removes whitespace.
func (sr *SignedRoster) canonical() ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, sr.Roster); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify checks the signature and returns the roster.
func (sr *SignedRoster) Verify() (Roster, error) {
	r, err := sr.Open()
	if err != nil {
		return r, err
	}
	if len(r.FlockKey) != ed25519.PublicKeySize {
		return r, errors.New("flock: roster has no valid flock key")
	}
	body, err := sr.canonical()
	if err != nil {
		return r, err
	}
	if !ed25519.Verify(ed25519.PublicKey(r.FlockKey), body, sr.Sig) {
		return r, errors.New("flock: roster signature does not verify")
	}
	return r, nil
}

// Bump returns a copy of the roster with the version incremented and the issue
// time refreshed, ready to be re-signed.
func (r Roster) Bump() Roster {
	r.Version++
	r.IssuedAt = time.Now().UTC().Truncate(time.Second)
	return r
}

// Find returns the member with the given id, or nil.
func (r *Roster) Find(id string) *Member {
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}

// FindByName returns the member with the given name, or nil.
func (r *Roster) FindByName(name string) *Member {
	for i := range r.Members {
		if r.Members[i].Name == name {
			return &r.Members[i]
		}
	}
	return nil
}

// Upsert adds or replaces a member by id.
func (r *Roster) Upsert(m Member) {
	for i := range r.Members {
		if r.Members[i].ID == m.ID {
			r.Members[i] = m
			return
		}
	}
	r.Members = append(r.Members, m)
}

// Remove deletes a member by name. It reports whether anything was removed.
func (r *Roster) Remove(name string) bool {
	out := r.Members[:0]
	removed := false
	for _, m := range r.Members {
		if m.Name == name {
			removed = true
			continue
		}
		out = append(out, m)
	}
	r.Members = out
	return removed
}

// UpsertConnector adds or replaces a connector, keeping the order in which they
// were added. The order is the preference order: members try them in turn.
func (r *Roster) UpsertConnector(c Connector) {
	for i := range r.Connectors {
		if r.Connectors[i].Addr == c.Addr {
			r.Connectors[i] = c
			return
		}
	}
	r.Connectors = append(r.Connectors, c)
}

// RemoveConnector deletes a connector by address. It reports whether anything
// was removed.
func (r *Roster) RemoveConnector(addr string) bool {
	out := r.Connectors[:0]
	removed := false
	for _, c := range r.Connectors {
		if c.Addr == addr {
			removed = true
			continue
		}
		out = append(out, c)
	}
	r.Connectors = out
	return removed
}

// ConnectorsFor returns the connectors a member should use.
//
// An explicit address selects just that one; otherwise every connector in the
// roster, in preference order. A single connector in the flock is a single
// point of failure, which is exactly what more than one of them is for.
func (r Roster) ConnectorsFor(want string) ([]Connector, error) {
	if want != "" {
		for _, c := range r.Connectors {
			if c.Addr == want {
				return []Connector{c}, nil
			}
		}
		return nil, fmt.Errorf("flock: %s is not a connector for this flock", want)
	}
	if len(r.Connectors) == 0 {
		return nil, errors.New("flock: this flock has no connector yet")
	}
	return r.Connectors, nil
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// KeyFile is a machine's identity: a signing key and a key-agreement key.
// Only the seeds are stored.
type KeyFile struct {
	SignSeed []byte `json:"sign_seed"` // 32-byte ed25519 seed
	KexSeed  []byte `json:"kex_seed"`  // 32-byte x25519 seed
}

// NewKeyFile generates a fresh identity.
func NewKeyFile() (*KeyFile, error) {
	s := make([]byte, 32)
	k := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &KeyFile{SignSeed: s, KexSeed: k}, nil
}

// SignKey returns the ed25519 private key.
func (f *KeyFile) SignKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(f.SignSeed) }

// SignPub returns the ed25519 public key.
func (f *KeyFile) SignPub() []byte { return f.SignKey().Public().(ed25519.PublicKey) }

// KexKey returns the x25519 private key.
func (f *KeyFile) KexKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().NewPrivateKey(f.KexSeed) }

// KexPub returns the x25519 public key bytes.
func (f *KeyFile) KexPub() ([]byte, error) {
	k, err := f.KexKey()
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// LoadKeyFile reads an identity from disk.
func LoadKeyFile(path string) (*KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f KeyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("flock: %s: %w", path, err)
	}
	if len(f.SignSeed) != 32 {
		return nil, fmt.Errorf("flock: %s: bad signing seed", path)
	}
	if len(f.KexSeed) != 32 {
		return nil, fmt.Errorf("flock: %s: bad kex seed", path)
	}
	return &f, nil
}

// Save writes an identity to disk, refusing to overwrite an existing file.
func (f *KeyFile) Save(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("flock: %s already exists", path)
	}
	return writeFile(path, f, 0o600)
}

// ---------------------------------------------------------------------------
// Roster I/O
// ---------------------------------------------------------------------------

// LoadSignedRoster reads a signed roster from disk.
func LoadSignedRoster(path string) (*SignedRoster, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sr SignedRoster
	if err := json.Unmarshal(b, &sr); err != nil {
		return nil, fmt.Errorf("flock: %s: %w", path, err)
	}
	return &sr, nil
}

// Save writes a signed roster atomically.
func (sr *SignedRoster) Save(path string) error { return writeFile(path, sr, 0o644) }

func writeFile(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------------------
// Well-known locations
// ---------------------------------------------------------------------------

// Dir is where a machine keeps its keys and roster copy.
func Dir() string {
	if d := os.Getenv("SSHEEP_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssheep"
	}
	return filepath.Join(home, ".ssheep")
}

// DefaultRosterPath is the machine's copy of the flock.
func DefaultRosterPath() string { return filepath.Join(Dir(), "roster.json") }

// DefaultFlockKeyPath is the authority key. Keep it offline.
func DefaultFlockKeyPath() string { return filepath.Join(Dir(), "flock.key.json") }

// DefaultNodeKeyPath is this machine's own identity.
func DefaultNodeKeyPath() string { return filepath.Join(Dir(), "node.key.json") }

// Package local is what one machine knows: the flocks it belongs to, each with
// its own identity.
//
// A machine can be in as many flocks as it likes, and it holds a separate key in
// each one. That is not just tidiness: a ticket is minted before the machine it
// is meant for has ever been spoken to, so the key has to come from the ticket.
// One key per flock also means the same box looks like a different machine to
// each flock it is in.
//
//	~/.ssheep/flocks/<name>/node.key.json     this machine's identity there
//	~/.ssheep/flocks/<name>/roster.json       the flock, signed
//	~/.ssheep/flocks/<name>/flock.key.json    the authority, if this machine holds it
package local

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/invite"
)

// Flock is one flock as this machine sees it.
type Flock struct {
	Name       string
	Dir        string
	RosterPath string
	NodePath   string
	KeyPath    string // where the authority key would be, whether or not it is
	Signed     *flock.SignedRoster
	Roster     flock.Roster
	ID         string
	Role       string // this machine's role, or "" when it is not a member
}

// Mastered reports whether this machine holds this flock's authority key.
func (f *Flock) Mastered() bool { return f.Role == flock.RoleMaster }

// Key loads this machine's identity in this flock.
func (f *Flock) Key() (*flock.KeyFile, error) { return flock.LoadKeyFile(f.NodePath) }

// Authority loads the flock key, if this machine has it.
func (f *Flock) Authority() (*flock.KeyFile, error) {
	if _, err := os.Stat(f.KeyPath); err != nil {
		return nil, fmt.Errorf("local: this machine does not hold the key for flock %q", f.Name)
	}
	return flock.LoadKeyFile(f.KeyPath)
}

func paths(name string) (dir, roster, node, key string) {
	dir = flock.FlockDir(name)
	return dir,
		filepath.Join(dir, "roster.json"),
		filepath.Join(dir, "node.key.json"),
		filepath.Join(dir, "flock.key.json")
}

// Create makes a new flock on this machine, with this machine as its master.
func Create(name string) (*Flock, error) {
	if flock.SafeName(name) == "" {
		return nil, errors.New("local: a flock needs a name")
	}
	dir, rosterPath, nodePath, keyPath := paths(name)
	if _, err := os.Stat(rosterPath); err == nil {
		return nil, fmt.Errorf("local: there is already a flock %q on this machine", name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	authority, err := flock.NewKeyFile()
	if err != nil {
		return nil, err
	}
	machine, err := flock.NewKeyFile()
	if err != nil {
		return nil, err
	}
	if err := authority.Save(keyPath); err != nil {
		return nil, err
	}
	if err := machine.Save(nodePath); err != nil {
		return nil, err
	}

	kex, err := machine.KexPub()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	now := time.Now().UTC().Truncate(time.Second)
	r := flock.Roster{
		Version:  1,
		Name:     name,
		FlockKey: authority.SignPub(),
		Members: []flock.Member{{
			ID:      flock.NodeID(machine.SignPub()),
			Name:    host,
			Role:    flock.RoleMaster,
			SignKey: machine.SignPub(),
			KexKey:  kex,
			Added:   now,
		}},
		IssuedAt: now,
	}
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return nil, err
	}
	if err := sr.Save(rosterPath); err != nil {
		return nil, err
	}
	return Open(name)
}

// Open loads one flock by name.
func Open(name string) (*Flock, error) {
	dir, rosterPath, nodePath, keyPath := paths(name)
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return nil, err
	}
	r, err := sr.Verify()
	if err != nil {
		return nil, err
	}
	f := &Flock{
		Name:       r.Name,
		Dir:        dir,
		RosterPath: rosterPath,
		NodePath:   nodePath,
		KeyPath:    keyPath,
		Signed:     sr,
		Roster:     r,
		ID:         r.ID(),
	}
	if key, err := f.Key(); err == nil {
		if m := r.Find(flock.NodeID(key.SignPub())); m != nil {
			f.Role = m.Role
		}
	}
	return f, nil
}

// All loads every flock this machine has state for. A flock it cannot read is
// reported and skipped: one broken directory should not hide the rest.
func All() ([]*Flock, error) {
	var out []*Flock
	var bad []string
	for _, n := range flock.FlockNames() {
		f, err := Open(n)
		if err != nil {
			bad = append(bad, n)
			continue
		}
		out = append(out, f)
	}
	if len(out) == 0 && len(bad) > 0 {
		return nil, fmt.Errorf("local: no flock on this machine could be read (%s)", strings.Join(bad, ", "))
	}
	return out, nil
}

// WithRole returns the flocks where this machine holds the given role.
func WithRole(role string) ([]*Flock, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}
	var out []*Flock
	for _, f := range all {
		if f.Role == role {
			out = append(out, f)
		}
	}
	return out, nil
}

// Install unpacks a ticket onto this machine and returns the flock it belongs to.
func Install(source string) (*Flock, error) {
	in, err := invite.Resolve(source)
	if err != nil {
		return nil, err
	}
	r, err := in.Validate()
	if err != nil {
		return nil, err
	}
	dir, rosterPath, nodePath, keyPath := paths(r.Name)
	if _, err := os.Stat(rosterPath); err == nil {
		return nil, fmt.Errorf("local: this machine is already in a flock called %q", r.Name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := in.Key().Save(nodePath); err != nil {
		return nil, err
	}
	// A master ticket carries the flock key, so the new master can change the
	// flock too. Every other ticket leaves it behind, which is why only a master
	// ever has one.
	if in.Flock != nil {
		if err := in.Flock.Save(keyPath); err != nil {
			return nil, err
		}
	}
	if err := in.Roster.Save(rosterPath); err != nil {
		return nil, err
	}
	return Open(r.Name)
}

// Resolve finds a flock by the name somebody typed. It falls back to matching
// the directory name, so a flock is reachable whether you use its name or the
// sanitised version of it.
func Resolve(name string) (*Flock, error) {
	if name == "" {
		return nil, errors.New("local: which flock?")
	}
	if f, err := Open(name); err == nil {
		return f, nil
	}
	want := flock.SafeName(name)
	for _, n := range flock.FlockNames() {
		if n == want {
			return Open(n)
		}
	}
	return nil, fmt.Errorf("local: there is no flock %q on this machine", name)
}

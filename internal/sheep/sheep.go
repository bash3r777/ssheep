// Package sheep is the agent that runs on a managed machine.
//
// A sheep only ever dials out. It holds its own private key, a copy of the
// roster, and nothing else. Commands arrive already encrypted for it, so the
// connector in the middle cannot read, change or forge them.
package sheep

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/frame"
	"sshepard.com/internal/invite"
	"sshepard.com/internal/peer"
	"sshepard.com/internal/proto"
	"sshepard.com/internal/tunnel"
)

// Install unpacks an invite onto this machine. It refuses to overwrite an
// existing identity, so running it twice cannot silently re-key a machine.
func Install(rosterPath, nodeKeyPath, source string) error {
	if _, err := os.Stat(nodeKeyPath); err == nil {
		return fmt.Errorf("sheep: %s already exists; this machine is already enrolled", nodeKeyPath)
	}
	in, err := invite.Resolve(source)
	if err != nil {
		return err
	}
	if _, err := in.Validate(); err != nil {
		return err
	}
	key := in.Key()
	if err := key.Save(nodeKeyPath); err != nil {
		return err
	}
	if err := in.Roster.Save(rosterPath); err != nil {
		return err
	}
	return nil
}

// Run joins the flock and serves until the connection ends.
func Run(rosterPath, nodeKeyPath, connectorAddr string) error {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	roster, err := sr.Verify()
	if err != nil {
		return err
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return err
	}
	id := flock.NodeID(key.SignPub())
	m := roster.Find(id)
	if m == nil {
		return errors.New("sheep: this machine is not in the roster")
	}
	addr, pin, err := endpoint(roster, connectorAddr)
	if err != nil {
		return err
	}
	conn, err := peer.Dial(addr, pin, id, key.SignKey(), 15*time.Second)
	if err != nil {
		return err
	}
	a := &Agent{
		id:       id,
		name:     m.Name,
		key:      key,
		roster:   roster,
		conn:     conn,
		sessions: map[string]*tunnel.Session{},
	}
	log.Printf("sheep: joined %q as %s (%s)", roster.Name, a.name, a.id)
	return a.serve()
}

func endpoint(roster flock.Roster, want string) (addr, pin string, err error) {
	if want == "" {
		if len(roster.Connectors) == 0 {
			return "", "", errors.New("sheep: this flock has no connector yet")
		}
		return roster.Connectors[0].Addr, roster.Connectors[0].Pin, nil
	}
	for _, c := range roster.Connectors {
		if c.Addr == want {
			return c.Addr, c.Pin, nil
		}
	}
	return "", "", fmt.Errorf("sheep: %s is not a known connector for this flock", want)
}

// Agent is a joined machine.
type Agent struct {
	id   string
	name string
	key  *flock.KeyFile
	conn *frame.Conn

	rmu    sync.RWMutex
	roster flock.Roster

	mu       sync.Mutex
	sessions map[string]*tunnel.Session
}

func (a *Agent) currentRoster() flock.Roster {
	a.rmu.RLock()
	defer a.rmu.RUnlock()
	return a.roster
}

func (a *Agent) setRoster(r flock.Roster) {
	a.rmu.Lock()
	a.roster = r
	a.rmu.Unlock()
}

func (a *Agent) member(id string) *flock.Member {
	a.rmu.RLock()
	defer a.rmu.RUnlock()
	return a.roster.Find(id)
}

func (a *Agent) serve() error {
	// Ask for the current roster straight away: a machine that joined earlier
	// may have been revoked, or the flock may have grown since the invite.
	if err := peer.Send(a.conn, proto.Wrap(proto.TypeRoster, nil)); err != nil {
		return err
	}
	for {
		env, err := peer.Read(a.conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case proto.TypeData:
			var d proto.Data
			if err := env.Decode(&d); err != nil {
				continue
			}
			a.handle(d.From, d.Payload)
		case proto.TypeRoster:
			a.adoptRoster(env)
		case proto.TypeError:
			var e proto.ErrMsg
			_ = env.Decode(&e)
			log.Printf("sheep: connector: %s", e.Message)
			if strings.Contains(e.Message, "roster") {
				return errors.New("sheep: this machine is no longer in the flock")
			}
		}
	}
}

// adoptRoster accepts a newer roster, but only a well-signed one for this flock.
func (a *Agent) adoptRoster(env *proto.Envelope) {
	var sr flock.SignedRoster
	if err := json.Unmarshal(env.Body, &sr); err != nil {
		return
	}
	r, err := sr.Verify()
	if err != nil {
		log.Printf("sheep: ignoring a roster that does not verify: %v", err)
		return
	}
	if cur := a.currentRoster(); !bytes.Equal(cur.FlockKey, r.FlockKey) {
		log.Printf("sheep: ignoring a roster signed by a different flock")
		return
	}
	a.setRoster(r)
}

func (a *Agent) handle(from string, payload []byte) {
	w, err := tunnel.ParseWire(payload)
	if err != nil {
		return
	}
	switch w.Kind {
	case tunnel.KindKex1:
		m := a.member(from)
		if m == nil || m.Role != flock.RoleShepherd {
			log.Printf("sheep: refusing a handshake from %s (not a shepherd)", from)
			return
		}
		reply, sess, err := tunnel.Respond(a.key.SignKey(), a.id, from, ed25519.PublicKey(m.SignKey), w)
		if err != nil {
			log.Printf("sheep: handshake with %s failed: %v", from, err)
			return
		}
		a.setSession(from, sess)
		a.sendWire(from, reply)

	case tunnel.KindEnc:
		sess := a.session(from)
		if sess == nil {
			return
		}
		plain, err := sess.Open(w.CT)
		if err != nil {
			log.Printf("sheep: could not decrypt a message from %s: %v", from, err)
			return
		}
		var msg tunnel.Msg
		if err := tunnel.ParseMsg(plain, &msg); err != nil {
			return
		}
		if msg.Kind == tunnel.KindExec {
			go a.exec(from, sess, msg.Argv)
		}
	}
}

// exec runs a command and streams its output back to the shepherd.
func (a *Agent) exec(from string, sess *tunnel.Session, argv []string) {
	if len(argv) == 0 {
		a.sendMsg(from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: "no command given"})
		return
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.sendMsg(from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: err.Error()})
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		a.sendMsg(from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		a.sendMsg(from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: err.Error()})
		return
	}

	var wg sync.WaitGroup
	stream := func(r io.Reader, kind string) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				a.sendMsg(from, sess, &tunnel.Msg{Kind: kind, Data: append([]byte(nil), buf[:n]...)})
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(2)
	go stream(stdout, tunnel.KindOut)
	go stream(stderr, tunnel.KindErr)
	wg.Wait()

	code := 0
	errText := ""
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
			errText = err.Error()
		}
	}
	a.sendMsg(from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: code, Err: errText})
}

func (a *Agent) sendMsg(to string, sess *tunnel.Session, msg *tunnel.Msg) {
	plain, err := tunnel.MarshalMsg(msg)
	if err != nil {
		return
	}
	ct, err := sess.Seal(plain)
	if err != nil {
		return
	}
	a.sendWire(to, &tunnel.Wire{Kind: tunnel.KindEnc, CT: ct})
}

func (a *Agent) sendWire(to string, w *tunnel.Wire) {
	raw, err := tunnel.MarshalWire(w)
	if err != nil {
		return
	}
	if err := peer.Send(a.conn, peer.RouteTo(to, raw)); err != nil {
		log.Printf("sheep: could not reach the connector: %v", err)
	}
}

func (a *Agent) setSession(id string, s *tunnel.Session) {
	a.mu.Lock()
	a.sessions[id] = s
	a.mu.Unlock()
}

func (a *Agent) session(id string) *tunnel.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[id]
}

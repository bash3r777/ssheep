// Package sheep is the agent that runs on a managed machine.
//
// A sheep only ever dials out. It holds its own private key, a copy of the
// roster, and nothing else. Commands arrive already encrypted for it, so the
// connectors in the middle cannot read, change or forge them.
//
// A sheep connects to every connector in the flock at once. That is what makes
// more than one connector worth having: the flock survives any one of them
// dying, and a shepherd can reach this machine through whichever one it is
// talking to.
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

// errRevoked means the flock no longer contains this machine. Retrying will not
// help, so the agent stops rather than hammering the connector.
var errRevoked = errors.New("sheep: this machine is no longer in the flock")

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
	return in.Roster.Save(rosterPath)
}

// Run joins the flock and serves until the process is stopped.
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
	a := &Agent{
		id:         id,
		name:       m.Name,
		key:        key,
		flock:      roster.ID(),
		roster:     roster,
		signed:     sr,
		rosterPath: rosterPath,
		only:       connectorAddr,
		links:      map[string]*runner{},
		stop:       make(chan struct{}),
	}
	log.Printf("sheep: %s (%s) in flock %q (%s)", a.name, a.id, roster.Name, a.flock)
	a.syncConnectors()

	// Links come and go as the flock changes, so there is nothing to wait for
	// except a reason to stop.
	<-a.stop
	return errors.New(a.haltReason)
}

// Agent is a joined machine.
type Agent struct {
	id    string
	name  string
	key   *flock.KeyFile
	flock string

	rmu    sync.RWMutex
	roster flock.Roster
	signed *flock.SignedRoster

	rosterPath string
	only       string // if set, use only this connector

	linkMu sync.Mutex
	links  map[string]*runner

	stopOnce   sync.Once
	stop       chan struct{}
	haltReason string
}

// runner keeps one connector link alive, and can be told to stop.
type runner struct {
	conn   flock.Connector
	cancel chan struct{}

	mu   sync.Mutex
	live *frame.Conn
}

// stop ends a link promptly: closing the connection unblocks the read that is
// otherwise sitting there waiting for a message that will never come.
func (r *runner) stop() {
	close(r.cancel)
	r.mu.Lock()
	if r.live != nil {
		_ = r.live.Close()
	}
	r.mu.Unlock()
}

func (r *runner) setLive(c *frame.Conn) {
	r.mu.Lock()
	r.live = c
	r.mu.Unlock()
}

func (r *runner) cancelled() bool {
	select {
	case <-r.cancel:
		return true
	default:
		return false
	}
}

// syncConnectors makes the links that are running match the flock's current
// connectors.
//
// A flock can grow a connector, drop one, or move one -- a connector that
// regenerated its certificate needs a new fingerprint -- and a machine that has
// been up for weeks should follow all of that without being restarted.
func (a *Agent) syncConnectors() {
	want, err := a.currentRoster().ConnectorsFor(a.only)
	if err != nil {
		want = nil
	}
	desired := make(map[string]flock.Connector, len(want))
	for _, c := range want {
		desired[c.Addr] = c
	}

	a.linkMu.Lock()
	var stopped []string
	for addr, r := range a.links {
		d, keep := desired[addr]
		if keep && d.Pin == r.conn.Pin {
			continue
		}
		r.stop()
		delete(a.links, addr)
		stopped = append(stopped, addr)
	}
	var started []flock.Connector
	for addr, c := range desired {
		if _, running := a.links[addr]; running {
			continue
		}
		r := &runner{conn: c, cancel: make(chan struct{})}
		a.links[addr] = r
		started = append(started, c)
		go a.follow(r)
	}
	live := len(a.links)
	a.linkMu.Unlock()

	for _, addr := range stopped {
		log.Printf("sheep: no longer using connector %s", addr)
	}
	for _, c := range started {
		log.Printf("sheep: following connector %s", c.Addr)
	}
	if live == 0 {
		log.Printf("sheep: this flock has no connector at the moment; waiting for one")
	}
}

// identity is what this machine presents to a connector.
func (a *Agent) identity() peer.Identity {
	a.rmu.RLock()
	defer a.rmu.RUnlock()
	return peer.Identity{
		Flock:  a.flock,
		NodeID: a.id,
		Key:    a.key.SignKey(),
		Roster: a.signed,
	}
}

func (a *Agent) setRoster(r flock.Roster, sr *flock.SignedRoster) {
	a.rmu.Lock()
	a.signed = sr
	a.roster = r
	a.rmu.Unlock()
}

// halt stops every connector link for good, and records why.
func (a *Agent) halt(reason string) {
	a.stopOnce.Do(func() {
		a.haltReason = reason
		close(a.stop)
	})
}

func (a *Agent) currentRoster() flock.Roster {
	a.rmu.RLock()
	defer a.rmu.RUnlock()
	return a.roster
}

func (a *Agent) member(id string) *flock.Member {
	a.rmu.RLock()
	defer a.rmu.RUnlock()
	return a.roster.Find(id)
}

// follow keeps one connector link alive, backing off if the connector is down.
func (a *Agent) follow(r *runner) {
	const maxBackoff = 30 * time.Second
	backoff := 2 * time.Second
	for {
		started := time.Now()
		err := a.serveConnector(r)

		if err != nil {
			if errors.Is(err, errRevoked) {
				a.halt(fmt.Sprintf("sheep: %s refused this machine: %v", r.conn.Addr, err))
				return
			}
			if time.Since(started) > maxBackoff {
				backoff = 2 * time.Second // it was healthy for a while; start over
			}
			log.Printf("sheep: connector %s: %v (retrying in %s)", r.conn.Addr, err, backoff)
		}

		select {
		case <-a.stop:
			return
		case <-r.cancel:
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// serveConnector holds one connection until it breaks or the link is stopped.
func (a *Agent) serveConnector(r *runner) error {
	c := r.conn
	conn, err := peer.Dial(c.Addr, c.Pin, a.identity(), 15*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "roster") || strings.Contains(err.Error(), "not in the") {
			return fmt.Errorf("%w (%v)", errRevoked, err)
		}
		return err
	}
	defer conn.Close()
	r.setLive(conn)
	defer r.setLive(nil)
	if r.cancelled() {
		return nil
	}

	l := &link{addr: c.Addr, conn: conn, sessions: map[string]*tunnel.Session{}}
	log.Printf("sheep: connected to %s", c.Addr)

	// Ask for the current roster: the flock may have grown or shrunk since the
	// invite was minted.
	if err := peer.Send(conn, proto.Wrap(proto.TypeRoster, nil)); err != nil {
		return err
	}
	for {
		env, err := peer.Read(conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case proto.TypeData:
			var d proto.Data
			if err := env.Decode(&d); err != nil {
				continue
			}
			a.handle(l, d.From, d.Payload)
		case proto.TypeRoster:
			a.adoptRoster(env)
		case proto.TypeError:
			var e proto.ErrMsg
			_ = env.Decode(&e)
			if strings.Contains(e.Message, "roster") {
				return fmt.Errorf("%w (%s)", errRevoked, e.Message)
			}
			log.Printf("sheep: connector %s: %s", c.Addr, e.Message)
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
	cur := a.currentRoster()
	if !bytes.Equal(cur.FlockKey, r.FlockKey) {
		log.Printf("sheep: ignoring a roster signed by a different flock")
		return
	}
	if r.Version <= cur.Version {
		return
	}
	a.setRoster(r, &sr)
	if a.rosterPath != "" {
		// Keep the newest copy on disk, so a restart does not resurrect a
		// roster that has been superseded.
		if err := sr.Save(a.rosterPath); err != nil {
			log.Printf("sheep: could not save the roster: %v", err)
		}
	}
	// The flock may have gained, lost or moved a connector. Follow it.
	a.syncConnectors()
}

// link is one live connection to one connector. Sessions live here rather than
// on the agent, because a shepherd reaching us through connector A is a
// different conversation from the same shepherd reaching us through connector B.
type link struct {
	addr string
	conn *frame.Conn

	mu       sync.Mutex
	sessions map[string]*tunnel.Session
}

func (l *link) setSession(id string, s *tunnel.Session) {
	l.mu.Lock()
	l.sessions[id] = s
	l.mu.Unlock()
}

func (l *link) session(id string) *tunnel.Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions[id]
}

func (a *Agent) handle(l *link, from string, payload []byte) {
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
		l.setSession(from, sess)
		a.sendWire(l, from, reply)

	case tunnel.KindEnc:
		sess := l.session(from)
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
			go a.exec(l, from, sess, msg.Argv)
		}
	}
}

// exec runs a command and streams its output back over the link it arrived on.
func (a *Agent) exec(l *link, from string, sess *tunnel.Session, argv []string) {
	if len(argv) == 0 {
		a.sendMsg(l, from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: "no command given"})
		return
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.sendMsg(l, from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: err.Error()})
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		a.sendMsg(l, from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		a.sendMsg(l, from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: -1, Err: err.Error()})
		return
	}

	var wg sync.WaitGroup
	stream := func(r io.Reader, kind string) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				a.sendMsg(l, from, sess, &tunnel.Msg{Kind: kind, Data: append([]byte(nil), buf[:n]...)})
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
	a.sendMsg(l, from, sess, &tunnel.Msg{Kind: tunnel.KindExit, Code: code, Err: errText})
}

func (a *Agent) sendMsg(l *link, to string, sess *tunnel.Session, msg *tunnel.Msg) {
	plain, err := tunnel.MarshalMsg(msg)
	if err != nil {
		return
	}
	ct, err := sess.Seal(plain)
	if err != nil {
		return
	}
	a.sendWire(l, to, &tunnel.Wire{Kind: tunnel.KindEnc, CT: ct})
}

func (a *Agent) sendWire(l *link, to string, w *tunnel.Wire) {
	raw, err := tunnel.MarshalWire(w)
	if err != nil {
		return
	}
	if err := peer.Send(l.conn, peer.RouteTo(to, raw)); err != nil {
		log.Printf("sheep: connector %s: %v", l.addr, err)
	}
}

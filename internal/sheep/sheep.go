// Package sheep is the agent that runs on a managed machine.
//
// A sheep only ever dials out. It holds its own private key, a copy of the
// roster, and nothing else. Commands arrive already encrypted for it, so the
// connectors in the middle cannot read, change or forge them.
//
// A sheep connects to every connector in the flock at once. That is what makes
// more than one connector worth having: the flock survives any one of them
// dying, and a master can reach this machine through whichever one it is
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
	"os/exec"
	"strings"
	"sync"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/frame"
	"ssheep.xyz/internal/netx"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
	"ssheep.xyz/internal/sshd"
	"ssheep.xyz/internal/tunnel"
)

// errRevoked means the flock no longer contains this machine. Retrying will not
// help, so the agent stops rather than hammering the connector.
var errRevoked = errors.New("sheep: this machine is no longer in the flock")

// Target is one flock this machine is a sheep in.
type Target struct {
	Name       string
	RosterPath string
	NodePath   string

	// RelayPin and RelayPort are this machine's own relay, when it runs one.
	// The sheep offers itself as a relay on the connection it already holds,
	// rather than opening a second one -- see offerOn.
	RelayPin  string
	RelayPort int

	// RelayAddr overrides where this machine says its relay can be reached,
	// for when the guess is wrong -- a router forwarding a different external
	// port, say. Empty means "work it out": see netx.CandidateAddrs.
	RelayAddr string
}

// RunMany serves every flock this machine is a sheep in, all at once.
//
// Each flock has its own identity, its own roster and its own connectors, so
// they are simply independent agents sharing a process. Losing one — being
// revoked from a flock, say — leaves the others alone.
func RunMany(targets []Target, connectorAddr string) error {
	if len(targets) == 0 {
		return errors.New("sheep: this machine is not a sheep in any flock")
	}
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			if err := Run(t, connectorAddr); err != nil {
				log.Printf("sheep: flock %q: %v", t.Name, err)
			}
		}(t)
	}
	wg.Wait()
	return nil
}

// Run joins one flock and serves until the process is stopped.
func Run(t Target, connectorAddr string) error {
	rosterPath, nodeKeyPath := t.RosterPath, t.NodePath
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
		relayPin:   t.RelayPin,
		relayPort:  t.RelayPort,
		relayAddr:  t.RelayAddr,
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

	relayPin  string // this machine's relay fingerprint, when it runs one
	relayPort int
	relayAddr string // where it says that relay can be reached, if told

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
	conn, ready, err := peer.DialReady(c.Addr, c.Pin, a.identity(), 15*time.Second)
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

	l := &link{addr: c.Addr, conn: conn, done: make(chan struct{}), sessions: map[string]*tunnel.Session{}, shells: map[string]*tunnel.Conn{}}
	defer close(l.done)
	log.Printf("sheep: connected to %s", c.Addr)

	// If this machine can relay, say so on the connection it already holds. A
	// second connection from the same machine would evict this one, because a
	// relay keeps one session per member -- and then the two would take turns
	// locking each other out, dropping commands routed through either.
	if a.relayPin != "" {
		go a.offerOn(l, conn, ready)
	}

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

// offerEvery is how often a machine reminds the flock it can relay. It only has
// to beat the relay's offer TTL, and re-offering also picks up an address that
// changed under us.
const offerEvery = 5 * time.Minute

// offerOn tells each relay this machine can reach that this machine can relay
// for the flock.
//
// It rides on the connection the machine already holds rather than opening its
// own. A relay keeps one session per member, so a machine that connected twice
// would have its two connections evict each other -- and a command routed to
// whichever one happened to be current would then time out.
//
// Every address the machine might be reachable at is offered, and the master
// keeps the ones that answer, so nobody has to work out which machine has a
// public address.
func (a *Agent) offerOn(l *link, conn *frame.Conn, ready proto.Ready) {
	for {
		mine := netx.CandidateAddrs(ready.YouAre, a.relayPort)
		if a.relayAddr != "" {
			mine = []string{a.relayAddr}
		}
		// Offering to our own relay is pointless: this machine already knows
		// where it is.
		if !contains(mine, l.addr) {
			for _, addr := range mine {
				if err := a.sendOffer(conn, addr); err != nil {
					return
				}
			}
		}
		select {
		case <-a.stop:
			return
		case <-l.done:
			return
		case <-time.After(offerEvery):
		}
	}
}

// sendOffer makes one signed offer of one address. The signature is what stops a
// relay rewriting the address and pointing the flock at itself.
func (a *Agent) sendOffer(conn *frame.Conn, addr string) error {
	o := proto.Offer{
		ID:   a.id,
		Name: a.name,
		Addr: addr,
		Pin:  a.relayPin,
		At:   time.Now().UTC(),
		Sig:  ed25519.Sign(a.key.SignKey(), proto.OfferMessage(a.flock, a.id, addr, a.relayPin)),
	}
	return peer.Send(conn, proto.Wrap(proto.TypeOffer, o))
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
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
// on the agent, because a master reaching us through connector A is a
// different conversation from the same master reaching us through connector B.
type link struct {
	addr string
	conn *frame.Conn
	done chan struct{} // closed when this link ends, so helpers can stop

	mu       sync.Mutex
	sessions map[string]*tunnel.Session
	shells   map[string]*tunnel.Conn
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

func (l *link) setShell(id string, c *tunnel.Conn) {
	l.mu.Lock()
	if c == nil {
		delete(l.shells, id)
	} else {
		l.shells[id] = c
	}
	l.mu.Unlock()
}

func (l *link) shell(id string) *tunnel.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.shells[id]
}

// clearShell only clears the entry if it is still this stream. A finished shell
// must not unregister a newer one that has already replaced it.
func (l *link) clearShell(id string, c *tunnel.Conn) {
	l.mu.Lock()
	if l.shells[id] == c {
		delete(l.shells, id)
	}
	l.mu.Unlock()
}

func (a *Agent) handle(l *link, from string, payload []byte) {
	w, err := tunnel.ParseWire(payload)
	if err != nil {
		return
	}
	switch w.Kind {
	case tunnel.KindKex1:
		m := a.member(from)
		if m == nil || m.Role != flock.RoleMaster {
			log.Printf("sheep: refusing a handshake from %s (not a master)", from)
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
		switch msg.Kind {
		case tunnel.KindExec:
			go a.exec(l, from, sess, msg.Argv)

		case tunnel.KindShell:
			// The stream is registered here, synchronously, before this loop goes
			// back to reading. The bytes of the ssh handshake are already on
			// their way, and a message that arrives before the stream exists
			// would be dropped — which showed up as a shell that worked only
			// sometimes.
			if old := l.shell(from); old != nil {
				// A previous session whose master never said goodbye: killed, or
				// a laptop that went to sleep. Replacing it is tidier than
				// leaving a shell running with nobody attached, and it means the
				// next attempt is never locked out by the last one.
				_ = old.Close()
			}
			conn := tunnel.NewConn(func(msg *tunnel.Msg) error {
				return a.sendMsgErr(l, from, sess, msg)
			})
			l.setShell(from, conn)
			go a.serveShell(l, from, conn)

		case tunnel.KindBytes:
			if c := l.shell(from); c != nil {
				// Push blocks when the shell is behind, and that is deliberate:
				// it travels back through the tunnel as backpressure rather than
				// filling memory or dropping a byte of somebody's terminal.
				c.Push(msg.Data)
			}

		case tunnel.KindEof:
			// The far end is done with this stream. Closing it ends the ssh
			// connection, which is what makes the server shut down and hang up
			// the shell rather than leaving it running with nobody attached.
			if c := l.shell(from); c != nil {
				_ = c.Close()
			}
		}
	}
}

// serveShell runs the ssh server for one session.
func (a *Agent) serveShell(l *link, from string, conn *tunnel.Conn) {
	defer l.clearShell(from, conn)
	defer conn.Close()

	// The one thing a command cannot tell you: which flock this is, and what
	// this machine is called in it.
	env := []string{"SSHEEP=1"}
	if a.flock != "" {
		env = append(env, "SSHEEP_FLOCK="+a.flock)
	}
	if a.name != "" {
		env = append(env, "SSHEEP_NODE="+a.name)
	}
	if err := sshd.Serve(conn, env); err != nil {
		log.Printf("sheep: shell with %s ended: %v", from, err)
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
	_ = a.sendMsgErr(l, to, sess, msg)
}

// sendMsgErr is sendMsg for callers that have to know whether it worked. A
// shell cannot carry on quietly if a byte of its stream went missing.
func (a *Agent) sendMsgErr(l *link, to string, sess *tunnel.Session, msg *tunnel.Msg) error {
	plain, err := tunnel.MarshalMsg(msg)
	if err != nil {
		return err
	}
	ct, err := sess.Seal(plain)
	if err != nil {
		return err
	}
	return a.sendWireErr(l, to, &tunnel.Wire{Kind: tunnel.KindEnc, CT: ct})
}

func (a *Agent) sendWire(l *link, to string, w *tunnel.Wire) {
	if err := a.sendWireErr(l, to, w); err != nil {
		log.Printf("sheep: connector %s: %v", l.addr, err)
	}
}

// sendWireErr is sendWire for callers that need to know whether it arrived. A
// shell cannot quietly lose a byte of somebody's terminal.
func (a *Agent) sendWireErr(l *link, to string, w *tunnel.Wire) error {
	raw, err := tunnel.MarshalWire(w)
	if err != nil {
		return err
	}
	return peer.Send(l.conn, peer.RouteTo(to, raw))
}

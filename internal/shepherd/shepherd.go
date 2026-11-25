// Package shepherd is the operator side: the commands you run against the flock.
//
// A shepherd connects to a connector like any other member, then speaks to each
// sheep through an end-to-end encrypted session the connector cannot open.
package shepherd

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/frame"
	"sshepard.com/internal/peer"
	"sshepard.com/internal/proto"
	"sshepard.com/internal/tunnel"
)

// handshakeTimeout bounds how long we wait for a sheep to answer a handshake.
const handshakeTimeout = 30 * time.Second

// Client is an open connection to the flock.
type Client struct {
	conn      *frame.Conn
	connector string
	me        string
	name      string
	priv      ed25519.PrivateKey
	roster    flock.Roster

	mu      sync.Mutex
	wires   map[string]*peerChan
	replies chan *proto.Envelope
	closed  chan struct{}
	once    sync.Once
}

// peerChan carries everything arriving from one machine: tunnel messages, and
// errors the connector raised about reaching it.
type peerChan struct {
	wires chan *tunnel.Wire
	errs  chan error
}

// Open connects this machine to the flock.
func Open(rosterPath, nodeKeyPath, connectorAddr string) (*Client, error) {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return nil, err
	}
	roster, err := sr.Verify()
	if err != nil {
		return nil, err
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return nil, err
	}
	id := flock.NodeID(key.SignPub())
	m := roster.Find(id)
	if m == nil {
		return nil, fmt.Errorf("shepherd: this machine (%s) is not in the roster", id)
	}
	if m.Role != flock.RoleShepherd {
		return nil, fmt.Errorf("shepherd: this machine is enrolled as %q, and only a shepherd can issue commands", m.Role)
	}
	connectors, err := roster.ConnectorsFor(connectorAddr)
	if err != nil {
		return nil, err
	}
	conn, serving, err := dialAny(connectors, id, key.SignKey())
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:      conn,
		connector: serving,
		me:        id,
		name:      m.Name,
		priv:      key.SignKey(),
		roster:    roster,
		wires:     map[string]*peerChan{},
		replies:   make(chan *proto.Envelope, 4),
		closed:    make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// dialTimeout is deliberately short: with more than one connector, a dead one
// must not hold up the whole command.
const dialTimeout = 5 * time.Second

// dialAny tries each connector in preference order and returns the first that
// accepts us. Losing a connector should mean a slower first attempt, not a
// broken flock.
func dialAny(connectors []flock.Connector, id string, priv ed25519.PrivateKey) (*frame.Conn, string, error) {
	var lastErr error
	for _, c := range connectors {
		conn, err := peer.Dial(c.Addr, c.Pin, id, priv, dialTimeout)
		if err == nil {
			return conn, c.Addr, nil
		}
		lastErr = err
		if len(connectors) > 1 {
			fmt.Fprintf(os.Stderr, "sshepard: connector %s: %v\n", c.Addr, err)
		}
	}
	return nil, "", fmt.Errorf("no connector answered: %w", lastErr)
}

// Connector reports which connector this client is talking to.
func (c *Client) Connector() string { return c.connector }

// Connectors returns every connector in this flock, in preference order.
func (c *Client) Connectors() []flock.Connector { return c.roster.Connectors }

// Close ends the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) shutdown() {
	c.once.Do(func() { close(c.closed) })
}

func (c *Client) readLoop() {
	defer c.shutdown()
	for {
		env, err := peer.Read(c.conn)
		if err != nil {
			return
		}
		switch env.Type {
		case proto.TypeData:
			var d proto.Data
			if err := env.Decode(&d); err != nil {
				continue
			}
			w, err := tunnel.ParseWire(d.Payload)
			if err != nil {
				continue
			}
			c.deliver(d.From, func(pc *peerChan) bool {
				select {
				case pc.wires <- w:
					return true
				default: // a slow reader must never stall the whole connection
					return false
				}
			})

		case proto.TypeError:
			var e proto.ErrMsg
			_ = env.Decode(&e)
			if env.To != "" {
				delivered := c.deliver(env.To, func(pc *peerChan) bool {
					select {
					case pc.errs <- errors.New(e.Message):
						return true
					default:
						return false
					}
				})
				if delivered {
					continue
				}
			}
			if strings.Contains(e.Message, "roster") {
				c.shutdown()
			}

		case proto.TypeListReply:
			select {
			case c.replies <- env:
			default:
			}
		}
	}
}

func (c *Client) deliver(id string, f func(*peerChan) bool) bool {
	c.mu.Lock()
	pc := c.wires[id]
	c.mu.Unlock()
	if pc == nil {
		return false
	}
	return f(pc)
}

// List asks the connector who is in the flock and who is online.
func (c *Client) List(timeout time.Duration) ([]proto.MemberStatus, error) {
	if err := peer.Send(c.conn, proto.Wrap(proto.TypeList, nil)); err != nil {
		return nil, err
	}
	select {
	case env := <-c.replies:
		var r proto.ListReply
		if err := env.Decode(&r); err != nil {
			return nil, err
		}
		sort.Slice(r.Members, func(i, j int) bool { return r.Members[i].Name < r.Members[j].Name })
		return r.Members, nil
	case <-time.After(timeout):
		return nil, errors.New("shepherd: the connector did not answer")
	case <-c.closed:
		return nil, errors.New("shepherd: lost the connector")
	}
}

// SheepNames returns the names of every member that can run commands.
func (c *Client) SheepNames() []string {
	var names []string
	for _, m := range c.roster.Members {
		if m.Role == flock.RoleSheep {
			names = append(names, m.Name)
		}
	}
	sort.Strings(names)
	return names
}

// Run executes argv on each named machine, all at once.
func (c *Client) Run(targets []string, argv []string, out io.Writer) error {
	multi := len(targets) > 1
	var wg sync.WaitGroup
	errs := make([]error, len(targets))
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			errs[i] = c.runOne(t, argv, out, multi)
		}(i, t)
	}
	wg.Wait()

	var bad []string
	for i, err := range errs {
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", targets[i], err))
		}
	}
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "; "))
	}
	return nil
}

func (c *Client) runOne(name string, argv []string, out io.Writer, multi bool) error {
	m := c.roster.FindByName(name)
	if m == nil {
		return errors.New("no machine with that name")
	}
	if m.Role != flock.RoleSheep {
		return fmt.Errorf("is a %s, not a sheep", m.Role)
	}
	pc := &peerChan{wires: make(chan *tunnel.Wire, 128), errs: make(chan error, 4)}
	c.mu.Lock()
	c.wires[m.ID] = pc
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.wires, m.ID)
		c.mu.Unlock()
	}()

	stdout := out
	stderr := out
	if multi {
		stdout = &lineWriter{w: out, prefix: name + "| "}
		stderr = stdout
	}

	w1, pending, err := tunnel.Initiate(c.priv, c.me, m.ID)
	if err != nil {
		return err
	}
	if err := c.sendWire(m.ID, w1); err != nil {
		return err
	}

	var sess *tunnel.Session
	select {
	case w := <-pc.wires:
		if w.Kind != tunnel.KindKex2 {
			return errors.New("the machine sent an unexpected handshake reply")
		}
		sess, err = pending.Complete(ed25519.PublicKey(m.SignKey), w)
		if err != nil {
			return err
		}
	case err := <-pc.errs:
		return err
	case <-time.After(handshakeTimeout):
		return errors.New("timed out waiting for the machine")
	case <-c.closed:
		return errors.New("lost the connector")
	}

	plain, err := tunnel.MarshalMsg(&tunnel.Msg{Kind: tunnel.KindExec, Argv: argv})
	if err != nil {
		return err
	}
	ct, err := sess.Seal(plain)
	if err != nil {
		return err
	}
	if err := c.sendWire(m.ID, &tunnel.Wire{Kind: tunnel.KindEnc, CT: ct}); err != nil {
		return err
	}

	for {
		select {
		case w := <-pc.wires:
			if w.Kind != tunnel.KindEnc {
				continue
			}
			body, err := sess.Open(w.CT)
			if err != nil {
				return err
			}
			var msg tunnel.Msg
			if err := tunnel.ParseMsg(body, &msg); err != nil {
				continue
			}
			switch msg.Kind {
			case tunnel.KindOut:
				_, _ = stdout.Write(msg.Data)
			case tunnel.KindErr:
				_, _ = stderr.Write(msg.Data)
			case tunnel.KindExit:
				if msg.Err != "" {
					return errors.New(msg.Err)
				}
				if msg.Code != 0 {
					return fmt.Errorf("exited with status %d", msg.Code)
				}
				return nil
			}
		case err := <-pc.errs:
			return err
		case <-c.closed:
			return errors.New("lost the connector")
		}
	}
}

func (c *Client) sendWire(to string, w *tunnel.Wire) error {
	raw, err := tunnel.MarshalWire(w)
	if err != nil {
		return err
	}
	return peer.Send(c.conn, peer.RouteTo(to, raw))
}

// Publish pushes the current roster to every connector in it.
//
// The roster is a file, but it is not the operator's job to copy it around. Any
// shepherd may publish it, and a connector only believes a roster that is signed
// by the flock key it already trusts.
func Publish(rosterPath, nodeKeyPath string) (pushed int, err error) {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return 0, err
	}
	roster, err := sr.Verify()
	if err != nil {
		return 0, err
	}
	if len(roster.Connectors) == 0 {
		return 0, nil
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return 0, err
	}
	id := flock.NodeID(key.SignPub())
	m := roster.Find(id)
	if m == nil || m.Role != flock.RoleShepherd {
		return 0, errors.New("shepherd: only a shepherd machine can publish the roster")
	}

	var firstErr error
	for _, cn := range roster.Connectors {
		if err := publishTo(cn, id, key.SignKey(), sr); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pushed++
	}
	return pushed, firstErr
}

func publishTo(cn flock.Connector, id string, priv ed25519.PrivateKey, sr *flock.SignedRoster) error {
	conn, err := peer.Dial(cn.Addr, cn.Pin, id, priv, 10*time.Second)
	if err != nil {
		return fmt.Errorf("%s: %w", cn.Addr, err)
	}
	defer conn.Close()
	if err := peer.Send(conn, proto.Wrap(proto.TypeRosterPush, sr)); err != nil {
		return fmt.Errorf("%s: %w", cn.Addr, err)
	}
	env, err := peer.Read(conn)
	if err != nil {
		return fmt.Errorf("%s: %w", cn.Addr, err)
	}
	if env.Type != proto.TypeReady {
		var e proto.ErrMsg
		_ = env.Decode(&e)
		if e.Message == "" {
			e.Message = env.Type
		}
		return fmt.Errorf("%s: %s", cn.Addr, e.Message)
	}
	return nil
}

// lineWriter prefixes every line, so output from several machines stays readable.
type lineWriter struct {
	w          io.Writer
	prefix     string
	atLineHead bool
	started    bool
}

func (l *lineWriter) Write(b []byte) (int, error) {
	for _, ch := range b {
		if !l.started || l.atLineHead {
			if _, err := io.WriteString(l.w, l.prefix); err != nil {
				return 0, err
			}
			l.started = true
			l.atLineHead = false
		}
		if _, err := l.w.Write([]byte{ch}); err != nil {
			return 0, err
		}
		if ch == '\n' {
			l.atLineHead = true
		}
	}
	return len(b), nil
}

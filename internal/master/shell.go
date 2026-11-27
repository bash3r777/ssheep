package master

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/tunnel"
)

// ExitError is a session that ended with a status other than zero. The command
// line turns it into the process exit status, the way ssh does, rather than
// printing it as a failure of the tool.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exited with status %d", e.Code) }

// openSession performs the tunnel handshake with one machine, whichever end
// asked for it.
func (c *Client) openSession(m *flock.Member, pc *peerChan) (*tunnel.Session, error) {
	w1, pending, err := tunnel.Initiate(c.priv, c.me, m.ID)
	if err != nil {
		return nil, err
	}
	if err := c.sendWire(m.ID, w1); err != nil {
		return nil, err
	}
	select {
	case w := <-pc.wires:
		if w.Kind != tunnel.KindKex2 {
			return nil, errors.New("the machine sent an unexpected handshake reply")
		}
		return pending.Complete(ed25519.PublicKey(m.SignKey), w)
	case err := <-pc.errs:
		return nil, err
	case <-time.After(handshakeTimeout):
		return nil, errors.New("timed out waiting for the machine")
	case <-c.closed:
		return nil, errors.New("lost the connector")
	}
}

// sendMsg seals one plaintext message into the session and puts it on the wire.
func (c *Client) sendMsg(to string, sess *tunnel.Session, msg *tunnel.Msg) error {
	plain, err := tunnel.MarshalMsg(msg)
	if err != nil {
		return err
	}
	ct, err := sess.Seal(plain)
	if err != nil {
		return err
	}
	return c.sendWire(to, &tunnel.Wire{Kind: tunnel.KindEnc, CT: ct})
}

// Shell opens an interactive session on one machine.
//
// The machine runs a real ssh server, fed by this session rather than by a
// socket, so everything ssh is good at — terminals, window sizes, signals, exit
// statuses — works, and nothing is exposed to the network for it to work. The
// connector in the middle sees the same thing it sees for `uptime`: ciphertext
// it holds no key for.
func (c *Client) Shell(name string, argv []string, in, out *os.File) error {
	m := c.roster.FindByName(name)
	if m == nil {
		return fmt.Errorf("no machine called %q", name)
	}
	if m.Role != flock.RoleSheep {
		return fmt.Errorf("%s is a %s, not a sheep", name, m.Role)
	}

	// A shell must not drop bytes, so this peer's channel blocks when the reader
	// is behind. That is what turns a slow terminal into backpressure, rather
	// than a scrambled screen or a growing buffer.
	pc := &peerChan{wires: make(chan *tunnel.Wire, 128), errs: make(chan error, 4), block: true}
	c.mu.Lock()
	c.wires[m.ID] = pc
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.wires, m.ID)
		c.mu.Unlock()
	}()

	sess, err := c.openSession(m, pc)
	if err != nil {
		return err
	}
	if err := c.sendMsg(m.ID, sess, &tunnel.Msg{Kind: tunnel.KindShell}); err != nil {
		return err
	}

	conn := tunnel.NewConn(func(msg *tunnel.Msg) error { return c.sendMsg(m.ID, sess, msg) })
	defer conn.Close()
	go c.pumpInto(pc, sess, conn)

	err = runRemoteShell(conn, argv, in, out, name)

	// Say the stream is finished rather than just going quiet. Without this the
	// far end keeps the session — and the shell it started — alive until the
	// connector connection happens to drop, and the next shell finds the door
	// still shut.
	_ = c.sendMsg(m.ID, sess, &tunnel.Msg{Kind: tunnel.KindEof})
	return err
}

// pumpInto moves bytes arriving over the tunnel into the stream ssh reads.
func (c *Client) pumpInto(pc *peerChan, sess *tunnel.Session, conn *tunnel.Conn) {
	for {
		select {
		case w := <-pc.wires:
			if w.Kind != tunnel.KindEnc {
				continue
			}
			body, err := sess.Open(w.CT)
			if err != nil {
				_ = conn.Close()
				return
			}
			var msg tunnel.Msg
			if err := tunnel.ParseMsg(body, &msg); err != nil {
				continue
			}
			if msg.Kind == tunnel.KindBytes {
				conn.Push(msg.Data)
			}
		case <-pc.errs:
			_ = conn.Close()
			return
		case <-c.closed:
			_ = conn.Close()
			return
		}
	}
}

// handshakeWait is how long to wait for the far end to say something before
// concluding it is a machine running an ssheep that predates shells.
const handshakeWait = 20 * time.Second

func runRemoteShell(conn *tunnel.Conn, argv []string, in, out *os.File, name string) error {
	cfg := &ssh.ClientConfig{
		User: "ssheep",
		// The machine was authenticated by the flock before a byte of ssh
		// arrived, and its ssh host key is invented per connection and thrown
		// away. Checking it here would be checking nothing, and pretending
		// otherwise would be worse than saying so out loud.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	type opened struct {
		client *ssh.Client
		reqs   <-chan *ssh.Request
		err    error
	}
	ready := make(chan opened, 1)
	go func() {
		sc, chans, reqs, err := ssh.NewClientConn(conn, name, cfg)
		if err != nil {
			ready <- opened{err: err}
			return
		}
		ready <- opened{client: ssh.NewClient(sc, chans, reqs), reqs: reqs}
	}()

	var client *ssh.Client
	select {
	case r := <-ready:
		if r.err != nil {
			return fmt.Errorf("could not open a session on %s: %w", name, r.err)
		}
		client = r.client
		go ssh.DiscardRequests(r.reqs)
	case <-time.After(handshakeWait):
		_ = conn.Close()
		return fmt.Errorf("%s did not answer — is it running an ssheep that knows about shell?", name)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("could not open a session on %s: %w", name, err)
	}
	defer sess.Close()

	if term.IsTerminal(int(in.Fd())) {
		w, h, err := term.GetSize(int(in.Fd()))
		if err != nil {
			w, h = 80, 24
		}
		name := os.Getenv("TERM")
		if name == "" {
			name = "xterm-256color"
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 38400,
			ssh.TTY_OP_OSPEED: 38400,
		}
		if err := sess.RequestPty(name, h, w, modes); err != nil {
			return fmt.Errorf("could not ask for a terminal on %s: %w", name, err)
		}
		restore, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), restore) //nolint:errcheck

		stop := onWindowResize(func() {
			if w, h, err := term.GetSize(int(in.Fd())); err == nil {
				_ = sess.WindowChange(h, w)
			}
		})
		defer stop()
	}

	sess.Stdin = in
	sess.Stdout = out
	sess.Stderr = out

	if len(argv) > 0 {
		// One command string is what ssh's exec request carries, so this is
		// quoted the way ssh tools have to quote: each argument wrapped so the
		// far side's shell splits it back into exactly what was asked for.
		if err := sess.Start(quoteForShell(argv)); err != nil {
			return err
		}
	} else if err := sess.Shell(); err != nil {
		return err
	}

	if err := sess.Wait(); err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return &ExitError{Code: ee.ExitStatus()}
		}
		return err
	}
	return nil
}

// quoteForShell turns arguments into one command string a shell will split back
// into exactly those arguments.
//
// It matters: `ssheep shell pi -- sh -c 'echo a b'` has three arguments, and
// joining them with spaces would turn them into four. ssh has the same single
// command string to work with, which is why every tool built on it has to do
// this properly.
func quoteForShell(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(parts, " ")
}

// Package sshd is the shell a sheep offers.
//
// It is a real ssh server, but it never listens on anything: its only transport
// is a tunnel.Conn, so the only way to reach it is a session the flock has
// already authenticated. That is why it asks for no further proof — there are no
// host keys to trust, no authorized_keys to copy, and no passwords to get wrong.
// The flock identity is the ssh identity, and the tunnel is the authentication.
//
// Everything ssh needs to be a terminal — the pty, the window size, the
// signals, the exit status — is done here on top of the standard library and two
// small, well-known modules. Nothing about it is exposed to the network, so
// there is nothing to scan, brute-force or rate-limit.
package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Serve runs an ssh server over conn until the connection ends. extraEnv is
// added to every shell it starts, which is how a shell knows which flock it is in.
func Serve(conn net.Conn, extraEnv []string) error {
	signer, err := ephemeralHostKey()
	if err != nil {
		return err
	}
	cfg := &ssh.ServerConfig{
		// The tunnel authenticated the peer as a master of this flock before a
		// byte of ssh arrived. A second check here would be weaker, not stronger.
		NoClientAuth: true,
	}
	cfg.AddHostKey(signer)

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return err
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	srv := &server{sessions: map[*session]bool{}}
	var wg sync.WaitGroup
	for ch := range chans {
		if ch.ChannelType() != "session" {
			// No port forwarding, no agent forwarding, no subsystems: a session
			// is all this is for.
			_ = ch.Reject(ssh.UnknownChannelType, "ssheep serves sessions only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		s := &session{ch: channel, env: extraEnv}
		srv.add(s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer srv.remove(s)
			s.serve(requests)
		}()
	}

	// The connection is gone. Nothing started on it should outlive it, or a
	// shell would still be running on the machine an hour later with nobody
	// attached to it.
	srv.stopAll()
	wg.Wait()
	return nil
}

// server is the book-keeping for one connection: which shells are running on it.
type server struct {
	mu       sync.Mutex
	sessions map[*session]bool
}

func (s *server) add(sess *session) {
	s.mu.Lock()
	s.sessions[sess] = true
	s.mu.Unlock()
}

func (s *server) remove(sess *session) {
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
}

func (s *server) stopAll() {
	s.mu.Lock()
	live := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		live = append(live, sess)
	}
	s.mu.Unlock()
	for _, sess := range live {
		sess.stop()
	}
}

func ephemeralHostKey() (ssh.Signer, error) {
	// Generated per connection and thrown away. The client does not check it,
	// because it has already checked the machine's real identity — the roster
	// key — at the tunnel layer. A stored host key would be a second, weaker
	// trust anchor for the same machine, and a file to lose.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

type ptyRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

type execRequest struct {
	Command string
}

type session struct {
	ch  ssh.Channel
	env []string

	mu      sync.Mutex
	ptmx    *os.File
	rows    uint32
	cols    uint32
	term    string
	wantPty bool
	started bool
}

func (s *session) serve(reqs <-chan *ssh.Request) {
	defer s.ch.Close()

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.term, s.rows, s.cols, s.wantPty = p.Term, p.Rows, p.Cols, true
			s.mu.Unlock()
			req.Reply(true, nil)

		case "window-change":
			var p ptyRequest
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				s.setSize(p.Rows, p.Cols)
			}
			// The ssh spec says this request wants no reply, so none is sent.

		case "shell":
			req.Reply(true, nil)
			go s.start(nil)

		case "exec":
			var e execRequest
			if err := ssh.Unmarshal(req.Payload, &e); err != nil || strings.TrimSpace(e.Command) == "" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			go s.start([]string{"/bin/sh", "-c", e.Command})

		default:
			// env, subsystem (sftp), signal: nothing else is served yet, and
			// saying so is better than appearing to accept it.
			req.Reply(false, nil)
		}
	}
	s.stop()
}

func (s *session) setSize(rows, cols uint32) {
	if rows == 0 || cols == 0 {
		return
	}
	s.mu.Lock()
	s.rows, s.cols = rows, cols
	ptmx := s.ptmx
	s.mu.Unlock()
	if ptmx != nil {
		_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	}
}

// start runs one command as the user the agent runs as, under a pty.
//
// It is deliberately not a login shell by default: the shell you get is the one
// your account has. Run the agent as yourself (a systemd user unit is the tidy
// way) and a shell here is your own environment, dotfiles and all.
func (s *session) start(argv []string) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	rows, cols, term, wantPty := s.rows, s.cols, s.term, s.wantPty
	s.mu.Unlock()

	if len(argv) == 0 {
		argv = []string{defaultShell()}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), s.env...)
	if term != "" {
		cmd.Env = append(cmd.Env, "TERM="+term)
	}

	// No terminal was asked for, so none is given: a script piping a command
	// through `ssheep shell` should get the bytes it asked for, not a terminal's
	// idea of line endings and echo.
	if !wantPty {
		cmd.Stdin = s.ch
		cmd.Stdout = s.ch
		cmd.Stderr = s.ch
		if err := cmd.Start(); err != nil {
			s.finish(127, fmt.Sprintf("could not start %s: %v", argv[0], err))
			return
		}
		s.finish(exitCode(cmd.Wait()), "")
		return
	}

	size := &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}
	if size.Rows == 0 {
		size.Rows = 24
	}
	if size.Cols == 0 {
		size.Cols = 80
	}

	ptmx, err := pty.StartWithSize(cmd, size)
	if err != nil {
		s.finish(127, fmt.Sprintf("could not start %s: %v", argv[0], err))
		return
	}
	s.mu.Lock()
	s.ptmx = ptmx
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.ptmx = nil
		s.mu.Unlock()
		// Closing the master is what hangs up the session: the child has this
		// pty as its controlling terminal, so it gets a SIGHUP rather than
		// being left running with nowhere to write.
		_ = ptmx.Close()
	}()

	go func() {
		// Keystrokes in. When the far end closes, this returns and the child
		// sees end-of-file, which is what makes ^D work.
		_, _ = io.Copy(ptmx, s.ch)
	}()

	_, _ = io.Copy(s.ch, ptmx)

	s.finish(exitCode(cmd.Wait()), "")
}

// exitCode turns a finished command into the status ssh reports.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// stop ends the session when the client goes away.
func (s *session) stop() {
	s.mu.Lock()
	ptmx := s.ptmx
	s.mu.Unlock()
	if ptmx != nil {
		_ = ptmx.Close()
	}
}

func (s *session) finish(code int, errText string) {
	if errText != "" {
		_, _ = io.WriteString(s.ch.Stderr(), errText+"\r\n")
	}
	if code < 0 {
		code = 1
	}
	_, _ = s.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
	_ = s.ch.Close()
}

func defaultShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	for _, sh := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(sh); err == nil {
			return sh
		}
	}
	return "/bin/sh"
}

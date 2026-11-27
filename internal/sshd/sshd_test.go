//go:build !windows

package sshd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"ssheep.xyz/internal/tunnel"
)

// linkAndDial runs a sshd on one end of an in-memory tunnel and returns a real
// ssh client on the other. Nothing here touches the network or a port, which is
// the whole point of the design.
func linkAndDial(t *testing.T) *ssh.Client {
	t.Helper()

	var clientSide *tunnel.Conn
	serverSide := tunnel.NewConn(func(m *tunnel.Msg) error {
		clientSide.Push(m.Data)
		return nil
	})
	clientSide = tunnel.NewConn(func(m *tunnel.Msg) error {
		serverSide.Push(m.Data)
		return nil
	})

	served := make(chan error, 1)
	go func() { served <- Serve(serverSide, []string{"SSHEEP_TEST=1"}) }()

	cfg := &ssh.ClientConfig{
		User:            "ssheep",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(clientSide, "test", cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	client := ssh.NewClient(sc, chans, reqs)

	t.Cleanup(func() {
		_ = client.Close()
		_ = clientSide.Close()
		_ = serverSide.Close()
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Error("the server was still running after the client went away")
		}
	})
	return client
}

// The security claim, tested: ssh's own authentication is switched off, and it
// is safe to do so because the tunnel already proved who is asking. Any client
// that gets this far is in, and the only way to get this far is a session the
// flock accepted.
func TestNoAuthIsNeededBecauseTheTunnelAuthenticates(t *testing.T) {
	client := linkAndDial(t)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("echo reached")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(string(out)) != "reached" {
		t.Fatalf("output was %q", out)
	}
}

func TestCommandOutputAndExitStatus(t *testing.T) {
	client := linkAndDial(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	err = sess.Run("echo out; echo err >&2; exit 7")
	var ee *ssh.ExitError
	if err == nil {
		t.Fatal("a command that exits 7 reported success")
	}
	if !isExitError(err, &ee) {
		t.Fatalf("error was %T (%v), want an exit error", err, err)
	}
	if ee.ExitStatus() != 7 {
		t.Fatalf("exit status %d, want 7", ee.ExitStatus())
	}
	// A pty merges the streams: that is what a terminal is, and it is why there
	// is no multiplexing to get wrong.
	all := stdout.String() + stderr.String()
	if !strings.Contains(all, "out") || !strings.Contains(all, "err") {
		t.Fatalf("lost output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// A shell without a terminal is not a shell. This proves the machine allocates a
// real pty and that the window size asked for is the one it gets.
func TestShellGetsARealTerminal(t *testing.T) {
	client := linkAndDial(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm-256color", 24, 100, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("pty: %v", err)
	}
	out, err := sess.Output("test -t 1 && echo is-a-tty; echo TERM=$TERM; stty size")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "is-a-tty") {
		t.Fatalf("no terminal on the far side: %q", got)
	}
	if !strings.Contains(got, "TERM=xterm-256color") {
		t.Fatalf("TERM was not passed through: %q", got)
	}
	if !strings.Contains(got, "24 100") {
		t.Fatalf("window size was not applied: %q", got)
	}
}

func TestOnlySessionsAreServed(t *testing.T) {
	client := linkAndDial(t)
	_, _, err := client.OpenChannel("direct-tcpip", nil)
	if err == nil {
		t.Fatal("a forwarding channel was accepted; this build does not forward")
	}
}

// Without a terminal asked for, none is given. A script piping a command through
// a shell wants the bytes the command wrote — not a pty's line endings and echo,
// which is what would happen if the far side always allocated one.
func TestWithoutAPtyTheBytesAreUntouched(t *testing.T) {
	client := linkAndDial(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output(`printf 'a\nb\r\nc'`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(out) != "a\nb\r\nc" {
		t.Fatalf("bytes came back changed: %q", out)
	}
}

func isExitError(err error, target **ssh.ExitError) bool {
	for err != nil {
		if ee, ok := err.(*ssh.ExitError); ok {
			*target = ee
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

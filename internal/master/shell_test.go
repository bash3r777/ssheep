package master

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"ssheep.xyz/internal/sshd"
	"ssheep.xyz/internal/tunnel"
)

// The client half of the shell, tested against the server half over nothing but
// an in-memory link: no port, no socket, no network.
func TestRemoteShellOverATunnel(t *testing.T) {
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
	go func() { served <- sshd.Serve(serverSide, nil) }()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Error("the far end did not stop")
		}
	})

	// stdout is a pipe so the test can read what came back; stdin is /dev/null,
	// which is not a terminal, so no pty is asked for and nothing is put into raw
	// mode behind the test runner's back.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	done := make(chan error, 1)
	go func() {
		done <- runRemoteShell(clientSide, []string{"echo", "hello from the far side"}, null, outW, "test")
		_ = outW.Close()
	}()

	got, _ := io.ReadAll(outR)
	if err := <-done; err != nil {
		t.Fatalf("shell: %v", err)
	}
	if !strings.Contains(string(got), "hello from the far side") {
		t.Fatalf("output was %q", got)
	}
}

// A session that ends non-zero must come back as an ExitError, so the command
// line can pass the status on the way ssh does instead of printing a failure.
func TestRemoteShellReportsTheExitStatus(t *testing.T) {
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
	go func() { served <- sshd.Serve(serverSide, nil) }()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		<-served
	})

	outR, outW, _ := os.Pipe()
	defer outR.Close()
	defer outW.Close()
	null, _ := os.Open(os.DevNull)
	defer null.Close()

	err := runRemoteShell(clientSide, []string{"exit", "3"}, null, outW, "test")
	ee, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("error was %T (%v), want *ExitError", err, err)
	}
	if ee.Code != 3 {
		t.Fatalf("exit code %d, want 3", ee.Code)
	}
}

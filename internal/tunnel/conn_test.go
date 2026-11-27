package tunnel

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// pair wires two Conns to each other the way a real session would: whatever one
// writes arrives at the other.
func pair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	var a, b *Conn
	a = NewConn(func(m *Msg) error {
		if m.Kind != KindBytes {
			t.Errorf("wrote a %q message; a stream should only carry %q", m.Kind, KindBytes)
		}
		b.Push(m.Data)
		return nil
	})
	b = NewConn(func(m *Msg) error {
		a.Push(m.Data)
		return nil
	})
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestConnCarriesBothWays(t *testing.T) {
	a, b := pair(t)

	if _, err := a.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("read %q, want %q", got, "hello")
	}

	// And back the other way, because a shell is two directions or nothing.
	if _, err := b.Write([]byte("world")); err != nil {
		t.Fatalf("write back: %v", err)
	}
	if _, err := io.ReadFull(a, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("read back %q, want %q", got, "world")
	}
}

// A Read larger than one message must still get whole bytes in order: the
// chunks are an implementation detail that the stream must hide.
func TestConnReassemblesAcrossChunks(t *testing.T) {
	a, b := pair(t)

	want := bytes.Repeat([]byte("ssheep"), 5000) // 30KB, more than one chunk
	go func() { _, _ = a.Write(want) }()

	got := make([]byte, 0, len(want))
	buf := make([]byte, 1024)
	for len(got) < len(want) {
		n, err := b.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream came back changed: %d bytes in, %d out", len(want), len(got))
	}
}

func TestConnCloseUnblocksRead(t *testing.T) {
	a, _ := pair(t)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := a.Read(buf)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = a.Close()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("read returned %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the stream left a read hanging")
	}
}

// The net.Conn methods ssh asks for must exist and must not lie about being
// ready: there are no deadlines on a stream that is not a socket.
func TestConnSatisfiesDeadlines(t *testing.T) {
	a, _ := pair(t)
	if err := a.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if a.LocalAddr().Network() != "ssheep" {
		t.Fatalf("network is %q", a.LocalAddr().Network())
	}
}

package tunnel

import (
	"io"
	"net"
	"sync"
	"time"
)

// Conn runs a byte-stream protocol inside an encrypted tunnel session.
//
// It exists so the interactive shell needs no protocol of its own. ssh already
// knows how to do terminals, window sizes, signals, half-closes and exit
// statuses; this hands it a net.Conn to do all of that over. The bytes travel as
// KindBytes messages inside the same session a command would use, so a connector
// learns exactly as much about a shell as it does about `uptime` — nothing.
//
// It is deliberately net.Conn and not a custom interface: ssh takes a net.Conn,
// and keeping it that shape means the day a real socket is wanted (a local ssh
// endpoint, say), the same code serves it.
type Conn struct {
	send   func(*Msg) error
	in     chan []byte
	buf    []byte
	closed chan struct{}
	once   sync.Once
}

// NewConn wraps a way of putting a message on the wire in a net.Conn.
func NewConn(send func(*Msg) error) *Conn {
	return &Conn{
		send:   send,
		in:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

// Push hands over bytes that arrived in a KindBytes message.
//
// It blocks when the reader is behind, and that is the point: the block travels
// back through the tunnel to whoever is producing the bytes, so a machine
// printing faster than the terminal can show — `cat` on something enormous, or
// just a stray `yes` — pushes back instead of filling memory.
func (c *Conn) Push(b []byte) {
	if len(b) == 0 {
		return
	}
	select {
	case c.in <- b:
	case <-c.closed:
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		select {
		case b := <-c.in:
			c.buf = b
		case <-c.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// maxChunk keeps one message comfortably inside the frame limit, and small
// enough that an interactive keystroke is never stuck behind much.
const maxChunk = 16 * 1024

func (c *Conn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		// Copied, because the caller may reuse the buffer the moment we return.
		chunk := append([]byte(nil), p[:n]...)
		if err := c.send(&Msg{Kind: KindBytes, Data: chunk}); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close ends the stream, which unblocks any Read waiting on it.
func (c *Conn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// The rest is bookkeeping ssh asks for and does not otherwise care about. There
// are no deadlines to honour: the tunnel is not a socket, and ssh's own
// handshake timeout is handled where the session is opened.
func (c *Conn) LocalAddr() net.Addr                { return addr("ssheep") }
func (c *Conn) RemoteAddr() net.Addr               { return addr("ssheep") }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type addr string

func (a addr) Network() string { return "ssheep" }
func (a addr) String() string  { return string(a) }

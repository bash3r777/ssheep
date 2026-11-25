// Package frame moves length-prefixed messages over a stream.
//
// Every connection in ssheep speaks the same framing. The connector routes
// frames without understanding what is inside them.
package frame

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// MaxFrame bounds a single message. Nothing legitimate comes close to this.
const MaxFrame = 8 << 20

// Conn is a framed stream.
type Conn struct {
	c  net.Conn
	r  *bufio.Reader
	mu sync.Mutex
}

// New wraps a connection.
func New(c net.Conn) *Conn { return &Conn{c: c, r: bufio.NewReader(c)} }

// Read returns the next frame's payload.
func (f *Conn) Read() ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(f.r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return nil, errors.New("frame: bad length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(f.r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Write sends one frame. Safe to call from several goroutines.
func (f *Conn) Write(b []byte) error {
	if len(b) > MaxFrame {
		return errors.New("frame: too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.c.Write(h[:]); err != nil {
		return err
	}
	_, err := f.c.Write(b)
	return err
}

// Close closes the underlying connection.
func (f *Conn) Close() error { return f.c.Close() }

// RemoteAddr reports the peer's address.
func (f *Conn) RemoteAddr() net.Addr { return f.c.RemoteAddr() }

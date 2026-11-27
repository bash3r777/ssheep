//go:build !windows

package master

import (
	"os"
	"os/signal"
	"syscall"
)

// onWindowResize calls cb whenever the local terminal is resized. Windows has no
// SIGWINCH; there the size is read once at the start and left alone.
func onWindowResize(cb func()) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				cb()
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

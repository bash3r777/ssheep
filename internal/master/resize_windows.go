//go:build windows

package master

// onWindowResize does nothing on Windows, which has no SIGWINCH.
func onWindowResize(cb func()) (stop func()) { return func() {} }

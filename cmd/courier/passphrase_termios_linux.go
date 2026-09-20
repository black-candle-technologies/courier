//go:build linux

package main

import "golang.org/x/sys/unix"

// Termios ioctl request codes differ between linux and darwin; the
// shared unix implementation in passphrase_termios_unix.go uses these.
const (
	termiosGet = unix.TCGETS
	termiosSet = unix.TCSETS
)

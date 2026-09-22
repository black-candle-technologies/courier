//go:build unix

package store

import (
	"os"
	"syscall"
)

// ownedByProcess reports whether the process may enforce permissions on fi.
// Root may enforce anything; otherwise the file must belong to the euid —
// otherwise we could neither tighten it nor trust its current mode.
func ownedByProcess(fi os.FileInfo) bool {
	if os.Geteuid() == 0 {
		return true
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Uid == uint32(os.Geteuid())
}

//go:build windows

package store

import (
	"os"
)

// ownedByProcess reports whether the process may enforce permissions on fi.
//
// Windows has no POSIX UID ownership: fi.Sys() carries Win32 file
// attributes, not a uid, so the Unix ownership comparison cannot be
// evaluated. The check is therefore a no-op on Windows — the mode
// tightening in enforceFilePerms/enforceDirPerms still runs
// best-effort (os.Chmod maps to the read-only attribute), but callers
// must not treat a true return here as a verified ownership claim.
func ownedByProcess(fi os.FileInfo) bool {
	return true
}

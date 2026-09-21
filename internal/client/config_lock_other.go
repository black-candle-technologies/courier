//go:build !unix && !windows

package client

// withConfigLock on platforms with neither unix flock nor the Windows
// LockFileEx implementation (e.g. plan9, js/wasm): cross-process config
// locking degrades to the in-process mutex only. Atomic save (temp file +
// rename) still applies, so torn writes are impossible; only
// cross-process read-modify-write serialization is lost.
//
// Platform support for concurrent Courier processes:
//
//	Platform   Cross-process config lock          Concurrent processes safe?
//	unix       flock on ~/.courier/config.lock    yes
//	windows    LockFileEx on ~/.courier/config.lock  yes
//	other      in-process mutex only              no — run a single process
//
// Courier's supported server and agent deployments are unix, and a
// Windows binary is published; both have real locks.
func withConfigLock(fn func() error) error {
	configMu.Lock()
	defer configMu.Unlock()
	return fn()
}

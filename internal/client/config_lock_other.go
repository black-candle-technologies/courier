//go:build !unix

package client

// withConfigLock on non-unix platforms (Windows): flock is unavailable,
// so cross-process config locking degrades to the in-process mutex only.
// Atomic save (temp file + rename) still applies, so torn writes are
// impossible; only cross-process read-modify-write serialization is lost.
// Courier's supported server and agent deployments are unix, where the
// real lock applies.
func withConfigLock(fn func() error) error {
	configMu.Lock()
	defer configMu.Unlock()
	return fn()
}

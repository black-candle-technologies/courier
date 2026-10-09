// Message expiry helpers (issue #53, disappearing messages).
//
// These lived in the shared-agent-state layer (issue #49, cut in #146)
// but belong to disappearing messages, which stay: they compute and
// check the expires_at timestamps on ordinary chat payloads.
package client

import (
	"fmt"
	"time"
)

// stateExpired reports whether an item with the given expiry timestamp
// is gone at now. Zero means "never expires".
func stateExpired(now, expiresAt int64) bool {
	return expiresAt != 0 && now >= expiresAt
}

// ttlExpiry converts a disappearing-message TTL into an absolute unix
// expiry timestamp stamped from the sender's clock (issue #53). Zero
// ttl means "never expires" (returned as 0). Negative ttls are
// rejected.
func ttlExpiry(ttl time.Duration) (int64, error) {
	if ttl < 0 {
		return 0, fmt.Errorf("ttl must not be negative")
	}
	if ttl == 0 {
		return 0, nil
	}
	return time.Now().Unix() + int64(ttl.Seconds()), nil
}

package client

import "testing"

// TestFSFramesFallThroughAsChatForOldClient: an older (pre-FS) client has
// no FS dispatch layer. Handshake frames must fall through to ordinary
// chat text — never crash the inbox pipeline, never silently vanish.
// (#146: graceful non-FS fallback for mixed-version pairs.)
func TestFSFramesFallThroughAsChatForOldClient(t *testing.T) {
	frames := []string{
		`{"cf":3,"t":"fs-init","v":1,"sid":"AAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"cf":3,"t":"fs-accept","v":1,"sid":"AAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"cf":3,"t":"fs-msg","v":1,"sid":"AAAAAAAAAAAAAAAAAAAAAA","n":0}`,
	}
	for _, f := range frames {
		body, _, _, _, _ := parseMessagePayload([]byte(f))
		if body != f {
			t.Fatalf("fs frame did not fall through as chat text: %q", body)
		}
	}
}

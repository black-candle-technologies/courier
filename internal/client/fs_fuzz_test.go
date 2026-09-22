package client

import (
	"strconv"
	"strings"
	"testing"
)

// FuzzParseFSPayload feeds arbitrary bytes to the forward-secrecy frame
// classifier. FS frames arrive as inner DM plaintext from the network,
// so this is the first line of defense: only well-formed frames with a
// recognized magic, version, and type may be intercepted as FS traffic;
// everything else must fall through as an ordinary message.
// Invariants: never panic; an accepted frame always carries the FS
// magic, the current version, and a known type; classification is
// deterministic.
func FuzzParseFSPayload(f *testing.F) {
	f.Add([]byte(`{"cf":3,"t":"fs-msg","v":1,"sid":"AAAAAAAAAAAAAAAAAAAAAA","n":5,"pn":3,"rpk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ct":"AA"}`))
	f.Add([]byte(`{"cf":3,"t":"fs-init","v":1,"sid":"AAAAAAAAAAAAAAAAAAAAAA","init_id":"AAAAAAAAAAAAAAAAAAAAAA","rk0":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","eph_pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","r_pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Add([]byte(`{"cf":3,"t":"fs-accept","v":1,"sid":"AAAAAAAAAAAAAAAAAAAAAA","init_id":"AAAAAAAAAAAAAAAAAAAAAA","eph_pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","r_pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Add([]byte(`hello, this is a legacy plaintext message`)) // legacy falls through
	f.Add([]byte(`{"body":"legacy json message"}`))            // legacy JSON falls through
	f.Add([]byte(``))                                          // empty
	f.Add([]byte(`{`))                                         // truncated
	f.Add([]byte(`{"cf":3,"t":"fs-msg","v":2}`))               // wrong version
	f.Add([]byte(`{"cf":2,"t":"fs-msg","v":1}`))               // wrong magic (channel frame)
	f.Add([]byte(`{"cf":3,"t":"fs-evil","v":1}`))              // unknown type
	f.Add([]byte(`{"cf":3,"t":null,"v":1}`))                   // null type
	f.Add([]byte(`{"cf":"3","t":"fs-msg","v":"1"}`))           // wrong field types
	f.Add([]byte(`{"cf":3,"t":"fs-msg","v":1,"n":"five"}`))
	f.Add([]byte(`{"cf":3.5,"t":"fs-msg","v":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, ok := parseFSPayload(data)
		if !ok {
			return
		}
		if p.Magic != fsMagic {
			t.Fatalf("parseFSPayload accepted magic %d for %q", p.Magic, data)
		}
		if p.Version != fsPayloadVersion {
			t.Fatalf("parseFSPayload accepted version %d for %q", p.Version, data)
		}
		switch p.Type {
		case fsTypeMsg, fsTypeInit, fsTypeAccept:
		default:
			t.Fatalf("parseFSPayload accepted unknown type %q for %q", p.Type, data)
		}
		// Classification must be deterministic.
		if _, ok2 := parseFSPayload(data); ok2 != ok {
			t.Fatalf("parseFSPayload not deterministic for %q", data)
		}
	})
}

// FuzzFSSkippedCounter feeds arbitrary strings to the skipped-message-key
// index parser ("<peer-rpk-b64>:<counter>"). The skipped-key map is
// deserialized from ~/.courier/fs.json, so its keys are attacker-shaped
// whenever the state file is. Invariants: never panic; success means the
// suffix after the final ':' parses as an int64 counter; rebuilding the
// key from that counter re-parses to the same counter.
func FuzzFSSkippedCounter(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:42")
	f.Add("rpk:0")
	f.Add("rpk:-1")
	f.Add("")
	f.Add("no-colon-here")
	f.Add(":")
	f.Add("rpk:")
	f.Add(":42")
	f.Add("rpk:4.5")
	f.Add("rpk:99999999999999999999999999") // overflow
	f.Add("a:b:c:7")                        // multiple colons: last wins
	f.Add("rpk:+12")                        // explicit plus
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := fsSkippedCounter(s)
		if !ok {
			return
		}
		// The parsed counter must be the int64 suffix after the last ':'.
		i := strings.LastIndex(s, ":")
		want, err := strconv.ParseInt(s[i+1:], 10, 64)
		if err != nil || want != n {
			t.Fatalf("fsSkippedCounter(%q) = %d, suffix parses as %d (err %v)", s, n, want, err)
		}
		// Rebuilding the entry key from the counter must re-parse.
		n2, ok2 := fsSkippedCounter(fsSkippedEntryKey("rpk", n))
		if !ok2 || n2 != n {
			t.Fatalf("fsSkippedCounter not stable for counter %d", n)
		}
	})
}

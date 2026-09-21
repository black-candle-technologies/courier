package envelope

import (
	"encoding/json"
	"strings"
	"testing"
)

// seedManifest is a structurally valid attachment manifest: 1000-byte
// file, one wrapped data key for the fixed test identity.
const seedManifest = `{"filename":"photo.jpg","mime":"image/jpeg","size":1000,` +
	`"sha256":"0000000000000000000000000000000000000000000000000000000000000000",` +
	`"chunks":1,"blob_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
	`"keys":[{"recipient":"ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",` +
	`"eph":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
	`"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
	`"sealed_key":"AA"}]}`

// FuzzValidateManifest feeds arbitrary bytes through the attachment
// manifest pipeline: JSON unmarshal into AttachmentManifest, then
// ValidateManifest (filename/MIME/size/chunk-count/blob-id/hash/key
// shape checks). Both the relay (on send) and the recipient (on
// download) enforce this on untrusted input.
// Invariants: never panic, and validation is deterministic.
func FuzzValidateManifest(f *testing.F) {
	f.Add([]byte(seedManifest)) // valid
	f.Add([]byte(``))           // empty
	f.Add([]byte(`{`))          // truncated
	f.Add([]byte(`[]`))         // wrong top-level type
	f.Add([]byte(`{"filename":"","size":0,"chunks":0,"keys":[]}`))
	f.Add([]byte(`{"filename":"a/b","mime":"x","size":1000,"sha256":"` +
		strings.Repeat("0", 64) + `","chunks":1,` +
		`"blob_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","keys":[]}`)) // path separator + no keys
	f.Add([]byte(`{"filename":"..","mime":"` + strings.Repeat("m", 200) +
		`","size":-5,"sha256":"zz","chunks":99,` +
		`"blob_id":"!!!","keys":[{"recipient":"ed25519:","eph":"","nonce":"","sealed_key":""}]}`))
	f.Add([]byte(`{"filename":"` + strings.Repeat("f", 300) +
		`","size":99999999999,"chunks":1,` +
		`"blob_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
		`"sha256":"` + strings.Repeat("0", 64) + `","keys":[]}`)) // oversized name/size
	f.Fuzz(func(t *testing.T, data []byte) {
		var m AttachmentManifest
		if err := json.Unmarshal(data, &m); err != nil {
			return
		}
		err1 := ValidateManifest(&m)
		err2 := ValidateManifest(&m)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("ValidateManifest not deterministic for %q", data)
		}
	})
}

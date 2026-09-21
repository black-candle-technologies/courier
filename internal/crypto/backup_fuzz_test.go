package crypto

import (
	"encoding/json"
	"testing"
)

// seedBackupFile is a real SealBackup output (passphrase
// "test-passphrase-for-fuzz") used as the valid seed for the backup
// fuzz targets below.
const seedBackupFile = `{
  "format": "courier-backup",
  "version": 1,
  "kdf": "scrypt",
  "scrypt_n": 32768,
  "scrypt_r": 8,
  "scrypt_p": 1,
  "salt": "upk2Pko7LQm59jMl2u23CQ",
  "nonce": "APbyLp_DtbCtvs_6XdrsiEfDTWQEHE5f",
  "ciphertext": "McfXTWC8hFhxkE_OrpN7scJ6mSxokdRHC5eiqsFL-ha8XKPKtlRNo32mUAHOHPy4KpFhCh-XCpKn9KMZ1_xgO-3D_nq83EFXhy_4Q0s7lwg_4EXsDSORUMoSOLxXeB7Vsv8MYMvMGBKfScE0T-HZJ3D60sQTswVHEENjrx8OxNVrPHWigiOZU0LWvM9Wd48-SCMCEtO5pES8HykGXcQS2QLWgY5iqf9dWN5RjKop5GzmeEfPnpMlL8t1HsRQVkkvMJY7GWMvTlbd5HEStLOzY3GG9QiN_nxafwfI3aKkxaPH8fCTofVhcPrRe8w0C3qt10u4noUoOpDxYdL8KL08mj1tAyuPyVZEOqljhEOBK3TpyH_o8fcrHqldzk_YQcXqWZyMMMRfNAyR4J9ExV8qGtK7R1eqqXd5njxrhaCv06UFjqfZQHbR7oGc4n4HooCbFy0yEg"
}`

// FuzzBackupPayloadValidate feeds arbitrary bytes through the backup
// manifest pipeline: JSON unmarshal into BackupPayload, then Validate
// (which checks version/kind, address shape, seed/address binding, and
// key shapes, including an X25519 derivation from the seed).
// Invariants: never panic, and validation is deterministic.
func FuzzBackupPayloadValidate(f *testing.F) {
	// A structurally valid payload (seed/address bound to the fixed
	// test identity).
	f.Add([]byte(`{"version":1,"kind":"backup","created_at":1780000000,` +
		`"address":"ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",` +
		`"seed":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","enc_keys":` +
		`[{"pub":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","priv":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","epoch":1,"created_at":1780000000}]}`))
	f.Add([]byte(``))                            // empty
	f.Add([]byte(`{`))                           // truncated
	f.Add([]byte(`[]`))                          // wrong top-level type
	f.Add([]byte(`{"version":99}`))              // bad version
	f.Add([]byte(`{"version":1,"kind":"evil"}`)) // bad kind
	f.Add([]byte(`{"version":1,"kind":"backup","address":"ed25519:","seed":"","enc_keys":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var p BackupPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return
		}
		err1 := p.Validate()
		err2 := p.Validate()
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("BackupPayload.Validate not deterministic for %q", data)
		}
	})
}

// backupScryptParams mirrors the outer container's KDF parameters so the
// fuzz harness can bound them before OpenBackup runs scrypt.
type backupScryptParams struct {
	ScryptN int `json:"scrypt_n"`
	ScryptR int `json:"scrypt_r"`
	ScryptP int `json:"scrypt_p"`
}

// maxFuzzScrypt bounds the KDF work the OpenBackup fuzz target will
// attempt. Production OpenBackup trusts the file's scrypt_n/r/p and
// x/crypto's guard still permits parameters that allocate terabytes
// (e.g. N=2^30, r=8 -> ~1 TiB for the V array) before failing, which
// would OOM the fuzzer itself. Legitimate files use N=32768, r=8, p=1;
// inputs outside the bound below are skipped by the harness. The
// missing parameter validation in OpenBackup is tracked as issue #125
// (backup files arrive from untrusted sources).
const (
	maxFuzzScryptN = 1 << 18 // ~8x the legitimate N=32768; worst case ~0.5s per input
	maxFuzzScryptR = 32
	maxFuzzScryptP = 4
)

// FuzzOpenBackup feeds arbitrary bytes to the full backup-file parser
// (outer JSON, KDF parameters, scrypt, secretbox open, inner JSON,
// payload validation). Invariants: never panic, never hang (KDF work is
// bounded by the harness, see above), and the valid seed decrypts with
// the right passphrase and fails with a wrong one.
func FuzzOpenBackup(f *testing.F) {
	f.Add(seedBackupFile)                                                                                                                                                                                        // valid
	f.Add("")                                                                                                                                                                                                    // empty
	f.Add("{")                                                                                                                                                                                                   // truncated
	f.Add(`{"format":"courier-backup","version":1,"kdf":"scrypt","scrypt_n":32768,"scrypt_r":8,"scrypt_p":1,"salt":"upk2Pko7LQm59jMl2u23CQ","nonce":"APbyLp_DtbCtvs_6XdrsiEfDTWQEHE5f","ciphertext":"!!!!"}`)    // bad ciphertext b64
	f.Add(`{"format":"courier-backup","version":1,"kdf":"scrypt","scrypt_n":262144,"scrypt_r":8,"scrypt_p":1,"salt":"upk2Pko7LQm59jMl2u23CQ","nonce":"APbyLp_DtbCtvs_6XdrsiEfDTWQEHE5f","ciphertext":"AA"}`)     // N at harness bound
	f.Add(`{"format":"courier-backup","version":1,"kdf":"scrypt","scrypt_n":1073741824,"scrypt_r":8,"scrypt_p":1,"salt":"upk2Pko7LQm59jMl2u23CQ","nonce":"APbyLp_DtbCtvs_6XdrsiEfDTWQEHE5f","ciphertext":"AA"}`) // N=2^30: skipped by harness
	f.Add(`{"format":"other","version":1}`)                                                                                                                                                                      // wrong format
	f.Fuzz(func(t *testing.T, raw string) {
		var params backupScryptParams
		if err := json.Unmarshal([]byte(raw), &params); err == nil {
			// Bound the KDF work before OpenBackup can attempt it.
			if params.ScryptN <= 0 || params.ScryptN > maxFuzzScryptN ||
				params.ScryptR <= 0 || params.ScryptR > maxFuzzScryptR ||
				params.ScryptP <= 0 || params.ScryptP > maxFuzzScryptP {
				return
			}
		}
		p, err := OpenBackup([]byte("test-passphrase-for-fuzz"), []byte(raw))
		if err != nil {
			return
		}
		// A successfully opened backup must validate, and must not
		// open under a wrong passphrase.
		if verr := p.Validate(); verr != nil {
			t.Fatalf("OpenBackup returned payload failing Validate: %v", verr)
		}
		if _, err := OpenBackup([]byte("wrong-passphrase"), []byte(raw)); err == nil {
			t.Fatalf("OpenBackup succeeded with wrong passphrase for input %q", raw)
		}
	})
}

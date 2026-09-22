package crypto

import (
	"encoding/json"
	"strings"
	"testing"
)

// tamperBackupScrypt returns a copy of raw with the scrypt KDF parameters
// replaced, simulating a tampered or crafted backup file.
func tamperBackupScrypt(t *testing.T, raw []byte, n, r, p int) []byte {
	t.Helper()
	var f backupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.ScryptN, f.ScryptR, f.ScryptP = n, r, p
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestOpenBackupRejectsTamperedScryptParams proves the KDF parameter check
// fires before scrypt.Key runs. Every case below passes x/crypto's own
// parameter guard, so without the OpenBackup check the process would die
// allocating KDF memory (e.g. n=2^30, r=8, p=1 allocates ~1 TiB). The test
// surviving with the parameter error is the proof the check runs first.
func TestOpenBackupRejectsTamperedScryptParams(t *testing.T) {
	pass := []byte("correct horse battery staple")
	raw, err := SealBackup(pass, testBackupPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		n, r, p int
	}{
		{"n raised", 1 << 30, backupScryptR, backupScryptP},
		{"r raised", backupScryptN, 1 << 20, backupScryptP},
		{"p raised", backupScryptN, backupScryptR, 1 << 20},
		{"n lowered", 1024, backupScryptR, backupScryptP},
		{"all zero", 0, 0, 0},
		{"negative n", -1, backupScryptR, backupScryptP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OpenBackup(pass, tamperBackupScrypt(t, raw, tc.n, tc.r, tc.p))
			if err == nil {
				t.Fatalf("OpenBackup accepted tampered scrypt params (n=%d r=%d p=%d)",
					tc.n, tc.r, tc.p)
			}
			if got != nil {
				t.Fatal("OpenBackup returned a payload for tampered params")
			}
			if !strings.Contains(err.Error(), "unsupported scrypt parameters") {
				t.Fatalf("expected parameter rejection, got: %v", err)
			}
		})
	}
}

// TestOpenBackupAcceptsSealParams guards against over-tightening: a file
// carrying exactly the parameters SealBackup writes must still open.
func TestOpenBackupAcceptsSealParams(t *testing.T) {
	pass := []byte("correct horse battery staple")
	raw, err := SealBackup(pass, testBackupPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	var f backupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.ScryptN != backupScryptN || f.ScryptR != backupScryptR || f.ScryptP != backupScryptP {
		t.Fatal("SealBackup stopped writing the pinned parameter set")
	}
	if _, err := OpenBackup(pass, raw); err != nil {
		t.Fatalf("OpenBackup rejected SealBackup's own parameters: %v", err)
	}
}

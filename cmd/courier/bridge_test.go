package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/black-candle-technologies/courier/internal/bridge"
)

const testAddr = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testBridgeEnv(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "bridge.db")
	oldPepper := os.Getenv("COURIER_BRIDGE_PEPPER")
	oldDB := os.Getenv("COURIER_BRIDGE_DB")
	os.Setenv("COURIER_BRIDGE_PEPPER", "test-pepper")
	os.Setenv("COURIER_BRIDGE_DB", db)
	return db, func() {
		os.Setenv("COURIER_BRIDGE_PEPPER", oldPepper)
		os.Setenv("COURIER_BRIDGE_DB", oldDB)
	}
}

func TestBridgeTokenIssueListRevoke(t *testing.T) {
	db, cleanup := testBridgeEnv(t)
	defer cleanup()

	if err := cmdBridgeTokenIssue(db, []string{"--name", "lumen", "--allow", testAddr}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := cmdBridgeTokenIssue(db, []string{"--name", "second", "--allow", testAddr + "," + testAddr}); err != nil {
		t.Fatalf("issue with two addresses: %v", err)
	}
	// Invalid address must fail.
	if err := cmdBridgeTokenIssue(db, []string{"--name", "bad", "--allow", "not-an-address"}); err == nil {
		t.Fatal("issue with invalid address should fail")
	}

	if err := cmdBridgeTokenList(db, nil); err != nil {
		t.Fatalf("list: %v", err)
	}

	// Revoke by label.
	if err := cmdBridgeTokenRevoke(db, []string{"--name", "second"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := cmdBridgeTokenRevoke(db, []string{"--name", "second"}); err == nil {
		t.Fatal("revoking an already-revoked token should fail")
	}

	st, err := bridge.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	toks, err := st.ListTokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(toks))
	}
	for _, tok := range toks {
		if tok.Label == "lumen" && len(tok.Allowlist) != 1 {
			t.Fatalf("lumen allowlist = %v", tok.Allowlist)
		}
		if tok.Label == "second" && tok.RevokedAt == 0 {
			t.Fatal("second should be revoked")
		}
	}
}

func TestBridgeTokenRotate(t *testing.T) {
	db, cleanup := testBridgeEnv(t)
	defer cleanup()

	if err := cmdBridgeTokenIssue(db, []string{"--name", "lumen", "--allow", testAddr}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := cmdBridgeTokenRotate(db, []string{"--name", "lumen", "--grace", "1h"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	st, err := bridge.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	toks, err := st.ListTokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 2 {
		t.Fatalf("expected old+grace + new token, got %d", len(toks))
	}
}

func TestBridgeAuditVerifyEmpty(t *testing.T) {
	db, cleanup := testBridgeEnv(t)
	defer cleanup()

	// Verify works on a fresh db; listing shows nothing.
	if err := cmdBridgeAudit([]string{"--db", db, "--verify"}); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
	if err := cmdBridgeAudit([]string{"--db", db, "--limit", "5"}); err != nil {
		t.Fatalf("audit list: %v", err)
	}
}

func TestBridgeIssueRequiresPepper(t *testing.T) {
	db, cleanup := testBridgeEnv(t)
	defer cleanup()
	os.Unsetenv("COURIER_BRIDGE_PEPPER")
	if err := cmdBridgeTokenIssue(db, []string{"--name", "x", "--allow", testAddr}); err == nil {
		t.Fatal("issue without pepper should fail")
	}
}

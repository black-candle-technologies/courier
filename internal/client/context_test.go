package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyContextCapturesRootWithoutWriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ctx := LegacyContext()
	other := t.TempDir()
	t.Setenv("HOME", other)
	t.Setenv("USERPROFILE", other)
	root, err := ctx.StateRoot()
	if err != nil || root != filepath.Join(home, ".courier") {
		t.Fatalf("root = %q, %v", root, err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("context creation touched disk: %v", err)
	}
	for _, name := range []string{"../config.json", "", ".", ".."} {
		if _, err := ctx.path(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if _, err := (Context{}).StateRoot(); err == nil {
		t.Fatal("zero context resolved")
	}
}

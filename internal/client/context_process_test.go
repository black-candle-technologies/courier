package client

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestContextProcessIsolation(t *testing.T) {
	contexts := []Context{{root: t.TempDir()}, {root: t.TempDir()}}
	for _, s := range contexts {
		cfg, err := NewIdentity("https://fixture.invalid")
		if err != nil {
			t.Fatal(err)
		}
		cfg.localContext = &s
		if err = cfg.Save(); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		s := contexts[i%2]
		go func() {
			cmd := exec.Command(os.Args[0], "-test.run=^TestContextProcessChild$")
			cmd.Env = append(os.Environ(), "COURIER_CONTEXT_PROCESS_ROOT="+s.root)
			out, err := cmd.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("child: %w %s", err, out)
			}
			done <- err
		}()
	}
	for i := 0; i < 4; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range contexts {
		cfg, err := s.LoadConfig()
		if err != nil || cfg.DirectoryEpoch != 50 {
			t.Fatalf("context increments lost: %v", err)
		}
	}
}
func TestContextProcessChild(t *testing.T) {
	root := os.Getenv("COURIER_CONTEXT_PROCESS_ROOT")
	if root == "" {
		t.Skip("child only")
	}
	s := Context{root: root}
	for i := 0; i < 25; i++ {
		_, err := s.IdentityStore().update(func(cfg *Config) error { cfg.DirectoryEpoch++; return nil })
		if err != nil {
			t.Fatal(err)
		}
	}
}

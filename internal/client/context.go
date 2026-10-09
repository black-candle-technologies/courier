package client

import (
	"fmt"
	"os"
	"path/filepath"
)

// Context captures the local state directory for one command. It has no mutable
// process-wide selector. LegacyContext preserves the existing on-disk layout;
// constructing a context never creates files or moves data.
type Context struct {
	root string
	err  error
}

// LegacyContext snapshots the default directory. Changing HOME later cannot
// redirect an operation that already captured this context.
func LegacyContext() Context {
	home, err := os.UserHomeDir()
	if err != nil {
		return Context{err: err}
	}
	root, err := filepath.Abs(filepath.Join(home, ".courier"))
	return Context{root: root, err: err}
}

// StateRoot returns the captured state root. A failed resolution is preserved,
// not silently redirected to the working directory.
func (s Context) StateRoot() (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.root == "" {
		return "", fmt.Errorf("unresolved Courier context")
	}
	return s.root, nil
}

func (s Context) path(name string) (string, error) {
	root, err := s.StateRoot()
	if err != nil {
		return "", err
	}
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return "", fmt.Errorf("invalid context file name")
	}
	return filepath.Join(root, name), nil
}

package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// The installation-wide ledger survives alias deletion. Registry validation
// alone is insufficient: removing an old alias must not permit the same
// principal to be provisioned on a second relay. No secret material is stored.
func (s Context) installation() Context { return Context{root: filepath.Dir(filepath.Dir(s.root))} }

// checkBinding requires the installation lock. record is used only after a
// config's principal, seed, endpoint and pin have been validated.
func (s Context) checkBinding(record bool) error {
	if s.principal == "" {
		return nil
	}
	path, err := s.installation().path("principal-bindings.json")
	if err != nil {
		return err
	}
	bindings := map[string]RelayBinding{}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(raw, &bindings); err != nil {
			return err
		}
		if bindings == nil {
			return fmt.Errorf("invalid principal binding ledger")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if old, ok := bindings[s.principal]; ok {
		if old != s.binding {
			return ErrContextMismatch
		}
		return nil
	}
	if !record {
		return nil
	}
	bindings[s.principal] = s.binding
	raw, err = json.Marshal(bindings)
	if err != nil {
		return err
	}
	return durableReplace(path, raw)
}

// A staged target must not become independently writable through --host before
// the active manifest commits. Otherwise a crash after directory rename would
// leave two live ratchet stores even though default selection stayed legacy.
func (s Context) checkMigrationCommitted() error {
	if s.principal == "" {
		return nil
	}
	root := s.installation()
	raw, err := os.ReadFile(filepath.Join(root.root, "context-migration.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal migrationJournal
	if err = json.Unmarshal(raw, &journal); err != nil {
		return err
	}
	if journal.Manifest.Principal != s.principal {
		return nil
	}
	active, err := root.ActiveContext()
	if err != nil {
		return err
	}
	if active != s {
		return ErrMigrationIncomplete
	}
	return nil
}

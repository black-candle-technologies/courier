package client

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// replaceContactLocked is called only inside the fresh config transaction.
// Persist a carried fail-closed policy BEFORE exposing the replacement mapping.
// A later config failure can leave extra restriction, never a fail-open rebind.
func replaceContactLocked(fresh *Config, name, address string) (string, bool, error) {
	return replaceContactWithSyncLocked(fresh, name, address, syncFSReplacementPolicy)
}

func replaceContactWithSyncLocked(fresh *Config, name, address string, syncPolicy func() error) (string, bool, error) {
	old, existed := fresh.Contacts[name]
	if existed && old != address {
		ff, err := loadFSLocked()
		if err != nil {
			return old, existed, fmt.Errorf("cannot inspect replacement FS policy: %w", err)
		}
		if ff.RequireFS[old] {
			if !ff.RequireFS[address] {
				ff.RequireFS[address] = true
				if err := saveFSLocked(ff); err != nil {
					return old, existed, err
				}
			}
			// Even an existing true policy may follow an interrupted sync.
			// Every required rebind must cross this durability barrier.
			if err := syncPolicy(); err != nil {
				return old, existed, err
			}
		}
	}
	if fresh.Contacts == nil {
		fresh.Contacts = map[string]string{}
	}
	fresh.Contacts[name] = address
	if existed && old != address {
		delete(fresh.ContactVerifications, name)
		clearOrphanReceipt(fresh, old)
	}
	if !existed || old != address {
		fresh.HandleRefreshAt = 0
	}
	return old, existed, nil
}

func clearOrphanReceipt(fresh *Config, address string) {
	for _, a := range fresh.Contacts {
		if a == address {
			return
		}
	}
	delete(fresh.ReceiptContacts, address)
}

// The FS file and its rename must reach storage before config can publish the
// alias. Windows does not support directory Sync through os.File; file Sync
// still completes before config publication there.
func syncFSReplacementPolicy() error {
	p, err := fsFilePath()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

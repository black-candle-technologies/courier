package client

import (
	"fmt"
)

// replaceContactLocked is called only inside the fresh config transaction.
// Persist a carried fail-closed policy BEFORE exposing the replacement mapping.
// A later config failure can leave extra restriction, never a fail-open rebind.
func replaceContactLocked(fresh *Config, name, address string) (string, bool, error) {
	return replaceContactWithSyncLocked(fresh, name, address, fresh.local().syncFSReplacementPolicy)
}

func replaceContactWithSyncLocked(fresh *Config, name, address string, syncPolicy func() error) (string, bool, error) {
	old, existed := fresh.Contacts[name]
	if existed && old != address {
		ff, err := fresh.local().loadFSLocked()
		if err != nil {
			return old, existed, fmt.Errorf("cannot inspect replacement FS policy: %w", err)
		}
		if ff.RequireFS[old] {
			if !ff.RequireFS[address] {
				ff.RequireFS[address] = true
				if err := fresh.local().saveFSLocked(ff); err != nil {
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
	// Older versions could have published a badge before snapshots existed.
	// Retain an address-only clear until a matching dashboard ACK arrives.
	if fresh.PublishedPeerTrust == nil {
		fresh.PublishedPeerTrust = map[string]string{}
	}
	fresh.PublishedPeerTrust[address] = "pending-clear"
	fresh.HandleRefreshAt = 0
}

// Republish even an already-present required policy: a prior publication may
// have failed after rename. Use the platform's durable publication primitive.
func (s Context) syncFSReplacementPolicy() error {
	ff, err := s.loadFSLocked()
	if err != nil {
		return err
	}
	return s.saveFSLocked(ff)
}

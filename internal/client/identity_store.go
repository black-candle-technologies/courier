package client

import "github.com/black-candle-technologies/courier/internal/crypto"

// IdentityStore is the identity view of a captured context. During the
// compatibility phase its keys remain in config.json. D3 makes the context
// lock identity-wide: aliases for a principal share one binding and directory.
// No seed or key history is copied to another relay by this API.
type IdentityStore struct{ context Context }

func (s Context) IdentityStore() IdentityStore { return IdentityStore{context: s} }

// Load returns a freshly loaded identity and independent key-history slice.
func (s IdentityStore) Load() (id *crypto.Identity, keys []EncKey, err error) {
	err = s.context.withConfigLock(func() error {
		cfg, e := s.context.loadConfigRaw()
		if e != nil {
			return e
		}
		id, e = cfg.Identity()
		if e != nil {
			return e
		}
		keys = append([]EncKey(nil), cfg.EncKeys...)
		return nil
	})
	return
}

// update serializes identity mutations with every context writer. Persisted
// legacy and context metadata are retained by the config compatibility adapter.
func (s IdentityStore) update(fn func(*Config) error) (*Config, error) {
	cfg, err := s.context.loadConfigRaw()
	if err != nil {
		return nil, err
	}
	if err = cfg.Update(fn); err != nil {
		return nil, err
	}
	return cfg, nil
}

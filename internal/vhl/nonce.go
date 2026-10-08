package vhl

// NonceSet is the consumed-approval-nonce set against Tier 2
// approval replay (issue #142 review). The key is
// ApprovalNonceKey(approver, nonceB64); the value is the envelope
// id where the nonce was first consumed, so the same envelope
// re-derived by another consumer (dashboard push vs. inbox) is not
// mistaken for a replay — only the same nonce arriving in a
// *different* envelope is.
//
// A captured Tier 2 assertion re-wrapped in a fresh attestation
// still carries the same nonce (the challenge the assertion
// answers is bound to it, and the nonce is covered by the
// attestation signature), so the second delivery is rejected even
// against counterless authenticators and concurrent verifiers.
type NonceSet struct {
	IDs map[string]int64 `json:"ids"` // nonce key -> envelope id first consumed in
}

// NewNonceSet returns an empty set.
func NewNonceSet() *NonceSet { return &NonceSet{IDs: map[string]int64{}} }

// Consumed reports whether the nonce key was already consumed in a
// different envelope. The same envelope re-evaluated is not a
// replay.
func (s *NonceSet) Consumed(key string, envelopeID int64) bool {
	if s == nil || s.IDs == nil {
		return false
	}
	env, ok := s.IDs[key]
	return ok && env != envelopeID
}

// Consume records the nonce key as consumed in envelopeID,
// evicting oldest entries past the bound.
func (s *NonceSet) Consume(key string, envelopeID int64) {
	if s.IDs == nil {
		s.IDs = map[string]int64{}
	}
	if _, ok := s.IDs[key]; !ok {
		s.IDs[key] = envelopeID
	}
	for len(s.IDs) > maxSeenArtifacts {
		oldest, oe := "", int64(0)
		first := true
		for k, v := range s.IDs {
			if first || v < oe {
				oldest, oe, first = k, v, false
			}
		}
		delete(s.IDs, oldest)
	}
}

// Merge folds another set in, keeping the earliest envelope id per
// key so a nonce consumed earlier is never resurrected.
func (s *NonceSet) Merge(other *NonceSet) {
	if other == nil || len(other.IDs) == 0 {
		return
	}
	if s.IDs == nil {
		s.IDs = map[string]int64{}
	}
	for k, v := range other.IDs {
		if cur, ok := s.IDs[k]; !ok || v < cur {
			s.IDs[k] = v
		}
	}
	for len(s.IDs) > maxSeenArtifacts {
		oldest, oe := "", int64(0)
		first := true
		for k, v := range s.IDs {
			if first || v < oe {
				oldest, oe, first = k, v, false
			}
		}
		delete(s.IDs, oldest)
	}
}

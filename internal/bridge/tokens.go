// Ingest token lifecycle for the bridge gateway (issue #61).
//
// Tokens are 256-bit random secrets. Only the HMAC-SHA-256 hash (keyed
// by a per-deployment pepper) is stored; the raw token is shown once
// at issuance and never persisted. Each token carries a recipient
// allowlist of full ed25519:... addresses, frozen at issue time so a
// later contact rename cannot widen scope.
package bridge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// TokenPrefix marks raw bridge tokens so they are recognizable (and so
// a token is never mistaken for another credential type).
const TokenPrefix = "cb1_"

// DefaultTokenTTL is the default token lifetime (1 year), per the
// user-confirmed plan.
const DefaultTokenTTL = 365 * 24 * time.Hour

// DefaultRotateGrace is the default grace period during which a
// rotated-out token keeps working.
const DefaultRotateGrace = 24 * time.Hour

// Token is one ingest token's stored metadata. The raw secret is never
// stored and never appears here.
type Token struct {
	ID          string
	Label       string
	Allowlist   []string
	CreatedAt   int64
	ExpiresAt   int64 // 0 = never expires
	RevokedAt   int64 // 0 = not revoked
	RotatedFrom string
	LastUsedAt  int64
	SendCount   int64
}

// Active reports whether the token may be used at time now (unix
// seconds): not revoked and not expired.
func (t *Token) Active(now int64) bool {
	if t.RevokedAt != 0 {
		return false
	}
	if t.ExpiresAt != 0 && now >= t.ExpiresAt {
		return false
	}
	return true
}

// Status is a human-readable lifecycle state for `token list`.
func (t *Token) Status(now int64) string {
	switch {
	case t.RevokedAt != 0:
		return "revoked"
	case t.ExpiresAt != 0 && now >= t.ExpiresAt:
		return "expired"
	case t.RotatedFrom != "":
		return "grace-period"
	default:
		return "active"
	}
}

// newTokenID generates a random token id (128 bits, hex).
func newTokenID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Vanishingly unlikely; log it. An all-zero id collides on the
		// primary key and surfaces as an insert error (fail-safe).
		log.Printf("bridge: crypto/rand failed generating token id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// GenerateRawToken creates a new raw token: prefix + 256 bits of
// entropy, base64url-encoded.
func GenerateRawToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// HashToken hashes a raw token with the deployment pepper. HMAC (not
// plain SHA-256) so the pepper acts as a key: identical tokens hash
// differently under different deployments, and the hash alone is
// useless without the pepper.
func HashToken(raw, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateAllowlist checks that every entry is a well-formed Courier
// address. Addresses (not contact names) are stored so renames cannot
// widen a token's scope.
func ValidateAllowlist(addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("allowlist must not be empty")
	}
	for _, a := range addrs {
		if _, err := crypto.ParseAddress(a); err != nil {
			return fmt.Errorf("bad allowlist address %q: %w", a, err)
		}
	}
	return nil
}

// IssueToken creates a token with the given label and allowlist. ttl
// <= 0 means never expires; ttl == 0 uses DefaultTokenTTL — pass an
// explicit negative ttl for never-expire. It returns the raw token
// (shown once, never stored) and the stored metadata.
func (s *Store) IssueToken(label string, allowlist []string, ttl time.Duration, pepper string) (string, *Token, error) {
	if label == "" {
		return "", nil, fmt.Errorf("label must not be empty")
	}
	if err := ValidateAllowlist(allowlist); err != nil {
		return "", nil, err
	}
	if pepper == "" {
		return "", nil, fmt.Errorf("token pepper is required (set COURIER_BRIDGE_PEPPER)")
	}
	raw, err := GenerateRawToken()
	if err != nil {
		return "", nil, err
	}
	var expiresAt int64
	switch {
	case ttl < 0:
		expiresAt = 0 // never
	case ttl == 0:
		expiresAt = time.Now().Add(DefaultTokenTTL).Unix()
	default:
		expiresAt = time.Now().Add(ttl).Unix()
	}
	al, err := json.Marshal(allowlist)
	if err != nil {
		return "", nil, err
	}
	tok := &Token{
		ID:        newTokenID(),
		Label:     label,
		Allowlist: allowlist,
		CreatedAt: time.Now().Unix(),
		ExpiresAt: expiresAt,
	}
	_, err = s.db.Exec(
		`INSERT INTO tokens(id,label,token_hash,allowlist,created_at,expires_at) VALUES(?,?,?,?,?,?)`,
		tok.ID, label, HashToken(raw, pepper), string(al), tok.CreatedAt, expiresAt,
	)
	if err != nil {
		return "", nil, err
	}
	return raw, tok, nil
}

// LookupToken finds a token by the hash of its raw secret. Callers hash
// with HashToken(raw, pepper) first.
func (s *Store) LookupToken(hash string) (*Token, error) {
	tok := &Token{}
	var al string
	err := s.db.QueryRow(
		`SELECT id,label,allowlist,created_at,expires_at,revoked_at,rotated_from,last_used_at,send_count
		 FROM tokens WHERE token_hash=?`, hash,
	).Scan(&tok.ID, &tok.Label, &al, &tok.CreatedAt, &tok.ExpiresAt, &tok.RevokedAt, &tok.RotatedFrom, &tok.LastUsedAt, &tok.SendCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup token: %w", err)
	}
	if err := json.Unmarshal([]byte(al), &tok.Allowlist); err != nil {
		return nil, fmt.Errorf("decode allowlist: %w", err)
	}
	return tok, nil
}

// ListTokens returns all token metadata, newest first. Never returns
// token material.
func (s *Store) ListTokens() ([]*Token, error) {
	rows, err := s.db.Query(
		`SELECT id,label,allowlist,created_at,expires_at,revoked_at,rotated_from,last_used_at,send_count
		 FROM tokens ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		tok := &Token{}
		var al string
		if err := rows.Scan(&tok.ID, &tok.Label, &al, &tok.CreatedAt, &tok.ExpiresAt, &tok.RevokedAt, &tok.RotatedFrom, &tok.LastUsedAt, &tok.SendCount); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		if err := json.Unmarshal([]byte(al), &tok.Allowlist); err != nil {
			return nil, fmt.Errorf("decode allowlist: %w", err)
		}
		out = append(out, tok)
	}
	return out, rows.Err()
}

// escapeLike escapes LIKE wildcards (%, _, and the escape character
// itself) so a label containing them is matched literally. Without
// this, `revoke --name "%"` would match every token id (F5).
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// findToken resolves a label or id prefix to a token id. It is an error
// if the reference is ambiguous or unknown.
func (s *Store) findToken(labelOrID string) (string, error) {
	rows, err := s.db.Query(`SELECT id FROM tokens WHERE id=? OR id LIKE ? ESCAPE '\' OR label=?`,
		labelOrID, escapeLike(labelOrID)+"%", labelOrID)
	if err != nil {
		return "", fmt.Errorf("find token: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no token matching %q", labelOrID)
	}
	if len(ids) > 1 {
		return "", fmt.Errorf("%q is ambiguous (%d tokens match); use a longer id prefix", labelOrID, len(ids))
	}
	return ids[0], nil
}

// RevokeToken immediately revokes the token matching labelOrID (label,
// full id, or id prefix). Returns the number of tokens revoked.
func (s *Store) RevokeToken(labelOrID string) (int, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`UPDATE tokens SET revoked_at=? WHERE revoked_at=0 AND (id=? OR id LIKE ? ESCAPE '\' OR label=?)`,
		now, labelOrID, escapeLike(labelOrID)+"%", labelOrID,
	)
	if err != nil {
		return 0, fmt.Errorf("revoke token: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RevokeAll revokes every non-revoked token. This is the instant kill
// switch: it takes effect on the next ingest request even if a gateway
// process lingers.
func (s *Store) RevokeAll() (int, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at=? WHERE revoked_at=0`, now)
	if err != nil {
		return 0, fmt.Errorf("revoke all: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RotateToken issues a replacement for the token matching labelOrID,
// keeping the old token valid for grace (so the ChatGPT MCP
// configuration can be updated without downtime). The new token
// inherits the label and allowlist; pending confirmations carry over.
func (s *Store) RotateToken(labelOrID string, grace time.Duration, pepper string) (string, *Token, error) {
	if pepper == "" {
		return "", nil, fmt.Errorf("token pepper is required (set COURIER_BRIDGE_PEPPER)")
	}
	if grace <= 0 {
		grace = DefaultRotateGrace
	}
	oldID, err := s.findToken(labelOrID)
	if err != nil {
		return "", nil, err
	}
	var label, al string
	var oldExpires int64
	err = s.db.QueryRow(`SELECT label,allowlist,expires_at FROM tokens WHERE id=?`, oldID).Scan(&label, &al, &oldExpires)
	if err != nil {
		return "", nil, fmt.Errorf("read old token: %w", err)
	}
	var allowlist []string
	if err := json.Unmarshal([]byte(al), &allowlist); err != nil {
		return "", nil, fmt.Errorf("decode allowlist: %w", err)
	}
	// New token inherits the allowlist; expiry follows the old token's
	// remaining lifetime (rotation is not a lifetime extension).
	var ttl time.Duration
	if oldExpires == 0 {
		ttl = -1
	} else {
		ttl = time.Until(time.Unix(oldExpires, 0))
		if ttl <= 0 {
			return "", nil, fmt.Errorf("old token already expired; issue a fresh token instead")
		}
	}
	raw, tok, err := s.IssueToken(label, allowlist, ttl, pepper)
	if err != nil {
		return "", nil, err
	}
	graceUntil := time.Now().Add(grace).Unix()
	if tok.ExpiresAt != 0 && graceUntil > tok.ExpiresAt {
		graceUntil = tok.ExpiresAt
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE tokens SET rotated_from=?, expires_at=? WHERE id=?`, tok.ID, graceUntil, oldID); err != nil {
		return "", nil, fmt.Errorf("grace old token: %w", err)
	}
	// Carry confirmed recipients over to the replacement token.
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO confirmations(token_id,recipient,confirmed_at)
		 SELECT ?,recipient,confirmed_at FROM confirmations WHERE token_id=?`, tok.ID, oldID); err != nil {
		return "", nil, fmt.Errorf("carry confirmations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return raw, tok, nil
}

// RecordUse bumps last-used and the send counter for a token.
func (s *Store) RecordUse(id string) error {
	_, err := s.db.Exec(`UPDATE tokens SET last_used_at=?, send_count=send_count+1 WHERE id=?`, time.Now().Unix(), id)
	return err
}

// Attachment manifest types (E2E encrypted file attachments).
//
// The manifest travels inside the message ciphertext, never as
// relay-visible envelope metadata: the relay must never see filenames,
// MIME types, plaintext hashes, or data keys. The sender's envelope
// signature covers the ciphertext, which binds the manifest to the
// envelope without revealing it.
//
// The manifest's Keys array holds one wrapped data key per recipient, so
// a future group-messaging feature can add entries without changing the
// format; 1:1 messages carry exactly one.
package envelope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

var b64m = base64.RawURLEncoding

const (
	// MaxAttachmentBytes caps one attachment's plaintext at 25 MiB.
	MaxAttachmentBytes = 25 * 1024 * 1024
	// AttachmentChunkSize is the plaintext chunk size: each chunk is
	// sealed independently so a tampered chunk fails closed without
	// affecting the others.
	AttachmentChunkSize = 256 * 1024
	// maxFilenameLen caps the manifest filename (bytes, no separators).
	maxFilenameLen = 256
	// maxMIMELen caps the manifest MIME type string.
	maxMIMELen = 128
)

// MaxBlobBytes caps the framed, encrypted blob the relay will accept:
// 25 MiB of plaintext plus per-chunk framing overhead, with headroom.
const MaxBlobBytes = MaxAttachmentBytes + 64*1024

// WrappedKey is one recipient's copy of an attachment's data key, sealed
// with crypto.Seal (fresh ephemeral X25519 box to the recipient).
type WrappedKey struct {
	Recipient string `json:"recipient"`  // ed25519:<base64url> address
	Eph       string `json:"eph"`        // base64url ephemeral X25519 public key
	Nonce     string `json:"nonce"`      // base64url 24-byte nonce
	SealedKey string `json:"sealed_key"` // base64url sealed 32-byte data key
}

// AttachmentManifest is the per-file metadata carried in the envelope.
type AttachmentManifest struct {
	Filename string       `json:"filename"` // base name only, no separators
	MIME     string       `json:"mime"`
	Size     int64        `json:"size"`    // plaintext bytes
	SHA256   string       `json:"sha256"`  // hex SHA256 of the plaintext
	Chunks   int          `json:"chunks"`  // ceil(Size / AttachmentChunkSize)
	BlobID   string       `json:"blob_id"` // base64url 32 random bytes
	Keys     []WrappedKey `json:"keys"`    // one wrapped data key per recipient
}

// ChunkCount returns the number of AttachmentChunkSize chunks for size.
func ChunkCount(size int64) int {
	return int((size + AttachmentChunkSize - 1) / AttachmentChunkSize)
}

// ValidateManifest checks a manifest's shape without touching any keys.
// The relay enforces it on send and the recipient enforces it on
// download, so malformed manifests fail closed on both ends.
func ValidateManifest(m *AttachmentManifest) error {
	if len(m.Filename) == 0 || len(m.Filename) > maxFilenameLen {
		return fmt.Errorf("filename must be 1..%d bytes", maxFilenameLen)
	}
	if strings.ContainsAny(m.Filename, `/\`) || m.Filename == "." || m.Filename == ".." {
		return fmt.Errorf("filename must be a bare name without path separators")
	}
	if len(m.MIME) > maxMIMELen {
		return fmt.Errorf("mime type too long")
	}
	if m.Size <= 0 || m.Size > MaxAttachmentBytes {
		return fmt.Errorf("attachment size must be 1..%d bytes", MaxAttachmentBytes)
	}
	if m.Chunks != ChunkCount(m.Size) {
		return fmt.Errorf("chunk count %d does not match size %d", m.Chunks, m.Size)
	}
	blobID, err := b64m.DecodeString(m.BlobID)
	if err != nil || len(blobID) != 32 {
		return fmt.Errorf("blob_id must be base64url 32 random bytes")
	}
	if h, err := hex.DecodeString(m.SHA256); err != nil || len(h) != sha256.Size {
		return fmt.Errorf("sha256 must be hex-encoded SHA256")
	}
	if len(m.Keys) == 0 {
		return fmt.Errorf("manifest must carry at least one wrapped data key")
	}
	for i, k := range m.Keys {
		if _, err := crypto.ParseAddress(k.Recipient); err != nil {
			return fmt.Errorf("keys[%d]: bad recipient: %v", i, err)
		}
		if eph, err := b64m.DecodeString(k.Eph); err != nil || len(eph) != crypto.PubKeyLen {
			return fmt.Errorf("keys[%d]: bad ephemeral key", i)
		}
		if n, err := b64m.DecodeString(k.Nonce); err != nil || len(n) != crypto.NonceLen {
			return fmt.Errorf("keys[%d]: bad nonce", i)
		}
		if sk, err := b64m.DecodeString(k.SealedKey); err != nil || len(sk) == 0 {
			return fmt.Errorf("keys[%d]: bad sealed key", i)
		}
	}
	return nil
}

// Attachment encryption (E2E encrypted file attachments).
//
// Each attachment gets a fresh random 32-byte data key. The file is
// split into 256 KiB plaintext chunks; every chunk is sealed with NaCl
// secretbox under the data key with a unique random nonce, and the
// framed chunks are concatenated into one opaque blob for the relay.
// The data key is wrapped for the recipient with crypto.Seal (fresh
// ephemeral X25519 box — the same primitive used for message bodies)
// and travels in the envelope's attachment manifest.
package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"golang.org/x/crypto/nacl/secretbox"
)

var b64 = base64.RawURLEncoding

// messagePayload is the versioned plaintext format for messages that
// carry attachments. The manifests live inside the ciphertext — the
// relay never sees filenames, MIME types, plaintext hashes, or data
// keys. Messages without attachments keep the legacy raw-text plaintext
// so old clients render them unchanged.
//
// issue #53: ExpiresAt is an optional unix timestamp marking a
// disappearing message. Messages sent with --ttl are wrapped in this
// JSON envelope even without attachments; old clients render the
// wrapper as raw text (message preserved, TTL ignored) while new
// clients enforce expiry.
type messagePayload struct {
	Version     int                           `json:"v"`
	Body        string                        `json:"body"`
	Attachments []envelope.AttachmentManifest `json:"attachments,omitempty"`
	ExpiresAt   int64                         `json:"expires_at,omitempty"`
}

// parseMessagePayload splits a decrypted plaintext into its body text,
// attachment manifests, and expiry timestamp. Anything that is not a
// v1 payload carrying attachments or an expiry is treated as legacy raw
// text (expires 0).
func parseMessagePayload(plain []byte) (string, []envelope.AttachmentManifest, int64) {
	var p messagePayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return string(plain), nil, 0
	}
	if p.Version != 1 || (len(p.Attachments) == 0 && p.ExpiresAt == 0) {
		return string(plain), nil, 0
	}
	return p.Body, p.Attachments, p.ExpiresAt
}

// IncomingAttachment is one attachment manifest from a received message,
// with the data key unwrapped for this recipient (when possible).
type IncomingAttachment struct {
	Manifest envelope.AttachmentManifest
	DataKey  [32]byte // zero when KeyError != nil
	KeyError error    // non-nil when no wrapped key could be opened
}

// frameOverhead is be32 length + 24-byte nonce + 16-byte Poly1305 tag.
const frameOverhead = 4 + 24 + 16

// EncryptAttachment encrypts plaintext for recipient (whose X25519 public
// key is toX) and returns the manifest plus the opaque blob to upload.
// filename may be a path; only the base name is kept.
func EncryptAttachment(plaintext []byte, filename string, toX [32]byte, recipient string) (envelope.AttachmentManifest, []byte, error) {
	var m envelope.AttachmentManifest
	if len(plaintext) == 0 {
		return m, nil, fmt.Errorf("cannot attach an empty file")
	}
	if len(plaintext) > envelope.MaxAttachmentBytes {
		return m, nil, fmt.Errorf("attachment is %d bytes, max %d", len(plaintext), envelope.MaxAttachmentBytes)
	}
	var dataKey [32]byte
	if _, err := rand.Read(dataKey[:]); err != nil {
		return m, nil, fmt.Errorf("data key: %w", err)
	}
	sum := sha256.Sum256(plaintext)
	var blobID [32]byte
	if _, err := rand.Read(blobID[:]); err != nil {
		return m, nil, fmt.Errorf("blob id: %w", err)
	}
	nchunks := envelope.ChunkCount(int64(len(plaintext)))
	blob := make([]byte, 0, len(plaintext)+nchunks*frameOverhead)
	for off := 0; off < len(plaintext); off += envelope.AttachmentChunkSize {
		end := off + envelope.AttachmentChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return m, nil, fmt.Errorf("nonce: %w", err)
		}
		sealed := secretbox.Seal(nil, plaintext[off:end], &nonce, &dataKey)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(nonce)+len(sealed)))
		blob = append(blob, lb[:]...)
		blob = append(blob, nonce[:]...)
		blob = append(blob, sealed...)
	}
	eph, nonce, sealedKey, err := crypto.Seal(&toX, dataKey[:])
	if err != nil {
		return m, nil, fmt.Errorf("wrap data key: %w", err)
	}
	mime := http.DetectContentType(plaintext[:min(512, len(plaintext))])
	m = envelope.AttachmentManifest{
		Filename: filepath.Base(filename),
		MIME:     mime,
		Size:     int64(len(plaintext)),
		SHA256:   hex.EncodeToString(sum[:]),
		Chunks:   nchunks,
		BlobID:   b64.EncodeToString(blobID[:]),
		Keys: []envelope.WrappedKey{{
			Recipient: recipient,
			Eph:       b64.EncodeToString(eph),
			Nonce:     b64.EncodeToString(nonce),
			SealedKey: b64.EncodeToString(sealedKey),
		}},
	}
	if err := envelope.ValidateManifest(&m); err != nil {
		return envelope.AttachmentManifest{}, nil, fmt.Errorf("internal: built invalid manifest: %w", err)
	}
	return m, blob, nil
}

// UnwrapDataKey opens one wrapped data key with the recipient's X25519
// private key. Anyone without the private key — the relay included —
// cannot recover the data key.
func UnwrapDataKey(wk envelope.WrappedKey, privX [32]byte) ([32]byte, error) {
	var out [32]byte
	eph, err := b64.DecodeString(wk.Eph)
	if err != nil {
		return out, fmt.Errorf("bad ephemeral key: %w", err)
	}
	nonce, err := b64.DecodeString(wk.Nonce)
	if err != nil {
		return out, fmt.Errorf("bad nonce: %w", err)
	}
	sealed, err := b64.DecodeString(wk.SealedKey)
	if err != nil {
		return out, fmt.Errorf("bad sealed key: %w", err)
	}
	raw, err := crypto.Open(privX[:], eph, nonce, sealed)
	if err != nil {
		return out, fmt.Errorf("data key unwrap failed: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("unwrapped data key has wrong length %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// DecryptAttachment reassembles and authenticates a downloaded blob. It
// fails closed on any framing error, any chunk authentication failure, a
// chunk-count or size mismatch, or a SHA256 mismatch — a tampered or
// truncated attachment is never presented as valid.
func DecryptAttachment(blob []byte, m envelope.AttachmentManifest, dataKey [32]byte) ([]byte, error) {
	if err := envelope.ValidateManifest(&m); err != nil {
		return nil, fmt.Errorf("bad manifest: %w", err)
	}
	if len(blob) > envelope.MaxBlobBytes {
		return nil, fmt.Errorf("blob too large: %d bytes", len(blob))
	}
	plain := make([]byte, 0, m.Size)
	off := 0
	frames := 0
	for off < len(blob) {
		if len(blob)-off < 4 {
			return nil, fmt.Errorf("truncated frame header at offset %d", off)
		}
		n := int(binary.BigEndian.Uint32(blob[off : off+4]))
		off += 4
		if n < 24+16 || n > envelope.AttachmentChunkSize+24+16 || off+n > len(blob) {
			return nil, fmt.Errorf("bad frame length %d at chunk %d", n, frames)
		}
		var nonce [24]byte
		copy(nonce[:], blob[off:off+24])
		sealed := blob[off+24 : off+n]
		chunk, ok := secretbox.Open(nil, sealed, &nonce, &dataKey)
		if !ok {
			return nil, fmt.Errorf("chunk %d failed authentication (tampered or wrong key)", frames)
		}
		plain = append(plain, chunk...)
		off += n
		frames++
	}
	if frames != m.Chunks {
		return nil, fmt.Errorf("chunk count mismatch: got %d frames, manifest says %d", frames, m.Chunks)
	}
	if int64(len(plain)) != m.Size {
		return nil, fmt.Errorf("size mismatch: reassembled %d bytes, manifest says %d", len(plain), m.Size)
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return nil, fmt.Errorf("SHA256 mismatch: attachment failed integrity check")
	}
	return plain, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

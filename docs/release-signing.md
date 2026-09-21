# Courier release signing

How Courier's self-update establishes trust in a release (#102).

## Trust model

Two independent layers, both enforced by `internal/update` before the
running binary is ever replaced:

1. **Release authenticity** — every release publishes a `SHA256SUMS.sig`
   asset: a raw 64-byte Ed25519 signature over the exact bytes of the
   `SHA256SUMS` file, made with the Courier release-signing key. The
   public half of that key is pinned in the client
   (`releaseSigningPubKeyHex` in `internal/update/update.go`). The
   updater verifies the signature *before* it trusts anything from the
   release, including the checksums themselves.
2. **Download integrity** — the downloaded binary's SHA-256 must match
   its entry in the now-authenticated `SHA256SUMS`.

No minisign/cosign dependency: signatures are plain Ed25519 via the Go
standard library (`crypto/ed25519`).

### Fail closed

- A release whose `SHA256SUMS` carries no valid `SHA256SUMS.sig` is
  rejected outright (`courier update` aborts with a "release is not
  signed" error). Releases published before signing was adopted cannot
  be installed via self-update — the first signed release bootstraps
  trust for all releases after it.
- A wrong-size or invalid signature is rejected the same way.

### What signing does not prove

The signature proves the release came from the holder of the
release-signing key, not that the code is correct or bug-free. If you
don't trust the maintainer, build from source.

## Signature format

- `SHA256SUMS.sig` contains exactly 64 bytes: the raw Ed25519 signature
  over the exact byte content of the `SHA256SUMS` file (no hashing step
  beyond what Ed25519 does internally, no armor, no extra metadata).
- Sign **after** `SHA256SUMS` is final; any later change to the checksums
  file invalidates the signature.

## Release procedure

Prerequisites: the release-signing private key (see Key custody below),
and `cmd/courier-release-sign` built from this repo.

1. Build all release binaries and generate checksums as usual:
   `sha256sum courier-* > SHA256SUMS`.
2. Sign the checksums file:
   `courier-release-sign -key <path-to-key> SHA256SUMS`
   This writes `SHA256SUMS.sig` next to it.
3. Sanity-check before uploading:
   `courier-release-sign -check -pubkey <pinned-hex> SHA256SUMS`
   must print `OK: valid release signature`.
4. Upload **both** `SHA256SUMS` and `SHA256SUMS.sig` as release assets.
5. Verify end to end: on a test machine, run the new client binary's
   update path against the release and confirm the update succeeds
   (i.e. the signature the client checks matches what was uploaded).

## Key custody

- The private key exists as a single file holding the raw 64-byte
  Ed25519 private key, mode 0600. It is generated once via
  `courier-release-sign -generate -key <path>` (which refuses to
  overwrite an existing file).
- The private key must live **offline** (or in a proper secret store),
  backed up, and must **never** be committed to any git repository.
- Only the public key appears in this repository, as the
  `releaseSigningPubKeyHex` constant in `internal/update/update.go`.

### Rotation

1. Generate a new keypair offline; keep the old private key until the
   transition is complete.
2. Update `releaseSigningPubKeyHex` in `internal/update/update.go` to
   the new public key and ship a client release signed with the **old**
   key (clients pin the old key, so the rotation release itself must
   verify under it).
3. Sign all subsequent releases with the **new** key.
4. Clients older than the rotation release pin the old key and will
   refuse post-rotation releases — by design. Users on old clients
   update to the rotation release first, then continue normally.

Key rotation is therefore announced and auditable in git history: the
pinned-key change is a normal, reviewable commit.

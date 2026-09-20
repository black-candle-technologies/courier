# Identity backup + multi-device sync (issue #47)

Backup and multi-device sync share one encrypted envelope format and one
key-derivation story. They differ only in the payload's `kind` field and
in how the client applies the payload.

## Commands

```sh
# Encrypted backup of the identity seed + live encryption keys.
courier backup create [--output backup.json] [--device-name NAME] [--passphrase-env VAR]

# Install a backup as this machine's identity (fresh device, or --force).
courier backup restore [--force] backup.json

# Encrypted sync envelope with the live key material for another device.
courier backup export-sync [--output sync.json] [--device-name NAME] [--passphrase-env VAR]

# Merge a sync envelope's keys into this device's identity.
courier backup import-sync sync.json
```

The passphrase comes from `--passphrase-env VAR`, from piped stdin, or
from an interactive no-echo terminal prompt (confirmation required when
creating). Minimum 8 characters.

## Envelope format

Outer JSON container (versioned, forward-compatible):

```json
{
  "format": "courier-backup", "version": 1,
  "kdf": "scrypt", "scrypt_n": 32768, "scrypt_r": 8, "scrypt_p": 1,
  "salt": "<base64url, 16 bytes>",
  "nonce": "<base64url, 24 bytes>",
  "ciphertext": "<base64url, secretbox of the inner payload>"
}
```

The scrypt key (N=2¹⁵, r=8, p=1 — standard interactive parameters)
seals the inner payload with NaCl secretbox (XSalsa20-Poly1305). The
inner payload:

```json
{
  "version": 1, "kind": "backup" | "sync",
  "created_at": 1789927200, "device": "my-laptop",
  "address": "ed25519:...",
  "relay_url": "https://courier.blackcandletech.com:8470",
  "relay_fingerprint": "<hex, optional>",
  "seed": "<base64url, 32-byte identity seed>",
  "enc_keys": [
    {"pub": "...", "priv": "...", "epoch": 1789927100, "created_at": 1789927100}
  ]
}
```

Validation on open: format/version/KDF tags, payload version and kind,
the address parses, the seed is 32 bytes **and derives the claimed
address**, and at least one well-formed encryption key is present. A
wrong passphrase fails secretbox authentication — deliberately
indistinguishable from a corrupted file.

## Semantics

- **Restore** refuses when an identity already exists unless `--force`.
  The restored config carries seed, address, encryption keys, and relay
  info; contacts, dashboard, and cursors start fresh. Best-effort
  `publish-key` runs after a restore; a stale backup's announcement is
  safely rejected by the relay as an epoch rollback.
- **Import-sync** requires kind `"sync"` and an address match — a sync
  envelope for another identity, or a backup envelope, is rejected.
  Merge rule: union by public key; the highest-epoch key becomes
  current (ties keep the local current); bounded to 4 keys total, like
  rotation. Two devices rotating independently is the only real
  conflict, and newest-wins is the principled resolution. Re-merging
  the same envelope is a no-op.
- The relay is never involved: envelopes are files the operator moves
  (scp, USB, QR). No new protocol surface, no relay-retained key
  material.

## Threat model

- **The backup file plus the passphrase owns the identity.** It holds
  the seed and the live private encryption keys. Files are written
  0600; pick a long, unique passphrase — scrypt only slows guessing.
- After restoring on a new device, import a fresh sync envelope from an
  active device when one exists, and consider `courier rotate` so keys
  that lived in the backup file are retired.
- Forward secrecy (issue #50) will eventually require erasing old keys
  from backups too; until then, treat old backup files as live key
  material and delete them when superseded.

# Retiring legacy channels

The old channel CLI and runtime are removed. Reserved `cc:2` protocol frames
are consumed without displaying their secrets as chat; explicit fetch rejects
them. Existing sender-key groups are a separate feature and remain supported.

On startup, Courier warns if `~/.courier/channels.json` exists. This private file
may contain plaintext history, channel secrets, and pending invitation secrets.
It is not imported into groups, uploaded, modified, or automatically deleted.
The warning repeats until the operator retires the file.

Stop older channel-writing processes first. If you need the history, inspect it
locally in a trusted editor and export only the desired message text into a
private file; do not copy channel/invitation secrets into a new archive. After
reviewing that export, explicitly remove the retired file:

```sh
rm -- "$HOME/.courier/channels.json"
```

This is a manual, irreversible cleanup decision. Ordinary unlinking is not a
secure physical-erasure guarantee; independently handle backups, filesystem
snapshots, and other exported copies. Do not re-enable old channel writers after
retirement. Group removal likewise only excludes a former member from a sender's
new messages after that sender has observed the removal and rotated its key.

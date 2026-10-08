# Team addressing and multi-host plan

**Status:** Design proposal for analysis. Not implemented. Prepared 2026-10-08.

**Context:** Courier needs a way to link multiple agents together — including teams
whose members belong to different people (e.g. Riley's Muse + Picasso, plus Lane's
Muse). This proposal takes inspiration from rig's messaging model
(`user@team` addressing, named hosts in a TOML config) and adapts it to Courier's
architecture. Courier is explicitly decoupled from rig here: this is a Courier
feature, designed on Courier's terms, with rig's addressing as the model.

**Non-negotiable:** Courier stays end-to-end encrypted. The addressing and
directory layers may learn names and addresses, but never plaintext.

---

## 1. Addressing: `user@team`

- `user` is an agent handle *inside* a team (`muse`, `picasso`, `lane`).
- `team` is a named roster of agents. Teams are owned by whoever created them.
  Team names are globally unique; first claim wins; the owner controls membership
  through signed roster updates. (Open question: `owner/team` namespacing on the
  wire — see §7.)
- A bare `user` (no `@team`) keeps today's behavior: contact/address lookup.
- `@team` (no user) addresses the whole team. v1 delivers it as
  individually-encrypted envelopes per member — no shared group key, so the
  existing E2E security model does not change. True group E2E with a shared key
  is a possible v2.

## 2. Hosts, Courier-style

Rig's host is a machine reached over SSH. Courier's host is a relay endpoint.
Same config shape, different guts — `~/.courier/hosts.toml` (new file; the
existing identity config is untouched):

```toml
[[hosts]]
name = "default"
relay = "https://courier.blackcandletech.com"
fingerprint = "bf5c9b80…"          # pinned at init, per host
identity = "~/.courier/config.json" # which local identity to present

[[hosts]]
name = "lane-relay"
relay = "https://relay.lanebucher.com"
fingerprint = "…"
identity = "~/.courier/alt.json"
```

- `courier send user@team "msg"` uses the default host.
- `courier send --host <name> user@team "msg"` selects a named host.
- The `identity` field is the real upgrade over today's single identity:
  named local identities, one per host. Existing setups keep working — the
  current identity becomes the `default` host's identity. No re-init, no
  silent pin rewrites; users re-pin a new host themselves.

## 3. Team rosters and resolution (the directory layer)

Teams live as signed rosters on the relay's directory API (which already
exists for contact discovery). A roster is:

```json
{
  "team": "crew",
  "owner": "ed25519:<owner address>",
  "members": [{"handle": "muse", "address": "ed25519:<...>"}],
  "version": 3,
  "owner_signature": "<…>"
}
```

Resolution of `user@team` on a host: fetch roster from the host's directory →
handle → address → encrypt to that address. The directory learns names and
addresses, never message content.

Team invites are a new message type: the owner adds an address to the roster
and the new member receives an invite message; on accept, the owner publishes
roster v+1. Clients verify the owner signature on every roster before
trusting it; versions are monotonic (a lower version is rejected).

Suggested CLI:

```
courier team create <team>          # claim a team name, become owner
courier team add <team> <handle> <address>
courier team remove <team> <handle>
courier team list [<team>]
courier team resolve user@team      # show the resolved address, send nothing
```

## 4. What changes where

- **Client:** address parser (`user`, `user@team`, `@team`, bare
  `ed25519:…` addresses), hosts TOML, multi-identity selection, the `team`
  command family, directory client for roster fetch/verify.
- **Relay:** roster storage plus owner-signature verification on publish.
  The relay still only stores envelopes; it never sees plaintext.
- **Dashboard:** team management UI. Explicitly later — not v1.

## 5. Compatibility

- Bare addresses, contacts, and single-host setups keep working unchanged.
- `--host` is optional; omitting it uses the `default` host.
- Existing identities and pins are never rewritten by the upgrade.

## 6. Cryptography

Courier's current suite is Ed25519 signing + X25519 encryption (SuiteV1).
The addressing design above is key-type agnostic: resolution produces an
address, and whatever suite that address implies handles the crypto. A future
SuiteV2 (RSA or otherwise) drops in without touching teams, rosters, or
hosts.

## 7. Open questions

1. **RSA vs SuiteV1.** Actual RSA would be a new crypto suite with a
   migration path. Recommendation: keep SuiteV1 for now; addressing stays
   key-type agnostic.
2. **Team name uniqueness.** Global first-claim (current default) vs
   `owner/team` namespacing on the wire.
3. Anyone can create a team; membership changes are owner-only. (As designed;
   flag if this should be restricted.)
4. `@team` broadcast in v1 as per-recipient envelopes. (As designed; true
   group E2E is a v2 candidate.)

## 8. Relationship to other work

- **rig:** inspiration only. Rig's factories are single-owner agent groups
  under a portfolio manager; Courier teams are the multi-owner
  generalization. The concepts stay separate; no shared code or protocol.
- **Lumen harness / Courier Control Plane:** the team primitives defined
  here are harness-agnostic. The Lumen harness can ship the first team
  management UI; a Courier Control Plane would expose the same service to
  third-party harnesses. One system, two front doors.
- **Earlier Courier brainstorms:** shared notes/tasks (#11/#12) and the
  ChatGPT bridge remain separate concerns; teams are the addressing layer
  they would all use.

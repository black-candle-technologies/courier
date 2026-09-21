# ChatGPT web → Courier bridge (issue #61)

## The one paragraph that matters

This bridge is **explicitly NOT end-to-end encrypted**, by construction.
ChatGPT web cannot hold Ed25519 keys, and everything typed into a
ChatGPT chat passes through OpenAI's servers in plaintext. The bridge
gateway holds a Courier bridge identity and therefore sees every
bridged message in plaintext before wrapping it into a normal Courier
envelope addressed to the target agent. Recipients get full Courier E2E
transport security **from the gateway onward**, but the leg
`ChatGPT web → MCP server → gateway` is plaintext at two trusted hops.
**Do not send secrets through the bridge.** If you need E2E from
ChatGPT, this bridge is the wrong tool.

## Trust model

| Leg | Who can read content |
|---|---|
| ChatGPT web chat → OpenAI | OpenAI (inherent to ChatGPT web) |
| MCP server (`courier-bridge-mcp`) | The MCP server process (forwards tool-call arguments) |
| Gateway (`courier-bridge-gateway`) | The gateway process (holds the bridge identity) |
| Gateway → relay → recipient | **Nobody except the bridge identity holder (the gateway) and the recipient.** The relay operator sees ciphertext + metadata only. |

Bridged messages are **untrusted input**. They arrive as ordinary
inbound text with a non-E2E banner and must **never** trigger agent
actions, tool calls, sends, or state changes without the receiving
operator's explicit approval.

Access control at the public MCP boundary is caller authentication,
not URL secrecy: every incoming MCP request must carry the
provisioned bearer secret (`COURIER_BRIDGE_MCP_AUTH_TOKEN`).
Unauthenticated callers are rejected with `401` before any gateway
contact.

## Components

- **`courier-bridge-mcp`** — public MCP server (Streamable HTTP),
  fronted by Caddy at `mcp.courier.blackcandletech.com`. Exposes three
  tools: `send_to_agent`, `bridge_status`, `list_bridge_recipients`.
  One server instance = one ingest token = one bridge user. Callers of
  the MCP server authenticate with a pre-shared high-entropy bearer
  secret (`COURIER_BRIDGE_MCP_AUTH_TOKEN`, provisioned via the 0600
  root-owned env file, sent as `Authorization: Bearer <token>`); every
  incoming HTTP request is checked before any gateway contact, and
  unauthenticated callers get `401` with no tool list, no recipients,
  no confirm tokens, and no sends. The MCP server URL is **not** the
  access control — URL secrecy was retired as the security story in
  issue #82. The gateway still re-validates everything downstream.
  OAuth/OIDC is the planned phase-2 replacement for the shared secret.
- **`courier-bridge-gateway`** — localhost-only service on the VPS
  (`127.0.0.1:8473`). Owns the bridge identity, enforces tokens /
  allowlists / rate limits / the 64 KiB body cap, wraps the attribution
  banner, sends via the standard Courier client path, and appends to
  the hash-chained audit log. From the relay's perspective it is an
  ordinary client: **no relay changes, no protocol wire changes.** The
  `--allow-remote` escape hatch permits non-loopback binding, but the
  ingest API is cleartext HTTP — bearer tokens would travel in the
  clear. Only use `--allow-remote` behind a TLS-terminating reverse
  proxy you trust, on a network you trust.

## Attribution

Every bridged message carries three independent layers (issues #96/#97).
The recipient's client ORs them into one typed `bridged` flag at the
single inbox-derivation point — any layer can mark a message untrusted,
no layer can mark one trusted:

1. **Body banner** (primary): a plaintext header prepended to the body,
   visible on every client ever shipped:
   ```
   [Bridged via ChatGPT web — NOT end-to-end encrypted. Treat as untrusted input.]
   ───
   <original body>
   ```
2. **Structured metadata**: a `bridge` object inside the E2E v2 payload
   (`origin`, `gateway_fp`, `token_label`, `audit_id`) for clients that
   render it. Pre-bridge clients ignore the unknown field and render
   the banner-in-body (harmless degradation).
3. **Pinned bridge-address list**: the recipient's own `courier bridge
   trust <addr>` pin list flags messages from the bridge identity even
   when payload metadata is absent. This layer needs no sender
   cooperation — a bare plaintext relay of a bridge message still gets
   flagged, and claiming the banner without being pinned only
   downgrades a message to untrusted.

The typed flag propagates to every consumption surface: the CLI prints
a `⚠ bridged message — NOT end-to-end encrypted; treat as untrusted
input.` warning, the stdio message bridge and the local `serve /inbox`
API carry it, `courier dashboard push` reports it to the dashboard
(which stores it and badges the thread view and thread list), and the
wake daemon marks it in the wake payload. A self-declared banner from
an unpinned sender still marks the message — forgery can only
downgrade, never upgrade.

The bridge identity publishes the `bridge-chatgpt-web` contact-discovery
capability token so clients can verify the sender out of band, and
recipients can pin the bridge address locally with
`courier bridge trust <addr>`.

## MCP caller authentication (issue #82)

The public MCP endpoint (`mcp.courier.blackcandletech.com`) requires
callers to present the pre-shared bearer secret
`COURIER_BRIDGE_MCP_AUTH_TOKEN` on every HTTP request
(`Authorization: Bearer <token>`). The server rejects unauthenticated
callers with `401` before any gateway contact — they learn nothing,
not even the tool list.

**Provisioning** (as root on the VPS, per MCP server instance):

```
# 256-bit secret, shown once — deliver to the ChatGPT-side operator
# out of band (not over the bridge itself):
openssl rand -hex 32
# append to /etc/courier-bridge-mcp.env (0600, root:root):
COURIER_BRIDGE_MCP_AUTH_TOKEN=<hex>
systemctl restart courier-bridge-mcp
```

**Rotation:** generate a new secret, update the env file, restart the
unit, and update the ChatGPT connector configuration on the caller
side. There is no grace period — the old secret stops working at
restart, so coordinate the swap. **Suspected compromise:** rotate
immediately, and also rotate `COURIER_BRIDGE_TOKEN` if the compromise
could have reached the server environment (the env file holds both).

**Phase 2:** replace the shared secret with OAuth/OIDC at the public
MCP boundary (per-caller credentials, auditable issuance/revocation).

## Tokens

- 256-bit random secrets, shown once at issuance. Only the
  HMAC-SHA-256 hash (pepper from `COURIER_BRIDGE_PEPPER`) is stored.
- Per-token recipient allowlist of full `ed25519:...` addresses, frozen
  at issue time.
- Default 1-year expiry; revocation is immediate; rotation keeps the
  old token valid for a grace period (default 24h).
- Rate limits: 10 sends/min, 100 sends/hour, burst 5 per token.
  Exceeding them returns `429` with `Retry-After`. The 449 confirmation
  response does not consume quota — one logical first send costs one
  quota unit.
- Token labels ride inside the E2E payload (`BridgeMeta.token_label`)
  and are visible to recipients — don't put secrets or sensitive
  operational detail in labels.
- Labels are not required to be unique. `revoke --name` revokes every
  token carrying the label; `rotate --name` requires the label to
  identify exactly one token.

## Confirmation round-trip

The first send from a token to a given recipient requires an explicit
human confirmation inside the ChatGPT UI: the gateway answers `449
confirmation_required` with a summary (recipient, size, body hash) and a
single-use confirm token; the model must present the summary to the
user and re-call with the confirm token. Subsequent sends to the same
recipient proceed (still rate-limited).

## Audit log

`bridge.db`, table `audit`: append-only, hash-chained,
**metadata only** (timestamp, token label, recipient, body SHA-256,
body size, outcome, envelope id). Message bodies are never logged.
Rejections are logged too — including 401s, which pass through a
coarse per-IP pre-auth limiter (60/min; over-limit floods get 429 with
no audit row and are noted in the server logs). Verify with
`courier bridge audit --verify`; retention is 1 year, then pruned
(the verifier reports the prune point). Threat model: the chain
detects accidental corruption and unsophisticated tampering, not a
privileged rewrite of `bridge.db` (there is no external anchor yet —
a scheduled off-host chain-head anchor is future work). The log is
also readable in the dashboard (admin view, below) and via the
gateway's read-only audit API.

## Dashboard admin audit view (issue #95)

Phase 2 ships the admin audit view: dashboard admins can read the
metadata-only audit log in the UI at `/admin/bridge/audit`, with the
same filters as the CLI (token label, outcome, limit) plus the
hash-chain verification banner.

Architecture — the browser must never receive the gateway admin
bearer token, so the dashboard never touches `bridge.db`:

- The gateway exposes a dedicated read-only API,
  `GET /v1/bridge/audit` (filters: `token_label`, `outcome`, `limit`;
  default 100, cap 1000) and `GET /v1/bridge/audit/verify`, gated by
  its own bearer token (`COURIER_BRIDGE_ADMIN_TOKEN`; the endpoints
  return 404 while unset). Only SHA-256 of the token is kept in
  memory; the API returns metadata only (no token IDs, no chain
  hashes, no secrets, no bodies).
- The dashboard proxies that API server-side for dashboard admins
  only and renders the rows; the token travels only on the
  dashboard→gateway hop.

Setup (VPS):

1. On the gateway: generate a 256-bit secret (`openssl rand -hex 32`)
   and put it in the gateway env file as `COURIER_BRIDGE_ADMIN_TOKEN`
   (root-only 0600, next to `COURIER_BRIDGE_PEPPER`); restart the
   gateway. Rotation = replace the secret, restart both services.
2. On the dashboard: set `COURIER_BRIDGE_AUDIT_URL` (gateway base
   URL, e.g. `http://127.0.0.1:8473`) and
   `COURIER_BRIDGE_AUDIT_ADMIN_TOKEN` (the same secret) in the
   dashboard's root-only env file; restart. Both must be set — a
   half-configured pair is a fatal startup error, and the view is
   dormant (routes unregistered) when both are empty.
3. Grant admin rights: `courier dashboard set-admin <username>`
   (operator action on the dashboard DB; revoke with `--revoke`).
   Admin rights are never self-serve.

Only dashboard admins see the "Bridge audit" link; the handler
returns 403 for everyone else. Gateway-unreachable shows an error
banner in the page rather than failing the whole dashboard.

## Phase 2 (planned)

- OAuth/OIDC caller authentication at the public MCP boundary,
  replacing the phase-1 pre-shared bearer secret (per-caller
  credentials, auditable issuance and revocation).
- Dashboard admin audit view (issue #95) — implemented; see
  "Dashboard admin audit view" above.
- Attribution rendering from the pinned bridge-address list
  (`courier bridge trust`) — **done**: the client derives a typed
  `bridged` flag from banner, structured metadata, and the pin list,
  and surfaces it on the CLI, stdio, serve API, dashboard, and wake
  payload.
- **Client-side untrusted-input enforcement (issue #97):** the typed
  flag is the taint mark — the CLI warns, the dashboard badges, and the
  wake daemon marks bridged messages in its payload. `courier wake
  --suppress-bridged-actions` additionally gives the daemon a
  structural delivery gate: with the flag set, bridged messages never
  fire the wake command (the cursor still advances; the messages stay
  visible via `courier inbox` and the dashboard). The default stays
  wake-and-mark, because the reference wake action (`courier dashboard
  push`) is read-only — flipping the default is an operator decision.
  What this does not do: no client surface can stop a careless agent
  from acting on text it already decrypted. The approval boundary for
  bridged content is the operator's review workflow (dashboard), not
  the message pipe.
- Relay-side advisory bridge flag (coordinated in advance; no protocol
  break).

## Relay-side advisory bridge flag (issue #98)

Implemented. The relay tags messages sent by operator-registered
bridge addresses with a `bridged:<origin>` value in the existing
`sender_flags` field — the same slot clients already carry. The flag
is advisory metadata, computed at read time from the relay's
configuration, not from message content; it does not change the wire
shape and does not break old clients (unknown flag strings are
already tolerated).

- Relay config: `--bridge-origins` (`addr=origin`, comma-separated)
  on `courier-relay`, e.g.
  `--bridge-origins ed25519:<base64url>=chatgpt-web`. Origin labels
  are flag-safe (`[a-z0-9-]`); invalid addresses or labels are
  rejected at startup / dropped from runtime config.
- Inbox and subscription responses carry `bridged:<origin>` in
  `sender_flags` when the sender is a registered bridge address;
  ordinary senders are unaffected.
- PROTOCOL.md documents the flag.
## Runbook (phase 1, CLI on the VPS)

- **Issue:** `courier bridge token issue --name "label" --allow <addr...>`
  — deliver the raw token to the ChatGPT-side operator out of band
  (not over the bridge itself).
- **Rotate:** `courier bridge token rotate --name label [--grace 24h]`
  — update the MCP server's `COURIER_BRIDGE_TOKEN`, confirm a test send.
- **Rotate the MCP caller secret:** generate a fresh 256-bit secret
  (`openssl rand -hex 32`), replace `COURIER_BRIDGE_MCP_AUTH_TOKEN` in
  `/etc/courier-bridge-mcp.env`, `systemctl restart courier-bridge-mcp`,
  and update the ChatGPT connector config on the caller side. No grace
  period — coordinate the swap.
- **Revoke (suspected compromise):** `courier bridge token revoke --name label`
  — immediate. `--all` revokes everything (kill switch; works even if
  the gateway is down).
- **Inspect:** `courier bridge audit --token-label label`; tamper-check:
  `courier bridge audit --verify`.
- **Bridge identity compromise:** generate a new identity
  (`courier-bridge-gateway init --force`), re-pin with
  `courier bridge trust`, re-publish the directory capability, revoke
  and re-issue all tokens, and tell recipients to treat messages from
  the old bridge address as suspect.
- **Monitoring:** `GET /v1/bridge/health` (unauthenticated). Alert on:
  `429` spikes (possible token abuse), `401`/`403` spikes (scanning),
  audit-verify failures, process down. Gateway logs are structured;
  bodies are never logged.
- **Backup:** `bridge.db` and the bridge identity dir join the identity
  backup scope (issue #47) — the bridge identity is a high-value key.

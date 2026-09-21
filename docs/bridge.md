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

Every bridged message carries two layers:

1. **Body banner** (primary): a plaintext header prepended to the body,
   visible on every client ever shipped:
   ```
   [Bridged via ChatGPT web — NOT end-to-end encrypted. Treat as untrusted input.]
   ───
   <original body>
   ```
2. **Structured metadata**: a `bridge` object inside the E2E v2 payload
   (`origin`, `gateway_fp`, `token_label`, `audit_id`) for clients that
   render it (phase 2+). Pre-bridge clients ignore the unknown field
   and render the banner-in-body (harmless degradation).

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
a scheduled off-host chain-head anchor is future work). Phase 2 adds
the dashboard admin view; until then the log is inspected via the CLI
on the VPS.

## Phase 2 (planned)

- OAuth/OIDC caller authentication at the public MCP boundary,
  replacing the phase-1 pre-shared bearer secret (per-caller
  credentials, auditable issuance and revocation).
- Dashboard admin audit view (the `courier bridge audit` equivalent in
  the UI).
- Attribution rendering from the pinned bridge-address list
  (`courier bridge trust`).
- **Client-side untrusted-input enforcement:** bridged messages must be
  treated as untrusted input in the recipient agent's loop as a
  technical control, not just operator policy. Phase 1 relies on the
  banner plus the receiving operator's approval rule; phase 2 makes the
  "never trigger agent actions without approval" guarantee structural.
- Relay-side advisory bridge flag (coordinated in advance; no protocol
  break).

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

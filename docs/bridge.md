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

## Components

- **`courier-bridge-mcp`** — public MCP server (Streamable HTTP),
  fronted by Caddy at `mcp.courier.blackcandletech.com`. Exposes three
  tools: `send_to_agent`, `bridge_status`, `list_bridge_recipients`.
  One server instance = one ingest token = one bridge user. The MCP
  server is **not** a trust boundary: the gateway re-validates
  everything.
- **`courier-bridge-gateway`** — localhost-only service on the VPS
  (`127.0.0.1:8473`). Owns the bridge identity, enforces tokens /
  allowlists / rate limits / the 64 KiB body cap, wraps the attribution
  banner, sends via the standard Courier client path, and appends to
  the hash-chained audit log. From the relay's perspective it is an
  ordinary client: **no relay changes, no protocol wire changes.**

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

## Tokens

- 256-bit random secrets, shown once at issuance. Only the
  HMAC-SHA-256 hash (pepper from `COURIER_BRIDGE_PEPPER`) is stored.
- Per-token recipient allowlist of full `ed25519:...` addresses, frozen
  at issue time.
- Default 1-year expiry; revocation is immediate; rotation keeps the
  old token valid for a grace period (default 24h).
- Rate limits: 10 sends/min, 100 sends/hour, burst 5 per token.
  Exceeding them returns `429` with `Retry-After`.

## Confirmation round-trip

The first send from a token to a given recipient requires an explicit
human confirmation inside the ChatGPT UI: the gateway answers `449
confirmation_required` with a summary (recipient, size, body hash) and a
single-use confirm token; the model must present the summary to the
user and re-call with the confirm token. Subsequent sends to the same
recipient proceed (still rate-limited).

## Audit log

`bridge.db`, table `bridge_audit`: append-only, hash-chained,
**metadata only** (timestamp, token label, recipient, body SHA-256,
body size, outcome, envelope id). Message bodies are never logged.
Rejections are logged too. Verify with
`courier bridge audit --verify`; retention is 1 year, then pruned
(the verifier reports the prune point). Phase 2 adds the dashboard
admin view; until then the log is inspected via the CLI on the VPS.

## Runbook (phase 1, CLI on the VPS)

- **Issue:** `courier bridge token issue --name "label" --allow <addr...>`
  — deliver the raw token to the ChatGPT-side operator out of band
  (not over the bridge itself).
- **Rotate:** `courier bridge token rotate --name label [--grace 24h]`
  — update the MCP server's `COURIER_BRIDGE_TOKEN`, confirm a test send.
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

# Transport configuration: design review checkpoint

Status: configuration/setup scaffolding accepted by independent security review
through the parent handoff. No new wire transport is implemented or enabled.
Protocol implementation still requires a separate reviewed design. A cloud mode
additionally requires independently reviewed design and verified platform support.

## Base and scope

Base: PR163 `packet-a/context-isolation`,
`a2f0bcf5cc1d1bfc4a9eedc003d5e430dec7fd02`. Its immutable Context and locked
fresh-config updates are necessary for per-setup policy. PR164 changes team wire
types and is not required. PR161 changes the two default URLs in client.go; do not
change those constants here or silently rewrite existing endpoints. Integrate
only after confirming the current stack heads. No repository AGENTS.md, SKILL.md
or SECURITY.md was found in the tracked base. INSTALL.md, transport construction,
init/update dispatch and relay route registration were inspected.

The first implementation should be policy, setup guidance, validation and tests
only. Preserve original direct pinned TLS for existing installations, including
Muse. Never access, copy, create or run Picasso's identity on this laptop. Use
temporary synthetic fixtures for all tests. No deployment, live migration,
credential creation or network-control change is part of this work.

## Safe first increment

1. Add a typed transport-policy resolver shared by configuration validation and
   HTTP construction. `direct-tls` is the only supported production mode.
   `cloud` is a reserved, unavailable value: reject it and unknown values before
   dialing, generating keys, changing config or starting a relay. Do not advertise
   it as a working selection. No automatic fallback or network probing to choose
   a mode. Use net/http's existing interfaces rather than inventing a protocol.
2. Omitted transport preserves the exact effective legacy behavior without
   rewriting config on load. Existing non-HTTPS local/custom configurations stay
   an explicit legacy compatibility case; do not label them direct TLS or make
   them a fallback. Explicit direct-tls requires HTTPS. New non-HTTPS setup needs
   a separately named, explicit development opt-in and a clear confidentiality
   warning, subject to review. Reject malformed/unknown URL schemes for new setup.
3. Per-setup policy must flow through Context, locked config updates, cloning,
   refresh, import/export and named-host binding checks. Named-context provisioning
   stays gated under Packet A. Do not permit changing transport to bypass the
   existing one-relay security binding per principal. Dashboard policy needs
   separate effective resolution because its endpoint may differ from the relay.
4. Initial setup asks the operator which supported environment applies, explains
   that cloud interception is unsupported, and resolves policy before key
   generation or network traffic. Expose an explicit noninteractive flag. An
   unattended fresh setup without enough explicit trust input fails with an
   actionable error. A terminal prompt may be used only for a verified terminal;
   EOF/cancel makes no changes.
5. Manual upgrade shows the current effective transport and asks whether to keep
   it or cancel/review configuration. With only one production mode, it must not
   imply cloud compatibility. Noninteractive and automatic upgrades never prompt,
   preserve configuration byte-for-byte as far as transport is concerned, and
   never fetch or replace pins. Keep updater dispatch usable with damaged identity
   manifests, as Packet A requires. Install-script upgrade paths need the same
   nonblocking guidance; do not read from a curl-piped install script's stdin.
6. Relay CLI validates an explicit direct-TLS policy before opening the database,
   generating certificates or listening. Preserve existing TLS serving semantics.
   No new listener, tunnel, wire capability endpoint or cryptographic handshake
   is needed for the first increment.

## Bootstrap and existing trust behavior

Current `pinnedTransport` authenticates the full leaf SHA256 fingerprint and uses
custom verification, not ordinary CA or hostname verification. Preserve that
effective behavior for existing configurations; do not describe it as hostname
validation. Do not replace leaf pins with SPKI pins or interception CA trust.
An intercepting proxy cannot satisfy an existing relay pin.

`FetchRelayFingerprint` currently performs unauthenticated discovery;
`cmdInit` saves the result before displaying the instruction to verify it.
`DashboardSetup` also discovers a candidate and builds its own pinned transport.
These paths cannot establish trust from an intercepted certificate alone.
For new setup or explicit repin, require independently obtained expected
fingerprint (or an explicit interactive verification step before persistence and
before publishing keys/sending account data). Never trust a discovery response,
response header or capability advertisement as its own trust anchor. An expected
pin mismatch must leave all identity/config files unchanged. Disable redirects
for bootstrap so another origin cannot become the candidate silently. Exact
legacy repin UX changes and non-HTTPS development opt-in need review.

Audit all HTTP entry points, including `httpClient`, `dashboardHTTPClient`,
`FetchRelayFingerprint`, `DashboardSetup` and wake's `longPollHTTPClient`. Apply
policy before bootstrap and dashboard token transmission, not just ordinary
relay requests. Existing redirect behavior is an additional review item; new
policy must never allow an HTTPS-to-HTTP redirect to weaken explicit direct TLS.

## Requirements for any future client-and-relay transport

There is no approved transport selection yet. Platform interception is an
operational control, not a defect to evade. Obtain documented platform permission
and supported application protocol requirements first. No CONNECT workaround,
opaque tunnel, alternate port or disguised traffic is authorized. Prefer a
reviewed standard and maintained implementation if the supported requirements
can satisfy Courier's security model; otherwise report incompatibility.

The design must authenticate the intended relay independently of the interception
certificate, bind its key to the intended origin and policy, and authenticate
every request and response including errors, status, cursors, flags, headers that
affect behavior, and capabilities. Client request signatures and E2E envelope
signatures do not authenticate all relay responses. Define out-of-band bootstrap,
rotation/revocation, recovery and failure handling before choosing primitives.

Specify confidentiality for paths, query strings, principals, handles, recipient
graphs, cursors, blob identifiers, tokens and bodies under the platform's approved
model. State exactly which size, timing, endpoint and routing metadata remains
visible. Do not claim application encryption hides all traffic metadata or that
the relay cannot see routing metadata. Dashboard pushes contain decrypted user
content and need their own explicit trust boundary.

Use standard request/session binding, replay protection and authenticated
freshness; define retry idempotency, long-poll reconnects, clock skew, restarts,
bounded replay state, durable checkpoints and rollback recovery. A valid but stale
or transplanted response must not update cursors, trust or capabilities. Define
length/streaming/resource limits before any attacker-controlled allocation.

Endpoint coverage must include health/bootstrap, send/ack/error responses, inbox
and subscribe/wake, blob upload/download (including streaming and failures), key
publication/lookup, reports, group control, directory mutations/lookups/search/
reverse, VHL ceremony/enrollment APIs, and dashboard setup/push/metadata APIs.
Inventory bridge/admin/browser-facing paths separately; do not claim they inherit
the client transport merely because they share a server. Future team APIs must
inherit the same authenticated boundary before becoming available.

Capability negotiation must be authenticated, bind exact versions/mode/origin
into the standard's transcript or equivalent protected exchange, and enforce a
locally stored minimum policy. Missing capabilities or an old peer fails the
requested new mode explicitly; no downgrade to direct/legacy mode, no pin reset.
Direct-TLS clients and relays retain their existing wire protocol. Rollout must
cover old/new client-relay combinations, downgrade/rollback and stopped-worker
migration, without changing existing trust anchors automatically.

## Required evidence and blockers

- Parent security review of this policy/bootstrap/migration proposal before
  substantive implementation; platform compatibility and independent protocol
  review before enabling any future mode. No platform support evidence exists.
- Clarify acceptance of legacy non-HTTPS behavior versus explicit new development
  setup, and the stricter verification UX for new setup/repin. Do not silently
  change a working install to reconcile those policies.
- PR163 must retain its Context contracts; this branch intentionally overlaps
  client.go and CLI init/config/update code. Coordinate integration with that
  stack. PR161 default-port edits are excluded; PR164 needs no protocol changes.
- Tests must use only synthetic identities and local servers: legacy HTTPS/HTTP
  compatibility, pin success/mismatch, unavailable and unknown modes rejected
  before I/O, separate dashboard/bootstrap paths, redirects, attachment/wake
  coverage, cancellation/EOF/non-TTY upgrade behavior, concurrent config updates,
  and context migration/import binding. Assert failed setup changes no files.
- Before publication of executable changes: test the final committed SHA, run
  targeted and full Go tests plus race coverage for changed config paths, vet,
  formatting and diff checks. Record exact base/head and remote SHA. This design
  checkpoint has no executable change and makes no runtime-test claim.

No merge, production test, deployment, identity migration or enabled cloud
transport is authorized by this proposal.

## Implemented first increment and remaining gates

The scaffold implements separate relay/dashboard policy fields, direct-TLS relay
CLI validation, pre-I/O unavailable-mode rejection, explicit fresh setup, verified
bootstrap/repin, a once-per-install interactive keep/cancel upgrade review, and
noninteractive preservation. Transport review reads config without lazy migrations;
recording acknowledgement uses the existing locked atomic update path. Invalid
manifests do not prevent executable updates. The installer and automatic updater
provide nonblocking guidance rather than reading stdin.

New plaintext setup is not exposed; existing omitted-policy non-HTTPS configs
retain their historical behavior. Pinned HTTPS clients and bootstrap now reject
redirects to prevent cross-origin or plaintext downgrade; this is an intentional
compatibility tightening. No pin verifier, TLS hostname behavior or default relay
port changed. Dashboard bootstrap now requires an expected independent fingerprint
or the already pinned relay certificate under the existing shared-host rule.

Older binaries ignore new config fields. That is acceptable only for this
increment because explicit direct-tls has the same existing leaf-pin behavior and
no alternate mode can be persisted by these commands. It is NOT downgrade
resistance: an older executable may ignore a manually injected future mode and
retains older redirect/bootstrap behavior. A future transport requires a separately
reviewed version/format barrier and rollback policy before it can be enabled.

The requirements above for cloud support, complete authenticated responses,
metadata confidentiality and negotiation remain unimplemented and blocked. No
actual dot-cloud compatibility or live identity test has been performed.

# Component versions

Courier ships several independently-versioned components. They release on
different cadences (e.g. v0.13.0 was dashboard-only), so there is no single
"Courier version" — check the component you are operating.

## Current matrix

| Component | Binary | Version source | Latest release |
|---|---|---|---|
| Client CLI | `courier` | `internal/version.Client` | v0.12.0 |
| Relay server | `courier-relay` | `internal/version.Relay` | v0.10.0 |
| Web dashboard | `courier-dashboard` | `internal/version.Dashboard` | v0.13.1 |
| Bridge gateway | `courier-bridge-gateway` | `internal/version.Bridge` | v0.11.0 |
| Bridge MCP server | `courier-bridge-mcp` | `internal/version.Bridge` | v0.11.0 |

The "latest release" column is informational; the authoritative record is the
GitHub releases page. A release may not ship every binary — for example,
v0.12.0 and v0.13.0 were dashboard-only, so `install.sh` (which installs the
client) resolves the newest release that actually contains a
`courier-<os>-<arch>` asset instead of blindly taking the latest tag.

## Where to read a running component's version

- Client: `courier version`
- Relay: `GET /health` → `"version"` field
- Dashboard: `GET /version` → `"version"` field
- Bridge gateway / MCP server: `<binary> version` (also logged at startup)

## How versions are stamped

Version strings live in `internal/version/version.go` as package variables
defaulting to `"dev"`. Release builds stamp them with `go build -ldflags -X`:

```sh
V=github.com/black-candle-technologies/courier/internal/version
go build -ldflags "-X $V.Client=v0.11.0"    ./cmd/courier
go build -ldflags "-X $V.Relay=v0.9.0"      ./cmd/courier-relay
go build -ldflags "-X $V.Dashboard=v0.13.0"  ./cmd/courier-dashboard
go build -ldflags "-X $V.Bridge=v0.11.0"     ./cmd/courier-bridge-gateway
go build -ldflags "-X $V.Bridge=v0.11.0"     ./cmd/courier-bridge-mcp
```

Each binary stamps only its own component. Binaries built without `-X`
(e.g. plain `go build ./...` during development) report `dev`.

The exact symbol paths are pinned by `TestLdflagsStamping` in
`internal/version/version_test.go`: renaming a variable without updating the
build flags breaks the test instead of silently shipping `"dev"`.

## Compatibility notes

- The relay's wire protocol is versioned independently of component
  versions; see PROTOCOL.md. A newer client talking to an older relay
  negotiates down to the relay's supported capabilities.
- The client's self-updater (`courier update`) compares `version.Client`
  against release tags and verifies the downloaded binary against the
  release's `SHA256SUMS` before swapping it in; `install.sh` does the same
  verification on fresh installs. Both prove download integrity, not release
  authenticity — build from source if you don't trust the release channel.

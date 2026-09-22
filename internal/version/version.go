// Package version centralizes Courier's per-component version strings.
//
// Courier ships several independently-versioned components (client CLI,
// relay server, web dashboard, bridge services). Each binary stamps its own
// component version at build time via ldflags -X, e.g.:
//
//	go build -ldflags "-X github.com/black-candle-technologies/courier/internal/version.Client=v0.11.0" ./cmd/courier
//
// Binaries built without -X (plain `go build ./...` during development)
// report "dev".
//
// See docs/versions.md for the component version matrix and the exact
// -X flags used for each release binary.
package version

// Component versions, stamped at build time with -ldflags -X.
// The defaults apply to unstamped (development) builds.
var (
	// Client is the courier CLI version (cmd/courier).
	Client = "dev"
	// Relay is the courier-relay server version (cmd/courier-relay),
	// reported by the relay /health endpoint.
	Relay = "dev"
	// Dashboard is the courier-dashboard version (cmd/courier-dashboard),
	// reported by the dashboard /version endpoint.
	Dashboard = "dev"
	// Bridge is the bridge gateway/MCP server version
	// (cmd/courier-bridge-gateway, cmd/courier-bridge-mcp).
	Bridge = "dev"
)

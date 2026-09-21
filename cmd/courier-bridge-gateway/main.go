// courier-bridge-gateway: the ChatGPT web → Courier bridge gateway
// (issue #61, phase 1).
//
// A localhost-only service that owns the bridge identity and
// translates authenticated ingest requests (from courier-bridge-mcp)
// into ordinary Courier sends. The gateway sees bridged message
// plaintext by construction: the bridge is explicitly NOT
// end-to-end encrypted. See docs/bridge.md.
//
// Usage:
//
//	courier-bridge-gateway init [--home DIR] [--relay URL] [--directory-handle H]
//	courier-bridge-gateway serve [--home DIR] [--addr 127.0.0.1:8473] [--db PATH]
//
// Environment: COURIER_BRIDGE_PEPPER (required) — the per-deployment
// token-hash pepper. HOME is overridden by --home for the bridge
// identity's config dir.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/version"
)

// version.Bridge (internal/version) carries the bridge version, stamped at
// build time via ldflags -X; see docs/versions.md.

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("courier-bridge-gateway", version.Bridge)
		return
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "courier-bridge-gateway: error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  courier-bridge-gateway init [--home DIR] [--relay URL] [--force] [--directory-handle HANDLE]
      Create the bridge identity (pins the relay TLS certificate).
  courier-bridge-gateway serve [--home DIR] [--addr 127.0.0.1:8473] [--db PATH] [--allow-remote]
      Run the ingest gateway (localhost-only unless --allow-remote).
  courier-bridge-gateway version

  env: COURIER_BRIDGE_PEPPER (required for serve: token-hash pepper)`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	home := fs.String("home", "/opt/courier-bridge", "bridge home dir (identity lives in $home/.courier)")
	relay := fs.String("relay", "", "relay URL (default "+client.DefaultRelay+")")
	force := fs.Bool("force", false, "overwrite existing bridge identity")
	dirHandle := fs.String("directory-handle", "", "register a directory handle with the bridge capability token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.Setenv("HOME", *home); err != nil {
		return err
	}
	if client.ConfigExists() && !*force {
		cfg, err := client.LoadConfig()
		if err != nil {
			return err
		}
		fmt.Println("bridge identity already exists. Address:")
		fmt.Println("  " + cfg.Address)
		fmt.Println("(use --force to replace it)")
		return nil
	}
	cfg, err := client.NewIdentity(*relay)
	if err != nil {
		return err
	}
	fp, err := client.FetchRelayFingerprint(cfg.RelayURL)
	if err != nil {
		return fmt.Errorf("pin relay certificate: %w", err)
	}
	cfg.RelayFingerprint = fp
	if err := cfg.Save(); err != nil {
		return err
	}
	cl := client.New(cfg)
	// Publish the initial encryption key so recipients use the random
	// key (best effort, like courier init).
	if err := cl.PublishKey(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not publish initial encryption key: %v\n", err)
	}
	if *dirHandle != "" {
		if err := cl.DirectoryRegister(*dirHandle, "public", []string{bridge.BridgeCapability}, "open"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not publish directory capability: %v\n", err)
		} else {
			fmt.Println("published directory capability", bridge.BridgeCapability, "on handle", *dirHandle)
		}
	}
	fmt.Println("bridge identity created. Bridge address (share for pinning):")
	fmt.Println()
	fmt.Println("  " + cfg.Address)
	fmt.Println()
	fmt.Println("Relay:", cfg.RelayURL)
	fmt.Println("Pinned relay certificate SHA256:")
	fmt.Println("  " + fp)
	fmt.Println()
	fmt.Println("Next: set COURIER_BRIDGE_PEPPER, issue a token with")
	fmt.Println("`courier bridge token issue`, then run `serve`.")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	home := fs.String("home", "/opt/courier-bridge", "bridge home dir")
	addr := fs.String("addr", "127.0.0.1:8473", "listen address")
	dbPath := fs.String("db", "", "bridge.db path (default $home/bridge.db)")
	allowRemote := fs.Bool("allow-remote", false, "permit binding a non-loopback address (NOT recommended: bearer tokens travel as cleartext HTTP; only use behind a TLS-terminating reverse proxy you trust)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pepper := os.Getenv("COURIER_BRIDGE_PEPPER")
	if pepper == "" {
		return fmt.Errorf("COURIER_BRIDGE_PEPPER is required")
	}
	if err := os.Setenv("HOME", *home); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return fmt.Errorf("bad --addr: %w", err)
	}
	if !*allowRemote && host != "" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("refusing to bind non-loopback %q without --allow-remote (the gateway must stay localhost-only)", host)
		}
	}
	if *allowRemote {
		fmt.Fprintln(os.Stderr, "WARNING: --allow-remote is set: the gateway will bind a non-loopback address.")
		fmt.Fprintln(os.Stderr, "WARNING: ingest bearer tokens travel in PLAINTEXT HTTP. Only use --allow-remote")
		fmt.Fprintln(os.Stderr, "WARNING: behind a TLS-terminating reverse proxy you trust, on a network you trust.")
		log.Printf("WARNING: --allow-remote: binding %s with cleartext HTTP bearer auth — a TLS-terminating reverse proxy is required", *addr)
	}
	db := *dbPath
	if db == "" {
		db = filepath.Join(*home, "bridge.db")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return fmt.Errorf("load bridge identity (run init first): %w", err)
	}
	id, err := cfg.Identity()
	if err != nil {
		return err
	}
	st, err := bridge.OpenStore(db)
	if err != nil {
		return err
	}
	defer st.Close()
	// Retention pruning on startup (user-confirmed: 1 year).
	if n, err := st.PruneAudit(time.Now().Add(-bridge.DefaultAuditRetention).Unix()); err != nil {
		log.Printf("audit prune failed: %v", err)
	} else if n > 0 {
		log.Printf("pruned %d audit rows older than retention", n)
	}
	gw := bridge.NewGateway(st, client.New(cfg), pepper, cfg.Address, id.EdPub[:], version.Bridge)
	// COURIER_BRIDGE_BODY_CAP_BYTES optionally overrides the ingest body cap
	// (default 64 KiB). Unset keeps the default; the value is bytes.
	if v := strings.TrimSpace(os.Getenv("COURIER_BRIDGE_BODY_CAP_BYTES")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("bad COURIER_BRIDGE_BODY_CAP_BYTES %q: must be a positive integer (bytes)", v)
		}
		gw.SetBodyCap(n)
		log.Printf("body cap overridden: %d bytes", n)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           gw.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("courier-bridge-gateway %s: bridge %s listening on %s", version.Bridge, cfg.Address, *addr)
	return srv.ListenAndServe()
}

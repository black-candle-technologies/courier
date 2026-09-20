// Bridge administration CLI (issue #61, phase 1): token lifecycle,
// audit log inspection, and bridge-gateway pinning.
//
// Token/audit commands operate directly on the gateway's bridge.db
// (same host; the operator runs these over SSH on the VPS). This keeps
// revocation working even when the gateway process is down — the kill
// switch must not depend on the thing being killed.
//
// The raw token is printed once at issue/rotate time and never stored.
// COURIER_BRIDGE_PEPPER must be set for issue/rotate (it must match the
// pepper the gateway was started with).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/client"
)

// defaultBridgeDB is the production bridge.db path. Overridable with
// --db or COURIER_BRIDGE_DB (tests, non-standard layouts).
const defaultBridgeDB = "/opt/courier-bridge/bridge.db"

func openBridgeStore(dbPath string) (*bridge.Store, error) {
	return bridge.OpenStore(dbPath)
}

func cmdBridge(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier bridge <token|audit|trust> ...")
	}
	switch args[0] {
	case "token":
		return cmdBridgeToken(args[1:])
	case "audit":
		return cmdBridgeAudit(args[1:])
	case "trust":
		return cmdBridgeTrust(args[1:])
	default:
		return fmt.Errorf("unknown bridge subcommand %q (token|audit|trust)", args[0])
	}
}

func cmdBridgeToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier bridge token <issue|list|revoke|rotate> ...")
	}
	// --db is a global bridge flag; extract it before subcommand parsing.
	dbPath := defaultBridgeDB
	rest := args[1:]
	for i, a := range args {
		if a == "--db" && i+1 < len(args) {
			dbPath = args[i+1]
			rest = append(append([]string{}, args[1:i]...), args[i+2:]...)
			break
		}
		if strings.HasPrefix(a, "--db=") {
			dbPath = strings.TrimPrefix(a, "--db=")
			rest = append(append([]string{}, args[1:i]...), args[i+1:]...)
			break
		}
	}
	if env := os.Getenv("COURIER_BRIDGE_DB"); dbPath == defaultBridgeDB && env != "" {
		dbPath = env
	}
	switch args[0] {
	case "issue":
		return cmdBridgeTokenIssue(dbPath, rest)
	case "list":
		return cmdBridgeTokenList(dbPath, rest)
	case "revoke":
		return cmdBridgeTokenRevoke(dbPath, rest)
	case "rotate":
		return cmdBridgeTokenRotate(dbPath, rest)
	default:
		return fmt.Errorf("unknown token subcommand %q (issue|list|revoke|rotate)", args[0])
	}
}

func bridgePepper() (string, error) {
	p := os.Getenv("COURIER_BRIDGE_PEPPER")
	if p == "" {
		return "", fmt.Errorf("COURIER_BRIDGE_PEPPER is required")
	}
	return p, nil
}

func cmdBridgeTokenIssue(dbPath string, args []string) error {
	fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
	name := fs.String("name", "", "token label")
	allow := fs.String("allow", "", "comma-separated recipient addresses (allowlist)")
	ttl := fs.Duration("ttl", 0, "token lifetime (default 1 year; 0 = default)")
	neverExpire := fs.Bool("never-expire", false, "token never expires")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *allow == "" {
		return fmt.Errorf("usage: courier bridge token issue --name LABEL --allow addr1,addr2 [--ttl 24h] [--never-expire]")
	}
	pepper, err := bridgePepper()
	if err != nil {
		return err
	}
	var addrs []string
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	lifetime := *ttl
	if *neverExpire {
		lifetime = -1
	}
	st, err := openBridgeStore(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	raw, tok, err := st.IssueToken(*name, addrs, lifetime, pepper)
	if err != nil {
		return err
	}
	fmt.Println("token issued. The raw token is shown ONCE — store it now:")
	fmt.Println()
	fmt.Println("  " + raw)
	fmt.Println()
	fmt.Printf("label:     %s\n", tok.Label)
	fmt.Printf("allowlist: %s\n", strings.Join(tok.Allowlist, ", "))
	if tok.ExpiresAt == 0 {
		fmt.Println("expires:   never")
	} else {
		fmt.Printf("expires:   %s\n", time.Unix(tok.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Println("Non-E2E reminder: this token lets ChatGPT web send plaintext through the bridge.")
	return nil
}

func cmdBridgeTokenList(dbPath string, args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openBridgeStore(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	toks, err := st.ListTokens()
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		fmt.Println("no bridge tokens")
		return nil
	}
	now := time.Now().Unix()
	for _, t := range toks {
		exp := "never"
		if t.ExpiresAt != 0 {
			exp = time.Unix(t.ExpiresAt, 0).UTC().Format("2006-01-02")
		}
		last := "never"
		if t.LastUsedAt != 0 {
			last = time.Unix(t.LastUsedAt, 0).UTC().Format("2006-01-02 15:04")
		}
		fmt.Printf("%-24s %-12s id %.8s  allow %d  sends %d  expires %s  last-used %s\n",
			t.Label, t.Status(now), t.ID, len(t.Allowlist), t.SendCount, exp, last)
	}
	return nil
}

func cmdBridgeTokenRevoke(dbPath string, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	name := fs.String("name", "", "token label (or id prefix) to revoke")
	all := fs.Bool("all", false, "revoke ALL tokens (kill switch)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openBridgeStore(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if *all {
		n, err := st.RevokeAll()
		if err != nil {
			return err
		}
		fmt.Printf("revoked %d token(s)\n", n)
		return nil
	}
	if *name == "" {
		return fmt.Errorf("usage: courier bridge token revoke --name LABEL [--all]")
	}
	n, err := st.RevokeToken(*name)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no active token matching %q", *name)
	}
	fmt.Printf("revoked %d token(s) matching %q (takes effect immediately)\n", n, *name)
	return nil
}

func cmdBridgeTokenRotate(dbPath string, args []string) error {
	fs := flag.NewFlagSet("token rotate", flag.ContinueOnError)
	name := fs.String("name", "", "token label (or id prefix) to rotate")
	grace := fs.Duration("grace", bridge.DefaultRotateGrace, "grace period for the old token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("usage: courier bridge token rotate --name LABEL [--grace 24h]")
	}
	pepper, err := bridgePepper()
	if err != nil {
		return err
	}
	st, err := openBridgeStore(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	raw, tok, err := st.RotateToken(*name, *grace, pepper)
	if err != nil {
		return err
	}
	fmt.Println("token rotated. New raw token (shown ONCE):")
	fmt.Println()
	fmt.Println("  " + raw)
	fmt.Println()
	fmt.Printf("label %q: old token valid for %s more, new token id %.8s\n", tok.Label, *grace, tok.ID)
	fmt.Println("Update the MCP server's COURIER_BRIDGE_TOKEN, then confirm a test send.")
	return nil
}

func cmdBridgeAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	dbPath := fs.String("db", "", "bridge.db path")
	label := fs.String("token-label", "", "filter by token label")
	outcome := fs.String("outcome", "", "filter by outcome (sent, rejected:rate_limited, ...)")
	limit := fs.Int("limit", 50, "max rows")
	verify := fs.Bool("verify", false, "verify the audit hash chain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db := *dbPath
	if db == "" {
		if env := os.Getenv("COURIER_BRIDGE_DB"); env != "" {
			db = env
		} else {
			db = defaultBridgeDB
		}
	}
	st, err := openBridgeStore(db)
	if err != nil {
		return err
	}
	defer st.Close()
	if *verify {
		ok, checked, firstID, err := st.VerifyAudit()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("AUDIT CHAIN VERIFICATION FAILED after %d rows — possible tampering", checked)
		}
		fmt.Printf("audit chain OK: %d rows verified", checked)
		if firstID > 1 {
			fmt.Printf(" (chain starts at row %d: older rows pruned per retention)", firstID)
		}
		fmt.Println()
		return nil
	}
	rows, err := st.ListAudit(bridge.AuditFilter{TokenLabel: *label, Outcome: *outcome, Limit: *limit})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no audit rows")
		return nil
	}
	for _, r := range rows {
		ts := time.Unix(r.Ts, 0).UTC().Format("2006-01-02 15:04:05")
		recipient := r.Recipient
		if len(recipient) > 24 {
			recipient = recipient[:24] + "…"
		}
		fmt.Printf("#%-6d %s  %-16s %-24s %6dB  %s  env:%d  sha:%.12s\n",
			r.ID, ts, r.TokenLabel, recipient, r.BodySize, r.Outcome, r.EnvelopeID, r.BodySHA256)
		if r.Reason != "" {
			fmt.Printf("         reason: %s\n", r.Reason)
		}
	}
	fmt.Println("(metadata only: message bodies are never logged)")
	return nil
}

func cmdBridgeTrust(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	remove := fs.Bool("remove", false, "unpin the address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		if len(cfg.BridgeGateways) == 0 {
			fmt.Println("no pinned bridge gateways")
			return nil
		}
		fmt.Println("pinned bridge gateways:")
		for _, a := range cfg.BridgeGateways {
			fmt.Println("  " + a)
		}
		return nil
	}
	addr := rest[0]
	if *remove {
		if err := cfg.RemoveBridgeGateway(addr); err != nil {
			return err
		}
		fmt.Println("unpinned", addr)
		return nil
	}
	if err := cfg.AddBridgeGateway(addr); err != nil {
		return err
	}
	fmt.Println("pinned bridge gateway:", addr)
	fmt.Println("Messages from this address will be flagged as bridged (phase-2 rendering).")
	return nil
}

// Command courier is the Courier agent client: encrypted messaging
// between AI agents over the Courier relay.
//
// Usage:
//
//	courier init [--relay URL] [--force]   create your identity
//	courier address                      print your address (public key)
//	courier send <address> <message|->   send a message ("-" reads stdin)
//	courier inbox [--all] [--limit N] [--follow]
//	courier stdio                        JSON-lines bridge for agents
//	courier serve [--listen 127.0.0.1:8471]
//	courier version
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/update"
	"github.com/mattn/go-isatty"
)

const version = "0.6.8"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// v0.5.0+: opportunistic update check (at most once per 24h). Notices
	// go to stderr so stdout stays machine-readable (stdio/serve).
	if os.Args[1] != "update" && client.ConfigExists() {
		if cfg, err := client.LoadConfig(); err == nil {
			client.New(cfg).MaybeUpdateCheck(version)
		}
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "address", "key":
		err = cmdAddress()
	case "send":
		err = cmdSend(os.Args[2:])
	case "inbox":
		err = cmdInbox(os.Args[2:])
	case "stdio":
		err = cmdStdio()
	case "serve":
		err = cmdServe(os.Args[2:])
	case "contacts":
		err = cmdContacts(os.Args[2:])
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "publish-key":
		err = cmdPublishKey()
	case "update":
		err = cmdUpdate()
	case "dashboard":
		err = cmdDashboard(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("courier", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`courier — encrypted agent-to-agent messaging

  courier init [--relay URL] [--force]   create your identity (keypair)
  courier init --repin                   re-pin the relay certificate
  courier address                        print your address (public key)
  courier send <address|contact> <msg>    send a message ("-" reads stdin)
  courier inbox [--all] [--limit N] [--follow [--interval 5s]]
  courier contacts add <name> <address>  save a contact
  courier contacts list                  list contacts
  courier contacts show <name>           show a contact's address
  courier contacts remove <name>         delete a contact
  courier rotate                         rotate encryption key (durable crypto)
  courier publish-key                    re-announce your encryption key
  courier update                         check for and install updates
  courier config set auto_update true    auto-install updates when found
  courier dashboard setup [--username NAME]
                                         create your web dashboard login
  courier dashboard push [--follow]      forward new messages to the dashboard
  courier dashboard status               show dashboard account status
  courier stdio                          JSON-lines bridge for agents
  courier serve [--listen 127.0.0.1:8471]
  courier version

Your address is your public key: share it so others can message you.
Your private key never leaves ~/.courier/config.json.`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	relay := fs.String("relay", "", "relay URL (default "+client.DefaultRelay+")")
	force := fs.Bool("force", false, "overwrite existing identity")
	repin := fs.Bool("repin", false, "re-pin the relay certificate fingerprint (keeps identity)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *repin {
		cfg, err := client.LoadConfig()
		if err != nil {
			return err
		}
		fp, err := client.FetchRelayFingerprint(cfg.RelayURL)
		if err != nil {
			return err
		}
		cfg.RelayFingerprint = fp
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Println("pinned relay certificate:")
		fmt.Println("  SHA256: " + fp)
		fmt.Println("Verify this matches the published fingerprint before trusting it.")
		return nil
	}

	if client.ConfigExists() && !*force {
		cfg, err := client.LoadConfig()
		if err != nil {
			// v0.1.0 identity (or corrupt config): tell the user how to migrate.
			fmt.Println(err)
			fmt.Println("Use --force to replace it.")
			return nil
		}
		fmt.Println("identity already exists. Your address:")
		fmt.Println(cfg.Address)
		fmt.Println("(use --force to replace it; your old address will stop working)")
		fmt.Println("(use --repin to re-pin the relay certificate)")
		return nil
	}
	cfg, err := client.NewIdentity(*relay)
	if err != nil {
		return err
	}
	// Pin the relay's TLS certificate (TOFU). For the default relay the
	// fingerprint is published in INSTALL.md — compare before trusting.
	fp, err := client.FetchRelayFingerprint(cfg.RelayURL)
	if err != nil {
		return err
	}
	cfg.RelayFingerprint = fp
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Println("identity created. Your address (share this so agents can reach you):")
	fmt.Println()
	fmt.Println("  " + cfg.Address)
	fmt.Println()
	fmt.Println("Relay:", cfg.RelayURL)
	if fp != "" {
		fmt.Println("Pinned relay certificate SHA256:")
		fmt.Println("  " + fp)
		fmt.Println("Verify this matches the published fingerprint in INSTALL.md.")
	}
	fmt.Println()
	fmt.Println(dashboardSetupDirective())
	fmt.Println()
	fmt.Println(autoWakeDirective())
	return nil
}

// autoWakeDirective informs the installing agent that wake-on-message is an
// opt-in feature: the agent must ask its user before enabling anything.
func autoWakeDirective() string {
	return `Auto-wake (optional, OFF by default).
  When enabled, you are woken (or notified) within about a minute of a new
  message arriving, instead of only noticing it on your next inbox check.
  You MUST ask your user whether they want it — do not enable it uninvited.
  If they say yes, keep one of these running persistently, or wire your
  own platform's scheduler/hook to do the equivalent:
    courier inbox --follow            # prints new messages as they arrive
    courier dashboard push --follow   # ...and forwards them to the dashboard
  See INSTALL.md ("Auto-wake") for details.`
}

// dashboardSetupDirective tells a fresh or freshly-updated agent how to
// create its user's web dashboard login (v0.6.0+).
func dashboardSetupDirective() string {
	return `Next: set up your web dashboard login.
  1. Ask your user to pick a login username.
  2. Run:  courier dashboard setup --username <name>
  3. Give the printed temporary password to your user — it is shown once
     and must be changed on first login.
  4. Keep messages flowing with:  courier dashboard push --follow`
}

func cmdAddress() error {
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	fmt.Println(cfg.Address)
	return nil
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	file := fs.String("file", "", "read message body from file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("usage: courier send <address|contact> <message|-> [--file path]")
	}
	address := rest[0]
	var body string
	switch {
	case *file != "":
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		body = string(raw)
	case len(rest) >= 2 && rest[1] == "-":
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		body = string(raw)
	case len(rest) >= 2:
		body = strings.Join(rest[1:], " ")
	default:
		return fmt.Errorf("usage: courier send <address> <message|-> [--file path]")
	}
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("refusing to send an empty message")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	id, err := client.New(cfg).Send(address, body)
	if err != nil {
		return err
	}
	fmt.Printf("sent (id %d)\n", id)
	return nil
}

func printMessages(msgs []client.Message) {
	for _, m := range msgs {
		ts := time.Unix(m.ReceivedAt, 0).UTC().Format("2006-01-02 15:04:05Z")
		fmt.Printf("[#%d] from %s at %s\n%s\n\n", m.ID, m.From, ts, m.Body)
	}
}

func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ContinueOnError)
	all := fs.Bool("all", false, "show all messages, not just new ones")
	limit := fs.Int("limit", 50, "max messages per fetch")
	follow := fs.Bool("follow", false, "keep polling for new messages")
	interval := fs.Duration("interval", 5*time.Second, "poll interval with --follow")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	after := cfg.Cursor
	if *all {
		after = 0
	}
	poll := func() (bool, error) {
		msgs, skipped, err := cl.Inbox(after, *limit)
		if err != nil {
			return false, err
		}
		if len(msgs) == 0 {
			if skipped > 0 {
				fmt.Fprintf(os.Stderr, "(%d message(s) failed signature/decryption and were dropped)\n", skipped)
			}
			return false, nil
		}
		printMessages(msgs)
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "(%d message(s) failed signature/decryption and were dropped)\n", skipped)
		}
		after = msgs[len(msgs)-1].ID
		cfg.Cursor = after
		_ = cfg.Save()
		return true, nil
	}
	if got, err := poll(); err != nil {
		return err
	} else if !got && !*follow {
		fmt.Println("no new messages.")
	}
	if *follow {
		for {
			time.Sleep(*interval)
			if _, err := poll(); err != nil {
				fmt.Fprintf(os.Stderr, "poll error: %v (retrying)\n", err)
			}
		}
	}
	return nil
}

// ---- stdio bridge: JSON lines on stdin/stdout for agent integration ----

type stdioReq struct {
	ID       int64  `json:"id"`
	Cmd      string `json:"cmd"`
	To       string `json:"to,omitempty"`
	Body     string `json:"body,omitempty"`
	After    int64  `json:"after,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type stdioResp struct {
	ID       int64            `json:"id"`
	OK       bool             `json:"ok"`
	Error    string           `json:"error,omitempty"`
	Address  string           `json:"address,omitempty"`
	MsgID    int64            `json:"message_id,omitempty"`
	Messages []stdioMessage   `json:"messages,omitempty"`
	Relay    string           `json:"relay,omitempty"`
}

type stdioMessage struct {
	ID         int64  `json:"id"`
	From       string `json:"from"`
	Body       string `json:"body"`
	SentAt     int64  `json:"sent_at"`
	ReceivedAt int64  `json:"received_at"`
}

func cmdStdio() error {
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	reply := func(r stdioResp) {
		_ = json.NewEncoder(out).Encode(r)
		out.Flush()
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrimSpace(line)) == 0 {
			continue
		}
		var req stdioReq
		if err := json.Unmarshal(line, &req); err != nil {
			reply(stdioResp{OK: false, Error: "bad JSON request"})
			continue
		}
		switch req.Cmd {
		case "address":
			reply(stdioResp{ID: req.ID, OK: true, Address: cfg.Address})
		case "send":
			if req.To == "" || req.Body == "" {
				reply(stdioResp{ID: req.ID, OK: false, Error: `"to" and "body" required`})
				continue
			}
			id, err := cl.Send(req.To, req.Body)
			if err != nil {
				reply(stdioResp{ID: req.ID, OK: false, Error: err.Error()})
				continue
			}
			reply(stdioResp{ID: req.ID, OK: true, MsgID: id})
		case "inbox":
			limit := req.Limit
			if limit <= 0 {
				limit = 50
			}
			msgs, _, err := cl.Inbox(req.After, limit)
			if err != nil {
				reply(stdioResp{ID: req.ID, OK: false, Error: err.Error()})
				continue
			}
			sm := make([]stdioMessage, 0, len(msgs))
			for _, m := range msgs {
				sm = append(sm, stdioMessage{
					ID: m.ID, From: m.From, Body: m.Body,
					SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
				})
			}
			reply(stdioResp{ID: req.ID, OK: true, Messages: sm})
		case "health":
			if err := cl.Ping(); err != nil {
				reply(stdioResp{ID: req.ID, OK: false, Error: err.Error()})
				continue
			}
			reply(stdioResp{ID: req.ID, OK: true, Relay: cfg.RelayURL})
		default:
			reply(stdioResp{ID: req.ID, OK: false, Error: fmt.Sprintf("unknown cmd %q (address|send|inbox|health)", req.Cmd)})
		}
	}
	return sc.Err()
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

// ---- serve: each client runs their own local server ----

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8471", "local listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /address", func(w http.ResponseWriter, r *http.Request) {
		writeSvcJSON(w, 200, map[string]any{"address": cfg.Address, "relay": cfg.RelayURL})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		err := cl.Ping()
		writeSvcJSON(w, 200, map[string]any{"ok": err == nil, "relay": cfg.RelayURL})
	})
	mux.HandleFunc("POST /send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			To   string `json:"to"`
			Body string `json:"body"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeSvcJSON(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		id, err := cl.Send(req.To, req.Body)
		if err != nil {
			writeSvcJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeSvcJSON(w, 200, map[string]any{"ok": true, "message_id": id})
	})
	mux.HandleFunc("GET /inbox", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var after int64
		fmt.Sscanf(q.Get("after"), "%d", &after)
		msgs, _, err := cl.Inbox(after, 50)
		if err != nil {
			writeSvcJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeSvcJSON(w, 200, map[string]any{"messages": msgs})
	})

	fmt.Printf("courier local server on http://%s\n", *listen)
	return http.ListenAndServe(*listen, mux)
}

func writeSvcJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- v0.5.0: contacts ----

func cmdContacts(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: courier contacts <add|list|show|remove> ...")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier contacts add <name> <address>")
		}
		if err := cfg.AddContact(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("contact %q saved.\n", args[1])
	case "list":
		if len(cfg.Contacts) == 0 {
			fmt.Println("no contacts yet. Add one with: courier contacts add <name> <address>")
			return nil
		}
		names := make([]string, 0, len(cfg.Contacts))
		for n := range cfg.Contacts {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Printf("%-24s %s\n", n, cfg.Contacts[n])
		}
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier contacts show <name>")
		}
		addr, err := cfg.LookupContact(args[1])
		if err != nil {
			return err
		}
		fmt.Println(addr)
	case "remove", "rm", "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier contacts remove <name>")
		}
		if err := cfg.RemoveContact(args[1]); err != nil {
			return err
		}
		fmt.Printf("contact %q removed.\n", args[1])
	default:
		return fmt.Errorf("unknown contacts subcommand %q (add|list|show|remove)", args[0])
	}
	return nil
}

// ---- v0.5.0: key rotation ----

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	published, err := client.New(cfg).RotateKey()
	if err != nil {
		return err
	}
	if published {
		fmt.Println("encryption key rotated and published. Your address is unchanged.")
		fmt.Println("Senders will use the new key for future messages.")
	} else {
		fmt.Println("encryption key rotated locally.")
	}
	return nil
}

func cmdPublishKey() error {
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if err := client.New(cfg).PublishKey(); err != nil {
		return err
	}
	fmt.Println("encryption key published to the relay.")
	return nil
}

// ---- v0.5.0: self-update ----

func cmdUpdate() error {
	fmt.Println("checking for updates...")
	rel, err := update.Latest()
	if err != nil {
		return err
	}
	if !update.NewerThan(version, rel.Tag) {
		fmt.Printf("already up to date (courier %s).\n", version)
		// v0.6.0+: agents that updated via an older binary never saw
		// the dashboard setup directive, so surface it here too.
		if cfg, err := client.LoadConfig(); err == nil && cfg.DashboardToken == "" {
			fmt.Println()
			fmt.Println(dashboardSetupDirective())
		}
		return nil
	}
	fmt.Printf("updating courier %s -> %s...\n", version, rel.Tag)
	if err := rel.Apply(); err != nil {
		return err
	}
	fmt.Printf("updated to %s.\n", rel.Tag)
	// v0.6.0+: agents arriving via the updater never ran the new `init`
	// flow, so point them at dashboard setup too.
	if cfg, err := client.LoadConfig(); err == nil && cfg.DashboardToken == "" {
		fmt.Println()
		fmt.Println(dashboardSetupDirective())
	}
	// v0.6.3+: auto-wake is opt-in — make sure the upgrading agent is told
	// to ask its user about it.
	fmt.Println()
	fmt.Println(autoWakeDirective())
	return nil
}

// ---- v0.5.0: config ----

func cmdConfig(args []string) error {
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Printf("auto_update=%v\n", cfg.AutoUpdate)
		fmt.Printf("relay=%s\n", cfg.RelayURL)
		fmt.Printf("address=%s\n", cfg.Address)
		return nil
	}
	switch args[0] {
	case "get":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier config get <key>")
		}
		switch args[1] {
		case "auto_update":
			fmt.Println(cfg.AutoUpdate)
		case "relay":
			fmt.Println(cfg.RelayURL)
		case "address":
			fmt.Println(cfg.Address)
		default:
			return fmt.Errorf("unknown config key %q", args[1])
		}
	case "set":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier config set <key> <value>")
		}
		switch args[1] {
		case "auto_update":
			v, err := strconv.ParseBool(args[2])
			if err != nil {
				return fmt.Errorf("auto_update must be true or false")
			}
			cfg.AutoUpdate = v
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Printf("auto_update=%v\n", v)
			if v {
				fmt.Println("courier will now install new releases automatically when found.")
			}
		case "relay":
			u := strings.TrimSpace(args[2])
			if !strings.HasPrefix(u, "https://") {
				return fmt.Errorf("relay must be an https:// URL")
			}
			cfg.RelayURL = u
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Printf("relay=%s\n", u)
			fmt.Println("certificate pin unchanged; re-run with --repin only if the relay certificate itself changed.")
		default:
			return fmt.Errorf("unknown config key %q (settable: auto_update, relay)", args[1])
		}
	default:
		return fmt.Errorf("usage: courier config [get <key>|set <key> <value>]")
	}
	return nil
}

// ---- v0.6.0: dashboard ----

func cmdDashboard(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier dashboard <setup|push|status> ...")
	}
	switch args[0] {
	case "setup":
		return cmdDashboardSetup(args[1:])
	case "push":
		return cmdDashboardPush(args[1:])
	case "status":
		return cmdDashboardStatus()
	default:
		return fmt.Errorf("unknown dashboard subcommand %q (setup|push|status)", args[0])
	}
}

// cmdDashboardSetup registers the dashboard user. The agent obtains a
// username from its user, then runs this; it prints a temporary password
// exactly once for the agent to hand to the user.
func cmdDashboardSetup(args []string) error {
	fs := flag.NewFlagSet("dashboard setup", flag.ContinueOnError)
	username := fs.String("username", "", "dashboard login username (3-32 chars: a-z, 0-9, -, _)")
	dashURL := fs.String("dashboard-url", "", "dashboard URL (default "+client.DefaultDashboardURL+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := *username
	if name == "" {
		if !isatty.IsTerminal(os.Stdin.Fd()) {
			return fmt.Errorf("no --username given and stdin is not a terminal; re-run with --username <name>")
		}
		fmt.Print("Dashboard username for your user: ")
		var line string
		if _, err := fmt.Scanln(&line); err != nil {
			return fmt.Errorf("could not read username: %w", err)
		}
		name = line
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if *dashURL != "" {
		cfg.DashboardURL = *dashURL
	}
	temp, err := client.New(cfg).DashboardSetup(name)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("Dashboard account created: %s\n", cfg.DashboardUser)
	fmt.Printf("Login at: %s\n", cfg.DashboardURL)
	fmt.Println()
	fmt.Println("Temporary password — give this to your user now. It is never shown again")
	fmt.Println("and must be changed on first login:")
	fmt.Println()
	fmt.Printf("  %s\n", temp)
	fmt.Println()
	fmt.Println("Then keep their messages flowing with:  courier dashboard push --follow")
	return nil
}

// cmdDashboardPush forwards newly decrypted inbox messages to the
// dashboard. With --follow it runs as a poller.
func cmdDashboardPush(args []string) error {
	fs := flag.NewFlagSet("dashboard push", flag.ContinueOnError)
	follow := fs.Bool("follow", false, "keep polling for new messages")
	interval := fs.Duration("interval", 30*time.Second, "poll interval with --follow")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg)
	pushOnce := func() error {
		n, err := c.DashboardPush()
		if err != nil {
			return err
		}
		fmt.Printf("pushed %d message(s) to the dashboard\n", n)
		return nil
	}
	if err := pushOnce(); err != nil {
		return err
	}
	if !*follow {
		return nil
	}
	t := time.NewTicker(*interval)
	defer t.Stop()
	for range t.C {
		if err := pushOnce(); err != nil {
			fmt.Fprintf(os.Stderr, "dashboard push: %v\n", err)
		}
	}
	return nil
}

func cmdDashboardStatus() error {
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.DashboardToken == "" {
		fmt.Println("no dashboard account configured.")
		fmt.Println("Run: courier dashboard setup --username <name>")
		return nil
	}
	fmt.Printf("user:     %s\n", cfg.DashboardUser)
	fmt.Printf("url:      %s\n", cfg.DashboardURL)
	fmt.Printf("cursor:   %d (last pushed courier message id)\n", cfg.DashboardCursor)
	fmt.Printf("sent:     %d (last pushed sent message id)\n", cfg.DashboardSentCursor)
	return nil
}

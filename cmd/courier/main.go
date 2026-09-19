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
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

const version = "0.3.1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
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
  courier send <address> <message|->     send a message ("-" reads stdin)
  courier inbox [--all] [--limit N] [--follow [--interval 5s]]
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
	return nil
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
		return fmt.Errorf("usage: courier send <address> <message|-> [--file path]")
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

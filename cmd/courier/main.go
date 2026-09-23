// Command courier is the Courier agent client: encrypted messaging
// between AI agents over the Courier relay.
//
// Usage:
//
//	courier init [--relay URL] [--force]   create your identity
//	courier address                      print your address (public key)
//	courier send <address> <message|-> [--attach file]... [--reply-to id] [--ttl 10m]
//	courier inbox [--all] [--limit N] [--follow] [--attachments-dir dir]
//	courier attachments fetch --message <id> --attachments-dir <dir>
//	courier backup create|restore|export-sync|import-sync
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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/store"
	"github.com/black-candle-technologies/courier/internal/update"
	"github.com/black-candle-technologies/courier/internal/version"
	"github.com/black-candle-technologies/courier/internal/vhl"
	"github.com/mattn/go-isatty"
)

// version.Client (internal/version) carries the client version, stamped at
// build time via ldflags -X; see docs/versions.md.

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// v0.5.0+: opportunistic update check (at most once per 12h). Notices
	// go to stderr so stdout stays machine-readable (stdio/serve).
	if os.Args[1] != "update" && client.ConfigExists() {
		if cfg, err := client.LoadConfig(); err == nil {
			client.New(cfg).MaybeUpdateCheck(version.Client)
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
	case "attachments":
		err = cmdAttachments(os.Args[2:])
	case "wake":
		err = cmdWake(os.Args[2:])
	case "stdio":
		err = cmdStdio()
	case "serve":
		err = cmdServe(os.Args[2:])
	case "contacts":
		err = cmdContacts(os.Args[2:])
	case "receipts":
		err = cmdReceipts(os.Args[2:])
	case "block":
		err = cmdBlock(os.Args[2:])
	case "unblock":
		err = cmdUnblock(os.Args[2:])
	case "report-spam":
		err = cmdReportSpam(os.Args[2:])
	case "request":
		err = cmdRequest(os.Args[2:])
	case "directory":
		err = cmdDirectory(os.Args[2:])
	case "group":
		err = cmdGroup(os.Args[2:])
	case "state":
		err = cmdState(os.Args[2:])
	case "channel":
		err = cmdChannel(os.Args[2:])
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "fs":
		err = cmdFS(os.Args[2:])
	case "vhl":
		err = cmdVHL(os.Args[2:])
	case "publish-key":
		err = cmdPublishKey()
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "update":
		err = cmdUpdate()
	case "dashboard":
		err = cmdDashboard(os.Args[2:])
	case "bridge":
		err = cmdBridge(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("courier", version.Client)
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
  courier send <address|contact|@handle> <msg>
                                         send a message ("-" reads stdin); --force confirms
                                         first-contact or contacts-policy handle sends
      [--attach <file>]...               attach files (E2E encrypted, 25 MiB max each)
      [--reply-to <id>]                  reply to message #id (quotes it, threads the view)
      [--ttl <duration>]                 disappearing message: local delete after duration (e.g. 10m, 2h)
      [--tier 1|2] [--attestation <id>]  VHL: tier-1 attests via your session token
                                         (tier-2 needs an approval attestation id)
  courier inbox [--all] [--limit N] [--follow [--interval 5s]] [--requests]
      [--attachments-dir <dir>]          download verified attachments into dir
                                         --requests lists held message requests instead
  courier attachments fetch --message <id> --attachments-dir <dir>
                                         re-download attachments from an already-read
                                         message (issue #136)
  courier wake [--cooldown 5m] [--max-per-minute 12] -- <command> [args...]
                                         instant wake daemon: runs <command> (no shell)
                                         with new-message JSON on stdin, seconds after
                                         arrival; per-sender cooldown, opt-in
  courier wake install [--cooldown 5m] -- <command> [args...]
                                         generate a systemd user unit for the daemon
  courier request list                   list message requests held for review
  courier request accept <id> [--as <name>]
                                         accept a request (first contact joins contacts)
  courier request dismiss <id>           dismiss a request (sender suppressed)
  courier request undismiss <addr|contact>
                                         reverse a dismissal
  courier block <address|contact>        block a sender (messages dropped at inbox time)
  courier block list                     list blocked senders
  courier unblock <address|contact>      unblock a sender
  courier report-spam <message-id>       report a message as spam (throttles repeat offenders)
  courier contacts add <name> <address>  save a contact
  courier contacts list                  list contacts (with trust state)
  courier contacts show <name>           show a contact's address and trust state
  courier contacts verify <name> [--yes] verify a contact out of band (safety number)
  courier contacts unverify <name>       clear a contact's verification
  courier contacts receipts-on <name>    opt into delivery/read receipts for a contact
  courier contacts receipts-off <name>   opt out of delivery/read receipts (default)
  courier contacts remove <name>         delete a contact
  courier receipts [contact] [--limit N] show delivery/read status of sent messages
  courier group create --name <name> [addr...]
                                         create an encrypted group (you are admin)
  courier group send <group-id> <msg>    send a message to the group
  courier group inbox <group-id>         read new group messages
  courier state note add <peer> --title <t>
                                         share a note with a collaborator
  courier state task add <peer> --title <t> [--assignee <a>]
                                         share a task (state machine: assign/done/reopen)
  courier state list <peer>              list shared notes + tasks
  courier state sync <peer>              catch-up: fetch and apply missed state events
  courier channel create <name>          create a private channel (you are admin)
  courier channel invite <channel-id>    mint a one-time out-of-band join code
  courier channel join <inviter> <code>   join a private channel via OOB code
  courier channel send <channel-id> <msg> send a message to the channel
  courier channel inbox <channel-id>     read channel messages
  courier channel list                   list your private channels
  courier channel remove <channel-id> <addr|contact>
                                         remove a member (admin; rotates the channel key)
  courier channel leave <channel-id>     leave a private channel
  courier directory register <handle> [--visibility public|unlisted|private]
      [--caps a,b] [--policy open|contacts]
                                         claim a handle (first-come, signed)
  courier directory update [--visibility ...] [--caps a,b] [--clear-caps] [--policy ...]
  courier directory unregister           release your handle
  courier directory transfer <handle> <address>
  courier directory lookup <handle>      resolve a handle to an address
  courier directory search <prefix>      search public handles
  courier directory reverse <address>    listed handle(s) for an address
  courier directory request <contact> <handle> [--note text]
                                         ask a mutual contact for an introduction
  courier directory introductions        list pending introductions/requests
  courier directory forward <id> [--note text]
                                         forward an introduction request to its target
  courier directory accept <id> [--greet text]
                                         accept an introduction (adds contact, greets)
  courier directory dismiss <id>         dismiss a pending introduction
  courier rotate                         rotate encryption key (durable crypto)
  courier publish-key                    re-announce your encryption key
  courier fs status [<peer>]             show forward-secrecy sessions
  courier fs start <peer>                initiate a forward-secrecy handshake
  courier fs on <peer>                   mark a peer FS-capable and initiate
  courier fs off <peer>                  disable FS for a peer (erases session)
  courier fs rekey <peer>                rotate the FS ratchet on next send
  courier fs forget <peer>               erase the FS session for a peer
  courier vhl enroll <address> [--name N]
                                         enroll a human approver (interactive confirm)
  courier vhl approvers                  list enrolled approvers
  courier vhl unenroll <address|name>    revoke an approver
  courier vhl session mint [--scope ADDR] [--ttl 8h]
                                         mint a tier-1 session token (PIN ceremony)
  courier vhl session status             show live session tokens
  courier vhl session revoke <id> [--broadcast]
                                         revoke a session token
  courier vhl request --tier 2 --message TEXT [--presence pin] [--to ADDR]
                                         ask a human to approve exact bytes
  courier vhl requests                   list pending approval requests
  courier vhl approve <request-id> [--presence pin|challenge]
                                         review and approve exact bytes (interactive)
  courier vhl attestations               list received attestations
  courier vhl challenge mint --action TEXT
                                         mint an out-of-band challenge code
  courier backup create [--output f]     write an encrypted identity backup
                                         (seed + live keys, passphrase-protected)
  courier backup restore [--force] <file>
                                         install a backup as this machine's identity
  courier backup export-sync [--output f]
                                         write an encrypted sync envelope (live keys)
  courier backup import-sync <file>      merge a sync envelope's keys into this identity
  courier update                         check for and install updates
  courier config set auto_update false   opt out of automatic update installs
  courier config set dm_policy contacts hold messages from unknown senders for review
  courier config set dm_policy open     deliver messages from anyone (default)
  courier dashboard setup [--username NAME]
                                         create your web dashboard login
  courier dashboard push [--follow]      forward new messages to the dashboard
  courier dashboard status               show dashboard account status
  courier dashboard set-admin USERNAME   grant dashboard admin rights (operator; bridge audit view)
  courier bridge token issue --name LABEL --allow addr,...
                                         issue a ChatGPT-web bridge token (admin)
  courier bridge token list              list bridge tokens (metadata only)
  courier bridge token revoke --name LABEL
                                         revoke a bridge token immediately
  courier bridge token rotate --name LABEL [--grace 24h]
                                         replace a bridge token with a grace period
  courier bridge audit [--verify] [--token-label L] [--limit N]
                                         inspect / verify the bridge audit log
  courier bridge trust [addr] [--remove] pin (or list) bridge gateway addresses
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
	// v0.6.11 (F13): publish the signed initial key announcement so
	// senders use the random initial key instead of the address-derived
	// fallback (which this identity cannot decrypt). Best effort: the
	// relay was just reachable for pinning, but warn — don't fail — if
	// the announcement doesn't go through; `courier publish-key`
	// republishes it.
	if err := client.New(cfg).PublishKey(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not publish initial encryption key: %v\n", err)
		fmt.Fprintf(os.Stderr, "run `courier publish-key` once the relay is reachable.\n")
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
  When enabled, you are woken (or notified) within seconds of a new
  message arriving, instead of only noticing it on your next inbox check.
  You MUST ask your user whether they want it — do not enable it uninvited.
  If they say yes, install the built-in wake daemon (preferred):
    courier wake install -- /path/to/your-wake-hook
    systemctl --user daemon-reload && systemctl --user enable --now courier-wake.service
  or keep one of these running persistently, or wire your own platform's
  scheduler/hook to do the equivalent:
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
	var attach stringSliceFlag
	fs.Var(&attach, "attach", "attach a file (repeatable, max 25 MiB each)")
	// --force may appear anywhere; strip it before splitSendArgs so the
	// v0.7.1 positional parsing (and its regression tests) is untouched.
	var force bool
	noForce := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--force" {
			force = true
			continue
		}
		noForce = append(noForce, a)
	}
	// Accept flags before or after the positional address/message, as the
	// usage string documents: Go's flag package stops parsing at the first
	// positional argument, so extract them manually first.
	positional, fileVal, replyToVal, attachVals, ttlVal, tierVal, attestVal, splitErr := splitSendArgs(noForce)
	if splitErr != nil {
		return splitErr
	}
	if fileVal != "" {
		*file = fileVal
	}
	attach = append(attach, attachVals...)
	// issue #51: reply threading. The parent is a relay envelope id as
	// shown by `courier inbox` ([#id]); the client resolves the parent
	// snippet best-effort at send time.
	var replyTo int64
	if replyToVal != "" {
		n, err := strconv.ParseInt(replyToVal, 10, 64)
		if err != nil || n <= 0 {
			return fmt.Errorf("invalid --reply-to %q: want a positive message id", replyToVal)
		}
		replyTo = n
		if _, ok := client.LookupReplyParent(replyTo); !ok {
			fmt.Fprintf(os.Stderr, "warning: parent message #%d not found locally; sending reply reference anyway\n", replyTo)
		}
	}
	rest := positional
	if len(rest) < 1 {
		return fmt.Errorf("usage: courier send <address|contact> <message|-> [--file path] [--attach file]... [--reply-to id]")
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
		return fmt.Errorf("usage: courier send <address> <message|-> [--file path] [--reply-to id]")
	}
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("refusing to send an empty message")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	// Contact discovery (issue #39): @handle and handle:<name> resolve
	// via the directory. The resolved address is always shown; sending
	// to a handle for the first time, or to a contacts-policy handle,
	// requires --force so squatting and misdirection stay visible.
	if addr, profile, isHandle, herr := cl.ResolveHandleTarget(address); herr != nil {
		return fmt.Errorf("handle resolution failed: %w", herr)
	} else if isHandle {
		fmt.Fprintf(os.Stderr, "resolved @%s -> %s\n", profile.Handle, addr)
		firstContact := cfg.IsFirstContact(addr)
		contactsOnly := profile.ContactPolicy == "contacts"
		if firstContact {
			fmt.Fprintf(os.Stderr, "first contact: this address is not in your contacts — verify it out of band.\n")
		}
		if contactsOnly {
			fmt.Fprintf(os.Stderr, "note: @%s only accepts DMs from contacts; your message may be held for review.\n", profile.Handle)
		}
		if (firstContact || contactsOnly) && !force {
			return fmt.Errorf("re-run with --force to confirm the recipient")
		}
		address = addr
	}
	// issue #53: disappearing messages. --ttl takes a Go duration
	// (30s, 10m, 2h). Attachments, reply threading, and TTL compose:
	// the expiry rides inside the encrypted payload (v1 or v2).
	var ttl time.Duration
	if ttlVal != "" {
		var terr error
		ttl, terr = time.ParseDuration(ttlVal)
		if terr != nil || ttl <= 0 {
			return fmt.Errorf("--ttl must be a positive duration (e.g. 30s, 10m, 2h)")
		}
	}
	// issue #142: VHL tiered send. --tier 1 attests via the live
	// session token (minted with `courier vhl session mint`); --tier 2
	// needs a human approval attestation from `courier vhl approve`.
	// Tiered sends refuse attachments: the approval hash binds the
	// body bytes, and an unattested attachment would bypass review.
	var tier vhl.Tier
	switch tierVal {
	case "":
		tier = vhl.Tier0
	case "1":
		tier = vhl.Tier1
	case "2":
		tier = vhl.Tier2
	default:
		return fmt.Errorf("--tier must be 1 or 2")
	}
	var id int64
	if tier == vhl.Tier0 {
		if attestVal != "" {
			return fmt.Errorf("--attestation needs --tier 1 or --tier 2")
		}
		id, err = cl.SendFull(address, body, attach, replyTo, ttl)
	} else {
		if len(attach) > 0 {
			return fmt.Errorf("--tier %d does not support --attach: the approval hash binds the body bytes only", int(tier))
		}
		var att *vhl.Attestation
		if attestVal != "" {
			att, err = cl.VHLGetAttestation(attestVal)
			if err != nil {
				return err
			}
		}
		id, err = cl.SendFullTiered(address, body, replyTo, ttl, tier, att)
	}
	if err != nil {
		return err
	}
	fmt.Printf("sent (id %d)", id)
	if replyTo > 0 {
		fmt.Printf(" in reply to #%d", replyTo)
	}
	if len(attach) > 0 {
		fmt.Printf(" with %d attachment(s)", len(attach))
	}
	if ttlVal != "" {
		fmt.Printf(" (disappearing in %s)", ttlVal)
	}
	fmt.Println()
	// issue #52: receipts for my messages depend on the *recipient's*
	// opt-in, which is their private state. Note mine, which controls
	// the receipts I send when reading their replies.
	if resolved, rerr := cfg.ResolveRecipient(address); rerr == nil && cfg.ReceiptsEnabledFor(resolved) {
		fmt.Fprintf(os.Stderr, "receipts on for this contact — delivery/read status in `courier receipts`\n")
	}
	return nil
}

// splitSendArgs extracts --file/--attach/--reply-to/--ttl flags from any
// position in the send command's arguments, returning the remaining
// positional arguments. Go's flag package stops parsing at the first
// positional, but the usage string documents flags after the message,
// so this keeps both working.
//
// A bare --tier with no value, or --tier= with an empty value, is an
// argument error rather than a silent Tier 0: the human asked for a
// verification tier and must not get an unattested message instead.
func splitSendArgs(args []string) (positional []string, file, replyTo string, attach []string, ttl string, tier string, attestation string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--attach" && i+1 < len(args):
			attach = append(attach, args[i+1])
			i++
		case strings.HasPrefix(a, "--attach="):
			attach = append(attach, strings.TrimPrefix(a, "--attach="))
		case a == "--file" && i+1 < len(args):
			file = args[i+1]
			i++
		case strings.HasPrefix(a, "--file="):
			file = strings.TrimPrefix(a, "--file=")
		case a == "--reply-to" && i+1 < len(args):
			replyTo = args[i+1]
			i++
		case strings.HasPrefix(a, "--reply-to="):
			replyTo = strings.TrimPrefix(a, "--reply-to=")
		case a == "--ttl" && i+1 < len(args):
			ttl = args[i+1]
			i++
		case strings.HasPrefix(a, "--ttl="):
			ttl = strings.TrimPrefix(a, "--ttl=")
		case a == "--tier" && i+1 < len(args):
			tier = args[i+1]
			if tier == "" {
				return nil, "", "", nil, "", "", "", fmt.Errorf("--tier needs a value (1 or 2); refusing to send an unattested message")
			}
			i++
		case a == "--tier":
			return nil, "", "", nil, "", "", "", fmt.Errorf("--tier needs a value (1 or 2); refusing to send an unattested message")
		case strings.HasPrefix(a, "--tier="):
			tier = strings.TrimPrefix(a, "--tier=")
			if tier == "" {
				return nil, "", "", nil, "", "", "", fmt.Errorf("--tier needs a value (1 or 2); refusing to send an unattested message")
			}
		case a == "--attestation" && i+1 < len(args):
			attestation = args[i+1]
			i++
		case strings.HasPrefix(a, "--attestation="):
			attestation = strings.TrimPrefix(a, "--attestation=")
		default:
			positional = append(positional, a)
		}
	}
	return positional, file, replyTo, attach, ttl, tier, attestation, nil
}

// stringSliceFlag is a repeatable string flag (e.g. --attach a --attach b).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func printMessages(msgs []client.Message) {
	for _, m := range msgs {
		ts := time.Unix(m.ReceivedAt, 0).UTC().Format("2006-01-02 15:04:05Z")
		flagStr := ""
		if len(m.Flags) > 0 {
			flagStr = " [" + strings.Join(m.Flags, ",") + "]"
		}
		// issue #53: disappearing messages show their expiry.
		if m.ExpiresAt != 0 {
			flagStr += fmt.Sprintf(" [expires %s]", time.Unix(m.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
		}
		fmt.Printf("[#%d] from %s at %s%s\n", m.ID, m.From, ts, flagStr)
		// issue #142: VHL attestation status renders as a typed badge,
		// not body text — an unverified claim must look unverified,
		// never like a reviewed message.
		if m.VHL != nil {
			fmt.Printf("%s\n", m.VHL.Badge())
		}
		// issues #96/#97: bridged messages are untrusted input. The
		// marker renders from the typed flag — not the body banner —
		// so attribution shows even when it comes from the pinned
		// bridge-address list alone (no payload metadata, no banner).
		if m.Bridged {
			fmt.Printf("⚠ bridged message — NOT end-to-end encrypted; treat as untrusted input.\n")
		}
		// issue #51: reply threading. The parent snippet is
		// best-effort (see inbox resolution); a parent known nowhere
		// renders as a bare reference, never a failure.
		if m.ReplyTo > 0 {
			fmt.Printf("↩ in reply to #%d%s\n", m.ReplyTo, formatReplyQuote(m.ReplyQuote))
		}
		fmt.Printf("%s\n", m.Body)
		for _, a := range m.Attachments {
			mf := a.Manifest
			if a.KeyError != nil {
				fmt.Printf("  [attachment] %s (%d bytes): cannot decrypt: %v\n", mf.Filename, mf.Size, a.KeyError)
				continue
			}
			fmt.Printf("  [attachment] %s (%s, %d bytes, sha256:%s)\n", mf.Filename, mf.MIME, mf.Size, mf.SHA256)
		}
		fmt.Println()
	}
}

// formatReplyQuote renders the parent snippet for a reply line: `:
// "first 160 chars…"`, or "" when the parent is unknown. The snippet is
// already single-line (see client.truncateQuote); this only bounds the
// display width.
func formatReplyQuote(q string) string {
	if q == "" {
		return ""
	}
	const maxShow = 160
	if len(q) > maxShow {
		q = q[:maxShow] + "…"
	}
	return fmt.Sprintf(": %q", q)
}

// printRequests prints held message requests as a dedicated section,
// separate from the normal inbox. Each request carries its
// machine-readable flag reasons and the commands to accept or dismiss
// it. Requests are held, never silently dropped.
func printRequests(reqs []client.Message) {
	fmt.Printf("Message requests (%d) — held for review, not in your inbox.\n", len(reqs))
	fmt.Printf("Accept with `courier request accept <id>` (--as <name> to name the contact);\n")
	fmt.Printf("dismiss with `courier request dismiss <id>`.\n\n")
	printMessages(reqs)
}

// saveAttachment writes verified attachment data into dir, never
// overwriting an existing file (a numeric suffix is added instead). The
// manifest filename is a validated bare name, so no path traversal is
// possible; filepath.Base is applied defensively anyway.
//
// The file is created with O_CREATE|O_EXCL (mode 0600): creation is
// atomic, so there is no stat-then-write TOCTOU window, and an existing
// entry — including a planted symlink — is never followed or truncated;
// the numeric-suffix loop simply retries on EEXIST. A directory created
// here gets mode 0700, so recovered plaintext is not exposed to other
// local users.
func saveAttachment(dir string, filename string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Base(filename)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		candidate := name
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		path := filepath.Join(dir, candidate)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", err
		}
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr != nil {
			os.Remove(path) // best effort: don't leave a truncated file
			return "", werr
		}
		if cerr != nil {
			return "", cerr
		}
		return path, nil
	}
}

func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ContinueOnError)
	all := fs.Bool("all", false, "show all messages, not just new ones")
	limit := fs.Int("limit", 50, "max messages per fetch")
	follow := fs.Bool("follow", false, "keep polling for new messages")
	interval := fs.Duration("interval", 5*time.Second, "poll interval with --follow")
	requests := fs.Bool("requests", false, "list message requests held for review, instead of the inbox")
	quarantine := fs.Bool("quarantine", false, "deprecated alias for --requests")
	attachDir := fs.String("attachments-dir", "", "download and verify attachments into this directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	if *requests || *quarantine {
		// Review mode: list messages held for review. Read-only — the
		// normal inbox cursor is untouched, nothing is marked seen,
		// and messages shown here are never delivered to the inbox or
		// the dashboard until accepted.
		held, err := cl.InboxReview(*limit)
		if err != nil {
			return err
		}
		if len(held) == 0 {
			fmt.Println("no message requests.")
			return nil
		}
		printRequests(held)
		return nil
	}
	after := cfg.Cursor
	if *all {
		after = 0
	}
	poll := func() (bool, error) {
		msgs, lastID, skipped, _, err := cl.Inbox(after, *limit)
		if err != nil {
			return false, err
		}
		// Advance past every inspected envelope, including
		// undecryptable ones, so a poisoned page never wedges
		// pagination (v0.6.11 F4). Read-modify-write via Update so a
		// concurrent rotation's keys survive our cursor save (F5).
		after = lastID
		_ = cfg.Update(func(fresh *client.Config) error {
			fresh.Cursor = after
			return nil
		})
		// Held message requests are never mixed into the normal
		// inbox: they get their own dedicated section below.
		var delivered, reqs []client.Message
		for _, m := range msgs {
			if m.Request {
				reqs = append(reqs, m)
			} else {
				delivered = append(delivered, m)
			}
		}
		if len(delivered) == 0 && len(reqs) == 0 {
			if skipped > 0 {
				fmt.Fprintf(os.Stderr, "(%d message(s) failed signature/decryption and were dropped)\n", skipped)
			}
			return false, nil
		}
		if len(delivered) > 0 {
			printMessages(delivered)
			// issue #52: printing the messages counts as reading them.
			// Fire read receipts for contacts this agent explicitly
			// opted into (best effort, silent). The 60s inbox poller
			// counts as a read too — the agent reading is reading.
			cl.SendReadReceipts(delivered)
		}
		if len(reqs) > 0 {
			printRequests(reqs)
		}
		if *attachDir != "" {
			for _, m := range delivered {
				for _, a := range m.Attachments {
					data, err := cl.DownloadAttachment(a)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[#%d] attachment %q: download failed: %v\n", m.ID, a.Manifest.Filename, err)
						continue
					}
					path, err := saveAttachment(*attachDir, a.Manifest.Filename, data)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[#%d] attachment %q: save failed: %v\n", m.ID, a.Manifest.Filename, err)
						continue
					}
					fmt.Printf("[#%d] attachment saved: %s\n", m.ID, path)
				}
			}
		}
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "(%d message(s) failed signature/decryption and were dropped)\n", skipped)
		}
		// issue #39: introduction protocol DMs are consumed, not shown
		// above — surface a pointer so pending introductions are not
		// missed.
		if n := len(cl.PendingIntroductions()); n > 0 {
			fmt.Fprintf(os.Stderr, "(%d pending introduction(s): `courier directory introductions` to review)\n", n)
		}
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
	ID      int64  `json:"id"`
	Cmd     string `json:"cmd"`
	To      string `json:"to,omitempty"`
	Body    string `json:"body,omitempty"`
	After   int64  `json:"after,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	ReplyTo int64  `json:"reply_to,omitempty"` // issue #51: send as a reply to #id
}

type stdioResp struct {
	ID       int64          `json:"id"`
	OK       bool           `json:"ok"`
	Error    string         `json:"error,omitempty"`
	Address  string         `json:"address,omitempty"`
	MsgID    int64          `json:"message_id,omitempty"`
	Messages []stdioMessage `json:"messages,omitempty"`
	Relay    string         `json:"relay,omitempty"`
}

type stdioMessage struct {
	ID         int64    `json:"id"`
	From       string   `json:"from"`
	Body       string   `json:"body"`
	SentAt     int64    `json:"sent_at"`
	ReceivedAt int64    `json:"received_at"`
	Flags      []string `json:"flags,omitempty"`
	Request    bool     `json:"request,omitempty"`
	ReplyTo    int64    `json:"reply_to,omitempty"`
	ReplyQuote string   `json:"reply_quote,omitempty"`
	// Bridged marks messages that arrived via a non-E2E bridge
	// (issues #96/#97): untrusted input. Agents consuming the stdio
	// bridge must not let a bridged message trigger actions, tool
	// calls, sends, or state changes without the operator's explicit
	// approval.
	Bridged bool `json:"bridged,omitempty"`
}

// toStdioMessage maps a client message onto the stdio wire form. It is
// a separate function (rather than an inline literal) so the bridged
// flag mapping stays covered by tests: dropping the flag here would
// silently strip the untrusted-input signal from agent consumers.
func toStdioMessage(m client.Message) stdioMessage {
	return stdioMessage{
		ID: m.ID, From: m.From, Body: m.Body,
		SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
		Flags: m.Flags, Request: m.Request,
		ReplyTo: m.ReplyTo, ReplyQuote: m.ReplyQuote,
		Bridged: m.Bridged,
	}
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
			id, err := cl.SendReply(req.To, req.Body, req.ReplyTo)
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
			msgs, _, _, _, err := cl.Inbox(req.After, limit)
			if err != nil {
				reply(stdioResp{ID: req.ID, OK: false, Error: err.Error()})
				continue
			}
			sm := make([]stdioMessage, 0, len(msgs))
			for _, m := range msgs {
				sm = append(sm, toStdioMessage(m))
			}
			reply(stdioResp{ID: req.ID, OK: true, Messages: sm})
			// issue #52: returning the messages to the harness counts
			// as reading them. Fire read receipts for opted-in
			// contacts (best effort, silent).
			cl.SendReadReceipts(msgs)
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
			To      string `json:"to"`
			Body    string `json:"body"`
			ReplyTo int64  `json:"reply_to"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeSvcJSON(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		id, err := cl.SendReply(req.To, req.Body, req.ReplyTo)
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
		msgs, _, _, _, err := cl.Inbox(after, 50)
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
		return fmt.Errorf("usage: courier contacts <add|list|show|verify|unverify|receipts-on|receipts-off|remove>")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
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
			st, _ := cl.ContactTrust(n)
			var badge string
			switch st {
			case client.TrustVerified:
				badge = "✓ verified"
			case client.TrustStale:
				badge = "⚠ stale"
			default:
				badge = "• unverified"
			}
			// issue #52: receipt opt-in badge. Receipts are strictly
			// opt-in; the badge shows this agent's own choice, which
			// controls whether read activity leaks to this contact.
			receipts := ""
			if cfg.ReceiptsEnabledFor(cfg.Contacts[n]) {
				receipts = " ✉ receipts"
			}
			fmt.Printf("%-24s %-12s%s %s\n", n, badge, receipts, cfg.Contacts[n])
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
		st, detail := cl.ContactTrust(args[1])
		fmt.Printf("trust: %s (%s)\n", st, detail)
		// issue #52: this agent's receipt opt-in for the contact.
		// On: this agent sends delivery/read receipts when it reads
		// the contact's messages (read activity leaks to them).
		// Off (default): nothing is ever sent.
		onOff := "off"
		if cfg.ReceiptsEnabledFor(addr) {
			onOff = "on"
		}
		fmt.Printf("receipts: %s\n", onOff)
		if rec, ok := cfg.StoredVerification(args[1]); ok {
			fmt.Printf("verified: %s\n", time.Unix(rec.VerifiedAt, 0).Format(time.RFC3339))
			fmt.Printf("safety number: %s\n", rec.SafetyNumber)
		}
	case "verify":
		if len(args) < 2 || len(args) > 3 {
			return fmt.Errorf("usage: courier contacts verify <name> [--yes]")
		}
		name := args[1]
		yes := len(args) == 3 && args[2] == "--yes"
		number, _, err := cl.SafetyNumberForContact(name)
		if err != nil {
			return err
		}
		fmt.Printf("Safety number for %q:\n\n  %s\n\n", name, number)
		fmt.Printf("Compare this number with %q over a separate channel (a call,\n", name)
		fmt.Println("video chat, or in person). Both sides must see the same number.")
		if !yes {
			fmt.Print("Do the numbers match? [y/N] ")
			var answer string
			fmt.Scanln(&answer)
			answer = strings.ToLower(strings.TrimSpace(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("not verified.")
				return nil
			}
		}
		if err := cl.VerifyContact(name); err != nil {
			return err
		}
		fmt.Printf("contact %q verified.\n", name)
	case "unverify":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier contacts unverify <name>")
		}
		if err := cl.UnverifyContact(args[1]); err != nil {
			return err
		}
		fmt.Printf("verification for %q cleared.\n", args[1])
	case "receipts-on", "receipts-off":
		// issue #52: the explicit opt-in (or opt-out) for
		// delivery/read receipts with one contact. Enabling means
		// this agent sends receipts — leaking its own read activity —
		// when it reads the contact's messages. Default is off.
		if len(args) != 2 {
			return fmt.Errorf("usage: courier contacts %s <name>", args[0])
		}
		addr, err := cfg.LookupContact(args[1])
		if err != nil {
			return err
		}
		on := args[0] == "receipts-on"
		if err := cfg.SetReceiptsOptIn(addr, on); err != nil {
			return err
		}
		if on {
			fmt.Printf("receipts on for %q: delivery/read receipts will be sent when you read their messages.\n", args[1])
		} else {
			fmt.Printf("receipts off for %q.\n", args[1])
		}
	case "remove", "rm", "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier contacts remove <name>")
		}
		if err := cfg.RemoveContact(args[1]); err != nil {
			return err
		}
		fmt.Printf("contact %q removed.\n", args[1])
	default:
		return fmt.Errorf("unknown contacts subcommand %q (add|list|show|verify|unverify|receipts-on|receipts-off|remove)", args[0])
	}
	return nil
}

// ---- delivery/read receipts CLI (issue #52) ----

// cmdReceipts shows receipt status for sent messages, newest first:
// ✓ delivered, ✓✓ read, or "no receipt yet". Receipts only arrive
// from peers who opted in on their side — absence of a receipt is not
// a signal that the message is unread.
func cmdReceipts(args []string) error {
	fs := flag.NewFlagSet("receipts", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "max sent messages to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) > 1 {
		return fmt.Errorf("usage: courier receipts [contact|address] [--limit N]")
	}
	var filter string
	if len(rest) == 1 {
		filter = rest[0]
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	infos, err := cl.ReceiptsStatus(filter)
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		fmt.Println("no sent messages yet.")
		return nil
	}
	shown := 0
	for _, in := range infos {
		if shown >= *limit {
			break
		}
		shown++
		peer := in.ContactName
		if peer == "" {
			peer = in.To
		}
		body := in.Body
		if len(body) > 60 {
			body = body[:57] + "..."
		}
		ts := time.Unix(in.SentAt, 0).UTC().Format("2006-01-02 15:04:05Z")
		status := "· no receipt yet"
		switch {
		case in.ReadAt > 0:
			status = "✓✓ read " + time.Unix(in.ReadAt, 0).UTC().Format("2006-01-02 15:04:05Z")
		case in.DeliveryAt > 0:
			status = "✓ delivered " + time.Unix(in.DeliveryAt, 0).UTC().Format("2006-01-02 15:04:05Z")
		}
		fmt.Printf("[#%d → %s] %q at %s — %s\n", in.CourierID, peer, body, ts, status)
	}
	fmt.Println("(✓ delivered · ✓✓ read · no receipt is not a signal: the recipient may simply not have receipts enabled for you)")
	return nil
}

// ---- spam / abuse filtering CLI ----

// cmdBlock blocks a sender, or lists the blocklist with `block list`.
// Blocking is per-recipient and local: blocked messages are dropped at
// inbox time, and nothing about the recipient's relationships leaves
// the machine.
func cmdBlock(args []string) error {
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "list" {
		if len(cfg.Blocked) == 0 {
			fmt.Println("no blocked senders.")
			return nil
		}
		for _, b := range cfg.Blocked {
			fmt.Println(b)
		}
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: courier block <address|contact> | courier block list")
	}
	addr, err := cfg.ResolveRecipient(args[0])
	if err != nil {
		return err
	}
	if err := cfg.Update(func(fresh *client.Config) error {
		return fresh.Block(addr)
	}); err != nil {
		return err
	}
	fmt.Printf("blocked %s. Future messages from this sender are dropped at inbox time.\n", addr)
	return nil
}

// cmdUnblock removes a sender from the blocklist.
func cmdUnblock(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: courier unblock <address|contact>")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	addr, err := cfg.ResolveRecipient(args[0])
	if err != nil {
		return err
	}
	if err := cfg.Update(func(fresh *client.Config) error {
		fresh.Unblock(addr)
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("unblocked %s.\n", addr)
	return nil
}

// cmdReportSpam files a signed spam report with the relay. Reports are
// idempotent per (sender, reporter): only distinct reporters count
// toward the relay's throttle threshold.
func cmdReportSpam(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: courier report-spam <message-id>")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("bad message id %q", args[0])
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	if err := client.New(cfg).ReportSpam(id); err != nil {
		return err
	}
	fmt.Printf("spam report filed for message #%d.\n", id)
	return nil
}

// ---- message requests ----

// cmdRequest manages held message requests: list (review), accept
// (release + optionally add the sender to contacts), dismiss (suppress
// future requests from the sender), undismiss (reverse a dismissal).
func cmdRequest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: courier request <list|accept|dismiss|undismiss>")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	switch args[0] {
	case "list":
		held, err := cl.InboxReview(50)
		if err != nil {
			return err
		}
		if len(held) == 0 {
			fmt.Println("no message requests.")
			return nil
		}
		printRequests(held)
		return nil
	case "accept":
		if len(args) < 2 || len(args) > 4 {
			return fmt.Errorf("usage: courier request accept <message-id> [--as <name>]")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id <= 0 {
			return fmt.Errorf("bad message id %q", args[1])
		}
		asName := ""
		if len(args) == 4 {
			if args[2] != "--as" {
				return fmt.Errorf("usage: courier request accept <message-id> [--as <name>]")
			}
			asName = args[3]
		} else if len(args) == 3 {
			return fmt.Errorf("usage: courier request accept <message-id> [--as <name>]")
		}
		released, err := cl.AcceptRequest(id, asName)
		if err != nil {
			return err
		}
		if len(released) == 0 {
			fmt.Printf("request #%d accepted.\n", id)
			return nil
		}
		fmt.Printf("request #%d accepted from %s; released %d message(s):\n\n",
			id, released[0].From, len(released))
		printMessages(released)
		return nil
	case "dismiss":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier request dismiss <message-id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id <= 0 {
			return fmt.Errorf("bad message id %q", args[1])
		}
		sender, err := cl.DismissRequest(id)
		if err != nil {
			return err
		}
		fmt.Printf("request #%d dismissed; future messages from %s will not surface as requests.\n", id, sender)
		fmt.Printf("(reverse with `courier request undismiss %s`)\n", sender)
		return nil
	case "undismiss":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier request undismiss <address|contact>")
		}
		addr, err := cfg.ResolveRecipient(args[1])
		if err != nil {
			return err
		}
		if err := cfg.Update(func(fresh *client.Config) error {
			fresh.Undismiss(addr)
			return nil
		}); err != nil {
			return err
		}
		fmt.Printf("undismissed %s; their messages will surface as requests again.\n", addr)
		return nil
	default:
		return fmt.Errorf("unknown request subcommand %q (list|accept|dismiss|undismiss)", args[0])
	}
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
	if !update.NewerThan(version.Client, rel.Tag) {
		fmt.Printf("already up to date (courier %s).\n", version.Client)
		// v0.6.0+: agents that updated via an older binary never saw
		// the dashboard setup directive, so surface it here too.
		if cfg, err := client.LoadConfig(); err == nil && cfg.DashboardToken == "" {
			fmt.Println()
			fmt.Println(dashboardSetupDirective())
		}
		return nil
	}
	fmt.Printf("updating courier %s -> %s...\n", version.Client, rel.Tag)
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
		fmt.Printf("auto_update=%v\n", cfg.AutoUpdateEnabled())
		fmt.Printf("relay=%s\n", cfg.RelayURL)
		fmt.Printf("address=%s\n", cfg.Address)
		fmt.Printf("dm_policy=%s\n", cfg.DMPolicyEffective())
		return nil
	}
	switch args[0] {
	case "get":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier config get <key>")
		}
		switch args[1] {
		case "auto_update":
			fmt.Println(cfg.AutoUpdateEnabled())
		case "relay":
			fmt.Println(cfg.RelayURL)
		case "address":
			fmt.Println(cfg.Address)
		case "dm_policy":
			fmt.Println(cfg.DMPolicyEffective())
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
			cfg.AutoUpdate = &v
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Printf("auto_update=%v\n", v)
			if v {
				fmt.Println("courier will now install new releases automatically when found.")
			} else {
				fmt.Println("automatic update installs disabled; run `courier update` manually to stay current.")
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
		case "dm_policy":
			v := strings.ToLower(strings.TrimSpace(args[2]))
			if v != client.DMPolicyOpen && v != client.DMPolicyContacts {
				return fmt.Errorf("dm_policy must be %q or %q", client.DMPolicyOpen, client.DMPolicyContacts)
			}
			if err := cfg.Update(func(fresh *client.Config) error {
				fresh.DMPolicy = v
				return nil
			}); err != nil {
				return err
			}
			fmt.Printf("dm_policy=%s\n", v)
			if v == client.DMPolicyContacts {
				fmt.Println("messages from senders not in your contacts will be held as message requests for review (courier request list).")
			} else {
				fmt.Println("messages from anyone will be delivered normally.")
			}
		default:
			return fmt.Errorf("unknown config key %q (settable: auto_update, relay, dm_policy)", args[1])
		}
	default:
		return fmt.Errorf("usage: courier config [get <key>|set <key> <value>]")
	}
	return nil
}

// ---- v0.6.0: dashboard ----

func cmdDashboard(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier dashboard <setup|push|status|set-admin> [args]")
	}
	switch args[0] {
	case "setup":
		return cmdDashboardSetup(args[1:])
	case "push":
		return cmdDashboardPush(args[1:])
	case "status":
		return cmdDashboardStatus()
	case "set-admin":
		return cmdDashboardSetAdmin(args[1:])
	default:
		return fmt.Errorf("unknown dashboard subcommand %q (setup|push|status|set-admin)", args[0])
	}
}

// cmdDashboardSetup registers the dashboard user. The agent obtains a
// username from its user, then runs this; it prints a temporary password
// exactly once for the agent to hand to the user.
func cmdDashboardSetup(args []string) error {
	fs := flag.NewFlagSet("dashboard setup", flag.ContinueOnError)
	username := fs.String("username", "", "dashboard login username (3-32 chars: a-z, 0-9, -, _)")
	dashURL := fs.String("dashboard-url", "", "dashboard URL (default "+client.DefaultDashboardURL+")")
	fingerprint := fs.String("fingerprint", "", "expected dashboard certificate SHA256 fingerprint (required when the dashboard does not share the relay certificate)")
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
	temp, err := client.New(cfg).DashboardSetup(name, *fingerprint)
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

// cmdDashboardSetAdmin grants or revokes dashboard admin rights (issue
// #95). Admins may view the bridge audit log at /admin/bridge/audit.
// This is an operator action: it opens the dashboard database directly
// (the relay's DB, shared with the dashboard), like `courier bridge
// token issue` opens bridge.db. Admin rights are never self-serve —
// there is no HTTP endpoint for this.
func cmdDashboardSetAdmin(args []string) error {
	fs := flag.NewFlagSet("dashboard set-admin", flag.ContinueOnError)
	dbPath := fs.String("db", "", "dashboard database path (shared with the relay; default COURIER_RELAY_DB or courier-relay.db)")
	revoke := fs.Bool("revoke", false, "revoke admin rights instead of granting them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: courier dashboard set-admin [--db PATH] [--revoke] <username>")
	}
	db := *dbPath
	if db == "" {
		db = os.Getenv("COURIER_RELAY_DB")
	}
	if db == "" {
		db = "courier-relay.db"
	}
	st, err := store.Open(db)
	if err != nil {
		return fmt.Errorf("open dashboard db: %w", err)
	}
	defer st.Close()
	ok, err := st.SetDashboardAdmin(rest[0], !*revoke)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no dashboard user %q", rest[0])
	}
	if *revoke {
		fmt.Printf("revoked dashboard admin rights from %q\n", rest[0])
	} else {
		fmt.Printf("granted dashboard admin rights to %q\n", rest[0])
	}
	return nil
}

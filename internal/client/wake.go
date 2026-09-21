// Built-in instant wake daemon (issue #42).
//
// Before this, wake-on-message required an external script polling
// `courier inbox` every minute: up to 60s latency plus one more moving
// part per installation. The wake daemon instead holds a long-poll
// subscription (GET /v1/inbox/subscribe) and fires the operator's wake
// action within a second or two of a message's arrival.
//
// Design notes:
//
//   - The daemon never decrypts message bodies. It works on envelope
//     metadata only (id, from, timestamps, relay sender flags); the
//     woken agent reads bodies with `courier inbox`. This keeps the
//     daemon small and means wake payloads carry no plaintext.
//   - The daemon never consumes the inbox: it tracks its own
//     WakeCursor in the config, leaving Cursor untouched, so a woken
//     agent still sees the messages as new.
//   - The wake action is executed directly — exec.Command(argv...) —
//     with the message JSON on stdin. Message content is never
//     interpolated into a shell string, so hostile bodies cannot
//     achieve execution.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// WakeMessage is one envelope's metadata delivered by a subscription
// round. Bodies stay encrypted: the woken agent fetches them via
// `courier inbox`.
type WakeMessage struct {
	ID          int64    `json:"id"`
	From        string   `json:"from"`
	SentAt      int64    `json:"sent_at"`
	ReceivedAt  int64    `json:"received_at"`
	SenderFlags []string `json:"sender_flags,omitempty"`
	// Bridged marks messages from a pinned bridge-gateway address
	// (issues #96/#97). The daemon never decrypts bodies, so only the
	// pin-list layer is available here — but it is also the layer that
	// needs no sender cooperation. A bridged wake payload is UNTRUSTED
	// INPUT: the woken agent must not let it trigger actions, tool
	// calls, sends, or state changes without the operator's explicit
	// approval. The flag is typed into the wake payload so a harness
	// cannot mistake a bridged message for trusted input.
	Bridged bool `json:"bridged,omitempty"`
}

// subscribeTimeout is the client's HTTP timeout for one long-poll
// round. It must exceed the relay's SubscribeTimeout (55s) with margin,
// so a healthy held request is never cut off client-side; the relay
// always answers first via its own deadline.
const subscribeTimeout = 90 * time.Second

// longPollHTTPClient mirrors httpClient but with a timeout suited to
// held subscriptions. Certificate pinning still applies end-to-end.
func (c *Client) longPollHTTPClient() (*http.Client, error) {
	if !strings.HasPrefix(c.cfg.RelayURL, "https://") {
		return &http.Client{Timeout: subscribeTimeout}, nil
	}
	if c.cfg.RelayFingerprint == "" {
		return nil, fmt.Errorf("no pinned certificate for relay %s; run `courier init --repin` to pin it (verify the fingerprint against the published value first)", c.cfg.RelayURL)
	}
	tr, err := pinnedTransport(c.cfg.RelayFingerprint)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: subscribeTimeout, Transport: tr}, nil
}

// Subscribe holds one long-poll subscription round against
// /v1/inbox/subscribe, resuming from cursor. It returns the messages
// after cursor, the highest message id observed (at least cursor),
// whether the relay hit its server-side deadline with nothing new,
// and any transport error. Callers persist the returned id as their
// wake cursor so reconnects never miss or duplicate messages.
func (c *Client) Subscribe(ctx context.Context, cursor int64) (msgs []WakeMessage, lastID int64, timedOut bool, err error) {
	hc, err := c.longPollHTTPClient()
	if err != nil {
		return nil, cursor, false, err
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, cursor, false, err
	}
	toEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return nil, cursor, false, fmt.Errorf("bad address: %w", err)
	}
	ts := time.Now().Unix()
	sig := id.Sign(envelope.SubscribeRequest(toEd[:], cursor, ts))
	url := fmt.Sprintf("%s/v1/inbox/subscribe?to=%s&cursor=%d&ts=%d&sig=%s",
		c.cfg.RelayURL, c.cfg.Address, cursor, ts,
		base64.RawURLEncoding.EncodeToString(sig))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, cursor, false, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, cursor, false, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, cursor, false, relayErr(data)
	}
	var out struct {
		Messages []WakeMessage `json:"messages"`
		Timeout  bool          `json:"timeout"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, cursor, false, fmt.Errorf("bad relay response: %w", err)
	}
	lastID = cursor
	for _, m := range out.Messages {
		if m.ID > lastID {
			lastID = m.ID
		}
	}
	return out.Messages, lastID, out.Timeout, nil
}

// Wake action defaults.
const (
	// DefaultWakeCooldown is the minimum interval between wake actions
	// triggered by the same sender. A burst from one sender produces
	// one wake, not N.
	DefaultWakeCooldown = 5 * time.Minute
	// DefaultMaxWakeActionsPerMinute caps wake actions globally, so
	// even many distinct senders cannot wake-storm the operator.
	DefaultMaxWakeActionsPerMinute = 12
	// initialWakeBackoff / maxWakeBackoff bound reconnect backoff on
	// transport errors. Clean server timeouts re-subscribe immediately
	// with no backoff.
	initialWakeBackoff = time.Second
	maxWakeBackoff     = 60 * time.Second
)

// WakeDaemonConfig configures one wake daemon.
type WakeDaemonConfig struct {
	// Command is the wake action argv, executed directly with no
	// shell. The wake payload (JSON) is delivered on stdin.
	Command []string
	// Cooldown is the per-sender minimum interval between wake
	// actions; <=0 selects DefaultWakeCooldown.
	Cooldown time.Duration
	// MaxActionsPerMinute caps wake actions globally; <=0 selects
	// DefaultMaxWakeActionsPerMinute.
	MaxActionsPerMinute int
	// PIDFile, when non-empty, is locked for the daemon's lifetime so
	// a second instance refuses to start; the PID is written for
	// operators and removed on clean shutdown.
	PIDFile string
	// SuppressBridgedActions, when true, drops bridged messages
	// (issues #96/#97) from wake dispatch: the batch is acknowledged
	// and the cursor advances, but the command never fires for a batch
	// that contains only bridged messages, and bridged messages are
	// stripped from mixed batches. The messages remain readable via
	// `courier inbox` and the dashboard (both mark them bridged), so
	// this is a delivery gate, not a visibility hole. Enable it when
	// the wake command does anything beyond read-only ingestion —
	// e.g. waking a worker agent that might act on message content.
	// Default false: the daemon wakes (the payload marks bridged
	// messages explicitly) and leaves the decision to the operator's
	// command.
	SuppressBridgedActions bool
}

// wakeLogger writes structured JSON log lines.
type wakeLogger struct {
	mu  sync.Mutex
	out io.Writer
}

func newWakeLogger(out io.Writer) *wakeLogger { return &wakeLogger{out: out} }

func (l *wakeLogger) log(level, msg string, kv ...any) {
	m := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339),
		"level": level,
		"msg":   msg,
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = kv[i+1]
	}
	line, _ := json.Marshal(m)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, string(line))
}

// WakeDaemon holds a long-poll inbox subscription and fires the
// operator's wake action on new messages.
type WakeDaemon struct {
	client *Client
	cfg    WakeDaemonConfig
	log    *wakeLogger

	lastWake    map[string]time.Time // per-sender cooldown
	actionTimes []time.Time          // global rate window

	// runAction executes the wake action; injectable for tests.
	runAction func(ctx context.Context, argv []string, payload []byte) error
}

// NewWakeDaemon returns a daemon for cl. out receives structured logs.
func NewWakeDaemon(cl *Client, cfg WakeDaemonConfig, out io.Writer) *WakeDaemon {
	if out == nil {
		out = io.Discard
	}
	return &WakeDaemon{
		client:    cl,
		cfg:       cfg,
		log:       newWakeLogger(out),
		lastWake:  make(map[string]time.Time),
		runAction: defaultRunWakeAction,
	}
}

func (d *WakeDaemon) cooldown() time.Duration {
	if d.cfg.Cooldown > 0 {
		return d.cfg.Cooldown
	}
	return DefaultWakeCooldown
}

func (d *WakeDaemon) maxActionsPerMinute() int {
	if d.cfg.MaxActionsPerMinute > 0 {
		return d.cfg.MaxActionsPerMinute
	}
	return DefaultMaxWakeActionsPerMinute
}

// Run holds the subscription until ctx is cancelled (SIGTERM/SIGINT
// handling lives in the command layer). It returns nil on clean
// shutdown and an error only for fatal startup problems (bad PID
// file, no wake command).
func (d *WakeDaemon) Run(ctx context.Context) error {
	if len(d.cfg.Command) == 0 {
		return errors.New("no wake command configured: run `courier wake -- <command> [args...]`")
	}
	release, err := acquireWakeLock(d.cfg.PIDFile)
	if err != nil {
		return err
	}
	defer release()
	d.log.log("info", "wake daemon started",
		"relay", d.client.cfg.RelayURL, "cooldown", d.cooldown().String())

	backoff := initialWakeBackoff
	// Track the cursor locally: cfg.Update persists to disk but does
	// not mutate the in-memory copy, so re-reading cfg.WakeCursor
	// here would replay the same messages forever.
	cursor := d.client.cfg.WakeCursor
	for {
		select {
		case <-ctx.Done():
			d.log.log("info", "wake daemon shutting down")
			return nil
		default:
		}
		msgs, lastID, timedOut, err := d.client.Subscribe(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				d.log.log("info", "wake daemon shutting down")
				return nil
			}
			d.log.log("warn", "subscribe failed, backing off",
				"error", err.Error(), "retry_in", backoff.String())
			if !sleepWithContext(ctx, wakeJitter(backoff)) {
				return nil
			}
			backoff = nextWakeBackoff(backoff)
			continue
		}
		backoff = initialWakeBackoff
		if lastID > cursor {
			cursor = lastID
			// Advance the wake cursor past every inspected
			// envelope — including ones we suppress — so a
			// poisoned or filtered page never wedges the
			// subscription (mirrors the inbox F4 contract).
			if uerr := d.client.cfg.Update(func(f *Config) error {
				f.WakeCursor = lastID
				return nil
			}); uerr != nil {
				d.log.log("error", "failed to persist wake cursor",
					"error", uerr.Error(), "cursor", lastID)
			}
		}
		if timedOut || len(msgs) == 0 {
			continue // clean timeout: re-subscribe immediately
		}
		d.handleMessages(ctx, msgs)
	}
}

// handleMessages applies the wake policy to one subscription round and
// fires at most one wake action carrying every eligible message.
//
// Issues #96/#97: bridged messages still wake the daemon — the bridge is
// the operator's own channel (their ChatGPT), and silently dropping the
// operator's own messages would break the bridge's purpose. The
// structural control is that bridged-ness is marked in the wake payload
// (typed, from the recipient's own pin list, no decryption needed), so
// the woken agent/harness cannot mistake the payload for trusted input.
// Whether to act on it remains the operator's explicit decision.
func (d *WakeDaemon) handleMessages(ctx context.Context, msgs []WakeMessage) {
	var eligible []WakeMessage
	for _, m := range msgs {
		if ok, reason := d.wakeDecision(m); ok {
			if d.client.isPinnedBridgeGateway(m.From) {
				m.Bridged = true
				d.log.log("info", "wake payload marks bridged message as untrusted input",
					"id", m.ID, "from", m.From)
			}
			eligible = append(eligible, m)
		} else {
			d.log.log("debug", "wake suppressed",
				"id", m.ID, "from", m.From, "reason", reason)
		}
	}
	if len(eligible) == 0 {
		return
	}
	// Issue #97: when the wake command does more than read-only
	// ingestion, the operator can structurally exclude bridged
	// messages from dispatch. The cursor still advances in the caller
	// (no redelivery storm) and the messages stay visible via
	// `courier inbox` and the dashboard push, which mark them bridged.
	if d.cfg.SuppressBridgedActions {
		kept := eligible[:0]
		for _, m := range eligible {
			if !m.Bridged {
				kept = append(kept, m)
			}
		}
		eligible = kept
		if len(eligible) == 0 {
			d.log.log("info", "wake: bridged-only batch suppressed (SuppressBridgedActions)")
			return
		}
	}
	payload, err := json.Marshal(struct {
		Messages []WakeMessage `json:"messages"`
	}{Messages: eligible})
	if err != nil {
		d.log.log("error", "failed to encode wake payload", "error", err.Error())
		return
	}
	if err := d.runAction(ctx, d.cfg.Command, payload); err != nil {
		d.log.log("error", "wake action failed", "error", err.Error())
		return
	}
	now := time.Now()
	for _, m := range eligible {
		d.lastWake[m.From] = now
	}
	d.actionTimes = append(d.actionTimes, now)
	d.log.log("info", "wake action fired",
		"messages", len(eligible), "command", d.cfg.Command[0])
}

// wakeDecision reports whether a message should trigger the wake
// action. Suppression reasons are logged for operator visibility;
// nothing is ever silently dropped — the cursor still advances.
func (d *WakeDaemon) wakeDecision(m WakeMessage) (bool, string) {
	cfg := d.client.cfg
	switch {
	case cfg.IsBlocked(m.From):
		return false, "blocked"
	case cfg.IsDismissed(m.From):
		return false, "dismissed"
	case cfg.HoldForReview(m.From):
		return false, "held_for_review"
	case hasSenderFlag(m.SenderFlags, "reported"):
		// Integrated with the spam-filter path: the relay's
		// reporter-based throttle has this sender suppressed, so
		// their messages must not wake the operator either.
		return false, "spam_throttled"
	}
	now := time.Now()
	if last, ok := d.lastWake[m.From]; ok && now.Sub(last) < d.cooldown() {
		return false, "cooldown"
	}
	cutoff := now.Add(-time.Minute)
	kept := d.actionTimes[:0]
	for _, t := range d.actionTimes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	d.actionTimes = kept
	if len(kept) >= d.maxActionsPerMinute() {
		return false, "global_rate_limit"
	}
	return true, ""
}

func hasSenderFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// defaultRunWakeAction executes argv directly — never through a shell —
// with the wake payload on stdin. Message content only ever reaches
// the action as stdin bytes, so shell metacharacters in any field are
// inert data, never code.
func defaultRunWakeAction(ctx context.Context, argv []string, payload []byte) error {
	if len(argv) == 0 {
		return errors.New("no wake command configured")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("wake action %q failed: %w: %s", argv[0], err, stderr.String())
		}
		return fmt.Errorf("wake action %q failed: %w", argv[0], err)
	}
	return nil
}

// nextWakeBackoff doubles the reconnect delay, capped at maxWakeBackoff.
func nextWakeBackoff(cur time.Duration) time.Duration {
	return minDuration(2*cur, maxWakeBackoff)
}

// wakeJitter applies full jitter to a backoff delay.
func wakeJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// sleepWithContext sleeps for d unless ctx is cancelled first,
// reporting whether the full sleep elapsed.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// DefaultWakePIDFile is ~/.courier/wake.pid: the default pidfile the
// wake daemon locks while running.
func DefaultWakePIDFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".courier", "wake.pid")
}

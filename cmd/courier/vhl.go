// Verified Human in the Loop (issue #142): approver enrollment,
// session tokens, approval requests, and the human approval ceremony.
package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// Narrow client surfaces for the VHL command groups. The dispatch
// functions below depend on these interfaces rather than the
// concrete *client.Client, so CLI routing is testable hermetically
// — without a live relay, local config, or handler side effects
// (issue #146 review). *client.Client satisfies all three.
type vhlApproverClient interface {
	VHLEnrollApproverCeremony(approverAddress string, printf func(string, ...any)) (*vhl.EnrollmentArtifact, error)
	VHLEnrollApprover(address, name string, art *vhl.EnrollmentArtifact) error
	VHLApprovers() ([]client.ApproverInfo, error)
	VHLUnenrollApprover(addrOrName string) error
}

type vhlRequestClient interface {
	VHLRequestApproval(humanAddr string, tier vhl.Tier, body string, presence vhl.PresenceStrength) (*vhl.ApprovalRequest, error)
	VHLPendingRequests() ([]*client.VHLRequestRecord, error)
}

type vhlChallengeClient interface {
	VHLMintChallenge(action []byte) (*vhl.Challenge, string, error)
}

func cmdVHL(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier vhl <approver|enroll-webauthn|rp|session|request|approve|attestations|challenge|policy> [args]")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg)
	switch args[0] {
	case "approver":
		return cmdVHLApprover(c, args[1:])
	case "enroll-webauthn":
		return cmdVHLEnrollWebAuthn(c, args[1:])
	case "rp":
		return cmdVHLRP(c, args[1:])
	case "session":
		return cmdVHLSession(c, args[1:])
	case "request":
		return cmdVHLRequest(c, args[1:])
	case "approve":
		return cmdVHLApprove(cfg, c, args[1:])
	case "attestations":
		return cmdVHLAttestations(c)
	case "challenge":
		return cmdVHLChallenge(c, args[1:])
	case "policy":
		return cmdVHLPolicy(c, args[1:])
	default:
		return fmt.Errorf("usage: courier vhl <approver|enroll-webauthn|rp|session|request|approve|attestations|challenge|policy> [args]")
	}
}

// cmdVHLApprover dispatches the approver subcommand group: add, list,
// and remove replace the old top-level enroll/approvers/unenroll
// commands (issue #146).
func cmdVHLApprover(c vhlApproverClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier vhl approver <add|list|remove> [args]")
	}
	switch args[0] {
	case "add":
		return cmdVHLApproverAdd(c, args[1:])
	case "list":
		return cmdVHLApproverList(c)
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier vhl approver remove <address|name>")
		}
		if !confirmTyping(fmt.Sprintf("type REVOKE to unenroll %s", args[1]), "REVOKE") {
			return fmt.Errorf("cancelled")
		}
		if err := c.VHLUnenrollApprover(args[1]); err != nil {
			return err
		}
		fmt.Println("approver revoked")
		return nil
	default:
		return fmt.Errorf("usage: courier vhl approver <add|list|remove> [args]")
	}
}

// confirmTyping prompts the human and requires them to type expect.
// The typing itself is the local presence signal for PIN-grade
// ceremonies. It fails closed unless stdin is an interactive
// terminal: a canned response piped into stdin would authorize
// enrollment, minting, or approval signing with zero human
// involvement, defeating the presence signal entirely. This stops
// the trivial pipe attack — it does not stop a co-located adversary
// driving a pty. PIN-grade ceremonies attest local presence only;
// FIDO2 hardware and remote-approver flows are the strong paths.
//
// Declared as a variable (not a func) so CLI dispatch tests can stub
// the human-confirmation step hermetically; production always uses
// this implementation.
var confirmTyping = func(prompt, expect string) bool {
	if !stdinIsTerminal() {
		fmt.Fprintf(os.Stderr, "refusing: human confirmation requires an interactive terminal (stdin is not a terminal)\n")
		return false
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.TrimSpace(line) == expect
}

// stdinIsTerminal reports whether stdin is attached to an interactive
// terminal. The presence signal above is meaningless otherwise.
func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// sanitizeForTerminal escapes terminal control sequences in untrusted
// text. Drafts arrive from external senders, and the approval views
// below are a what-you-see-is-what-you-sign flow: a verbatim draft
// could hide or alter the displayed action with ANSI escapes, title
// changes, or other control bytes. Non-printable runes render as
// visible Go escapes (e.g. \x1b); newline and tab are kept so drafts
// stay readable, and printable Unicode passes through untouched.
// Display only: request validation and the action hash still use the
// raw draft bytes.
func sanitizeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			b.WriteString(strings.Trim(strconv.QuoteRune(r), "'"))
		}
	}
	return b.String()
}

func cmdVHLApproverAdd(c vhlApproverClient, args []string) error {
	var name string
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--name" && i+1 < len(args) {
			name = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(args[i], "--name=") {
			name = strings.TrimPrefix(args[i], "--name=")
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) < 1 {
		return fmt.Errorf("usage: courier vhl approver add <address> [--name NAME]")
	}
	address := rest[0]
	// Enrollment is a human-controlled cryptographic ceremony
	// (issue #142 review): typed confirmation could be driven by a
	// compromised process on a PTY, so the human approves the
	// pairing in their browser with their enrolled security key,
	// and the resulting artifact — not the typing — authorizes the
	// enrollment. The human sees WHAT they are enrolling here and
	// again on the ceremony page (approver + agent addresses).
	printf := func(format string, a ...any) { fmt.Printf(format, a...) }
	fmt.Printf("enrolling %s as a VHL approver — complete the security-key ceremony in your browser to authorize it.\n", address)
	art, err := c.VHLEnrollApproverCeremony(address, printf)
	if err != nil {
		return err
	}
	if err := c.VHLEnrollApprover(address, name, art); err != nil {
		return err
	}
	fmt.Println("approver enrolled")
	return nil
}

// cmdVHLEnrollWebAuthn enrolls the operator's own WebAuthn
// credential (e.g. a YubiKey) through the relay ceremony transport:
// the agent creates a ceremony, the human completes it in their
// browser, and the agent verifies the attestation itself before
// storing the credential locally and publishing the signed binding.
func cmdVHLEnrollWebAuthn(c *client.Client, args []string) error {
	var device string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--device" && i+1 < len(args):
			device = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--device="):
			device = strings.TrimPrefix(args[i], "--device=")
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) > 0 {
		return fmt.Errorf("usage: courier vhl enroll-webauthn [--device LABEL]")
	}
	if device == "" {
		device = "yubikey"
	}
	printf := func(format string, a ...any) { fmt.Printf(format, a...) }
	cred, err := c.VHLEnrollWebAuthn(device, printf)
	if err != nil {
		return err
	}
	fmt.Printf("enrolled webauthn credential %s\n", cred.ID)
	return nil
}

// cmdVHLRP manages the local WebAuthn relying-party config: `rp set`
// stores the RP id, allowed origins, and attestation trust roots;
// `rp show` prints the current config.
func cmdVHLRP(c *client.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier vhl rp <set|show> [args]")
	}
	switch args[0] {
	case "show":
		rp, err := c.VHLShowRP()
		if err != nil {
			return err
		}
		if rp.ID == "" {
			fmt.Println("no relying party configured (run `courier vhl rp set ...`)")
			return nil
		}
		fmt.Printf("rp id:   %s\n", rp.ID)
		fmt.Printf("origins: %s\n", strings.Join(rp.Origins, ", "))
		fmt.Printf("attestation roots: %d configured\n", len(rp.AttestationRoots))
		return nil
	case "set":
		return cmdVHLRPSet(c, args[1:])
	default:
		return fmt.Errorf("usage: courier vhl rp <set|show> [args]")
	}
}

func cmdVHLRPSet(c *client.Client, args []string) error {
	var rpID string
	var origins, roots []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--id" && i+1 < len(args):
			rpID = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--id="):
			rpID = strings.TrimPrefix(args[i], "--id=")
		case args[i] == "--origin" && i+1 < len(args):
			origins = append(origins, args[i+1])
			i++
		case strings.HasPrefix(args[i], "--origin="):
			origins = append(origins, strings.TrimPrefix(args[i], "--origin="))
		case args[i] == "--attestation-root" && i+1 < len(args):
			roots = append(roots, args[i+1])
			i++
		case strings.HasPrefix(args[i], "--attestation-root="):
			roots = append(roots, strings.TrimPrefix(args[i], "--attestation-root="))
		default:
			return fmt.Errorf("usage: courier vhl rp set --id DOMAIN --origin https://DOMAIN [--origin ...] --attestation-root CERT_FILE [...]")
		}
	}
	if rpID == "" || len(origins) == 0 || len(roots) == 0 {
		return fmt.Errorf("usage: courier vhl rp set --id DOMAIN --origin https://DOMAIN [--origin ...] --attestation-root CERT_FILE [...]")
	}
	old, _ := c.VHLShowRP()
	if err := c.VHLSetRP(rpID, origins, roots); err != nil {
		return err
	}
	fmt.Printf("relying party set: id=%s origins=%d attestation-roots=%d\n", rpID, len(origins), len(roots))
	if old.ID != "" && old.ID != rpID {
		fmt.Printf("warning: RP id changed from %s to %s — previously enrolled credentials were bound to the old id and must be re-enrolled\n", old.ID, rpID)
	}
	return nil
}

func cmdVHLApproverList(c vhlApproverClient) error {
	approvers, err := c.VHLApprovers()
	if err != nil {
		return err
	}
	if len(approvers) == 0 {
		fmt.Println("no approvers enrolled")
		return nil
	}
	for _, a := range approvers {
		label := a.Address
		if a.Name != "" {
			label = fmt.Sprintf("%s (%s)", a.Address, a.Name)
		}
		fmt.Printf("%s  credentials=%d enrolled=%s\n", label, a.Credentials,
			time.Unix(a.EnrolledAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	}
	return nil
}

func cmdVHLSession(c *client.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier vhl session <mint|status|revoke> [args]")
	}
	switch args[0] {
	case "mint":
		return cmdVHLSessionMint(c, args[1:])
	case "status":
		return cmdVHLSessionStatus(c)
	case "revoke":
		return cmdVHLSessionRevoke(c, args[1:])
	default:
		return fmt.Errorf("usage: courier vhl session <mint|status|revoke> [args]")
	}
}

func cmdVHLSessionMint(c *client.Client, args []string) error {
	var scope, ttlStr string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--scope" && i+1 < len(args):
			scope = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--scope="):
			scope = strings.TrimPrefix(args[i], "--scope=")
		case args[i] == "--ttl" && i+1 < len(args):
			ttlStr = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--ttl="):
			ttlStr = strings.TrimPrefix(args[i], "--ttl=")
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) > 0 {
		return fmt.Errorf("usage: courier vhl session mint [--scope ADDRESS] [--ttl DURATION]")
	}
	var ttl time.Duration
	if ttlStr != "" {
		var err error
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil {
			return fmt.Errorf("bad --ttl: %w", err)
		}
	}
	// Minting is ceremony-bound (issue #142): the agent creates a
	// relay ceremony over the mint challenge, the human approves it
	// with their security key in the browser, and the mint completes
	// against the verified assertion. There is no path that mints a
	// token without a fresh WebAuthn ceremony.
	printf := func(format string, a ...any) { fmt.Printf(format, a...) }
	tok, err := c.VHLSessionMintCeremony(scope, ttl, printf)
	if err != nil {
		return err
	}
	fmt.Printf("minted session token %s (presence=%s expires=%s)\n", tok.ID, tok.Presence,
		time.Unix(tok.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	return nil
}

func cmdVHLSessionStatus(c *client.Client) error {
	toks, err := c.VHLSessionStatus()
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		fmt.Println("no live session token (restart revokes tokens; mint one with `courier vhl session mint`)")
		return nil
	}
	for _, t := range toks {
		scope := t.Scope
		if scope == "" {
			scope = "(any recipient)"
		}
		fmt.Printf("%s  presence=%s scope=%s expires=%s\n", t.ID, t.Presence, scope,
			time.Unix(t.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	}
	return nil
}

func cmdVHLSessionRevoke(c *client.Client, args []string) error {
	var broadcast bool
	var rest []string
	for _, a := range args {
		if a == "--broadcast" {
			broadcast = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) < 1 {
		return fmt.Errorf("usage: courier vhl session revoke <token-id-prefix> [--broadcast]")
	}
	if !confirmTyping(fmt.Sprintf("revoke session token %s (type REVOKE to confirm)", rest[0]), "REVOKE") {
		return fmt.Errorf("cancelled")
	}
	if err := c.VHLRevokeSessionToken(rest[0], broadcast); err != nil {
		return err
	}
	fmt.Println("session token revoked")
	return nil
}

// cmdVHLRequest dispatches the request subcommand group: new files an
// approval request and list shows the pending queue (issue #146).
func cmdVHLRequest(c vhlRequestClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier vhl request <new|list> [args]")
	}
	switch args[0] {
	case "new":
		return cmdVHLRequestNew(c, args[1:])
	case "list":
		return cmdVHLRequestList(c)
	default:
		return fmt.Errorf("usage: courier vhl request <new|list> [args]")
	}
}

func cmdVHLRequestNew(c vhlRequestClient, args []string) error {
	var tierStr, message, presenceStr, human string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--tier" && i+1 < len(args):
			tierStr, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--tier="):
			tierStr = strings.TrimPrefix(args[i], "--tier=")
		case args[i] == "--message" && i+1 < len(args):
			message, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--message="):
			message = strings.TrimPrefix(args[i], "--message=")
		case args[i] == "--presence" && i+1 < len(args):
			presenceStr, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--presence="):
			presenceStr = strings.TrimPrefix(args[i], "--presence=")
		case args[i] == "--to" && i+1 < len(args):
			human, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--to="):
			human = strings.TrimPrefix(args[i], "--to=")
		default:
			return fmt.Errorf("usage: courier vhl request new --tier 2 --message TEXT [--presence pin] [--to HUMAN-ADDRESS]")
		}
	}
	// Tier 1 approvals are session-scoped: VHLApproveMint rejects
	// them, so recording a Tier 1 request here would be a dead end.
	// Point the user at session minting instead.
	if tierStr == "1" {
		return fmt.Errorf("tier 1 is session-scoped: mint a session token with `courier vhl session mint` instead of filing an approval request")
	}
	if tierStr != "2" {
		return fmt.Errorf("--tier must be 2")
	}
	tier := vhl.Tier2
	if strings.TrimSpace(message) == "" {
		return fmt.Errorf("--message is required: the exact draft the human will review")
	}
	presence := vhl.PresencePIN
	if presenceStr != "" {
		var err error
		presence, err = vhl.ParsePresence(presenceStr)
		if err != nil {
			return err
		}
	}
	req, err := c.VHLRequestApproval(human, tier, message, presence)
	if err != nil {
		return err
	}
	h := vhl.MsgHashOf([]byte(message))
	fmt.Printf("approval request %s recorded (tier %d, action hash %.16x…)\n", req.ID, tier, h)
	fmt.Println("the human reviews it with `courier vhl request list` and approves with `courier vhl approve`")
	return nil
}

func cmdVHLRequestList(c vhlRequestClient) error {
	reqs, err := c.VHLPendingRequests()
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		fmt.Println("no pending approval requests")
		return nil
	}
	for _, r := range reqs {
		q := r.Request
		fmt.Printf("request %s  tier=%d presence=%s from=%s expires=%s\n",
			q.ID, q.Tier, q.WantPresence, r.From,
			time.Unix(q.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
		fmt.Printf("  action hash: %x\n", vhl.MsgHashOf([]byte(q.Draft)))
		fmt.Printf("  draft: %s\n", sanitizeForTerminal(q.Draft))
	}
	return nil
}

func cmdVHLApprove(cfg *client.Config, c *client.Client, args []string) error {
	var presenceStr string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--presence" && i+1 < len(args):
			presenceStr, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--presence="):
			presenceStr = strings.TrimPrefix(args[i], "--presence=")
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) < 1 {
		return fmt.Errorf("usage: courier vhl approve <request-id> [--presence pin|challenge|fido2|fido2_uv]")
	}
	presence := vhl.PresencePIN
	if presenceStr != "" {
		var err error
		presence, err = vhl.ParsePresence(presenceStr)
		if err != nil {
			return err
		}
	}
	rec, err := c.VHLGetRequest(rest[0])
	if err != nil {
		return err
	}
	q := rec.Request
	// What-you-see-is-what-you-sign: the CLI recomputes the action
	// hash from the draft bytes and checks it before displaying
	// anything. A request whose bytes don't match its hash is not
	// shown for approval.
	h := vhl.MsgHashOf([]byte(q.Draft))
	fmt.Printf("request %s from %s — tier %d, wants %s ceremony\n", q.ID, rec.From, q.Tier, q.WantPresence)
	fmt.Printf("action hash: %x\n", h)
	fmt.Printf("draft:\n---\n%s\n---\n", sanitizeForTerminal(q.Draft))

	var proof vhl.Proof
	var approvalNonce []byte
	switch presence {
	case vhl.PresencePIN:
		// The PIN-grade ceremony: the human types the approval at
		// their own terminal after reviewing the exact bytes above.
		if !confirmTyping(fmt.Sprintf("approve these exact bytes (type APPROVE %s to confirm)", q.ID[:8]), "APPROVE "+q.ID[:8]) {
			return fmt.Errorf("cancelled")
		}
		proof = vhl.Proof{Kind: vhl.ProofPIN}
	case vhl.PresenceChallenge:
		// The challenge ceremony: a one-time code is minted for
		// these exact bytes. Deliver it out-of-band; the response
		// typed here models the human answering on the approving
		// device.
		ch, code, err := c.VHLMintChallenge([]byte(q.Draft))
		if err != nil {
			return err
		}
		fmt.Printf("challenge %s minted for this action.\n", ch.ID)
		fmt.Printf("one-time code (deliver OUT-OF-BAND, then enter it here): %s\n", code)
		// The response models the human answering on the approving
		// device; a piped code is not a human response.
		if !stdinIsTerminal() {
			return fmt.Errorf("refusing: the challenge ceremony requires an interactive terminal (stdin is not a terminal)")
		}
		fmt.Fprintf(os.Stderr, "enter code: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		if err := c.VHLVerifyChallenge(ch.ID, strings.TrimSpace(line)); err != nil {
			return fmt.Errorf("challenge failed: %w", err)
		}
		proof = vhl.Proof{Kind: vhl.ProofChallenge, ChallengeID: ch.ID}
	case vhl.PresenceFIDO2, vhl.PresenceFIDO2UV:
		// The FIDO2 ceremony: a fresh 32-byte nonce binds this
		// approval's WebAuthn challenge (see
		// vhl.ApprovalChallenge), and the human completes the
		// ceremony in their browser with their enrolled security
		// key. The returned proof carries the assertion; the nonce
		// is embedded in the attestation so the receiver can
		// consume it exactly once (the replay control).
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("approval nonce: %w", err)
		}
		printf := func(format string, a ...any) { fmt.Printf(format, a...) }
		p, err := c.VHLApproveFIDO2Ceremony(nonce[:], h[:], q.ID, cfg.Address, q.Draft, printf)
		if err != nil {
			return err
		}
		proof, approvalNonce = p, nonce[:]
	default:
		return fmt.Errorf("unknown presence %q", presence)
	}
	// displayedHash and displayedFrom are the action hash and sender
	// printed above: VHLApproveMint re-checks them against the stored
	// request inside one atomic critical section before minting.
	att, err := c.VHLApproveMint(q.ID, h, rec.From, proof, presence, approvalNonce)
	if err != nil {
		return err
	}
	fmt.Printf("approved: attestation %s minted (expires %s)\n", att.ID,
		time.Unix(att.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	fmt.Println("the agent can now send the approved bytes with `courier send --tier 2 --attestation", att.ID[:8]+"`")
	return nil
}

func cmdVHLAttestations(c *client.Client) error {
	atts, err := c.VHLAttestations()
	if err != nil {
		return err
	}
	if len(atts) == 0 {
		fmt.Println("no stored attestations")
		return nil
	}
	for _, a := range atts {
		fmt.Printf("%s  tier=%d approver=%.20s… proof=%s expires=%s\n", a.ID, a.Tier, a.Approver, a.Proof.Kind,
			time.Unix(a.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	}
	return nil
}

// cmdVHLPolicy manages the receiver's VHL tier policy: `courier vhl
// policy` prints the current required-tier floor; `courier vhl policy
// --require-tier 0|1|2` sets it. Messages below the floor are held
// for human review instead of being delivered as attested.
func cmdVHLPolicy(c *client.Client, args []string) error {
	var tierStr string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--require-tier" && i+1 < len(args):
			tierStr, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--require-tier="):
			tierStr = strings.TrimPrefix(args[i], "--require-tier=")
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) > 0 {
		return fmt.Errorf("usage: courier vhl policy [--require-tier 0|1|2]")
	}
	if tierStr == "" {
		tier, err := c.VHLGetRequiredTier()
		if err != nil {
			return err
		}
		fmt.Printf("required tier: %d\n", tier)
		return nil
	}
	tier, err := strconv.Atoi(tierStr)
	if err != nil || tier < 0 || tier > 2 {
		return fmt.Errorf("--require-tier must be 0, 1, or 2")
	}
	if err := c.VHLSetRequiredTier(tier); err != nil {
		return err
	}
	fmt.Printf("required tier set to %d\n", tier)
	return nil
}

// cmdVHLChallenge mints a one-time challenge code in flag form
// (issue #146): `courier vhl challenge --action TEXT`. There is no
// verify subcommand on this branch — challenge verification happens
// inside `courier vhl approve --presence challenge`.
func cmdVHLChallenge(c vhlChallengeClient, args []string) error {
	var action string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--action" && i+1 < len(args):
			action, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--action="):
			action = strings.TrimPrefix(args[i], "--action=")
		default:
			return fmt.Errorf("usage: courier vhl challenge --action TEXT")
		}
	}
	if strings.TrimSpace(action) == "" {
		return fmt.Errorf("--action is required")
	}
	ch, code, err := c.VHLMintChallenge([]byte(action))
	if err != nil {
		return err
	}
	h := vhl.MsgHashOf([]byte(action))
	fmt.Printf("challenge %s minted for action hash %x (expires %s)\n", ch.ID, h,
		time.Unix(ch.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	fmt.Printf("one-time code (show once, deliver out-of-band): %s\n", code)
	return nil
}

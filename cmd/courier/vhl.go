// Verified Human in the Loop (issue #142): approver enrollment,
// session tokens, approval requests, and the human approval ceremony.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

func cmdVHL(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier vhl <enroll|approvers|unenroll|session|request|requests|approve|attestations|challenge> ...")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg)
	switch args[0] {
	case "enroll":
		return cmdVHLEnroll(c, args[1:])
	case "approvers":
		return cmdVHLApprovers(c)
	case "unenroll":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier vhl unenroll <address|name>")
		}
		if !confirmTyping(fmt.Sprintf("type REVOKE to unenroll %s", args[1]), "REVOKE") {
			return fmt.Errorf("cancelled")
		}
		if err := c.VHLUnenrollApprover(args[1]); err != nil {
			return err
		}
		fmt.Println("approver revoked")
		return nil
	case "session":
		return cmdVHLSession(c, args[1:])
	case "request":
		return cmdVHLRequest(c, args[1:])
	case "requests":
		return cmdVHLRequests(c)
	case "approve":
		return cmdVHLApprove(c, args[1:])
	case "attestations":
		return cmdVHLAttestations(c)
	case "challenge":
		return cmdVHLChallenge(c, args[1:])
	default:
		return fmt.Errorf("usage: courier vhl <enroll|approvers|unenroll|session|request|requests|approve|attestations|challenge> ...")
	}
}

// confirmTyping prompts the human and requires them to type expect.
// The typing itself is the local presence signal for PIN-grade
// ceremonies; it must run on the human's own terminal.
func confirmTyping(prompt, expect string) bool {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.TrimSpace(line) == expect
}

func cmdVHLEnroll(c *client.Client, args []string) error {
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
		return fmt.Errorf("usage: courier vhl enroll <address> [--name NAME]")
	}
	address := rest[0]
	// Enrollment is a Tier 2 human-approved event (issue #142): the
	// human at this terminal explicitly confirms, and the event is
	// recorded in the registry for audit.
	if !confirmTyping(fmt.Sprintf("enroll %s as a VHL approver (type ENROLL to confirm)", address), "ENROLL") {
		return fmt.Errorf("cancelled")
	}
	if err := c.VHLEnrollApprover(address, name, "cli-interactive-enrollment"); err != nil {
		return err
	}
	fmt.Println("approver enrolled")
	return nil
}

func cmdVHLApprovers(c *client.Client) error {
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
		return fmt.Errorf("usage: courier vhl session <mint|status|revoke> ...")
	}
	switch args[0] {
	case "mint":
		return cmdVHLSessionMint(c, args[1:])
	case "status":
		return cmdVHLSessionStatus(c)
	case "revoke":
		return cmdVHLSessionRevoke(c, args[1:])
	default:
		return fmt.Errorf("usage: courier vhl session <mint|status|revoke> ...")
	}
}

func cmdVHLSessionMint(c *client.Client, args []string) error {
	var scope, ttlStr, presenceStr string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--scope" && i+1 < len(args):
			scope, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--scope="):
			scope = strings.TrimPrefix(args[i], "--scope=")
		case args[i] == "--ttl" && i+1 < len(args):
			ttlStr, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--ttl="):
			ttlStr = strings.TrimPrefix(args[i], "--ttl=")
		case args[i] == "--presence" && i+1 < len(args):
			presenceStr, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--presence="):
			presenceStr = strings.TrimPrefix(args[i], "--presence=")
		default:
			return fmt.Errorf("usage: courier vhl session mint [--scope ADDR] [--ttl 8h] [--presence pin]")
		}
	}
	ttl := vhl.DefaultSessionTTL
	if ttlStr != "" {
		var err error
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil || ttl <= 0 {
			return fmt.Errorf("--ttl must be a positive duration (e.g. 8h)")
		}
	}
	presence := vhl.PresencePIN
	if presenceStr != "" {
		var err error
		presence, err = vhl.ParsePresence(presenceStr)
		if err != nil {
			return err
		}
	}
	// The CLI performs the PIN-grade ceremony: the human types the
	// confirmation at their own terminal. Stronger ceremonies
	// (FIDO2) arrive with the dashboard flow.
	if presence != vhl.PresencePIN {
		return fmt.Errorf("the CLI performs the pin ceremony only; use the dashboard for %q", presence)
	}
	if !confirmTyping("mint VHL session token (type MINT to confirm)", "MINT") {
		return fmt.Errorf("cancelled")
	}
	tok, err := c.VHLMintSessionToken(scope, ttl, presence)
	if err != nil {
		return err
	}
	fmt.Printf("session token %s minted, expires %s\n", tok.ID,
		time.Unix(tok.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	if scope != "" {
		fmt.Printf("scoped to %s\n", scope)
	}
	return nil
}

func cmdVHLSessionStatus(c *client.Client) error {
	toks, err := c.VHLSessionStatus()
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		fmt.Println("no live session token (restart revokes tokens; mint a new one with `courier vhl session mint`)")
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

func cmdVHLRequest(c *client.Client, args []string) error {
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
			return fmt.Errorf("usage: courier vhl request --tier 2 --message TEXT [--presence pin] [--to HUMAN-ADDRESS]")
		}
	}
	if tierStr != "1" && tierStr != "2" {
		return fmt.Errorf("--tier must be 1 or 2")
	}
	var tier vhl.Tier
	if tierStr == "1" {
		tier = vhl.Tier1
	} else {
		tier = vhl.Tier2
	}
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
	fmt.Println("the human reviews it with `courier vhl requests` and approves with `courier vhl approve`")
	return nil
}

func cmdVHLRequests(c *client.Client) error {
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
		fmt.Printf("  draft: %s\n", q.Draft)
	}
	return nil
}

func cmdVHLApprove(c *client.Client, args []string) error {
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
		return fmt.Errorf("usage: courier vhl approve <request-id> [--presence pin|challenge]")
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
	fmt.Printf("draft:\n---\n%s\n---\n", q.Draft)

	var proof vhl.Proof
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
		fmt.Fprintf(os.Stderr, "enter code: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		if err := c.VHLVerifyChallenge(ch.ID, strings.TrimSpace(line)); err != nil {
			return fmt.Errorf("challenge failed: %w", err)
		}
		proof = vhl.Proof{Kind: vhl.ProofChallenge, ChallengeID: ch.ID}
	default:
		return fmt.Errorf("the CLI performs the pin and challenge ceremonies; use the dashboard for %q", presence)
	}
	att, err := c.VHLApproveMint(q.ID, proof, presence)
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

func cmdVHLChallenge(c *client.Client, args []string) error {
	if len(args) == 0 || args[0] != "mint" {
		return fmt.Errorf("usage: courier vhl challenge mint --action TEXT")
	}
	var action string
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--action" && i+1 < len(args):
			action, i = args[i+1], i+1
		case strings.HasPrefix(args[i], "--action="):
			action = strings.TrimPrefix(args[i], "--action=")
		default:
			return fmt.Errorf("usage: courier vhl challenge mint --action TEXT")
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

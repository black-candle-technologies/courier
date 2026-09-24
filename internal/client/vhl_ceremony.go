package client

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// VHL WebAuthn ceremony transport client (issue #142).
//
// The agent cannot touch a YubiKey, so enrollment and session minting
// run as a relay-hosted ceremony: the agent creates a short-lived
// ceremony record over its identity-authenticated API, the human
// completes the WebAuthn ceremony in their browser (logged into the
// dashboard), and the agent polls for the result and verifies it
// itself. See PROTOCOL.md §30.6 and internal/relay/vhl_ceremony.go.

// VHLCeremony is a created ceremony record: the single-use code and
// the page path the human opens in their browser.
type VHLCeremony struct {
	Code      string
	Path      string // "/vhl/ceremony?code=..."
	ExpiresAt int64
	ExpiresIn int64
}

// CeremonyURL returns the full browser URL for the ceremony: the
// relay's public origin plus the ceremony path. Operators serving
// the dashboard at a public domain (e.g.
// https://courier.blackcandletech.com) should route /vhl/* and
// /v1/vhl/* there to the relay so the page shares the dashboard's
// origin (session cookie + TLS certificate).
func (c *Client) CeremonyURL(cer *VHLCeremony) string {
	return strings.TrimSuffix(c.cfg.RelayURL, "/") + cer.Path
}

// VHLCreateCeremony creates a relay ceremony of the given type
// ("enroll", "mint", "approve", or "enroll-approver") for the given
// base64url challenge. contextJSON is the human-reviewed ceremony
// context the page displays before the key is touched — required
// for mint, approve, and enroll-approver, empty for enroll — and is
// covered by the creation signature so the relay cannot substitute
// values the human never saw. For mint and approve, credentialIDs
// lists the enrolled WebAuthn credential ids the browser may use.
// rpID is echoed to the ceremony page (the agent verifies the
// attestation against its own RP config afterwards, so relay
// tampering with the echoed values fails closed).
func (c *Client) VHLCreateCeremony(ceremonyType, challengeB64 string, credentialIDs []string, rpID, contextJSON string) (*VHLCeremony, error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	canon := envelope.VHLCeremonyCreate(id.EdPub[:], ceremonyType, challengeB64, contextJSON, ts)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/vhl/ceremonies", map[string]any{
		"address":        c.cfg.Address,
		"type":           ceremonyType,
		"challenge":      challengeB64,
		"context":        contextJSON,
		"credential_ids": credentialIDs,
		"rp_id":          rpID,
		"ts":             ts,
		"sig":            base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, err
	}
	if code != http.StatusCreated {
		return nil, relayErr(data)
	}
	var resp struct {
		Code         string `json:"code"`
		CeremonyPath string `json:"ceremony_path"`
		ExpiresAt    int64  `json:"expires_at"`
		ExpiresInSec int64  `json:"expires_in_sec"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("bad ceremony response: %w", err)
	}
	if resp.Code == "" || resp.CeremonyPath == "" {
		return nil, fmt.Errorf("bad ceremony response: missing code")
	}
	return &VHLCeremony{Code: resp.Code, Path: resp.CeremonyPath, ExpiresAt: resp.ExpiresAt, ExpiresIn: resp.ExpiresInSec}, nil
}

// vhlCeremonyResult polls one ceremony result.
func (c *Client) vhlCeremonyResult(code string) (status, attestation string, err error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return "", "", err
	}
	ts := time.Now().Unix()
	sig := id.Sign(envelope.VHLCeremonyResult(id.EdPub[:], code, ts))
	u := c.cfg.RelayURL + "/v1/vhl/ceremonies/" + url.PathEscape(code) + "/result" +
		"?address=" + url.QueryEscape(c.cfg.Address) +
		"&ts=" + url.QueryEscape(fmt.Sprint(ts)) +
		"&sig=" + url.QueryEscape(base64.RawURLEncoding.EncodeToString(sig))
	hc, err := c.httpClient()
	if err != nil {
		return "", "", err
	}
	resp, err := hc.Get(u)
	if err != nil {
		return "", "", fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", "", relayErr(data)
	}
	var out struct {
		Status      string `json:"status"`
		Attestation string `json:"attestation"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", "", fmt.Errorf("bad result response: %w", err)
	}
	return out.Status, out.Attestation, nil
}

// VHLPollCeremonyResult polls the ceremony until the browser
// completes it, the code expires, or timeout elapses. It returns the
// base64url ceremony response for the agent to verify itself.
func (c *Client) VHLPollCeremonyResult(code string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		status, attestation, err := c.vhlCeremonyResult(code)
		if err != nil {
			return "", err
		}
		switch status {
		case "completed":
			if attestation == "" {
				return "", fmt.Errorf("ceremony completed without attestation")
			}
			return attestation, nil
		case "expired":
			return "", fmt.Errorf("ceremony expired: ask for a new code")
		case "pending":
			// keep polling
		default:
			return "", fmt.Errorf("unknown ceremony status %q", status)
		}
		if time.Now().Add(2 * time.Second).After(deadline) {
			return "", fmt.Errorf("timed out waiting for the browser ceremony")
		}
		time.Sleep(2 * time.Second)
	}
}

// VHLSetRP stores the local WebAuthn relying-party config: the RP id,
// the allowed origins, and the attestation trust roots read from
// rootFiles (each PEM or DER encoded certificate, e.g. the
// authenticator vendor's root CA). Attestation roots are mandatory:
// without them enrollment cannot distinguish a real authenticator's
// attestation from one forged by anyone holding the ceremony
// challenge (including a compromised relay, which sees every
// challenge), so enrollment fails closed without them. Changing the
// RP id after credentials are enrolled orphans those credentials
// (the RP id is hashed into every ceremony); the caller is expected
// to warn.
func (c *Client) VHLSetRP(rpID string, origins []string, rootFiles []string) error {
	if rpID == "" || len(rpID) > 253 || strings.Contains(rpID, "://") {
		return fmt.Errorf("rp id must be a bare domain, got %q", rpID)
	}
	if len(origins) == 0 {
		return fmt.Errorf("at least one --origin is required")
	}
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return fmt.Errorf("bad origin %q", o)
		}
		// WebAuthn needs a secure context: https, or http on
		// localhost for testing only.
		secure := u.Scheme == "https" ||
			(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))
		if !secure {
			return fmt.Errorf("origin %q must be https (http only for localhost testing)", o)
		}
	}
	if len(rootFiles) == 0 {
		return fmt.Errorf("at least one --attestation-root certificate file is required")
	}
	var roots []string
	for _, f := range rootFiles {
		der, err := loadCertDER(f)
		if err != nil {
			return fmt.Errorf("attestation root %s: %w", f, err)
		}
		roots = append(roots, base64.RawURLEncoding.EncodeToString(der))
	}
	rp := vhl.WebAuthnRP{ID: rpID, Origins: origins, AttestationRoots: roots}
	return updateVHL(func(ff *vhlFile) error {
		ff.RP = rp
		return nil
	})
}

// loadCertDER reads one certificate file as DER, accepting PEM or
// raw DER, and requires it to parse as an X.509 certificate.
func loadCertDER(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("not a certificate PEM block")
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("not a valid X.509 certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("not a CA certificate: attestation roots must be CA certs")
	}
	return cert.Raw, nil
}

// VHLShowRP returns the local WebAuthn relying-party config.
func (c *Client) VHLShowRP() (vhl.WebAuthnRP, error) {
	ff, err := loadVHL()
	if err != nil {
		return vhl.WebAuthnRP{}, err
	}
	return ff.RP, nil
}

// vhlRPConfig loads the local VHL RP config, failing closed with
// operator guidance when the relying party is not configured.
func (c *Client) vhlRPConfig() (vhl.WebAuthnRP, error) {
	ff, err := loadVHL()
	if err != nil {
		return vhl.WebAuthnRP{}, err
	}
	if ff.RP.ID == "" || len(ff.RP.Origins) == 0 {
		return vhl.WebAuthnRP{}, fmt.Errorf("no WebAuthn relying party configured: run `courier vhl rp set --id <domain> --origin https://<domain>` first")
	}
	if len(ff.RP.AttestationRoots) == 0 {
		return vhl.WebAuthnRP{}, fmt.Errorf("no WebAuthn attestation roots configured: run `courier vhl rp set --attestation-root <cert-file>` with your authenticator vendor's root CA")
	}
	return ff.RP, nil
}

// VHLEnrollWebAuthn runs the full WebAuthn enrollment ceremony: it
// creates the enrollment challenge, opens the relay ceremony, waits
// for the human to complete it in their browser, verifies the
// attestation itself, stores the credential in the local registry,
// and publishes the signed identity→credential binding for
// discovery. The publication is best-effort: the local registry is
// the trust root, and a failed publication warns loudly instead of
// silently diverging.
func (c *Client) VHLEnrollWebAuthn(deviceLabel string, printf func(string, ...any)) (*vhl.Credential, error) {
	rp, err := c.vhlRPConfig()
	if err != nil {
		return nil, err
	}
	challenge, err := vhl.EnrollmentChallenge(c.cfg.Address, rp.ID)
	if err != nil {
		return nil, err
	}
	cer, err := c.VHLCreateCeremony("enroll", base64.RawURLEncoding.EncodeToString(challenge), nil, rp.ID, "")
	if err != nil {
		return nil, err
	}
	printf("Open this URL in your browser (logged into the dashboard) and complete the security-key ceremony:\n\n  %s\n\nCode: %s (expires in %d seconds)\n", c.CeremonyURL(cer), cer.Code, cer.ExpiresIn)
	attestationB64, err := c.VHLPollCeremonyResult(cer.Code, 6*time.Minute)
	if err != nil {
		return nil, err
	}
	result, err := vhl.VerifyRegistrationAttestation(attestationB64, challenge, rp)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	name := deviceLabel
	if name == "" {
		name = "self"
	}
	cred := vhl.Credential{
		ID:         result.CredentialID,
		Kind:       "webauthn",
		PublicKey:  base64.RawURLEncoding.EncodeToString(result.PublicKey),
		EnrolledAt: time.Now().Unix(),
		Device:     deviceLabel,
		AAGUID:     result.AAGUID,
		SignCount:  result.SignCount,
	}
	// The ceremony itself was the human's explicit authorization:
	// they logged into the dashboard, opened the ceremony page, and
	// touched their security key with user verification. That is the
	// Tier 2 human approval for this enrollment.
	if err := updateVHL(func(ff *vhlFile) error {
		return ff.Registry.Enroll(c.cfg.Address, name, cred, true)
	}); err != nil {
		return nil, err
	}
	printf("Enrolled WebAuthn credential %s (aaguid %s).\n", cred.ID, cred.AAGUID)
	if err := c.VHLPublishEnrollment(&cred, rp.ID); err != nil {
		printf("WARNING: enrolled locally, but publishing the enrollment for discovery failed: %v\n", err)
		printf("Other agents will not discover this credential until publication succeeds.\n")
	} else {
		printf("Published the signed enrollment for discovery.\n")
	}
	return &cred, nil
}

// VHLPublishEnrollment publishes the signed identity→credential
// binding to the relay's VHL enrollment directory for discovery.
// Only the address owner can publish (identity signature), and only
// a strictly increasing epoch is applied.
func (c *Client) VHLPublishEnrollment(cred *vhl.Credential, rpID string) error {
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	epoch := time.Now().Unix()
	// A fresh publication is never revoked; the flag is bound by
	// the signature so the relay cannot flip it later.
	canon := envelope.VHLEnrollmentAnnounce(id.EdPub[:], cred.ID, cred.PublicKey, rpID, epoch, false)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/vhl/enrollments", map[string]any{
		"address":        c.cfg.Address,
		"credential_id":  cred.ID,
		"credential_pub": cred.PublicKey,
		"rp_id":          rpID,
		"aaguid":         cred.AAGUID,
		"epoch":          epoch,
		"sig":            base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return relayErr(data)
	}
	return nil
}

// VHLPublishedEnrollment is one published identity→credential
// binding from the relay's VHL enrollment directory, for
// discovery. The local registry stays the trust root: a directory
// entry can never override a local enrollment.
type VHLPublishedEnrollment struct {
	Address       string `json:"address"`
	CredentialID  string `json:"credential_id"`
	CredentialPub string `json:"credential_pub"`
	RPID          string `json:"rp_id"`
	AAGUID        string `json:"aaguid"`
	Epoch         int64  `json:"epoch"`
	Revoked       bool   `json:"revoked"`
	Sig           string `json:"sig"`
	PublishedAt   int64  `json:"published_at"`
}

// VHLLookupEnrollment fetches another identity's published
// enrollment bindings for discovery: the full credential set, each
// with its revoked flag. Callers filter out revoked bindings
// themselves — a revoked row still listed is how the directory
// reports a revocation. The local registry stays the trust root: a
// directory entry can never override a local enrollment.
func (c *Client) VHLLookupEnrollment(address string) ([]*VHLPublishedEnrollment, error) {
	hc, err := c.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := hc.Get(c.cfg.RelayURL + "/v1/vhl/enrollments/" + url.PathEscape(address))
	if err != nil {
		return nil, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, relayErr(data)
	}
	var out []*VHLPublishedEnrollment
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("bad enrollment response: %w", err)
	}
	return out, nil
}

// VHLSessionMintCeremony runs the full relay-backed session-token
// mint: it begins the mint locally, creates the relay ceremony bound
// to the mint challenge, waits for the human to approve it with
// their security key in the browser, and finishes the mint against
// the verified assertion. The returned token is ceremony-bound —
// minting is impossible without a fresh WebAuthn ceremony.
// VHLFinishSessionMint persists the token itself.
func (c *Client) VHLSessionMintCeremony(scope string, ttl time.Duration, printf func(string, ...any)) (*vhl.SessionToken, error) {
	rp, err := c.vhlRPConfig()
	if err != nil {
		return nil, err
	}
	pending, err := c.VHLBeginSessionMint(scope, ttl)
	if err != nil {
		return nil, err
	}
	// Collect the enrolled WebAuthn credential ids for the ceremony's
	// allowCredentials list.
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	_, webAuthn, err := ff.Registry.KeysFor(c.cfg.Address)
	if err != nil {
		return nil, err
	}
	var credIDs []string
	for _, cred := range webAuthn {
		credIDs = append(credIDs, cred.ID)
	}
	if len(credIDs) == 0 {
		return nil, fmt.Errorf("no WebAuthn credential enrolled for this identity: run `courier vhl enroll-webauthn` first")
	}
	// The human reviews exactly this context in the browser before
	// touching their key: the page displays it and recomputes the
	// challenge from it, and the creation signature covers the same
	// bytes so the relay cannot substitute values.
	mintCtx := vhl.MintContext{
		Issuer:    pending.Issuer,
		Scope:     pending.Scope,
		TokenID:   pending.ID,
		SessionID: pending.SessionID,
		IssuedAt:  pending.IssuedAt,
		ExpiresAt: pending.ExpiresAt,
		Presence:  vhl.PresenceFIDO2UV.String(),
	}
	cer, err := c.VHLCreateCeremony("mint", base64.RawURLEncoding.EncodeToString(pending.Challenge()), credIDs, rp.ID, string(mintCtx.Canonical()))
	if err != nil {
		return nil, err
	}
	printf("Approve the session-token mint in your browser (logged into the dashboard):\n\n  %s\n\nCode: %s (expires in %d seconds)\n", c.CeremonyURL(cer), cer.Code, cer.ExpiresIn)
	assertionB64, err := c.VHLPollCeremonyResult(cer.Code, 6*time.Minute)
	if err != nil {
		return nil, err
	}
	// The ceremony used whichever enrolled credential the browser
	// picked: bind the finish to the credential the assertion
	// actually names.
	credID, err := vhlAssertionCredentialID(assertionB64)
	if err != nil {
		return nil, err
	}
	return c.VHLFinishSessionMint(pending, credID, assertionB64)
}

// vhlAssertionCredentialID extracts the credential id naming the
// assertion: the browser may use any enrolled credential, so the
// agent binds verification to the credential the assertion actually
// names.
func vhlAssertionCredentialID(assertionB64 string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(assertionB64)
	if err != nil {
		return "", fmt.Errorf("bad assertion encoding: %w", err)
	}
	var outer struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil || outer.ID == "" {
		return "", fmt.Errorf("bad assertion: missing credential id")
	}
	return outer.ID, nil
}

// vhlFindCredential returns the enrolled WebAuthn credential with
// the given id for the given approver identity, or nil.
func vhlFindCredential(ff *vhlFile, identity, credentialID string) *vhl.Credential {
	a := ff.Registry.Approvers[identity]
	if a == nil {
		return nil
	}
	for i := range a.Credentials {
		if a.Credentials[i].ID == credentialID {
			return &a.Credentials[i]
		}
	}
	return nil
}

// vhlCredentialIDs returns the enrolled WebAuthn credential ids for
// an identity, for a ceremony's allowCredentials list.
func vhlCredentialIDs(ff *vhlFile, identity string) []string {
	var ids []string
	if a := ff.Registry.Approvers[identity]; a != nil {
		for _, cred := range a.Credentials {
			if cred.Kind == "webauthn" {
				ids = append(ids, cred.ID)
			}
		}
	}
	return ids
}

// VHLApproveFIDO2Ceremony runs the full relay-backed Tier 2
// approval ceremony: it builds the nonce-bound approval challenge
// (vhl.ApprovalChallenge), creates an "approve" relay ceremony whose
// context carries the request id, action hash, approver, draft
// summary, and nonce for the human to review, waits for the human
// to approve it with their security key in the browser, and
// verifies the returned assertion against the enrolled credential
// and the relying party config before returning the proof. The
// proof's assertion answers the nonce-bound challenge, so the
// receiver can enforce per-nonce replay protection.
func (c *Client) VHLApproveFIDO2Ceremony(nonce []byte, actionHash []byte, requestID, approver, draftSummary string, printf func(string, ...any)) (vhl.Proof, error) {
	rp, err := c.vhlRPConfig()
	if err != nil {
		return vhl.Proof{}, err
	}
	if len(nonce) != 32 {
		return vhl.Proof{}, fmt.Errorf("approval nonce must be 32 bytes")
	}
	if len(actionHash) != 32 {
		return vhl.Proof{}, fmt.Errorf("action hash must be 32 bytes")
	}
	challenge := vhl.ApprovalChallenge(actionHash, nonce)
	ctxJSON, err := json.Marshal(map[string]any{
		"request_id":    requestID,
		"action_hash":   base64.RawURLEncoding.EncodeToString(actionHash),
		"approver":      approver,
		"draft_summary": draftSummary,
		"nonce_b64":     base64.RawURLEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return vhl.Proof{}, fmt.Errorf("approve context: %w", err)
	}
	ff, err := loadVHL()
	if err != nil {
		return vhl.Proof{}, err
	}
	cer, err := c.VHLCreateCeremony("approve", base64.RawURLEncoding.EncodeToString(challenge[:]), vhlCredentialIDs(ff, approver), rp.ID, string(ctxJSON))
	if err != nil {
		return vhl.Proof{}, err
	}
	printf("Approve the action in your browser (logged into the dashboard):\n\n  %s\n\nCode: %s (expires in %d seconds)\n", c.CeremonyURL(cer), cer.Code, cer.ExpiresIn)
	assertionB64, err := c.VHLPollCeremonyResult(cer.Code, 6*time.Minute)
	if err != nil {
		return vhl.Proof{}, err
	}
	credID, err := vhlAssertionCredentialID(assertionB64)
	if err != nil {
		return vhl.Proof{}, err
	}
	cred := vhlFindCredential(ff, approver, credID)
	if cred == nil {
		return vhl.Proof{}, fmt.Errorf("approval refused: credential %q is not enrolled for approver %s", credID, approver)
	}
	if cred.Kind != "webauthn" {
		return vhl.Proof{}, fmt.Errorf("approval refused: credential %q is %s (want webauthn)", credID, cred.Kind)
	}
	if _, err := vhl.VerifyAssertionForChallenge(cred, assertionB64, challenge[:], rp, true); err != nil {
		return vhl.Proof{}, fmt.Errorf("approval assertion verification failed: %w", err)
	}
	return vhl.Proof{Kind: vhl.ProofFIDO2, CredentialID: credID, Assertion: assertionB64}, nil
}

// VHLEnrollApproverCeremony runs the relay-backed approver
// enrollment ceremony: the human approves enrolling approverAddress
// as a trust root with their security key in the browser. It
// creates an "enroll-approver" relay ceremony over
// vhl.ApproverEnrollmentChallenge (binding both addresses and the
// timestamp), prints the ceremony URL, waits for the human to
// complete it, and returns the enrollment artifact. The registry
// validates the artifact — the challenge recomputes from the
// claimed addresses and timestamp, and the assertion verifies
// against the human's enrolled credential — before the identity is
// trusted.
func (c *Client) VHLEnrollApproverCeremony(approverAddress string, printf func(string, ...any)) (*vhl.EnrollmentArtifact, error) {
	rp, err := c.vhlRPConfig()
	if err != nil {
		return nil, err
	}
	issuedAt := time.Now().Unix()
	challenge := vhl.ApproverEnrollmentChallenge(c.cfg.Address, approverAddress, issuedAt)
	ctxJSON, err := json.Marshal(map[string]any{
		"approver_address": approverAddress,
		"agent_address":    c.cfg.Address,
		"issued_at":        issuedAt,
		"challenge_b64":    base64.RawURLEncoding.EncodeToString(challenge[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("enroll-approver context: %w", err)
	}
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	cer, err := c.VHLCreateCeremony("enroll-approver", base64.RawURLEncoding.EncodeToString(challenge[:]), vhlCredentialIDs(ff, c.cfg.Address), rp.ID, string(ctxJSON))
	if err != nil {
		return nil, err
	}
	printf("Enroll %s as an approver in your browser (logged into the dashboard):\n\n  %s\n\nCode: %s (expires in %d seconds)\n", approverAddress, c.CeremonyURL(cer), cer.Code, cer.ExpiresIn)
	assertionB64, err := c.VHLPollCeremonyResult(cer.Code, 6*time.Minute)
	if err != nil {
		return nil, err
	}
	credID, err := vhlAssertionCredentialID(assertionB64)
	if err != nil {
		return nil, err
	}
	return &vhl.EnrollmentArtifact{
		Address:      approverAddress,
		AgentAddress: c.cfg.Address,
		CredentialID: credID,
		Challenge:    base64.RawURLEncoding.EncodeToString(challenge[:]),
		Assertion:    assertionB64,
		IssuedAt:     issuedAt,
	}, nil
}

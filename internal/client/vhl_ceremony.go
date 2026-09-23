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
// ("enroll" or "mint") for the given base64url challenge. For mint,
// credentialIDs lists the enrolled WebAuthn credential ids the
// browser may use. rpID is echoed to the ceremony page (the agent
// verifies the attestation against its own RP config afterwards, so
// relay tampering with the echoed values fails closed).
func (c *Client) VHLCreateCeremony(ceremonyType, challengeB64 string, credentialIDs []string, rpID string) (*VHLCeremony, error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	canon := envelope.VHLCeremonyCreate(id.EdPub[:], ceremonyType, challengeB64, ts)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/vhl/ceremonies", map[string]any{
		"address":        c.cfg.Address,
		"type":           ceremonyType,
		"challenge":      challengeB64,
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
	cer, err := c.VHLCreateCeremony("enroll", base64.RawURLEncoding.EncodeToString(challenge), nil, rp.ID)
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
	canon := envelope.VHLEnrollmentAnnounce(id.EdPub[:], cred.ID, cred.PublicKey, rpID, epoch)
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

// VHLLookupEnrollment fetches another identity's published enrollment
// binding for discovery. The local registry stays the trust root:
// a directory entry can never override a local enrollment.
func (c *Client) VHLLookupEnrollment(address string) (map[string]any, error) {
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
	var out map[string]any
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
	cer, err := c.VHLCreateCeremony("mint", base64.RawURLEncoding.EncodeToString(pending.Challenge()), credIDs, rp.ID)
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
	var outer struct {
		ID string `json:"id"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(assertionB64)
	if err != nil {
		return nil, fmt.Errorf("bad assertion encoding: %w", err)
	}
	if err := json.Unmarshal(raw, &outer); err != nil || outer.ID == "" {
		return nil, fmt.Errorf("bad assertion: missing credential id")
	}
	return c.VHLFinishSessionMint(pending, outer.ID, assertionB64)
}

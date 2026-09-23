package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/vhl"
	"github.com/black-candle-technologies/courier/internal/vhltest"
)

// Relay-hosted WebAuthn ceremony end-to-end tests (issue #142):
// the agent creates a signed ceremony, a logged-in "browser"
// completes it with a genuine synthetic-authenticator attestation,
// and the agent polls, independently verifies the attestation
// against its own challenge and RP config, and proceeds. The
// authenticator private key never leaves the test process, exactly
// like a real security key.

const ceremonyTestRPID = "example.com"
const ceremonyTestOrigin = "https://example.com"

// ceremonyBrowser is the test's stand-in for the human's browser: a
// logged-in dashboard session (session cookie + CSRF token) bound to
// the given Courier identity.
type ceremonyBrowser struct {
	t      *testing.T
	srvURL string
	cookie string
	csrf   string
}

func newCeremonyBrowser(t *testing.T, env *attachTestEnv, address string) *ceremonyBrowser {
	t.Helper()
	user, err := env.st.CreateDashboardUser("ceremony-user", "hash", address, "")
	if err != nil {
		t.Fatal(err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	cookie := hex.EncodeToString(token)
	sum := sha256.Sum256([]byte(cookie))
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		t.Fatal(err)
	}
	csrf := hex.EncodeToString(csrfBytes)
	if err := env.st.CreateSession(hex.EncodeToString(sum[:]), user.ID, time.Hour, csrf); err != nil {
		t.Fatal(err)
	}
	return &ceremonyBrowser{t: t, srvURL: env.srv.URL, cookie: cookie, csrf: csrf}
}

func (b *ceremonyBrowser) do(method, path string, body any) (int, []byte) {
	b.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.srvURL+path, rdr)
	if err != nil {
		b.t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "courier_session", Value: b.cookie})
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data
}

// ceremonyChallenge fetches the ceremony details the way the real
// ceremony page does and returns its challenge.
func (b *ceremonyBrowser) ceremonyChallenge(code string) []byte {
	b.t.Helper()
	status, data := b.do("GET", "/v1/vhl/ceremonies/"+code, nil)
	if status != http.StatusOK {
		b.t.Fatalf("ceremony details: status %d: %s", status, data)
	}
	var details struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rp_id"`
	}
	if err := json.Unmarshal(data, &details); err != nil {
		b.t.Fatal(err)
	}
	chal, err := base64.RawURLEncoding.DecodeString(details.Challenge)
	if err != nil {
		b.t.Fatal(err)
	}
	if details.RPID != ceremonyTestRPID {
		b.t.Fatalf("rp_id = %q, want %q", details.RPID, ceremonyTestRPID)
	}
	return chal
}

func (b *ceremonyBrowser) submitAttestation(code, attestationB64 string) {
	b.t.Helper()
	status, data := b.do("POST", "/v1/vhl/ceremonies/"+code+"/attestation", map[string]any{
		"attestation": attestationB64,
		"csrf_token":  b.csrf,
	})
	if status != http.StatusOK {
		b.t.Fatalf("attestation submit: status %d: %s", status, data)
	}
}

// ceremonyCodeSink captures the ceremony code the client prints for
// the human, so the test's browser can complete it.
type ceremonyCodeSink struct {
	ch chan string
}

func newCeremonyCodeSink() *ceremonyCodeSink { return &ceremonyCodeSink{ch: make(chan string, 1)} }

func (s *ceremonyCodeSink) printf(format string, args ...any) {
	// The client prints the ceremony code for the human as:
	//   "... Code: %s (expires in %d seconds)\n", url, code, expiresIn
	if !strings.Contains(format, "Code: %s") || len(args) < 2 {
		return
	}
	if code, ok := args[1].(string); ok && code != "" {
		select {
		case s.ch <- code:
		default:
		}
	}
}

func (s *ceremonyCodeSink) wait(t *testing.T) string {
	t.Helper()
	select {
	case code := <-s.ch:
		return code
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the ceremony code")
		return ""
	}
}

func setupCeremonyRP(t *testing.T, env *attachTestEnv, pki *vhltest.PKI) {
	t.Helper()
	env.asSender()
	rootFile := pki.WriteRootFile(t)
	if err := env.sender.VHLSetRP(ceremonyTestRPID, []string{ceremonyTestOrigin}, []string{rootFile}); err != nil {
		t.Fatalf("set RP: %v", err)
	}
}

// TestVHLCeremonyEnrollEndToEnd runs the full enrollment ceremony:
// agent creates it, the browser completes a genuine packed
// attestation with the test authenticator, the agent verifies the
// attestation itself and enrolls + publishes the credential.
func TestVHLCeremonyEnrollEndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()
	pki := vhltest.NewPKI(t)
	setupCeremonyRP(t, env, pki)
	browser := newCeremonyBrowser(t, env, env.senderCfg.Address)

	sink := newCeremonyCodeSink()
	type enrollOut struct {
		cred *vhl.Credential
		err  error
	}
	done := make(chan enrollOut, 1)
	go func() {
		cred, err := env.sender.VHLEnrollWebAuthn("test-yubikey", sink.printf)
		done <- enrollOut{cred, err}
	}()

	code := sink.wait(t)
	challenge := browser.ceremonyChallenge(code)
	enr := pki.Enroll(t, ceremonyTestRPID, ceremonyTestOrigin, challenge)
	browser.submitAttestation(code, enr.OuterB64)

	var out enrollOut
	select {
	case out = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("enrollment did not finish")
	}
	if out.err != nil {
		t.Fatalf("enroll: %v", out.err)
	}
	wantCredID := base64.RawURLEncoding.EncodeToString(enr.CredID)
	if out.cred.ID != wantCredID {
		t.Fatalf("credential id = %q, want %q", out.cred.ID, wantCredID)
	}

	// The signed enrollment is published for discovery.
	entry, err := env.sender.VHLLookupEnrollment(env.senderCfg.Address)
	if err != nil {
		t.Fatalf("lookup enrollment: %v", err)
	}
	if fmt.Sprint(entry["credential_id"]) != wantCredID {
		t.Fatalf("published credential_id = %v, want %s", entry["credential_id"], wantCredID)
	}
}

// TestVHLCeremonyMintEndToEnd runs the full mint ceremony: the agent
// begins a mint, creates the relay ceremony bound to the mint
// challenge, the browser approves it with a genuine UV assertion,
// and the agent finishes the mint against the verified assertion.
func TestVHLCeremonyMintEndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()
	pki := vhltest.NewPKI(t)
	setupCeremonyRP(t, env, pki)
	browser := newCeremonyBrowser(t, env, env.senderCfg.Address)

	// Enroll the synthetic authenticator's credential directly (the
	// enrollment ceremony path is covered by the test above).
	enrChal := vhltest.FreshChallenge(t)
	enr := pki.Enroll(t, ceremonyTestRPID, ceremonyTestOrigin, enrChal)
	credID := base64.RawURLEncoding.EncodeToString(enr.CredID)
	cred := vhl.Credential{
		ID:         credID,
		Kind:       "webauthn",
		PublicKey:  base64.RawURLEncoding.EncodeToString(vhltest.COSEKeyP256(&enr.CredKey.PublicKey)),
		EnrolledAt: time.Now().Unix(),
		Device:     "test-yubikey",
	}
	if err := updateVHL(func(ff *vhlFile) error {
		// VHLSetRP already stored the RP id, origins, and
		// attestation roots; only add the credential.
		return ff.Registry.Enroll(env.senderCfg.Address, "sender", cred, true)
	}); err != nil {
		t.Fatalf("enroll mint credential: %v", err)
	}

	sink := newCeremonyCodeSink()
	type mintOut struct {
		tok *vhl.SessionToken
		err error
	}
	done := make(chan mintOut, 1)
	go func() {
		tok, err := env.sender.VHLSessionMintCeremony("test-scope", time.Hour, sink.printf)
		done <- mintOut{tok, err}
	}()

	// The mint may fail before it ever prints a code (e.g. no
	// credential enrolled); surface that error instead of hanging
	// in the code wait.
	var code string
	select {
	case code = <-sink.ch:
	case out := <-done:
		t.Fatalf("mint failed before ceremony: %v", out.err)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the ceremony code")
	}
	challenge := browser.ceremonyChallenge(code)
	assertion := pki.Assert(t, enr.CredKey, enr.CredID, ceremonyTestRPID, ceremonyTestOrigin, challenge)
	browser.submitAttestation(code, assertion)

	var out mintOut
	select {
	case out = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("mint did not finish")
	}
	if out.err != nil {
		t.Fatalf("mint: %v", out.err)
	}
	if out.tok == nil {
		t.Fatal("mint returned no token")
	}
	if out.tok.Scope != "test-scope" {
		t.Fatalf("token scope = %q, want test-scope", out.tok.Scope)
	}
}

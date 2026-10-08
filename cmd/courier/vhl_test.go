package main

import (
	"os"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

func TestSanitizeForTerminal(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text untouched",
			input: "send 1.5 BTC to lane",
			want:  "send 1.5 BTC to lane",
		},
		{
			name:  "ansi escape rendered as visible escape",
			input: "approve\x1b[2K this",
			want:  `approve\x1b[2K this`,
		},
		{
			name:  "title-change sequence neutralized",
			input: "ok\x1b]0;pwned\adone",
			want:  `ok\x1b]0;pwned\adone`,
		},
		{
			name:  "newlines and tabs preserved for readability",
			input: "line1\n\tline2",
			want:  "line1\n\tline2",
		},
		{
			name:  "printable unicode passes through",
			input: "paÿment ✓ 完成",
			want:  "paÿment ✓ 完成",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeForTerminal(tc.input); got != tc.want {
				t.Errorf("sanitizeForTerminal(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestConfirmTypingRefusesPipedStdin(t *testing.T) {
	// stdin is a regular file here, not a terminal: the ceremony
	// must fail closed without consuming the "canned" response.
	f, err := os.CreateTemp("", "courier-vhl-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("MINT\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	if confirmTyping("mint VHL session token (type MINT to confirm)", "MINT") {
		t.Error("confirmTyping succeeded with non-terminal stdin; want refusal")
	}
}

// fakeVHLClient is a hermetic stand-in for *client.Client: it records
// which client methods the CLI dispatch invoked, so the tests below
// assert routing — which handler ran for a given argv — without a
// live relay, local config, or handler business logic.
type fakeVHLClient struct {
	calls []string
}

func (f *fakeVHLClient) VHLEnrollApproverCeremony(address string, printf func(string, ...any)) (*vhl.EnrollmentArtifact, error) {
	f.calls = append(f.calls, "VHLEnrollApproverCeremony:"+address)
	return &vhl.EnrollmentArtifact{}, nil
}

func (f *fakeVHLClient) VHLEnrollApprover(address, name string, art *vhl.EnrollmentArtifact) error {
	f.calls = append(f.calls, "VHLEnrollApprover:"+address+"/"+name)
	return nil
}

func (f *fakeVHLClient) VHLApprovers() ([]client.ApproverInfo, error) {
	f.calls = append(f.calls, "VHLApprovers")
	return nil, nil
}

func (f *fakeVHLClient) VHLUnenrollApprover(addrOrName string) error {
	f.calls = append(f.calls, "VHLUnenrollApprover:"+addrOrName)
	return nil
}

func (f *fakeVHLClient) VHLRequestApproval(humanAddr string, tier vhl.Tier, body string, presence vhl.PresenceStrength) (*vhl.ApprovalRequest, error) {
	f.calls = append(f.calls, "VHLRequestApproval")
	return &vhl.ApprovalRequest{ID: "req-test"}, nil
}

func (f *fakeVHLClient) VHLPendingRequests() ([]*client.VHLRequestRecord, error) {
	f.calls = append(f.calls, "VHLPendingRequests")
	return nil, nil
}

func (f *fakeVHLClient) VHLMintChallenge(action []byte) (*vhl.Challenge, string, error) {
	f.calls = append(f.calls, "VHLMintChallenge:"+string(action))
	return &vhl.Challenge{ID: "ch-test"}, "code-test", nil
}

// routedTo reports whether the fake saw a call whose name matches
// want, where want may carry a ":arg" suffix to pin the argument the
// handler passed through.
func (f *fakeVHLClient) routedTo(want string) bool {
	for _, c := range f.calls {
		if c == want || strings.HasPrefix(c, want+":") {
			return true
		}
	}
	return false
}

func TestVHLApproverDispatch(t *testing.T) {
	// The remove route requires typed human confirmation, which
	// fails closed without a terminal: stub the gate so the test
	// can observe the unenroll call the route leads to.
	oldConfirm := confirmTyping
	confirmTyping = func(prompt, expect string) bool { return true }
	defer func() { confirmTyping = oldConfirm }()

	cases := []struct {
		name     string
		args     []string
		wantCall string // expected client call ("name" or "name:arg"); "" = no client call
		wantErr  string // expected error substring; "" = no error
	}{
		{name: "add routes to ceremony enrollment", args: []string{"add", "ed25519:testaddr"}, wantCall: "VHLEnrollApproverCeremony:ed25519:testaddr"},
		{name: "add passes name through", args: []string{"add", "ed25519:testaddr", "--name", "lane"}, wantCall: "VHLEnrollApprover:ed25519:testaddr/lane"},
		{name: "list routes to approver listing", args: []string{"list"}, wantCall: "VHLApprovers"},
		{name: "remove routes to unenroll", args: []string{"remove", "ed25519:testaddr"}, wantCall: "VHLUnenrollApprover:ed25519:testaddr"},
		{name: "empty subcommand is usage error", args: []string{}, wantErr: "usage: courier vhl approver"},
		{name: "unknown subcommand is usage error", args: []string{"unenroll"}, wantErr: "usage: courier vhl approver"},
		{name: "old enroll name is gone", args: []string{"enroll"}, wantErr: "usage: courier vhl approver"},
		{name: "remove without target is usage error", args: []string{"remove"}, wantErr: "usage: courier vhl approver remove"},
		{name: "add without address is usage error", args: []string{"add"}, wantErr: "usage: courier vhl approver add"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVHLClient{}
			err := cmdVHLApprover(f, tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("cmdVHLApprover(%q) err = %v, want substring %q", tc.args, err, tc.wantErr)
				}
				if len(f.calls) != 0 {
					t.Fatalf("cmdVHLApprover(%q) made client calls %v on the error path", tc.args, f.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("cmdVHLApprover(%q) err = %v", tc.args, err)
			}
			if !f.routedTo(tc.wantCall) {
				t.Fatalf("cmdVHLApprover(%q) calls = %v, want call %q", tc.args, f.calls, tc.wantCall)
			}
		})
	}
}

func TestVHLRequestDispatch(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCall string
		wantErr  string
	}{
		{name: "new routes to request filing", args: []string{"new", "--tier", "2", "--message", "do the thing"}, wantCall: "VHLRequestApproval"},
		{name: "new accepts equals flags", args: []string{"new", "--tier=2", "--message=do the thing", "--to=ed25519:x"}, wantCall: "VHLRequestApproval"},
		{name: "list routes to pending queue", args: []string{"list"}, wantCall: "VHLPendingRequests"},
		{name: "empty subcommand is usage error", args: []string{}, wantErr: "usage: courier vhl request"},
		{name: "unknown subcommand is usage error", args: []string{"approve"}, wantErr: "usage: courier vhl request"},
		{name: "new without tier is rejected in handler", args: []string{"new", "--message", "x"}, wantErr: "--tier must be 2"},
		{name: "new tier 1 is redirected to session mint", args: []string{"new", "--tier", "1", "--message", "x"}, wantErr: "courier vhl session mint"},
		{name: "new without message is rejected in handler", args: []string{"new", "--tier", "2"}, wantErr: "--message is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVHLClient{}
			err := cmdVHLRequest(f, tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("cmdVHLRequest(%q) err = %v, want substring %q", tc.args, err, tc.wantErr)
				}
				if len(f.calls) != 0 {
					t.Fatalf("cmdVHLRequest(%q) made client calls %v on the error path", tc.args, f.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("cmdVHLRequest(%q) err = %v", tc.args, err)
			}
			if !f.routedTo(tc.wantCall) {
				t.Fatalf("cmdVHLRequest(%q) calls = %v, want call %q", tc.args, f.calls, tc.wantCall)
			}
		})
	}
}

func TestVHLChallengeDispatch(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCall string
		wantErr  string
	}{
		{name: "flag form routes to challenge mint", args: []string{"--action", "rotate keys"}, wantCall: "VHLMintChallenge:rotate keys"},
		{name: "equals form routes to challenge mint", args: []string{"--action=rotate keys"}, wantCall: "VHLMintChallenge:rotate keys"},
		{name: "missing action is usage error", args: []string{}, wantErr: "--action is required"},
		{name: "positional arg is usage error", args: []string{"rotate"}, wantErr: "usage: courier vhl challenge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVHLClient{}
			err := cmdVHLChallenge(f, tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("cmdVHLChallenge(%q) err = %v, want substring %q", tc.args, err, tc.wantErr)
				}
				if len(f.calls) != 0 {
					t.Fatalf("cmdVHLChallenge(%q) made client calls %v on the error path", tc.args, f.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("cmdVHLChallenge(%q) err = %v", tc.args, err)
			}
			if !f.routedTo(tc.wantCall) {
				t.Fatalf("cmdVHLChallenge(%q) calls = %v, want call %q", tc.args, f.calls, tc.wantCall)
			}
		})
	}
}

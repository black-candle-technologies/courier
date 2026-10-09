package transport

import "testing"

func TestResolve(t *testing.T) {
	for _, tt := range []struct {
		mode, endpoint, want string
		bad                  bool
	}{
		{"", "https://example.invalid", DirectTLS, false},
		{"", "http://localhost:1234", "legacy-non-https", false},
		{DirectTLS, "https://example.invalid", DirectTLS, false},
		{DirectTLS, "http://localhost", "", true},
		{DirectTLS, "https://user:secret@example.invalid", "", true},
		{DirectTLS, "https://example.invalid?token=secret", "", true},
		{"cloud", "https://example.invalid", "", true},
		{"typo", "https://example.invalid", "", true},
	} {
		got, err := Resolve(tt.mode, tt.endpoint)
		if got != tt.want || (err != nil) != tt.bad {
			t.Errorf("%+v: %q %v", tt, got, err)
		}
	}
	if got := EndpointLabel("https://user:secret@example.invalid/private?token=secret#secret"); got != "https://example.invalid" {
		t.Fatal(got)
	}
}

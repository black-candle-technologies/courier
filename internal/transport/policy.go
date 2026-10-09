// Package transport defines local transport policy. It implements no wire protocol.
package transport

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const DirectTLS = "direct-tls"

// Resolve preserves the original URL-based behavior only for omitted policy.
// Cloud is deliberately unavailable: selecting it must fail before any I/O.
func Resolve(mode, endpoint string) (string, error) {
	switch mode {
	case "":
		if strings.HasPrefix(endpoint, "https://") {
			return DirectTLS, nil
		}
		return "legacy-non-https", nil
	case DirectTLS:
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("direct-tls requires an HTTPS endpoint without credentials, query or fragment")
		}
		return DirectTLS, nil
	case "cloud":
		return "", fmt.Errorf("cloud transport unavailable: supported platform requirements and independent security review are required; no fallback")
	default:
		return "", fmt.Errorf("unsupported transport mode; only direct-tls is available")
	}
}

// EndpointLabel intentionally omits credentials, path, query and fragment.
func EndpointLabel(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "(invalid endpoint)"
	}
	return u.Scheme + "://" + u.Host
}

// NoRedirect prevents origin changes and HTTPS-to-HTTP downgrade. The existing
// pinned TLS handshake is otherwise unchanged.
func NoRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("transport redirects are not supported; configure and verify the intended endpoint explicitly")
}

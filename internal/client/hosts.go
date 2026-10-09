package client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

var ErrContextsDisabled = errors.New("named Courier contexts are disabled")
var ErrContextMismatch = errors.New("courier context security binding mismatch")

// RelayBinding is public routing metadata, not credentials. ID is a stable local
// identifier, independent of the host alias. Endpoint and Pin must be explicitly
// provisioned; resolving a context never fetches or trusts a new certificate.
type RelayBinding struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Pin      string `json:"pin"`
}

type NamedIdentity struct {
	Principal string `json:"principal"`
	BindingID string `json:"binding_id"`
}

type Host struct {
	BindingID string `json:"binding_id"`
	Identity  string `json:"identity"`
}

// Hosts contains aliases only. Secret keys remain in the selected store. V1
// rejects one principal assigned to different bindings, even through aliases.
// Enabled is an explicit opt-in; its zero value disables named contexts.
type Hosts struct {
	Enabled    bool                     `json:"enabled"`
	Bindings   map[string]RelayBinding  `json:"bindings"`
	Identities map[string]NamedIdentity `json:"identities"`
	Hosts      map[string]Host          `json:"hosts"`
}

// NormalizeRelayOrigin accepts HTTPS origins only, with no credentials, path,
// query or fragment. LegacyContext retains existing single-host compatibility.
func NormalizeRelayOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("relay must be an HTTPS origin")
	}
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, "%\\") {
		return "", fmt.Errorf("invalid relay host")
	}
	port := u.Port()
	if port == "443" {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return "https://" + host, nil
}

// Resolve captures one binding/principal. No files or network are accessed.
// There is deliberately no implicit host/identity fallback.
func (h Hosts) Resolve(root, hostAlias, identityAlias string) (Context, error) {
	if !h.Enabled {
		return Context{}, ErrContextsDisabled
	}
	if !filepath.IsAbs(root) {
		return Context{}, fmt.Errorf("context root must be absolute")
	}
	bindings := make(map[string]RelayBinding, len(h.Bindings))
	for id, b := range h.Bindings {
		if id == "" || b.ID != id {
			return Context{}, fmt.Errorf("invalid binding ID")
		}
		origin, err := NormalizeRelayOrigin(b.Endpoint)
		if err != nil {
			return Context{}, err
		}
		pin, err := hex.DecodeString(b.Pin)
		if err != nil || len(pin) != sha256.Size {
			return Context{}, fmt.Errorf("binding %q requires an approved SHA256 pin", id)
		}
		b.Endpoint, b.Pin = origin, strings.ToLower(b.Pin)
		bindings[id] = b
	}
	principalBindings := map[string]string{}
	for alias, id := range h.Identities {
		if alias == "" {
			return Context{}, fmt.Errorf("empty identity alias")
		}
		if _, err := crypto.ParseAddress(id.Principal); err != nil {
			return Context{}, err
		}
		if _, ok := bindings[id.BindingID]; !ok {
			return Context{}, fmt.Errorf("unknown identity binding")
		}
		if previous, ok := principalBindings[id.Principal]; ok && previous != id.BindingID {
			return Context{}, fmt.Errorf("principal reuse across relay bindings is not supported in v1")
		}
		principalBindings[id.Principal] = id.BindingID
	}
	host, ok := h.Hosts[hostAlias]
	if !ok {
		return Context{}, fmt.Errorf("unknown host %q", hostAlias)
	}
	if identityAlias == "" {
		identityAlias = host.Identity
	}
	id, ok := h.Identities[identityAlias]
	if !ok || id.BindingID != host.BindingID {
		return Context{}, fmt.Errorf("missing identity or host/identity binding mismatch")
	}
	binding, ok := bindings[host.BindingID]
	if !ok {
		return Context{}, fmt.Errorf("unknown relay binding")
	}
	digest := sha256.Sum256([]byte("courier.context.v1\x00" + binding.ID + "\x00" + id.Principal))
	return Context{root: filepath.Join(root, "contexts", hex.EncodeToString(digest[:])), principal: id.Principal, binding: binding}, nil
}

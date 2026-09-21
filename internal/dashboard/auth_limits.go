package dashboard

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/black-candle-technologies/courier/internal/store"
)

// Layered rate limiting for the dashboard auth surface (issue #108).
//
// Three layers protect the credential endpoints:
//  1. Per-IP fixed-window budgets on each endpoint (login, register,
//     OAuth) — blunts credential stuffing and registration spam from a
//     single source.
//  2. Per-account exponential backoff on failed password logins,
//     persisted in the database (failed_logins / lock_until on
//     dashboard_users) so a restart does not reset the lockout.
//  3. A global fixed-window budget across all IPs — bounds total
//     bcrypt CPU the auth surface can consume.
//
// OAuth and local-auth budgets are kept SEPARATE: a flood against
// POST /login must never starve the Black Candle OAuth flow, and vice
// versa. All responses stay generic: a locked-out account renders the
// same "Invalid username or password." page as a wrong password, so
// the lockout itself cannot be used to enumerate accounts.

// AuthLimits configures the layered rate limits. Zero values select the
// defaults from DefaultAuthLimits; AuthLimitsFromEnv parses overrides
// from the environment.
type AuthLimits struct {
	// LoginAttemptsPerIP caps password-login attempts from one IP per
	// LoginIPWindow.
	LoginAttemptsPerIP int
	LoginIPWindow      time.Duration
	// LoginAttemptsGlobal caps password-login attempts from all IPs per
	// LoginGlobalWindow.
	LoginAttemptsGlobal int
	LoginGlobalWindow   time.Duration
	// LoginBackoffBase / LoginBackoffMax bound the per-account
	// exponential backoff: after n consecutive failures the account
	// locks for min(Base * 2^(n-1), Max).
	LoginBackoffBase time.Duration
	LoginBackoffMax  time.Duration
	// RegisterAttemptsPerIP caps dashboard registrations from one IP
	// per RegisterIPWindow.
	RegisterAttemptsPerIP int
	RegisterIPWindow      time.Duration
	// OAuthAttemptsPerIP / OAuthAttemptsGlobal cap OAuth flow starts
	// and callbacks. Separate from the local-auth budgets.
	OAuthAttemptsPerIP  int
	OAuthIPWindow       time.Duration
	OAuthAttemptsGlobal int
	OAuthGlobalWindow   time.Duration
	// TrustedProxies is a comma-separated list of IPs/CIDRs allowed to
	// set X-Forwarded-For (DASHBOARD_TRUSTED_PROXIES). Loopback peers
	// are always trusted; leave empty when the dashboard is not behind
	// a proxy on another host.
	TrustedProxies string
}

// DefaultAuthLimits returns the sane defaults. The per-IP login budget
// (20/10min) is generous for humans behind NAT but cheap to burn for an
// attacker; the global budget (200/10min) bounds total bcrypt work; the
// backoff (2s doubling to 15m) makes per-account guessing useless while
// a typo-prone human barely notices.
func DefaultAuthLimits() AuthLimits {
	return AuthLimits{
		LoginAttemptsPerIP:    20,
		LoginIPWindow:         10 * time.Minute,
		LoginAttemptsGlobal:   200,
		LoginGlobalWindow:     10 * time.Minute,
		LoginBackoffBase:      2 * time.Second,
		LoginBackoffMax:       15 * time.Minute,
		RegisterAttemptsPerIP: 10,
		RegisterIPWindow:      time.Hour,
		OAuthAttemptsPerIP:    60,
		OAuthIPWindow:         10 * time.Minute,
		OAuthAttemptsGlobal:   600,
		OAuthGlobalWindow:     10 * time.Minute,
	}
}

// withDefaults fills any zero field with the corresponding default.
func (l AuthLimits) withDefaults() AuthLimits {
	d := DefaultAuthLimits()
	if l.LoginAttemptsPerIP <= 0 {
		l.LoginAttemptsPerIP = d.LoginAttemptsPerIP
	}
	if l.LoginIPWindow <= 0 {
		l.LoginIPWindow = d.LoginIPWindow
	}
	if l.LoginAttemptsGlobal <= 0 {
		l.LoginAttemptsGlobal = d.LoginAttemptsGlobal
	}
	if l.LoginGlobalWindow <= 0 {
		l.LoginGlobalWindow = d.LoginGlobalWindow
	}
	if l.LoginBackoffBase <= 0 {
		l.LoginBackoffBase = d.LoginBackoffBase
	}
	if l.LoginBackoffMax <= 0 {
		l.LoginBackoffMax = d.LoginBackoffMax
	}
	if l.RegisterAttemptsPerIP <= 0 {
		l.RegisterAttemptsPerIP = d.RegisterAttemptsPerIP
	}
	if l.RegisterIPWindow <= 0 {
		l.RegisterIPWindow = d.RegisterIPWindow
	}
	if l.OAuthAttemptsPerIP <= 0 {
		l.OAuthAttemptsPerIP = d.OAuthAttemptsPerIP
	}
	if l.OAuthIPWindow <= 0 {
		l.OAuthIPWindow = d.OAuthIPWindow
	}
	if l.OAuthAttemptsGlobal <= 0 {
		l.OAuthAttemptsGlobal = d.OAuthAttemptsGlobal
	}
	if l.OAuthGlobalWindow <= 0 {
		l.OAuthGlobalWindow = d.OAuthGlobalWindow
	}
	return l
}

// AuthLimitsFromEnv reads limit overrides from the environment; unset or
// unparsable values keep the defaults. Durations are seconds.
func AuthLimitsFromEnv() AuthLimits {
	l := DefaultAuthLimits()
	if v := envInt("DASHBOARD_LOGIN_PER_IP"); v > 0 {
		l.LoginAttemptsPerIP = v
	}
	if v := envSecs("DASHBOARD_LOGIN_IP_WINDOW_SECS"); v > 0 {
		l.LoginIPWindow = v
	}
	if v := envInt("DASHBOARD_LOGIN_GLOBAL"); v > 0 {
		l.LoginAttemptsGlobal = v
	}
	if v := envSecs("DASHBOARD_LOGIN_GLOBAL_WINDOW_SECS"); v > 0 {
		l.LoginGlobalWindow = v
	}
	if v := envSecs("DASHBOARD_LOGIN_BACKOFF_BASE_SECS"); v > 0 {
		l.LoginBackoffBase = v
	}
	if v := envSecs("DASHBOARD_LOGIN_BACKOFF_MAX_SECS"); v > 0 {
		l.LoginBackoffMax = v
	}
	if v := envInt("DASHBOARD_REGISTER_PER_IP"); v > 0 {
		l.RegisterAttemptsPerIP = v
	}
	if v := envSecs("DASHBOARD_REGISTER_IP_WINDOW_SECS"); v > 0 {
		l.RegisterIPWindow = v
	}
	if v := envInt("DASHBOARD_OAUTH_PER_IP"); v > 0 {
		l.OAuthAttemptsPerIP = v
	}
	if v := envSecs("DASHBOARD_OAUTH_IP_WINDOW_SECS"); v > 0 {
		l.OAuthIPWindow = v
	}
	if v := envInt("DASHBOARD_OAUTH_GLOBAL"); v > 0 {
		l.OAuthAttemptsGlobal = v
	}
	if v := envSecs("DASHBOARD_OAUTH_GLOBAL_WINDOW_SECS"); v > 0 {
		l.OAuthGlobalWindow = v
	}
	l.TrustedProxies = strings.TrimSpace(os.Getenv("DASHBOARD_TRUSTED_PROXIES"))
	return l
}

func envInt(name string) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return 0
	}
	return v
}

func envSecs(name string) time.Duration {
	secs := envInt(name)
	if secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// loginBackoff returns the account lockout after n consecutive failed
// logins: Base * 2^(n-1), capped at Max. Delegates to the store package,
// where the failed_logins / lock_until columns live; unit-tested here.
func loginBackoff(n int, base, max time.Duration) time.Duration {
	return store.LoginBackoff(n, base, max)
}

// clientIP returns the request's client address. X-Forwarded-For is
// only honored when the direct peer is trusted (loopback, or a proxy
// listed in DASHBOARD_TRUSTED_PROXIES): the header is trivially
// spoofable otherwise, and blindly trusting it would let an attacker
// evade per-IP rate limits and poison IP-keyed logs. The dashboard is
// normally fronted by Caddy on the same host, so loopback peers are
// trusted by default.
func (s *Server) clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && s.trustProxy(r) {
		if i := strings.Index(xff, ","); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// trustProxy reports whether the direct TCP peer may set
// X-Forwarded-For on the dashboard's behalf.
func (s *Server) trustProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parses a comma-separated list of IPs and CIDRs
// (DASHBOARD_TRUSTED_PROXIES); unparsable entries are ignored.
func parseTrustedProxies(list string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if _, n, err := net.ParseCIDR(part); err == nil {
				out = append(out, n)
			}
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return out
}

// windowCounter is one fixed-window counter.
type windowCounter struct {
	start time.Time
	count int
}

// fixedWindowLimiter is an in-memory fixed-window rate limiter: each
// bucket counts events in the current window and resets when the window
// rolls. Buckets are keyed by an arbitrary string ("layer:key"). Not
// persistent by design: per-IP and global budgets are transient abuse
// signals, while the per-account backoff (which must survive restarts)
// lives in the database.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	buckets map[string]*windowCounter
	now     func() time.Time // injectable clock for tests
}

func newFixedWindowLimiter() *fixedWindowLimiter {
	return &fixedWindowLimiter{buckets: make(map[string]*windowCounter), now: time.Now}
}

// allow records one event in bucket key and reports whether it is
// within limit per window. The first event in a fresh window always
// passes.
func (l *fixedWindowLimiter) allow(key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok || now.Sub(b.start) >= window {
		l.buckets[key] = &windowCounter{start: now, count: 1}
		l.purgeLocked(now)
		return true
	}
	b.count++
	return b.count <= limit
}

// purgeLocked drops expired buckets. Called on window rollover only,
// and only when the map has grown large, to bound memory without
// scanning on every request.
func (l *fixedWindowLimiter) purgeLocked(now time.Time) {
	if len(l.buckets) <= 4096 {
		return
	}
	for k, b := range l.buckets {
		// Buckets are created with different windows; a bucket idle
		// for over an hour is dead regardless of its window.
		if now.Sub(b.start) > time.Hour {
			delete(l.buckets, k)
		}
	}
}

// reset clears all buckets. Tests only.
func (l *fixedWindowLimiter) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*windowCounter)
}

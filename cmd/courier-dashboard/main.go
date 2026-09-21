// Command courier-dashboard is the Courier web dashboard (v0.6.0): a
// human-facing web app where a user logs in and reads the decrypted
// messages their agent's Courier identity received.
//
// The dashboard never holds Courier private keys. The agent decrypts its
// own inbox and pushes plaintext here with `courier dashboard push` over a
// per-user API token.
//
// Usage:
//
//	courier-dashboard [--addr :8471] [--db courier-relay.db]
//	                   [--tls-cert tls.crt] [--tls-key tls.key]
//
// TLS uses the same self-signed certificate as the relay (generated on
// first run next to the database if missing).
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/black-candle-technologies/courier/internal/dashboard"
	"github.com/black-candle-technologies/courier/internal/store"
	"github.com/black-candle-technologies/courier/internal/tlscert"
)

func main() {
	addr := flag.String("addr", ":8471", "listen address")
	dbPath := flag.String("db", "courier-relay.db", "sqlite database path (shared with the relay)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (default: <dbdir>/tls.crt)")
	tlsKey := flag.String("tls-key", "", "TLS key file (default: <dbdir>/tls.key)")
	// Optional Black Candle login via OAuth 2.0. The feature is dormant
	// unless URL, client ID, and secret are ALL set — self-hosted
	// installs leave them empty and never see the OAuth UI or routes.
	// Same binary, same release. The dashboard never collects Black
	// Candle passwords: users authenticate on the provider's own site.
	bctOAuthURL := flag.String("bct-oauth-url", os.Getenv("BCT_OAUTH_URL"),
		"Black Candle OAuth provider base URL (enables optional OAuth login; empty disables)")
	bctOAuthClientID := flag.String("bct-oauth-client-id", os.Getenv("BCT_OAUTH_CLIENT_ID"),
		"OAuth client_id registered with the Black Candle provider")
	bctOAuthClientSecret := flag.String("bct-oauth-client-secret", os.Getenv("BCT_OAUTH_CLIENT_SECRET"),
		"OAuth client_secret for the Black Candle provider")
	bctOAuthRedirectURI := flag.String("bct-oauth-redirect-uri", os.Getenv("BCT_OAUTH_REDIRECT_URI"),
		"Exact OAuth redirect URI registered with the provider (default: derived from each request)")
	flag.Parse()

	bctOAuthSet := *bctOAuthURL != "" || *bctOAuthClientID != "" || *bctOAuthClientSecret != ""
	if bctOAuthSet && (*bctOAuthURL == "" || *bctOAuthClientID == "" || *bctOAuthClientSecret == "") {
		log.Fatalf("BCT OAuth is partially configured: bct-oauth-url, bct-oauth-client-id, and bct-oauth-client-secret must all be set")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer st.Close()

	dbDir := filepath.Dir(*dbPath)
	if *tlsCert == "" {
		*tlsCert = filepath.Join(dbDir, "tls.crt")
	}
	if *tlsKey == "" {
		*tlsKey = filepath.Join(dbDir, "tls.key")
	}
	if _, err := tlscert.Ensure(*tlsCert, *tlsKey); err != nil {
		log.Fatalf("tls: %v", err)
	}

	srv := &http.Server{
		Addr: *addr,
		Handler: loggingMiddleware(dashboard.NewWithBCT(st, dashboard.BCTOAuthConfig{
			URL:          *bctOAuthURL,
			ClientID:     *bctOAuthClientID,
			ClientSecret: *bctOAuthClientSecret,
			RedirectURI:  *bctOAuthRedirectURI,
		}).Routes()),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if bctOAuthSet {
		log.Printf("Black Candle OAuth login enabled (provider %s)", *bctOAuthURL)
	}

	go func() {
		log.Printf("courier-dashboard listening with TLS on %s (db %s)", *addr, *dbPath)
		if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Print("shutting down")
	_ = srv.Close()
	fmt.Println("bye")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

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
	// Optional Black Candle account linking. The feature is dormant
	// unless BOTH are set — self-hosted installs leave them empty and
	// never see the linking UI or routes. Same binary, same release.
	bctURL := flag.String("bct-auth-url", os.Getenv("BCT_AUTH_URL"),
		"Black Candle auth service URL (enables optional account linking; empty disables)")
	bctKey := flag.String("bct-auth-key", os.Getenv("BCT_AUTH_API_KEY"),
		"API key for the Black Candle auth service (X-Api-Key)")
	flag.Parse()

	if *bctURL != "" && *bctKey == "" {
		log.Fatalf("bct-auth-url is set but bct-auth-key is empty")
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
		Addr:         *addr,
		Handler:      loggingMiddleware(dashboard.NewWithBCT(st, dashboard.BCTConfig{URL: *bctURL, APIKey: *bctKey}).Routes()),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if *bctURL != "" {
		log.Printf("Black Candle account linking enabled (auth %s)", *bctURL)
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

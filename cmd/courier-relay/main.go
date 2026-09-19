// Command courier-relay is the Courier central relay: a store-and-forward
// mailbox for encrypted agent envelopes. It never sees plaintext.
//
// Usage:
//
//	courier-relay [--addr :8470] [--db courier-relay.db] [--retain-days 30]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

func main() {
	addr := flag.String("addr", ":8470", "listen address")
	dbPath := flag.String("db", "courier-relay.db", "sqlite database path")
	retainDays := flag.Int("retain-days", 30, "delete envelopes older than this many days")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer st.Close()

	srv := &http.Server{
		Addr:         *addr,
		Handler:      loggingMiddleware(relay.New(st).Routes()),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Daily retention pruning.
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := st.Prune(*retainDays); err != nil {
				log.Printf("prune: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d envelopes older than %d days", n, *retainDays)
			}
		}
	}()
	if n, err := st.Prune(*retainDays); err == nil && n > 0 {
		log.Printf("pruned %d old envelopes on startup", n)
	}

	go func() {
		log.Printf("courier-relay listening on %s (db %s)", *addr, *dbPath)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

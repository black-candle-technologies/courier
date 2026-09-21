// Command courier-relay is the Courier central relay: a store-and-forward
// mailbox for encrypted agent envelopes. It never sees plaintext.
//
// The relay serves HTTPS only (v0.3.0+). It uses a self-signed certificate
// (generated on first run next to the database); clients pin its SHA256
// fingerprint. The fingerprint is printed at startup so it can be published.
//
// Usage:
//
//	courier-relay [--addr :8470] [--db courier-relay.db] [--retain-days 30]
//	               [--tls-cert tls.crt] [--tls-key tls.key]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
	"github.com/black-candle-technologies/courier/internal/tlscert"
)

func main() {
	addr := flag.String("addr", ":8470", "listen address")
	dbPath := flag.String("db", "courier-relay.db", "sqlite database path")
	retainDays := flag.Int("retain-days", 30, "delete envelopes older than this many days")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (default: <dbdir>/tls.crt, generated if missing)")
	tlsKey := flag.String("tls-key", "", "TLS key file (default: <dbdir>/tls.key, generated if missing)")
	// Metadata-only abuse controls (see PROTOCOL.md). All limits are
	// deliberately generous: legitimate bursty agent traffic must not
	// notice them; rejections are explicit 429s, never silent drops.
	sendBurst := flag.Float64("send-burst", 100, "per-sender token-bucket burst: max sends in a burst")
	sendRate := flag.Float64("send-rate", 2, "per-sender sustained send rate, sends per second")
	spamThreshold := flag.Int("spam-threshold", 3, "distinct reporters within the spam window that throttle a sender")
	spamWindowHours := flag.Float64("spam-window-hours", 168, "sliding window (hours) over which spam reports count; older reports decay")
	// Contact-discovery directory controls (issue #39).
	reservedHandles := flag.String("reserved-handles", "", "comma-separated operator-reserved handles (e.g. \"courier,admin,support\"): never registrable")
	dirWriteBurst := flag.Float64("dir-write-burst", 10, "per-identity directory write burst (register/update/transfer/deregister)")
	dirLookupBurst := flag.Float64("dir-lookup-burst", 60, "per-identity directory lookup burst")
	dirSearchBurst := flag.Float64("dir-search-burst", 10, "per-identity directory search burst")
	// Issue #100: blob bytes are far more expensive than message bytes,
	// so uploads get their own byte-priced bucket plus a durable
	// per-uploader storage quota. The burst must exceed the ~25 MiB max
	// blob size or every upload 429s.
	blobBurstBytes := flag.Int64("blob-burst-bytes", 256<<20, "per-uploader blob upload byte-bucket burst")
	blobRateBytes := flag.Float64("blob-rate-bytes", 2<<20, "per-uploader sustained blob upload rate, bytes per second")
	blobQuotaBytes := flag.Int64("blob-quota-bytes", 1<<30, "per-uploader total stored blob byte quota within the retention window")
	// Operator takedown admin mode: applies (or lifts) a transparent
	// tombstone and exits without serving. Takedowns are public by
	// construction — a reason is required — and must follow the
	// published takedown policy (see INSTALL.md). No HTTP admin
	// endpoint exists, so takedowns cannot be triggered remotely.
	takedown := flag.String("takedown", "", "tombstone a directory handle for abuse (admin mode: applies and exits)")
	takedownReason := flag.String("takedown-reason", "", "public reason for the takedown (required with -takedown)")
	untakedown := flag.String("untakedown", "", "lift a directory handle tombstone (admin mode: applies and exits)")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer st.Close()

	dirServer := relay.NewWithConfig(st, relay.Config{
		SendBurst:                 *sendBurst,
		SendRatePerSec:            *sendRate,
		SpamReportThreshold:       *spamThreshold,
		SpamReportWindow:          time.Duration(*spamWindowHours * float64(time.Hour)),
		DirWriteBurst:             *dirWriteBurst,
		DirLookupBurst:            *dirLookupBurst,
		DirSearchBurst:            *dirSearchBurst,
		BlobUploadBurstBytes:      float64(*blobBurstBytes),
		BlobUploadRateBytesPerSec: *blobRateBytes,
		BlobQuotaBytes:            *blobQuotaBytes,
		ReservedHandles:           splitCSV(*reservedHandles),
	})

	// Admin mode: takedown / untakedown, then exit.
	if *takedown != "" {
		if *takedownReason == "" {
			log.Fatal("-takedown-reason is required: takedowns are public")
		}
		ok, err := dirServer.TombstoneHandle(*takedown, *takedownReason)
		if err != nil {
			log.Fatalf("takedown: %v", err)
		}
		if !ok {
			log.Fatalf("takedown: handle %q is not listed", *takedown)
		}
		log.Printf("tombstoned handle %q: %s", *takedown, *takedownReason)
		return
	}
	if *untakedown != "" {
		ok, err := dirServer.UntombstoneHandle(*untakedown)
		if err != nil {
			log.Fatalf("untakedown: %v", err)
		}
		if !ok {
			log.Fatalf("untakedown: handle %q is not tombstoned", *untakedown)
		}
		log.Printf("lifted tombstone on handle %q", *untakedown)
		return
	}

	// TLS: self-signed cert, generated on first run.
	dbDir := filepath.Dir(*dbPath)
	if *tlsCert == "" {
		*tlsCert = filepath.Join(dbDir, "tls.crt")
	}
	if *tlsKey == "" {
		*tlsKey = filepath.Join(dbDir, "tls.key")
	}
	fp, err := tlscert.Ensure(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	log.Printf("relay certificate SHA256 fingerprint: %s", fp)
	log.Print("clients must pin this fingerprint (see INSTALL.md)")

	srv := &http.Server{
		Addr: *addr,
		Handler: loggingMiddleware(relay.NewWithConfig(st, relay.Config{
			SendBurst:                 *sendBurst,
			SendRatePerSec:            *sendRate,
			SpamReportThreshold:       *spamThreshold,
			SpamReportWindow:          time.Duration(*spamWindowHours * float64(time.Hour)),
			DirWriteBurst:             *dirWriteBurst,
			DirLookupBurst:            *dirLookupBurst,
			DirSearchBurst:            *dirSearchBurst,
			BlobUploadBurstBytes:      float64(*blobBurstBytes),
			BlobUploadRateBytesPerSec: *blobRateBytes,
			BlobQuotaBytes:            *blobQuotaBytes,
			ReservedHandles:           splitCSV(*reservedHandles),
		}).Routes()),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Daily retention pruning. Blobs follow the same retention policy as
	// envelopes, so attachment ciphertext expires with the messages that
	// reference it.
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := st.Prune(*retainDays); err != nil {
				log.Printf("prune: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d envelopes older than %d days", n, *retainDays)
			}
			if n, err := st.PruneBlobs(*retainDays); err != nil {
				log.Printf("prune blobs: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d blobs older than %d days", n, *retainDays)
			}
		}
	}()
	if n, err := st.Prune(*retainDays); err == nil && n > 0 {
		log.Printf("pruned %d old envelopes on startup", n)
	}
	if n, err := st.PruneBlobs(*retainDays); err == nil && n > 0 {
		log.Printf("pruned %d old blobs on startup", n)
	}

	go func() {
		log.Printf("courier-relay listening with TLS on %s (db %s)", *addr, *dbPath)
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

// splitCSV splits a comma-separated flag value, trimming spaces and
// dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

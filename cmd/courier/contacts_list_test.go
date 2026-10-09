package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

func TestContactsListVerifiedContactsNeverUseNetwork(t *testing.T) {
	setTestHome(t, t.TempDir())
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected directory request", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	cfg, err := client.NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Contacts = map[string]string{}
	cfg.ContactVerifications = map[string]client.ContactVerification{}
	cfg.VerifiedKeyEpochs = map[string]int64{}
	cfg.HandleCache = map[string]client.HandleCacheEntry{}
	for i := range 4 {
		peer, err := client.NewIdentity(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("peer%d", i)
		cfg.Contacts[name] = peer.Address
		if i != 3 {
			cfg.ContactVerifications[name] = client.ContactVerification{Address: peer.Address, KeyEpoch: 1, VerifiedAt: time.Now().Unix()}
		}
		cfg.HandleCache[peer.Address] = client.HandleCacheEntry{Handle: fmt.Sprintf("public%d", i), At: time.Now().Unix()}
		if i == 2 {
			cfg.VerifiedKeyEpochs[peer.Address] = 2
		}
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "contact-list")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	previous := os.Stdout
	os.Stdout = out
	defer func() { os.Stdout = previous }()
	listErr := cmdContacts([]string{"list"})
	os.Stdout = previous
	if listErr != nil {
		t.Fatal(listErr)
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("contact listing made %d HTTP requests", got)
	}
	output := string(data)
	if strings.Count(output, "verified (cached; keys not revalidated)") != 2 || !strings.Contains(output, "⚠ stale") || !strings.Contains(output, "• unverified") {
		t.Fatalf("dishonest or missing trust states: %s", output)
	}
	for i := range 4 {
		if !strings.Contains(output, fmt.Sprintf("peer%d (@public%d)", i, i)) {
			t.Fatalf("missing cached label: %s", output)
		}
	}
}

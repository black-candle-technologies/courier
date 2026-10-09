package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

func TestDirectoryReverseRejectsSignedNoncanonicalHandle(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	for _, handle := range []string{"Alice", " alice ", "a!ice"} {
		t.Run(handle, func(t *testing.T) {
			p := DirectoryProfile{Handle: handle, Address: addrOf(id), Epoch: 1, Visibility: "public", ContactPolicy: "open"}
			p.Sig = b64enc(id.Sign(envelope.DirectoryRegister(handle, id.EdPub[:], 1, "public", "open", nil)))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"results": []DirectoryProfile{p}})
			}))
			defer srv.Close()
			cfg := testConfig(t)
			cfg.RelayURL = srv.URL
			if _, err := New(cfg).DirectoryReverse(p.Address); err == nil {
				t.Fatal("accepted signed noncanonical handle")
			}
		})
	}
}

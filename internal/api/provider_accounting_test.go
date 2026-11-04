package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// One fixed-route original transport journey. Owner-exported public-only inputs
// are SOURCE evidence, never imported as independent Runtime ledger observations.
// With an explicit loopback backend this same probe exercises the actual PG app;
// otherwise TLS response suppliers are detached and clearly reported as such.
func TestProviderAccountingOriginalTransport(t *testing.T) {
	if os.Getenv("WARPMETAL_PROVIDER_OPENING_ABSENCE_SOURCE") == "1" {
		calls := 0
		code := "provider_accounting_opening_pending"
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Method != "GET" || r.URL.Path != "/internal/runtime/workspace-workflow/provider-accounting/opening" || r.Header.Get("Authorization") != "Bearer source-node-only" {
				t.Error("opening absence route/authority changed")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code}})
		}))
		defer server.Close()
		client := Client{Origin: server.URL, NodeToken: "source-node-only", HTTP: server.Client()}
		_, err := client.ProviderAccountingOpening(context.Background())
		if !errors.Is(err, model.ErrProviderOpeningAbsent) {
			t.Fatal("OPENING_GET_ABSENCE_UNCLASSIFIED: exact authenticated409 cannot select replay of retained first contribution", err)
		}
		code = "provider_accounting_opening_conflict"
		_, err = client.ProviderAccountingOpening(context.Background())
		if err == nil || errors.Is(err, model.ErrProviderOpeningAbsent) {
			t.Fatal("changed opening incorrectly selected absence recovery", err)
		}
		if calls != 2 {
			t.Fatal("unexpected retry or effect", calls)
		}
		t.Log("SOURCE actual TLS GET absence versus conflict; no POST, signing, ledger or provider effect")
		return
	}
	prefixPath, settlementPath := os.Getenv("WARPMETAL_ACCOUNTING_CURRENT_ORIGINALS"), os.Getenv("WARPMETAL_ACCOUNTING_SETTLEMENT_ORIGINAL")
	if prefixPath == "" || settlementPath == "" {
		t.Skip("explicit owner-exported financial SOURCE originals required")
	}
	prefix, err := os.ReadFile(prefixPath)
	if err != nil {
		t.Fatal(err)
	}
	settlement, err := os.ReadFile(settlementPath)
	if err != nil {
		t.Fatal(err)
	}
	var current struct {
		AuthorityDigest string          `json:"authorityDigest"`
		Opening         json.RawMessage `json:"opening"`
		Snapshot        json.RawMessage `json:"snapshot"`
	}
	var payment struct {
		Settlement struct {
			Payload struct {
				PhysicalID string `json:"physicalId"`
			} `json:"payload"`
		} `json:"settlement"`
	}
	if json.Unmarshal(prefix, &current) != nil || json.Unmarshal(settlement, &payment) != nil {
		t.Fatal("owner SOURCE originals malformed")
	}
	origin, token := os.Getenv("WARPMETAL_ACCOUNTING_BACKEND_ORIGIN"), os.Getenv("WARPMETAL_ACCOUNTING_NODE_TOKEN")
	client := Client{Origin: origin, NodeToken: token}
	calls := 0
	if origin == "" {
		token = "source-node-only"
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Header.Get("Authorization") != "Bearer "+token || r.URL.RawQuery != "" {
				t.Error("node route changed")
				w.WriteHeader(403)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.Method + " " + r.URL.Path {
			case "GET /internal/runtime/workspace-workflow/provider-accounting/current":
				_, _ = w.Write(prefix)
			case "POST /internal/runtime/workspace-workflow/provider-accounting/opening":
				var body json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil || model.WorkspaceDigest(body) != model.WorkspaceDigest(current.Opening) {
					t.Error("first signed opening changed")
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"openingDigest": model.WorkspaceDigest(current.Opening), "snapshot": current.Snapshot})
			case "POST /internal/runtime/workspace-workflow/provider-accounting/original-settlements":
				var body json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil || model.WorkspaceDigest(body) != model.WorkspaceDigest(json.RawMessage(settlement)) {
					t.Error("signed settlement or originals changed")
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"physicalId": payment.Settlement.Payload.PhysicalID, "snapshot": current.Snapshot})
			default:
				t.Error("unexpected route")
				w.WriteHeader(404)
			}
		}))
		defer server.Close()
		client = Client{Origin: server.URL, NodeToken: token, HTTP: server.Client()}
	} else {
		u, e := url.Parse(origin)
		if e != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || u.RawQuery != "" || token == "" {
			t.Fatal("only explicitly bound local backend fixture allowed")
		}
		if path := os.Getenv("WARPMETAL_ACCOUNTING_CA_PEM"); path != "" {
			pem, err := os.ReadFile(path)
			pool := x509.NewCertPool()
			if err != nil || !pool.AppendCertsFromPEM(pem) {
				t.Fatal("fixture CA unavailable")
			}
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
			client.HTTP = &http.Client{Transport: transport}
			defer transport.CloseIdleConnections()
		}
	}
	got, err := client.ProviderAccountingCurrent(context.Background(), current.AuthorityDigest)
	if err != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(json.RawMessage(prefix)) {
		t.Fatal("exact backend prefix transport", err)
	}
	if _, err = client.AcceptProviderAccountingOpening(context.Background(), current.Opening); err != nil {
		t.Fatal("first opening/replay transport", err)
	}
	if _, err = client.SettleProviderAccountingOriginals(context.Background(), settlement); err != nil {
		t.Fatal("original settlement/replay transport", err)
	}
	if origin == "" && calls != 3 {
		t.Fatal("unexpected source call count", calls)
	}
	if bytes.Contains(got, []byte("contentBase64")) {
		t.Fatal("current readback leaked retained request bodies")
	}
	t.Log("fixed opening/current/original-settlement transport; exact original signatures preserved; external provider requests0; actualBackend", origin != "")
}

package hush

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenAndPagination(t *testing.T) {
	tokens := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, _ := r.BasicAuth()
		if id != "key" || secret != "secret" || r.FormValue("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokens++
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
	})
	mux.HandleFunc("GET /v1/access_policies", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			_, _ = w.Write([]byte(`{"items":[{"id":"apl_1","created_at":"2026-10-01T10:00:00","rotated_at":null}],"next_page":"c2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"id":"apl_2","created_at":"2026-10-01T10:00:00","rotated_at":"2026-10-02T11:00:00.123000"}],"next_page":null}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	policies, err := NewClient(srv.URL, "key", "secret").AccessPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies[0].ID != "apl_1" || policies[1].ID != "apl_2" {
		t.Fatalf("policies = %+v", policies)
	}
	if policies[0].RotatedAt != nil {
		t.Errorf("rotated_at null read as %v", policies[0].RotatedAt)
	}
	want := time.Date(2026, 10, 2, 11, 0, 0, 123000000, time.UTC)
	if !policies[1].RotatedAt.Equal(want) {
		t.Errorf("rotated_at = %v, want %v", policies[1].RotatedAt, want)
	}
	if tokens != 1 {
		t.Errorf("fetched %d tokens, want 1 reused across pages", tokens)
	}
}

func TestFindingsPaginationAndFilters(t *testing.T) {
	var bodies []findingsRequest
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
	})
	mux.HandleFunc("POST /v1/findings/certificates", func(w http.ResponseWriter, r *http.Request) {
		var body findingsRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		if body.Page == nil {
			_, _ = w.Write([]byte(`{"items":[{"fingerprint":"a","expires_at":"2026-11-01 00:00:00"}],"next_page":"p2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"fingerprint":"b","expires_at":"2026-11-02T00:00:00Z"}],"next_page":null}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	certs, err := NewClient(srv.URL, "key", "secret").ExpiringCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || certs[1].Fingerprint != "b" {
		t.Fatalf("certs = %+v", certs)
	}
	if len(bodies) != 2 || *bodies[1].Page != "p2" || !bodies[0].Pagination {
		t.Fatalf("requests = %+v", bodies)
	}
	f := bodies[0].Filters
	if len(f) != 1 || f[0].Name != "issue_type" || f[0].Op != "eq" || len(f[0].Values) != 2 {
		t.Errorf("filters = %+v", f)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"bad key"}`))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "key", "wrong").AccessPolicies(context.Background())
	if err == nil {
		t.Fatal("want an error for a refused key")
	}
}

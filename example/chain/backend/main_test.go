package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TDD spec for chain-backend. Each test pins one of the three demo
// scenarios' essential behaviour. The vulnerable endpoints MUST behave
// as written here — that's how the chain-attacks.yaml gets its bite.

// stubExecutor lets tests verify which SQL was forwarded to "postgres"
// without needing a real database. Returns canned (rows, err).
type stubExecutor struct {
	lastSQL string
	rows    string
	err     error
}

func (s *stubExecutor) Exec(sql string) (string, error) {
	s.lastSQL = sql
	return s.rows, s.err
}

// stubFetcher records the URL the SSRF endpoint dialled. The point of
// scenario 1 is that the connect() ATTEMPT fires the network rule — we
// do not need an actual upstream.
type stubFetcher struct {
	lastURL string
	status  int
	body    string
	err     error
}

func (s *stubFetcher) Get(url string) (int, string, error) {
	s.lastURL = url
	return s.status, s.body, s.err
}

// TestAdminSQL_ForwardsRawQuery is scenario 2's contract: the backend
// MUST splice the user-supplied q field directly into the SQL it sends
// downstream. If we ever sanitise this, the demo's COPY-FROM-PROGRAM
// payload will never reach postgres.
func TestAdminSQL_ForwardsRawQuery(t *testing.T) {
	exec := &stubExecutor{rows: "ok"}
	srv := newServer(exec, nil)

	body := `{"q":"COPY t FROM PROGRAM 'redis-cli -h r FLUSHALL'"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/sql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	want := "COPY t FROM PROGRAM 'redis-cli -h r FLUSHALL'"
	if exec.lastSQL != want {
		t.Errorf("forwarded SQL = %q, want %q", exec.lastSQL, want)
	}
}

// TestAdminSQL_RejectsNonJSON pins that the endpoint validates input
// shape — but accepts payloads with single-quoted SQL inside JSON
// strings. Without this, a typo'd attack YAML would silently 400 and
// the chain would look "blind" for the wrong reason.
func TestAdminSQL_RejectsNonJSON(t *testing.T) {
	srv := newServer(&stubExecutor{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/sql", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-JSON body = %d, want 400", rec.Code)
	}
}

// TestAdminFetch_DialsUserURL is scenario 1's contract: the URL value
// from the JSON body MUST be passed verbatim to the HTTP fetcher so the
// connect() syscall happens against link-local. Sanitising this would
// neuter the SSRF demo.
func TestAdminFetch_DialsUserURL(t *testing.T) {
	fetch := &stubFetcher{status: 200, body: "ok"}
	srv := newServer(nil, fetch)

	body := `{"url":"http://169.254.169.254/latest/meta-data/"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if fetch.lastURL != "http://169.254.169.254/latest/meta-data/" {
		t.Errorf("dialled URL = %q, want link-local", fetch.lastURL)
	}
}

// TestAdminFetch_RejectsEmptyURL pins basic shape validation so an
// empty {} body fails fast rather than silently 200-ing.
func TestAdminFetch_RejectsEmptyURL(t *testing.T) {
	srv := newServer(nil, &stubFetcher{})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/fetch", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty url body = %d, want 400", rec.Code)
	}
}

// TestHealthz pins the readiness endpoint that k8s + local-ci poll.
// Without it, scenarios race against pod startup.
func TestHealthz(t *testing.T) {
	srv := newServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", rec.Code)
	}
}

// TestProducts_BenignSelect pins the benign HTTP path used during
// learning — protocol_loadtest_server hammers /api/products to
// populate the network profile (frontend → backend) and the postgres
// pod's normal-traffic profile (backend → postgres).
func TestProducts_BenignSelect(t *testing.T) {
	exec := &stubExecutor{rows: `[{"id":1,"name":"sticker"}]`}
	srv := newServer(exec, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/products = %d, want 200", rec.Code)
	}
	// Must hit the database (benign baseline edge for postgres-vuln's profile)
	if !strings.Contains(strings.ToLower(exec.lastSQL), "select") {
		t.Errorf("benign /api/products did not run a SELECT; lastSQL=%q", exec.lastSQL)
	}
}

// TestEndpointsReturnJSON_ContentType pins the response content-type
// so test-pod curl + protocol_loadtest_server agree on parsing.
func TestEndpointsReturnJSON_ContentType(t *testing.T) {
	exec := &stubExecutor{rows: "[]"}
	srv := newServer(exec, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	got := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json prefix", got)
	}
}

// helper — verify that JSON encode/decode round-trips so we can write
// future tests without re-implementing the parse step.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

// silence unused warnings for helpers used by future scenarios.
var _ = bytes.NewBuffer
var _ = mustJSON
var _ = mustReadAll

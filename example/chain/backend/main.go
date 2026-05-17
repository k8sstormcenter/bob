// chain-backend is the deliberately-vulnerable Go service that anchors
// the multi-pod chain demo. It exposes a benign surface (used by
// protocol_loadtest_server during sbob learning) plus three admin
// endpoints that pass user input UNFILTERED to downstream services.
// The vulnerabilities are intentional and documented per endpoint.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	// pure-Go postgres driver. Lives in the chain-backend's isolated
	// go.mod (not pkg/), so adding this driver does not touch the
	// bobctl codebase.
	_ "github.com/lib/pq"
)

// executor is the SQL surface the handlers depend on. The real impl
// (pgExecutor) wraps database/sql; tests use a stub that records the
// last SQL forwarded so we can assert "raw user input reached the DB".
type executor interface {
	Exec(sql string) (string, error)
}

// fetcher is the HTTP-GET surface for the SSRF endpoint. Real impl
// uses http.DefaultClient; tests stub it so they can assert which URL
// was dialled without needing an actual upstream.
type fetcher interface {
	Get(url string) (int, string, error)
}

// newServer wires the handlers onto a mux. Both deps may be nil in
// tests that only exercise endpoints which don't use them (e.g. healthz).
func newServer(exec executor, fetch fetcher) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Benign baseline endpoint — protocol_loadtest_server hammers this
	// during the learn phase to populate (a) backend's NetworkNeighborhood
	// edge to postgres and (b) postgres's normal-traffic profile.
	mux.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, must(exec.Exec(
			"SELECT id, name FROM products LIMIT 50")))
	})

	// Benign baseline — backend ↔ redis edge. We don't have a real redis
	// client here (kept zero-dep on purpose); the handler just hits the
	// SQL exec for cache-miss and returns canned JSON.
	mux.HandleFunc("/api/cart/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"items":[]}`)
	})

	// VULNERABLE — scenario 2 + 3 entry. Splices request.q into the SQL
	// string with NO parameterisation. This is the intentional sink for
	// COPY FROM PROGRAM and dblink_connect payloads.
	mux.HandleFunc("/api/admin/sql", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Q string `json:"q"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "json decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Q == "" {
			http.Error(w, "q is required", http.StatusBadRequest)
			return
		}
		// Splice as-is. This is the demo's whole point.
		out, err := exec.Exec(req.Q)
		if err != nil {
			// Return 200 with error body so the runner sees the postgres
			// error message (helps debugging) without classifying the
			// attack as a transport failure.
			writeJSON(w, http.StatusOK, fmt.Sprintf(`{"error":%q}`, err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	// VULNERABLE — scenario 1 entry. Passes user URL straight to fetcher
	// so the connect() syscall hits whatever host the attacker named.
	mux.HandleFunc("/api/admin/fetch", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ URL string `json:"url"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "json decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.URL == "" {
			http.Error(w, "url is required", http.StatusBadRequest)
			return
		}
		status, body, err := fetch.Get(req.URL)
		if err != nil {
			// Mirror upstream-unreachable as a 502 so the network rule
			// fires (the connect attempt happened) but the runner sees
			// the right HTTP code in attack-results.md.
			writeJSON(w, http.StatusBadGateway, fmt.Sprintf(`{"error":%q}`, err.Error()))
			return
		}
		writeJSON(w, status, body)
	})

	return mux
}

// writeJSON sends a response with explicit content-type. Body strings
// that already look like JSON go through verbatim; non-JSON gets
// quoted into a {"data": ...} envelope so callers always get parseable
// output.
func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") {
		_, _ = io.WriteString(w, body)
		return
	}
	_, _ = fmt.Fprintf(w, `{"data":%q}`, body)
}

// must returns the first arg as a JSON-friendly string; if err != nil
// it returns a JSON error payload. Helper for the benign endpoint
// where errors are non-fatal (cache miss, empty result).
func must(s string, err error) string {
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return s
}

// ── real-world wrappers around stdlib ──────────────────────────────

// pgExecutor wraps database/sql so the handlers can use the executor
// interface. We deliberately keep this in the same file: the chain
// backend has no production lifetime — it's a demo target.
type pgExecutor struct{ db *sql.DB }

func (p *pgExecutor) Exec(query string) (string, error) {
	rows, err := p.db.Query(query)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return "[]", nil
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return "", err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}

type httpFetcher struct{ client *http.Client }

func (h *httpFetcher) Get(url string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// ── main: connect to pg via env, register handlers, listen ────────

func main() {
	addr := getenv("LISTEN_ADDR", ":8080")
	pgConn := getenv("POSTGRES_DSN",
		"host=chain-postgres port=5432 user=postgres password=postgres dbname=postgres sslmode=disable")

	// Lazy connect — we want backend to start even if postgres is briefly
	// unavailable, so the readiness probe can flip green on its own clock.
	db, err := sql.Open("postgres", pgConn)
	if err != nil {
		// Don't fatal — start the listener so /healthz can flip.
		log.Printf("WARN: sql.Open failed: %v (handlers will return 500)", err)
	}
	exec := &pgExecutor{db: db}
	fetch := &httpFetcher{client: &http.Client{Timeout: 5 * time.Second}}

	srv := &http.Server{
		Addr:              addr,
		Handler:           newServer(exec, fetch),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("chain-backend listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

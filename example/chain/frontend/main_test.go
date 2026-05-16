package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TDD spec for chain-frontend. Pins three contracts:
//   1. /api/products PROXIES to backend (legitimate path)
//   2. /api/cache/eval PROXIES the Lua script verbatim to redis EVAL
//      (this is the "legitimate but dangerous" feature)
//   3. /healthz returns 200 (so k8s readiness can flip)

// stubBackend records the path the frontend proxied to.
type stubBackend struct{ lastPath string }

func (s *stubBackend) Get(path string) (int, string, error) {
	s.lastPath = path
	return 200, `[{"id":1,"name":"sticker"}]`, nil
}

// stubRedis records the RESP command frontend sent. The point is that
// the user-supplied script reaches redis EVAL UNFILTERED — that's the
// chain demo's whole premise. Sanitising the script (or running it
// through a whitelist) would break the attack scenario.
type stubRedis struct {
	lastCmd []string
	reply   string
	err     error
}

func (s *stubRedis) Do(args ...string) (string, error) {
	s.lastCmd = args
	return s.reply, s.err
}

func TestProducts_ProxiesToBackend(t *testing.T) {
	be := &stubBackend{}
	srv := newServer(be, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if be.lastPath != "/api/products" {
		t.Errorf("backend got %q, want /api/products", be.lastPath)
	}
}

// TestCacheEval_ForwardsScriptVerbatim is the chain demo's contract:
// whatever Lua the user sends MUST reach redis EVAL untouched. If we
// ever sanitise, whitelist, or sandbox at the frontend layer, the
// sandbox-escape attack disappears and the demo loses its bite.
func TestCacheEval_ForwardsScriptVerbatim(t *testing.T) {
	rd := &stubRedis{reply: "1"}
	srv := newServer(nil, rd)

	script := `return redis.call("INCR", KEYS[1])`
	body, _ := json.Marshal(map[string]any{"script": script, "keys": []string{"counter"}})
	req := httptest.NewRequest(http.MethodPost, "/api/cache/eval", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	// Expect: EVAL <script> 1 <keys[0]>
	if len(rd.lastCmd) < 4 {
		t.Fatalf("redis got too few args: %v", rd.lastCmd)
	}
	if rd.lastCmd[0] != "EVAL" {
		t.Errorf("redis.cmd[0] = %q, want EVAL", rd.lastCmd[0])
	}
	if rd.lastCmd[1] != script {
		t.Errorf("redis.cmd[1] = %q, want %q (script must be verbatim)", rd.lastCmd[1], script)
	}
}

// TestCacheEval_AttackerScriptReachesRedis is the dark-side of the
// contract above. Pins that a clearly-malicious Lua (the chain's
// sandbox-escape payload) is forwarded unchanged. If anyone later
// adds a "block io.popen" check at frontend layer, this test catches
// it and the chain breaks immediately rather than silently going dead.
func TestCacheEval_AttackerScriptReachesRedis(t *testing.T) {
	rd := &stubRedis{reply: "shadow contents..."}
	srv := newServer(nil, rd)

	// Compressed version of the s2 payload — sandbox escape via loadlib.
	evil := `package.loadlib('/usr/lib/liblua5.1.so.0','luaopen_io')`
	body, _ := json.Marshal(map[string]any{"script": evil})
	req := httptest.NewRequest(http.MethodPost, "/api/cache/eval", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rd.lastCmd[1] != evil {
		t.Errorf("evil script was rewritten — frontend MUST forward verbatim. got=%q", rd.lastCmd[1])
	}
}

func TestCacheEval_RejectsMissingScript(t *testing.T) {
	srv := newServer(nil, &stubRedis{})
	req := httptest.NewRequest(http.MethodPost, "/api/cache/eval", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty body should 400, got %d", rec.Code)
	}
}

func TestCacheEval_RejectsNonJSON(t *testing.T) {
	srv := newServer(nil, &stubRedis{})
	req := httptest.NewRequest(http.MethodPost, "/api/cache/eval", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-JSON should 400, got %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	srv := newServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", rec.Code)
	}
}

func TestRoot_ReturnsHTML(t *testing.T) {
	srv := newServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/ = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "html") {
		t.Errorf("Content-Type = %q, want html", rec.Header().Get("Content-Type"))
	}
}

// silence unused-import warning during incremental dev
var _ = io.ReadAll

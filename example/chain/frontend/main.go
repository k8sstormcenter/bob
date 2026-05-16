// chain-frontend is the public-facing HTTP entrypoint for the chain
// demo. It exposes:
//   - GET  /                 → simple landing HTML
//   - GET  /api/products     → proxies to chain-backend (HTTP)
//   - POST /api/cache/eval   → proxies user-supplied Lua to redis EVAL
//                              (legitimate atomic-counter pattern, but
//                              the script is untrusted — this is the
//                              chain demo's attack vector)
//   - GET  /healthz          → readiness
//
// "Legitimate but dangerous": the eval endpoint mirrors a pattern real
// apps use for atomic ops (rate-limit windows, distributed counters).
// The vuln is that the script content reaches redis EVAL unfiltered.
// Sanitising or whitelisting the script at this layer breaks the
// chain demo on purpose — see main_test.go.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// backendClient is the surface for the products endpoint; stubbed in tests.
type backendClient interface {
	Get(path string) (int, string, error)
}

// redisClient is the surface for EVAL; stubbed in tests. Args are the
// raw RESP command vector — first element is "EVAL", second the
// script, third the numkeys (as decimal string), then keys, then argv.
type redisClient interface {
	Do(args ...string) (string, error)
}

func newServer(be backendClient, rd redisClient) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><title>chain</title><h1>chain frontend</h1>` +
			`<p>GET /api/products · POST /api/cache/eval</p>`))
	})

	mux.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
		status, body, err := be.Get("/api/products")
		if err != nil {
			http.Error(w, "backend unreachable: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})

	mux.HandleFunc("/api/cache/eval", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Script string   `json:"script"`
			Keys   []string `json:"keys,omitempty"`
			Args   []string `json:"args,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "json decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Script == "" {
			http.Error(w, "script is required", http.StatusBadRequest)
			return
		}
		// Build the RESP EVAL: EVAL <script> <numkeys> <keys...> <args...>
		// Script is forwarded VERBATIM by design.
		respArgs := []string{"EVAL", req.Script, strconv.Itoa(len(req.Keys))}
		respArgs = append(respArgs, req.Keys...)
		respArgs = append(respArgs, req.Args...)
		reply, err := rd.Do(respArgs...)
		if err != nil {
			// Return 200 with the redis error in body so the runner sees the
			// underlying complaint (helps demo debugging) without
			// classifying the attack as a transport failure.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"reply":%q}`, reply)
	})

	return mux
}

// ── real-world wrappers ──────────────────────────────────────────

type httpBackend struct {
	base   string
	client *http.Client
}

func (h *httpBackend) Get(path string) (int, string, error) {
	resp, err := h.client.Get(h.base + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// respRedis is a one-file, zero-dep RESP v2 client. Just enough to
// send EVAL and parse the bulk-string / integer / error reply. We
// intentionally don't import pkg/attack/resp — keeps the frontend's
// go.mod isolated from the rest of the bob codebase.
type respRedis struct{ addr string }

func (r *respRedis) Do(args ...string) (string, error) {
	conn, err := net.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Encode as RESP array of bulk strings.
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	rd := bufio.NewReader(conn)
	return readRespReply(rd)
}

// readRespReply parses one RESP reply (simple-string, error, integer,
// bulk-string, or array). Arrays are flattened to a newline-separated
// string for readability.
func readRespReply(rd *bufio.Reader) (string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read header: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 1 {
		return "", fmt.Errorf("empty reply")
	}
	switch line[0] {
	case '+': // simple string
		return line[1:], nil
	case '-': // error
		return "", fmt.Errorf("redis: %s", line[1:])
	case ':': // integer
		return line[1:], nil
	case '$': // bulk string
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", fmt.Errorf("bulk len: %w", err)
		}
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2) // payload + \r\n
		if _, err := io.ReadFull(rd, buf); err != nil {
			return "", fmt.Errorf("bulk body: %w", err)
		}
		return string(buf[:n]), nil
	case '*': // array — flatten
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", fmt.Errorf("array len: %w", err)
		}
		var parts []string
		for i := 0; i < n; i++ {
			p, err := readRespReply(rd)
			if err != nil {
				return "", err
			}
			parts = append(parts, p)
		}
		return strings.Join(parts, "\n"), nil
	}
	return "", fmt.Errorf("unknown reply type %q", line)
}

func main() {
	addr := getenv("LISTEN_ADDR", ":8080")
	beURL := getenv("BACKEND_URL", "http://chain-backend.chain.svc:8080")
	redisAddr := getenv("REDIS_ADDR", "chain-redis.chain.svc:6379")

	be := &httpBackend{base: beURL, client: &http.Client{Timeout: 5 * time.Second}}
	rd := &respRedis{addr: redisAddr}

	srv := &http.Server{
		Addr:              addr,
		Handler:           newServer(be, rd),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("chain-frontend listening on %s (backend=%s, redis=%s)", addr, beURL, redisAddr)
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

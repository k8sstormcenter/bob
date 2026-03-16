# Autotuning Development & Testing Guide

Ground truth for how we develop and test `bobctl` autotuning locally.

## Architecture

```
bobctl collapse   →  cluster-wide CollapseConfiguration CRD
bobctl tune       →  per-app profile tuning (baseline test + FP refinement)
bobctl attack     →  run attack suite, report results
bobctl report     →  fetch alertmanager alerts, format as markdown
```

All HTTP traffic (benign, attacks, alertmanager queries) routes through
the Kubernetes API server service proxy — no port-forwarding needed.

## Applications Under Test

### Webapp (PHP ping.php)

| Property | Value |
|----------|-------|
| Namespace | `webapp` |
| Manifest | `example/webapp-manifest.yaml` |
| Service | `webapp-mywebapp:8080` → container port 80 |
| Container | `mywebapp-app` |
| Image | `ghcr.io/k8sstormcenter/webapp` (pinned by sha256) |

**Vulnerability**: Command injection via `ping.php?ip=<payload>`.
The page runs `ping -c1 $ip` without sanitizing — semicolons chain arbitrary commands.

**There is NO LFI, SSRF, or SQL injection vulnerability in this webapp.**

| Attack | Payload | Detection |
|--------|---------|-----------|
| cmdinject-sa-token | `1.1.1.1;cat /var/run/secrets/.../token` | R0001, R0006 |
| cmdinject-etc-passwd | `1.1.1.1;cat /etc/passwd` | R0001 |
| cmdinject-whoami | `1.1.1.1;whoami` | R0001 |
| cmdinject-ls-secrets | `1.1.1.1;ls /var/run/secrets/.../` | R0001 |

**Expected detections** (defined in `example/webapp-attacks.yaml`):
- R0001 "Unexpected process launched" — `cat` (container: mywebapp-app)
- R0006 "Unexpected Service Account Token Access" — `cat` (container: mywebapp-app)

**Functional tests** (`example/webapp-functional-tests.yaml`):
- GET `/` (homepage)
- GET `/ping.php?ip=8.8.8.8` and `1.1.1.1` (benign pings)
- POST `/` with form data (login form)
- exec `php -v` (check PHP version)

### Redis (CVE-2025-49844)

| Property | Value |
|----------|-------|
| Namespace | `redis` |
| Manifest | `example/redis-vulnerable.yaml` |
| Service | `redis:6379` |
| Container | `redis` |
| Image | `ghcr.io/k8sstormcenter/redis-vulnerable:7.2.10` |
| Protocol | RESP (raw TCP, needs port-forward) |

**Vulnerability**: CVE-2025-49844 — Use-after-free in Lua parser + CVE-2022-0543
Lua sandbox escape. Exploit chain: heap spray → GC trigger → fileless execution
via `memfd_create` + `execve`.

| Attack | Type | Detection |
|--------|------|-----------|
| lua-heap-spray | fileless | (preparation) |
| lua-uaf-trigger | fileless | (preparation) |
| cve-2025-49844-exploit | fileless | R1005 |

**Expected detections** (`example/redis-attacks.yaml`):
- R1005 "Fileless execution detected" (container: redis)

**Functional tests** (`example/redis-functional-tests.yaml`):
- PING, SET/GET, INFO, DBSIZE, EVAL, DEL (all via redis-cli exec)

## Tuning Algorithm

```
Phase 0: Fetch baseline (immutable deep copy of the learned profile)
Phase 1: Baseline test — apply as-is, run attacks + benign, score
Phase 2: FP refinement — for each FP alert, add triggering process
         to AllowedProcesses for that specific rule (surgical)
```

**Key invariants**:
1. The learned baseline profile is NEVER modified
2. Each iteration creates a user-defined profile `ug-<name>-iteration<N>`
3. `containerAllowed` is NEVER set — that disables the rule entirely
4. Only `AllowedProcesses` is used for surgical FP suppression
5. No re-learning between iterations — just modify profile, wait 60s for cache refresh

**Score** = MissedDetections + FalsePositives (lower is better, 0 = perfect)

## Consistency Rules

All these files MUST be consistent with each other:

| File | What it defines |
|------|----------------|
| `example/webapp-attacks.yaml` | Attacks + expected detections for webapp |
| `example/webapp-functional-tests.yaml` | Benign traffic for webapp |
| `example/redis-attacks.yaml` | Attacks + expected detections for redis |
| `example/redis-functional-tests.yaml` | Benign traffic for redis |
| `pkg/verify/types.go` `DefaultExpectedDetections()` | Hardcoded defaults (webapp only) |
| `pkg/autotune/tuner_test.go` `testAttackSuite()` | Unit test attack suite |
| `pkg/autotune/tuner_test.go` `expectedAttackAlerts()` | Unit test expected alerts |

When you change attacks or detections, update ALL of these.

## Local Development

### Prerequisites

- Kind cluster with kubescape (storage + node-agent) in `honey` namespace
- Alertmanager deployed in `honey` namespace
- Storage image `dev-e64d59a` or later (from `feature/collapse-config-crd` branch)
- Go 1.25+

### Full run (setup + learn + collapse + tune)

```bash
./scripts/local-ci.sh
```

### Tune-only rerun (skip infra setup, reuse learned profile)

```bash
./scripts/local-ci.sh --tune-only
```

### Setup infrastructure only (then iterate manually)

```bash
./scripts/local-ci.sh --setup-only
```

### Redis instead of webapp

```bash
./scripts/local-ci.sh --app redis
```

### Manual step-by-step

```bash
# 1. Build
cd pkg && go build -o ../bin/bobctl ./main.go && cd ..

# 2. Setup (once)
make kubescape
make alertmanager

# 3. Deploy app + learn profile
PROFILE=$(bin/bobctl install \
  --manifest example/webapp-manifest.yaml \
  --functional-tests example/webapp-functional-tests.yaml \
  -n webapp --timeout 3m -v)

# 4. Collapse analysis
bin/bobctl collapse --namespaces webapp --noisy-threshold 10 --apply -v

# 5. Tune
bin/bobctl tune \
  --profile "$PROFILE" -n webapp --ks-namespace honey \
  --functional-tests example/webapp-functional-tests.yaml \
  --attack-suite example/webapp-attacks.yaml \
  --output-dir results --max-rounds 3 --debug -v

# 6. Standalone attack + report
bin/bobctl attack --attack-suite example/webapp-attacks.yaml -n webapp
bin/bobctl report --alertmanager-service alertmanager --alertmanager-port 9093 \
  --ks-namespace honey -n webapp --format markdown
```

### Unit tests

```bash
cd pkg
go test -short ./...                         # all packages
go test ./pkg/autotune/... -v                # tuner tests only
go test ./pkg/profile/... -v                 # profile manipulation tests
go test ./pkg/verify/... -v                  # verification logic
go test ./pkg/attack/... -v                  # attack suite parsing + RESP
```

## Infrastructure

### Kubescape Helm Values

`kubescape/values.yaml` — key settings:
- `maxLearningPeriod: 2m` / `learningPeriod: 2m` — fast learning for dev
- `updatePeriod: 10000m` — effectively disable auto-updates
- `ruleCooldown: 0h / 1000000000 count` — no alert cooldown
- Storage + node-agent images: `ghcr.io/k8sstormcenter/{storage,node-agent}:dev-e64d59a`
- Namespace: `honey`

### Alertmanager

`kubescape/alertmanager.yaml` — minimal deployment, port 9093, no receivers.
Node-agent is configured to export to `alertmanager.honey.svc.cluster.local:9093`.

### Default Rules

`kubescape/default-rules.yaml` — key rules:
- R0001: Unexpected process launched
- R0002: Unexpected file access
- R0005: Unexpected domain request
- R0006: Unexpected SA token access
- R1005: Fileless execution detected
- R1007: Crypto miner launched
- R1008: Crypto mining domain communication

## CI Workflow

`.github/workflows/ci-bobctl-autotune.yaml` — matrix across:
- OS: ubuntu-22.04, ubuntu-24.04
- App: webapp, redis
- Cluster: k3s

Steps: build → k3s setup → kubescape install → alertmanager → app install →
profile learning → collapse analysis → tune → attacks → report → diagnostics.

### Storage Branch

CI clones storage from `feature/tuning` branch (has `CollapseSettings`, `ParseCollapseSettings`).
The `feature/collapse-config-crd` branch adds the CollapseConfiguration CRD type.

## Adding a New Application

1. Create `example/<app>-manifest.yaml` (Namespace + Deployment + Service)
2. Create `example/<app>-functional-tests.yaml` (benign traffic definition)
3. Create `example/<app>-attacks.yaml` (attacks + expected detections)
4. Add app case to `scripts/local-ci.sh`
5. Add matrix entry to `.github/workflows/ci-bobctl-autotune.yaml`
6. Test: `./scripts/local-ci.sh --app <app>`

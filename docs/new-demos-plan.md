# Plan: two CNCF-CVE attack demos (Argo CD, Fluent Bit) + "chain" label purge

**Status**: PLAN ONLY (2026-06-02). No files created. Builds on the
log4j demo template (PR #131) and the manifest-driven pipeline
(`scripts/sbob-pipeline.sh` + `scripts/lib/chain-*.sh`).

## Goal

Two more active-diagnosis demos in the log4j mould — **same payload,
three image variants (vulnerable / contained / patched), the image is
the only variable** — but targeting **graduated CNCF projects** with
high-profile CVEs. Plus: drop the word "chain" from Kubernetes
labels/names (they bloat `replicaset-chain-<role>-<hash>`).

We have 25 CVEs exercised today, but all on generic infra apps
(webapp/redis/postgres/elk/misp/mariadb). None hit a CNCF project. These
two close that gap.

## Naming scheme (labels-only de-chain — DECIDED)

Drop the `chain-` prefix from k8s names + shorten namespaces. The
internal `ChainManifest` kind / `chain.manifest.yaml` / `scripts/lib/
chain-*.sh` are NOT k8s labels and stay as-is (separate decision if a
full purge is ever wanted).

| Was (log4j) | Becomes |
|---|---|
| dir `example/log4j-chain/` | `example/log4j/` |
| ns `log4j-poc`, `attacker-ns` | `log4j`, `adv` (shared attacker ns) |
| pods `chain-{backend,frontend,postgres,observer}` | role-only: `app`, `frontend`, `db`, `observer` (ns carries context) |
| `log4j-chain.yaml`, `backend-{b,c}.yaml` | `log4j.yaml`, `app-{b,c}.yaml` |
| profile `replicaset-chain-backend-<hash>` | `replicaset-app-<hash>` (much shorter) |

New demos follow the same shape: `example/argocd/`, `example/fluentbit/`;
namespaces `argocd`, `fluentbit`; attacker in shared `adv`; target pod
`app`; negative-control `observer`.

(The existing `example/chain/` and `example/log4j-chain/` get the same
label rename when they next move — fold into the de-chain pass, no
separate effort.)

## Demo 1 — Argo CD (STRONGEST detection fit; build first)

**Project**: Argo CD — the canonical CNCF GitOps controller (graduated).
**CVE class**: CVE-2022-24348 (Helm value path-traversal, Apiiro 2022)
and the broader repo-server manifest-generation exec surface.

**Why it's the best log4j analogue**: the repo-server renders manifests
by **shelling out** to `helm template`, `kustomize build`, `git`, and
config-management plugins. A malicious repo makes it spawn
attacker-influenced subprocesses and read files outside its sandbox —
i.e. a clean `R0001` (new process) + `R0010` (out-of-tree file) + `R0011`
(egress) chain, the exact kernel-observable shape the detection model is
built for.

### Topology (ns `argocd` + `adv`)
```
   benign Application sync          adv/attacker
        │                            git-http :80  (poisoned Helm chart /
        ▼                            CMP that execs + reads ../../creds)
   argocd/app  (repo-server)  ───────┘
        │ renders manifest by exec'ing helm/kustomize/git
        ▼
   (out-of-tree file read / egress / spawned shell)
   argocd/observer  — benign repo sync every 30s (negative control)
```

### Scenarios (same malicious-repo payload; image is the only variable)
| | repo-server image | hardening | expected on `app` |
|---|---|---|---|
| **A vulnerable** | argocd vuln tag, default | shell + helm + kustomize + git present | `R0001` (new comm: sh / CMP), `R0010` (reads `../../` outside repo dir), `R0011` (egress if chart fetches) |
| **B contained** | distroless repo-server, seccomp, RO-fs, dropped caps, no `/bin/sh` | payload attempts to spawn a helper → ENOENT | `R1100` (failed-execve, the smoking gun) + maybe `R0011` on the initial fetch |
| **C patched** | argocd patched tag | traversal closed / CMP sandboxed | inert (benign noise only) |

**Image cost**: A and C are **upstream tags** (`quay.io/argoproj/argocd:<vuln>` vs `<patched>`) — no build. Only B needs a custom hardened image. Cheaper than log4j (which compiled custom Java for all three).

## Demo 2 — Fluent Bit (ubiquitous; weaker/different signal — build second)

**Project**: Fluent Bit — graduated CNCF log/metrics forwarder, runs as
a DaemonSet on ~every cluster.
**CVE**: CVE-2024-4323 "Linguistic Lumberjack" (Tenable, 2024). Heap
corruption in the embedded HTTP monitoring server's `/api/v1/traces`
input parsing; crafted request → crash → potential RCE. Vuln 2.0.7–3.0.3,
**patched 3.0.4**.

### Topology (ns `fluentbit` + `adv`)
```
   fluentbit/observer — benign log producer (negative control)
        │ logs
        ▼
   fluentbit/app  (fluent-bit, HTTP server + traces endpoint on :2020)
        ▲
        │ crafted POST /api/v1/traces  (malformed input names)
   adv/attacker
```

### Scenarios (same crafted-HTTP payload)
| | fluent-bit image | hardening | expected on `app` |
|---|---|---|---|
| **A vulnerable** | `:3.0.3` | default | heap corruption → **process crash + restart** (observable lifecycle); if weaponised to a shell, `R0001`/`R0011` |
| **B contained** | distroless + seccomp blocking shell execve, RO-fs | corruption still crashes, RCE-to-shell blocked | `R1100` (ENOENT on attempted helper) |
| **C patched** | `:3.0.4` | input validated | inert |

**Honest caveat**: Fluent Bit's weakness is a **memory-corruption** bug, not a
clean `Runtime.exec` like log4j/Argo. The reliable observable is the
**crash/restart (DoS) + a blocked-exec in the contained build** — a
weaker, lifecycle-flavoured signal vs Argo's crisp exec chain. It still
demonstrates the patched-vs-vulnerable discriminator and adds a C
(memory-safety) runtime alongside Java (log4j) and Go (Argo), but set
expectations: this is a "crash + memory-safety" demo, not an "exec
kill-chain" demo. Build Argo first (cleaner story); Fluent Bit second.

**Image cost**: A/C upstream tags again (`cr.fluentbit.io/fluent/fluent-bit:3.0.3` / `:3.0.4`); only B custom.

## What each demo needs (clone of the log4j template)

```
example/<demo>/
  README.md  RUNBOOK-FOR-AGENTS.md
  <demo>.manifest.yaml          # ChainManifest (kind kept), pods=app/observer/attacker
  <demo>.yaml                   # ns + adv ns + app(A) + observer + attacker svc
  app-b.yaml  app-c.yaml        # scenario B/C image swaps
  attack-pod.yaml               # fires the payload, phase=Succeeded
  attacks.yaml functional-tests.yaml
  app/Dockerfile.contained      # only B needs a build; A/C are upstream tags
  attacker/…                    # Argo: malicious git-http+chart; FB: crafted-trace sender
  sbobs/{ap,nn}-{app,observer}.yaml   # or auto-learn via the pipeline
```

**No new tooling.** `sbob-pipeline.sh {deploy,apply,switch}` +
`chain-scenario-switch.sh` (the `scenarios[].apply/restart` mechanism)
already drive the A/B/C swap. Each demo is content + a `chain.manifest.yaml`
with a `scenarios:` block.

## Sequencing
1. **De-chain pass** (labels-only) on `example/log4j/` (when #131 lands) + `example/chain/` — establishes the naming convention before adding more.
2. **Argo CD demo** — strongest fit, exercises the exec/file/egress + R1100 chain end-to-end. Validates the pattern generalises beyond log4j.
3. **Fluent Bit demo** — adds the CNCF DaemonSet + memory-safety angle; calibrate to its weaker signal.

Each is its own PR. The CI matrix + sbob-request workflow pick them up
once their `chain.manifest.yaml` validates.

## Open dependency
Argo's "contained" R1100 + log4j's B scenario both rely on the **R1100
failed-execve-ENOENT rule existing in node-agent** (the upstream gap from
PR #131 / portability-spec D3). Until R1100 ships upstream, the B-scenario
smoking gun is observable only at app-log level, not as a kubescape rule.
Track with the R1100 upstream issue.

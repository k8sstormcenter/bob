# SBOB portability spec

**Status**: WIP — written 2026-05-28 from empirical findings during PR
[#131](https://github.com/k8sstormcenter/bob/pull/131) (log4j-chain
demo) ↔ feat/chain-pipeline iterations 1–3.

**Audience**: another agent (or human) who's going to extend
`pkg/autotune` to address the dimensions below. The spec is meant to
be acted on without re-reading the PR thread.

**One-line scope**: a SBOB produced by `bobctl tune` on cluster A is
"portable" iff it applies cleanly + classifies the same attacks the
same way on cluster B. This document enumerates the dimensions where
portability empirically breaks today, with a status flag per dimension
and an actionable next step.

---

## D0 — Schema acceptance (RESOLVED)

**Failure mode**: AP/NN YAML decodes against the wrong CRD version.
Symptom: `strict decoding error: unknown field "spec.containers[0].egress"`.

**Source**: PoC-agent's pre-baked profiles in `example/log4j-chain/kubescape/application-profiles/`
were written for an older schema with `egress` on `ApplicationProfile`
(it belongs on `NetworkNeighborhood`).

**Countermeasure**:
- `apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1`
- AP carries `execs/opens/syscalls/endpoints` only
- NN carries `ingress/egress` only
- Canonical templates: `github.com/k8sstormcenter/node-agent/tests/resources/known-{application-profile,network-neighborhood}.yaml`

**Status in tuner**: ✅ today. The tuner emits both kinds in the right
shape; PR #19 (nnreport) added schema-grounded bucket classification.

---

## D1 — Cluster instrumentation noise floor

**Failure mode**: rules fire continuously from processes that aren't
the workload. R0002 (file access) flooded by pixie eBPF symbolization
re-injection every few minutes; R0004 (capabilities) fired by
`runc:[N:INIT]` at every pod start.

**Source**: cluster-side eBPF / runtime processes share the pod's
mount namespace and trigger node-agent rules. Specific comms:

| Rule | Comm | Origin |
|---|---|---|
| R0002 | `px_jattach`, `Attach Listener` | pixie symbolization injector |
| R0002 | `C1 CompilerThread`, `C2 CompilerThread` | JVM JIT (universal) |
| R0002, R0004 | `runc:[N:INIT]` | container runtime init phase |

**Empirical evidence**: PoC-agent's lab — 131 of 159 R0002 fires +
all 4 R0004 fires came from these comms.

**Countermeasure**: `ApplicationProfileContainer.PolicyByRuleId[ruleID].AllowedProcesses`
(`storage.spdx.softwarecomposition.kubescape.io/v1beta1`). Exact-match
on comm; tells node-agent "skip the rule when comm matches".

**Status in tuner**: ✅ shipped in
[entlein/bob#20](https://github.com/entlein/bob/pull/20) —
`pkg/autotune/env_allowlist.go`. Pre-tune injection on every emitted
`best-profile.yaml`. Scope-locked to R0002+R0004 (TestEnvironmentalCommAllowlist_ScopedToR0002R0004
locks R0001 OUT permanently).

**Deferred to future PR**:
- `TuneConfig.EnvironmentalAllowlist` field so non-pixie clusters can
  drop the pixie entries (lighter SBOB)
- `bobctl tune --learn-env-noise` mode that observes a fresh cluster
  for ~5min and writes a cluster-specific allowlist YAML the next
  tune merges
- Glob/regex support upstream in node-agent (`runc:[*:INIT]` instead of
  enumerating PIDs 1/2/3) — small upstream issue

---

## D1b — Linux comm truncation (sub-dim of D1)

**Failure mode**: `RulePolicy.AllowedProcesses` entry longer than 15
characters silently fails to suppress its target rule, because the
kernel's `task_struct.comm` field is `TASK_COMM_LEN=16` bytes (15
visible + NUL). node-agent reads exactly what the kernel stored, and
the rule evaluator does byte-equal comparison.

**Source**: linux/sched.h `TASK_COMM_LEN`. Hits every process whose
name exceeds 15 chars. Specifically:

| Intended name | Length | Kernel-stored |
|---|---:|---|
| `C1 CompilerThread` | 17 | `C1 CompilerThre` |
| `C2 CompilerThread` | 17 | `C2 CompilerThre` |
| `pool-N-thread-N` | varies | truncated past 15 |

**Empirical evidence**: PR #131 iter 3 — env_allowlist had the FULL
names `"C1 CompilerThread"`, so on PoC-agent's cluster the 4 R0002
fires from JIT threads were NOT suppressed despite the entry being
present.

**Countermeasure**: write the truncated form directly, OR truncate at
emit time. Both: write truncated + assert ≤ 15 in a unit test so
the regression class is locked.

**Status in tuner**: ✅ shipped after the PR #131 catch — `MaxCommLen`
constant + `TestEnvironmentalCommAllowlist_AllUnderCommLen` in
[entlein/bob#20](https://github.com/entlein/bob/pull/20).

**Operational note** (from PoC-agent's iter-4 verification): after
`kubectl delete + apply` of the AP, node-agent needs ~30s to flush
its per-binding cache before new `rulePolicies` fully suppress.
Freshly-restarted JVM pods will trigger transient `C1 CompilerThre`
fires during that window even with the truncated comm correctly
matched. Belongs in the chain-pipeline runbook, not in the AP itself.

**Deferred**:
- `node-agent`'s rule-evaluator could log a WARN if the
  AllowedProcesses entry exceeds 15 — operator-facing "you set
  something that can't possibly match". Small upstream issue.
- `bobctl tune` post-apply could optionally sleep 30s + re-check
  before declaring the SBOB stable.

---

## D2 — Base-image / libc divergence

**Failure mode**: AP execs reference a binary path that's symlinked
elsewhere on a different base image. Specifically:

- AP: `execs: [/bin/sleep]` → R0001 fires on alpine because alpine's
  `/bin/sleep` is a busybox symlink, observed `exepath=/bin/busybox`
- AP: `opens: [/etc/ld-musl-x86_64.path]` (musl) — won't match on
  glibc clusters; or vice versa
- AP: `opens: [/base/N/pg_internal.init]` (postgres-15 cluster path)
  — won't match postgres-16's layout

**Source**: a real-world chain often spans 3+ base images in one
namespace (e.g. log4j-chain: `postgres:15-alpine` + `nginx:1.27-alpine`
+ `curlimages/curl:8.6.0` (alpine) + `eclipse-temurin:11-jdk` (debian)).
Hand-curating per-pod is fragile; learned profiles bake in
cluster-A's exact paths.

**Empirical evidence**: my k3s test (vanilla debian-host, no pixie) +
PoC-agent's iximiuz lab observed different paths for the same
workload. Specifically observer's `sleep` fires R0004 because comm=sleep,
exepath=/bin/busybox; my AP had `/bin/sleep` as the exec path.

**Countermeasure** (none yet shipped):

1. **Path canonicalization at apply time** — extend the Normalizer
   pkg (`pkg/profile/network/` today does CIDR / DNS) with a new
   `pkg/profile/exec/` that:
   - knows about busybox-symlink families (`/bin/sleep` ↔
     `/bin/busybox` for sleep, ls, cat, etc.)
   - rewrites paths to "canonical + tags" in the AP itself
   - emits Normalizer.Rewrite entries (tracked in `nn-report.json`)
2. **Per-base-image variant SBOBs** — `sbobs/alpine/`, `sbobs/debian/`,
   pipeline detects per-pod base image via the deployment manifest
   and applies the right variant
3. **Probabilistic-allow at the rule level** — node-agent's
   `RulePolicy` extended to accept allowed-path patterns (`/bin/{sleep,busybox}`)

Order of effort: 1 < 2 < 3. Recommend starting with 1.

**Status in tuner**: ❌ not implemented. Open for the parallel agent.

**Test plan for the parallel agent**:
- Add a fixture: `testdata/portability/alpine-vs-debian-symlinks.yaml`
  with both alpine + debian observation pairs for the same workload
- Add a `pkg/profile/exec/normalize_test.go` proving rewrites work
- Integration test: apply the same AP to a kind cluster with alpine
  pod and debian pod; both should produce no R0001/R0004 false
  positives

---

## D3 — Rule availability divergence

**Failure mode**: AP carries a `rulePolicies` entry for a rule that
doesn't exist in the target cluster's node-agent build. The AP applies
fine but the rule never fires; the active-diagnosis framework reads
this as a clean run when it should be reading "rule isn't available
here".

**Source**: in-flight rules (e.g. R1100 "failed execve ENOENT") may
exist as a Go file + binding YAML on PoC-agent's branch but not be
compiled into the deployed node-agent on the target cluster.

**Empirical evidence**: PoC-agent observed B's smoking-gun
`exec_failed: Cannot run program "/bin/sh"` in chain-backend stderr
but R1100 fired 0× because kubescape 1.30.2 doesn't ship the rule.

**Countermeasure** (none yet shipped):

1. **Pre-flight rule probe** — at `bobctl tune` start, query
   `kubescape/rulemanager` for the available rule IDs; refuse to
   write `rulePolicies` entries for missing rules + emit a warning
2. **Rule-availability surface in `nn-report.json`** — already have
   the schema for diagnostics; add a `rule_availability: {R0001: true,
   R1100: false, ...}` block so the diagnose framework can interpret
   "no R1100 fire" as "rule absent" rather than "clean"

**Status in tuner**: ❌ not implemented. Open for the parallel agent.

**Test plan**:
- Mock the rule manager endpoint
- Assert tuner refuses to add `R1100` to `rulePolicies` if R1100 isn't
  in the cluster's rule set
- Assert the kpi.json sidecar gains a `rule_availability` field

---

## D4 — Storage server merge behavior

**Failure mode**: `kubectl apply` of a User-supplied AP to a cluster
that has a pre-existing (auto-learned) AP for the same workload
causes strategic-merge-patch to drop new entries. Symptom: applied AP
has 4 execs (including new `psql`) but on-cluster AP shows only 3.

**Source**: kube-apiserver's strategic-merge-patch for slice fields
without merge-key markers. The fields `execs`, `opens`, `syscalls`,
`rulePolicies` lack `+patchMergeKey` directives on the CRD so PATCH
semantics fall back to whole-list overwrite — but only for the fields
the apply manifest carries. If `kubectl apply` reads the on-cluster
AP and computes the diff against `last-applied-configuration`, a
restart of the patch cycle can reach for a stale snapshot.

**Empirical evidence**: PoC-agent's iximiuz lab — psql + rulePolicies
+ recent opens all stripped after apply. My k3s with same storage rc
— NOT reproduced. Difference is cluster-state (stale prior AP on
their cluster) not storage code.

**Countermeasure** (none yet shipped):

1. **Always `kubectl delete applicationprofile <name> -n <ns>` before
   `kubectl apply`** — guarantees a clean write, breaks the
   strategic-merge dance. Should be in the pipeline runbook +
   `scripts/lib/chain-apply-sbobs.sh`.
2. **`kubectl replace --force`** — same effect, atomic
3. **Patch CRD with `+patchMergeKey=path` markers** on `execs[].path`
   etc — upstream fix, requires PR against
   `kubescape/storage`. Would make `kubectl apply` honor slice
   identity correctly without delete-first.

Recommend (1) as the immediate runbook fix + (3) as the upstream PR.

**Status in tuner**: ⚠️ partially — tuner doesn't apply SBOBs itself
(that's the pipeline's job). But `scripts/lib/chain-apply-sbobs.sh`
in `feat/chain-pipeline` SHOULD enforce delete-before-apply when it
ships.

**Test plan**:
- Apply a v1 AP, then a v2 AP without delete; assert v2's new entries
  are visible on-cluster
- If the assertion fails, surface a clear error from
  `chain-apply-sbobs.sh`

---

## D7 — Signal availability divergence in the OBSERVER

**Failure mode**: the observer pipeline (pixie, falco, sysmon, etc.)
doesn't capture every signal the diagnose framework expects. The
verdict layer reads "signal not present" and concludes "behavior
absent" when actually "observer can't see it".

**Source** (per PoC-agent on PR #132):

- **Pixie's `pgsql_events` is SAMPLED**, not event-stream. A sub-1s
  psql query (e.g. log4j's `Payload` exec runs in ~50ms) gets missed.
  Scenario A's `pgwire_datarow_backend_to_pg` signal returns
  `no_event` even though the chain completed end-to-end → verdict
  `A-stage3-blocked` instead of `A`.
- **Pixie's `process_stats` is sampled**, not event-driven. A
  short-lived `Runtime.exec → wait → exit` in <500ms misses entirely.
  PoC-agent had to migrate `new_process_under_java` from pixie to
  kubescape R0001 (event-driven) to recover the signal.

**Architectural mirror of D3**: same "capability advertisement"
pattern, different layer (observer vs rule).

**Countermeasure** (none yet shipped):

- Extend `kpi.json`'s `diagnostics` block with `signal_availability`:
  ```json
  {
    "signal_availability": {
      "pgwire_datarow_backend_to_pg": {
        "source": "pixie/pgsql_events",
        "sampling_rate": "1/100",
        "expected_latency_ms": 800,
        "fidelity": "best-effort"
      },
      "new_process_under_java": {
        "source": "kubescape/R0001",
        "fidelity": "event-driven"
      }
    },
    "instrumentation": {
      "pixie": true,
      "falco": false
    }
  }
  ```
- Verdict layer marks "signal NOT present" vs "signal absent because
  observer can't see it". Critical for any active-diagnosis claim —
  without it, every observer gap looks like clean behavior.

**Status in tuner**: ❌ not started. Co-belongs with D3.

**Test plan**:
- Mock an observer manifest declaring `signal_availability`
- Tuner reads it pre-tune, emits `kpi.json.diagnostics.signal_availability`
- Verdict layer's diagnose can distinguish "no fire" from "no
  visibility"

---

## D7a — `networkEventsStreaming`: installer guidance (the network knob)

**The question installers ask: "do I need `networkEventsStreaming` or
not?"** It is a per-cluster node-agent capability in the
kubescape-operator helm values (`capabilities.networkEventsStreaming:
enable | disable`), **independent of the AP/NN policy you ship**. It
gates whether node-agent streams network events to the rule engine —
i.e. whether the shipped NetworkNeighborhood is actually *evaluated*,
not just present.

**Decision:**

| You want to detect… | Rules | Need `networkEventsStreaming: enable`? |
|---|---|---|
| Unexpected DNS / domain (exfil, C2 callback) | **R0005** | **Yes** |
| Unexpected egress IP (lateral movement, reverse shell) | **R0011** | **Yes** (+ `R0011.isTriggerAlert: true`) |
| Process / exec / file / syscall / malware / crypto | R0001, R0002, R0006, R0008, R0010, R1xxx | **No** — these never read the NN |

**Rules of thumb:**

- **The NN is inert without the knob.** Shipping a tuned
  `NetworkNeighborhood` to a customer does nothing unless *that
  customer's* cluster has `networkEventsStreaming: enable`. With it
  off, R0005/R0011 are **blind** — they silently never fire, which
  reads as "clean / no detection" when it is really "no visibility"
  (the D7 failure mode above). This is the single most common
  portability surprise for network detection.
- **It is opt-in for a reason.** Streaming every network event adds
  node-agent overhead, so the upstream default — and every
  `kubescape/values_*.yaml` *except* the CI one — is `disable`. Only
  enable it for clusters that actually run the network detection story.
- **It is a cluster knob, not an SBOB/profile entry.** Do not try to
  encode it in the AP or NN; it cannot be shipped in the policy. The
  installer must set it in their own helm values.
- **If your product's value prop includes DNS/egress detection, the
  installer guidance MUST instruct customers to enable it** (and set
  `R0011.isTriggerAlert: true` for R0011). Otherwise the network half
  of the policy is dead on arrival.

**In this repo:** `kubescape/values.yaml` (used by `make kubescape`,
the CI tune + portability path) sets `enable` — load-bearing, because
postgres / postgres-vuln / misp expect 12–15 R0005 detections each and
would miss them all if flipped to `disable`. The old `disable` variants
have been moved to `kubescape/deprecated/` (`values_orig`,
`values_vendor`, `valuesk0s`) so they stop being mistaken for a
starting point; `kubescape/values.yaml` is the single source of truth.
Older example READMEs (chain, log4j, argocd) still describe `values.yaml`
as `disable` — stale wording from before the CI flip; the knob, not
those docs, is the source of truth.

### The consumer-URL crashloop (when streaming is enabled)

Enabling `networkEventsStreaming` makes node-agent ship the captured
`NetworkStream` to an HTTP **consumer**. The setting is
`exporters.httpExporterConfig.url`, and node-agent POSTs to
**`<url>/v1/networkstreams`** — so the URL must point at a service that
accepts that path. In the standard kubescape stack that is the
**synchronizer**:

```
http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io
```

**Pitfalls that crashloop or silently drop the stream:**

- **Empty / malformed URL → CrashLoopBackOff.** `HTTPExporterConfig.Validate()`
  rejects an empty URL; if the HTTP exporter is the *only* exporter,
  node-agent hits `InitExporters - no exporters were initialized`
  (`exporters_bus.go`) and `Fatal`s on boot. Fix: give it a real URL, or
  keep another exporter configured (an `alertManagerExporterUrls` entry is
  enough — this is why **bob's CI does NOT crashloop**: it always has the
  alertmanager exporter, so a missing/failed stream consumer only logs a
  Warning).
- **No scheme.** This URL needs the full `http://…` scheme — unlike
  `alertManagerExporterUrls`, which takes bare `host:port` (node-agent
  prepends the scheme there). Putting bare `host:port` here passes
  validation but fails at request time.
- **Wrong service / unreachable consumer → not a crash.** Sends just
  fail with a logged Warning each interval. **Local R0005/R0011 detection
  still works** — those rules evaluate against the captured NN on-node;
  the consumer is only for shipping the stream to a backend. (bob's honey
  stack deploys no synchronizer and sets no `httpExporterConfig.url`, yet
  R0005 fires correctly — proof the consumer is optional for detection.)

**Rule of thumb for installers:** if you only want on-cluster detection,
enable the knob and you need *no* consumer URL (just keep the alertmanager
exporter). Only set `exporters.httpExporterConfig.url` if you actually want
the network stream forwarded to a backend — and then it must be a full
`http(s)://host:port/base-path` reachable consumer.

---

## D5 — Cross-attack time-window contamination (NOT an SBOB problem)

**Failure mode**: diagnose framework reads alerts/conn_stats from a
time window that spans multiple attack scenarios; events from scenario
A leak into the verdict for scenario C.

**Source**: PoC-agent's pxl uses `start_time = -10m` which overlaps
A → B → C iteration.

**Countermeasure**: harness side (their `diagnose.py`), out of scope
for the SBOB / tuner. Documented here so the parallel agent doesn't
chase it.

**Status**: PoC-agent's job. Their fix: shrink to `-90s` + filter by
container UID.

---

## D6 — Image distribution

**Failure mode**: Demo's deployment manifest references images that
aren't published to a reachable registry. Symptom: `ImagePullBackOff`
on every cluster except the one that built them.

**Empirical**: log4j-chain references `ghcr.io/k8sstormcenter/log4j-chain-*`
images that never had a publish workflow. PoC-agent's interim: ttl.sh
anonymous tags (24h TTL).

**Countermeasure**: GHCR publish workflow per image set. There's a
template in main: `.github/workflows/ci-chain-images.yaml` (existing
chain demo). Forking it for log4j is mechanical.

**Status in tuner**: out of scope (image distribution is a repo
concern, not a tuner concern). But the **chain-pipeline manifest's
`deploy:` block** could validate image refs are reachable before
deploying (avoid mid-tune ImagePullBackOff).

---

## Summary table

| Dim | Failure mode | Status | Next action | Effort |
|---|---|---|---|---|
| D0 | Schema mismatch | ✅ resolved | — | — |
| D1 | Env noise (pixie, runc) | ✅ in tuner | TuneConfig.EnvAllowlist + learn-env-noise mode | M |
| D1b | Comm truncation (15-char) | ✅ in tuner | upstream WARN in node-agent | S |
| D2 | Base-image / libc | ❌ not started | `pkg/profile/exec/` normalizer | L |
| D3 | Rule availability | ❌ not started | pre-flight rule probe + `kpi.json.diagnostics.rule_availability` | M |
| D4 | Strategic-merge strip | ✅ runbook fix confirmed | `kubectl delete` before apply in `chain-apply-sbobs.sh` | S |
| D5 | Time-window contamination | n/a | (harness owns it) | — |
| D6 | Image distribution | ⚠️ runbook | GHCR publish workflow + image-reachable validation | S |
| D7 | Observer signal availability | ❌ not started | `kpi.json.diagnostics.signal_availability` (co-PR with D3) | M |

Effort tags: S = <1d, M = 1–3d, L = >3d.

---

## For the parallel agent

Revised priority order (per PoC-agent's #132 feedback — D3+D7
combined unblocks the diagnose-framework layer):

1. **D4 in `scripts/lib/chain-apply-sbobs.sh`** (chain-pipeline
   branch). Tiny. Confirmed fix: `kubectl delete applicationprofile
   <name> -n <ns>` before `kubectl apply`.
2. **D3 + D7 together** (one inner-repo PR). Same architectural
   pattern (capability advertisement: rules + signals). Schema goes
   into `kpi.json.diagnostics`. Without it, every observer gap looks
   like clean behavior. Co-ordinate with PoC-agent on the
   rulemanager endpoint shape + the signal manifest format.
3. **D2 `pkg/profile/exec/` normalizer** in inner repo (vote from
   PoC-agent: expand the existing Normalizer pkg, don't add a new
   top-level concern). Biggest portability gain.
4. **D1 follow-ups** — `TuneConfig.EnvAllowlist` field + `bobctl tune
   --learn-env-noise` mode.
5. **D6 GHCR publish workflow for log4j**. Mechanical; mirrors
   `ci-chain-images.yaml`.

Each is independent of the chain-pipeline refactor (PR #132); they
can land in parallel.

**Additional utility from PoC-agent's #132 reply**: a
`pkg/profile/kubescape_unflatten.go` helper to walk
`RuntimeProcessDetails.processTree.childrenMap` and surface the leaf
process's `comm`/`path`/`pid` at the top level. Used by any diagnose
framework reading R0001's nested processTree — currently
PoC-agent's `diagnose.py` has a private `_flatten_kubescape` impl.
Lifting it into a shared package avoids re-implementation.

---

## Resolved questions (PoC-agent answered on PR #132)

1. **`RulePolicy.AllowedProcesses` exact-match vs glob**: deliberate
   (consistent with how `execs` does exact path matching). Glob upstream
   is a small node-agent issue worth filing — the test pattern from
   `TestEnvironmentalCommAllowlist_ScopedToR0002R0004` carries over
   (assert glob-allow doesn't accidentally widen to R0001).
2. **Normalizer pkg expansion vs new top-level**: expand. D2's
   exec-path rewrites are the same operation conceptually as the
   existing CIDR/DNS rewrites — `pkg/profile/exec/` subpkg.
3. **`rule_availability` placement**: `kpi.json.diagnostics`.
   Adding a sibling key keeps the schema cohesive. See D7's expanded
   shape (includes `signal_availability` + `instrumentation`).

— BoB-agent

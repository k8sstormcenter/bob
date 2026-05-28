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
| D2 | Base-image / libc | ❌ not started | `pkg/profile/exec/` normalizer | L |
| D3 | Rule availability | ❌ not started | pre-flight rule probe + nn-report.json field | M |
| D4 | Strategic-merge strip | ⚠️ runbook | delete-before-apply in chain-apply-sbobs.sh | S |
| D5 | Time-window contamination | n/a | (harness owns it) | — |
| D6 | Image distribution | ⚠️ runbook | GHCR publish workflow + image-reachable validation | S |

Effort tags: S = <1d, M = 1–3d, L = >3d.

---

## For the parallel agent

If another agent picks up implementation, suggested split (in
descending priority by Monday-impact):

1. **D4 fix in `scripts/lib/chain-apply-sbobs.sh`** (chain-pipeline
   branch). Tiny, unblocks PoC-agent's lab.
2. **D2 `pkg/profile/exec/` normalizer** in inner repo. Biggest
   portability gain.
3. **D1 follow-ups** (TuneConfig field + learn mode) in inner repo.
4. **D3 rule probe** — coordinate with PoC-agent on the rulemanager
   query endpoint shape first.
5. **D6 GHCR publish workflow for log4j** — coordinate with PoC-agent.

Each is independent of the chain-pipeline refactor (PR #132); they
can land in parallel.

---

## Open questions

1. Is the `RulePolicy.AllowedProcesses` exact-match a node-agent
   bug or a deliberate design? (Glob would simplify D1 dramatically.)
2. Should the Normalizer pkg expand to cover D2 paths (`exec`
   subpkg), or should that be a new top-level concern? Architecture
   call.
3. For D3, does the `rule_availability` belong in `kpi.json`'s
   `diagnostics:` block or in a new `cluster.json`?

Comment + iterate on this spec via PR #132 or open a fresh issue.

— BoB-agent

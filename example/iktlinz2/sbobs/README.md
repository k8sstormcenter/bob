# chain-2 SBoBs

Seven files, matching chain 1's set. Four are carried over from
`example/iktlinz/sbobs/` byte-for-byte because they are protocol-independent;
two are chain 2's own, for the postgres specimen; chain 1's `cp-agent-worker.yaml`
has no counterpart here and neither chain applies it.

| file | ns | applied |
| --- | --- | --- |
| `cp-agent-orchestrator-orchestrator.yaml` | agent-system | yes |
| `cp-agent-orchestrator-otel-collector.yaml` | agent-system | yes |
| `cp-spog-dashboard.yaml` | oopservability | yes |
| `cp-target-allocator.yaml` | oopservability | yes |
| `cp-oopservability-postgres-postgres.yaml` | oopservability | yes |
| `cp-oopservability-postgres-metric-receiver.yaml` | oopservability | yes |

`agent-worker` and `ran-privileged` are the attacker's pods and get none. The
worker has no benign function to observe at all — it exists to be a foothold —
so any window recorded from it is attack behaviour, and a profile built from one
would declare a DNS sweep, apt installs and a reverse shell as its normal
egress. That is worse than no profile: an empty section is visibly empty, a
poisoned one looks authored.

## Binding

Kubescape does **not** bind these by image. The pod template's
`kubescape.io/user-defined-profile` label is what binds, and the profile name
must be `<label value>-<container name>` — so `oopservability-postgres` plus
`postgres` and `metric-receiver`. `imageID` and `imageTag` are content, not the
binding key; dx's own mirror says as much, that telling a shadow profile from an
effective one "needs the pod's user-defined-profile label, which no profile
carries" (`internal/kssync/collections.go:433`).

The specimen's pod template already carries that label, so it is born bound and
never rolls. Do not stamp it after the fact: patching the template rolls the
Deployment and the attack then lands on a pod the tracer never saw (entlein/dx#172,
 #179).

## Provenance of the two postgres profiles

**Learned by the node-agent, not reconstructed.** The specimen ran unprofiled
first, so kubescape learned it; these are that learned pair, converted rather
than authored — `kubescape.io/managed-by: User` on the annotation, renamed to
`<label>-<container>`, `status`/`resourceVersion`/`uid`/`creationTimestamp`/
`managedFields` stripped, and `spec` kept **exactly** as learned.

| | postgres | metric-receiver |
| --- | --- | --- |
| execs | 24 | 2 |
| opens | 160 (see below) | 149 |
| capabilities | CAP_FOWNER, CAP_SETPCAP, CAP_SYS_ADMIN | null |
| ingress | 1 (`:5432` from agent-system) | null |

An earlier pair was reconstructed from dx's own shadow traces and process
forest with `dx-shadow-fragment`, and the gap is worth recording: 14 execs
against 48, **no opens at all** against 205, and no capabilities or seccomp
profile. That is the distance between what dx's fragment tooling can rebuild and
what the node-agent actually saw, measured on the same pod in the same window.

## Generated, not hand-edited

Both profiles come from the pipeline, so they are reproducible rather than
artisanal:

```
bobctl get → bobctl generalize -d <dir> --sbob <name> → bobctl portable → bobctl validate
```

`generalize --sbob` replaces the learned labels and annotations with
`kubescape.io/managed-by=User`, and its default collapse pass is what makes the
profile durable.

### Why the collapse pass is not optional

The learned `opens` baked **eleven** literal `/dev/shm/PostgreSQL.<random>`
paths. Postgres names its shared-memory segment with a fresh random suffix on
every boot, so none of those eleven can ever recur: the next boot's segment is
unlisted, every backend touching it is an unexpected file access, and R0002
fires continuously. Measured on the born-bound specimen before the pass was
applied — 14 alerts in 5 minutes, one every ~20 seconds, all on the same live
segment. A storm like that pollutes the very window the measurement reads, so
the cell cannot be fired at all.

The collapse pass replaces the eleven with `/dev/shm/⋯`, carrying the union of
their flags. Deleting them would not have worked: `opens` is an allowlist, so
the storm comes from the live path being **absent**, not from the stale ones
being present, and an allowlist is fixed by adding a pattern that matches.

Note `⋯` (U+22EF) and not `*`, and a whole segment either way. There is no
partial-segment glob — every wildcard the node-agent emits in this profile sits
between slashes, `/proc/⋯/cgroup`, `/usr/share/zoneinfo/*` — and `⋯` is what
storage's own detector emits, so it is the form the file has after a round trip.

`bobctl validate` passes the uncollapsed profile, and `--fix` leaves it
unchanged: its dead-wildcard widening is for wildcards that match nothing, while
this is the inverse — literals that matched once and can never match again.
The pass that handles it is `generalize`, upstream of validation.

The finding generalises past this specimen: **a learned profile is not durable
across a restart for any workload that uses a random per-boot path**, and a
stateful server is exactly that workload. Nothing in the artifact marks which
entries are ephemeral.

### What the pass changes

| | learned | shipped |
| --- | --- | --- |
| execs | 48 | 24 |
| opens | 205 | 160 |

The pass also drops `syscalls`, which is right: syscalls are not used here, and
every shipped SBoB in both chains carries `syscalls: null`. An earlier hand
conversion kept the learned 113, which was a divergence from chain 1 introduced
by converting by hand instead of running the pipeline.

## The dc_snoop gap that gap exposed

Chasing why the reconstruction had no `opens` found a capture defect, on one pod:

| source | rows for the postgres pod |
| --- | --- |
| node-agent learned `opens` | 205 |
| dx `dx_process_forest` | 302 |
| dx `dc_snoop` | **0** |

dx's forest saw the pod perfectly well. Its `dc_snoop` surface captured **not one
file-open** on a pod another sensor learned 205 from. This is not the pod being
unobservable; it is targeted.

It has a direct, predictable consequence for the measurement:
`sa-token-read-postgres` scores on `dc_snoop` over this pod, so it grounds
**zero** — and the cause is a dx capture gap, not the attack failing. Step 14's
token read did execute and did land its `pgsql_events` row. Anyone reading the
cell's coverage number must not read that obligation as a miss.

## What the profile turns on

Arguments are captured by the node-agent and land in
`dx_src__kubescape_logs.cmdline`, but only when a rule fires on the process. An
unprofiled pod trips no unexpected-process rule, so nothing is recorded. These
profiles are what make that level reachable: once the specimen is governed, the
RCE's `sh -c id` should fire a rule and have its command line captured. An
over-permissive exec section does not merely miss the RCE — it stops the argument
evidence from ever being collected.

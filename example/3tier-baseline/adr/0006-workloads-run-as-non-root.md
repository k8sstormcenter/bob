# ADR-0006 — Workloads run as non-root

**Status:** accepted — verified at runtime and statically
**Applies to:** every tier

## Context

Most stock container images start as root, do their setup, and drop privileges. It works, it is
conventional, and it means the process that handles untrusted input begins life with every
capability the container is allowed.

Rootless and distroless variants exist for essentially every mainstream image and remove the
problem rather than managing it. Measured on the images this demo uses:

| | stock `nginx` | Chainguard `nginx` |
|---|---|---|
| `User` | *empty* → **root** | `65532` → non-root |
| `Entrypoint` | `/docker-entrypoint.sh` (a shell script) | `/usr/sbin/nginx` (the binary) |
| shell / package manager | present | **absent** |
| files in image | tens of thousands | **203** |

The stock image needs `CHOWN`, `SETUID` and `SETGID` precisely *because* it starts as root and
drops. The Chainguard one never becomes root and needs none of them.

## Decision

Containers set `runAsNonRoot: true`, a numeric `runAsUser`, `allowPrivilegeEscalation: false` and
a read-only root filesystem. Where a rootless image variant exists, use it.

## Verified by

**Runtime** — `R0004 Linux Capabilities Anomalies`, severity 1. Observed on a stock `nginx`
frontend bound to a `capabilities: []` profile:

```
Unexpected capability used: CAP_SETPCAP  in syscall read with PID 135767
Unexpected capability used: CAP_SYS_ADMIN in syscall read with PID 135767
Unexpected capability used: CAP_SETUID   in syscall read with PID 135767
```

**Static** — kubescape controls `C-0013` (non-root), `C-0016` (privilege escalation),
`C-0017` (immutable filesystem), `C-0046` (insecure capabilities).

### R0004 is invisible in `kubectl logs`

The six events above are in alertmanager. In the same window node-agent's stdout contained
**zero** R0004 — zero by RuleID, zero by rule name, zero by message text — while R0002 appeared
19 times. `R0007`, `R1009` and `R1016` behave the same way.

These four carry `isTriggerAlert: false`, but that is a field on the exported alert payload
(`pkg/exporters/http_exporter.go`), not a switch that suppresses it; the stdout exporter applies
no filter on it. The cause of the stdout omission is not established here. The consequence is:
**read alertmanager.** `review.py` does, and lists these four under
`not_visible_in_node_agent_logs` so a reader knows the log view is short.

> **This ADR previously said capability posture was static-only**, on the strength of grepping
> `kubectl logs` for R0004 across a cluster of root-entrypoint images and finding nothing. The
> measurement was real; the conclusion was wrong, because the evidence source was incomplete —
> the same incompleteness already documented for `R0006` elsewhere in this directory, and not
> applied here. A control that works, recorded as missing, is the more expensive error of the two.

## Evidence emitted

```
ADR-0006 [C-0013] container may run as root
         5 workloads: api, cache, db, frontend, worker
         evidence class: DECLARED — read from the manifest, not observed
```

Note the report labels this `declared`, not `observed`, and ranks it below anything the detector
actually saw. That distinction is the point: a coding agent should spend its first edit on a
proven violation, not on a manifest default.

## Consequences

* This ADR is checked at merge time and at scan time, never continuously at runtime.
* It fails identically on every workload using a stock image, which makes it low-information as a
  per-workload finding. The report collapses it to a single entry listing the affected workloads.

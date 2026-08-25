# ADR-0006 — Workloads run as non-root — and why this one is static-only

**Status:** accepted, with a stated verification gap
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

**Static only** — kubescape controls `C-0013` (non-root containers), `C-0016` (privilege
escalation), `C-0017` (immutable filesystem), `C-0046` (insecure capabilities).

### The gap, stated plainly

The runtime rule that would confirm this decision — `R0004 Linux Capabilities Anomalies` — ships
with **`isTriggerAlert: false`**. It is enabled and evaluated, and it enriches other findings, but
it never raises an alert on its own.

This was verified rather than assumed. Across a 60-minute window on a cluster running stock
`nginx`, `postgres`, `redis`, `busybox`, kyverno and kubescape's own components — all of them
root-entrypoint images, against tier profiles declaring `capabilities: []` — **R0004 fired zero
times.** The only runtime rule that fired at all in that window was R0002.

So a tier profile's `capabilities` list does not produce feedback as configured. It still documents
intent, and it still enriches other alerts, but an ADR must not depend on it for detection.

There is a second, independent reason not to lean on it even if it did alert: capability use
happens during container *initialisation*, which is the window where the profile is not yet
enforcing (see [ADR-0005](0005-every-workload-declares-its-tier.md) on warm-up). The
drop-privileges pattern would be systematically missed regardless.

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

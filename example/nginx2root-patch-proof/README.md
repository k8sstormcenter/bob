<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# nginx2root: before/after evidence

Worked example for [`docs/proposals/sbob-coverage.md`](../../docs/proposals/sbob-coverage.md). The requirement is in the proposal; this page has the setup and every piece of evidence behind each status.

## Setup

| | affected | fixed |
|---|---|---|
| nginx | `1.31.8@sha256:165ddde8…` | `1.31.9@sha256:08f354a3…` |
| behind it | Argo CD v3.6.1 | Argo CD v3.6.1 |
| config | 4 workers, `listen 443 ssl`, `http2 on`, `location /argocd/` → Argo CD API server | identical |

- **Cluster:** three-node k3s lab (AMD EPYC-Rome) with Kubescape and Pixie.
- **Reproduction:** Rapid7's published crash trigger ([sfewer-r7/CVE-2026-123007](https://github.com/sfewer-r7/CVE-2026-123007)), unmodified, run over loopback from a sidecar in the nginx pod. Same method on both builds.
- **Not covered:** code execution. Rapid7's code-execution path needs AVX-512, which these CPUs lack. That run follows on AVX-512 hardware.

## Advisory indicators → what we observed

Neither the vendor nor the researchers publish hashes, domains or IPs for this one. The attack is protocol-driven, so the indicators are behavioural. Each row is one indicator, the runtime observable it maps to, and what the run produced.

| Indicator | Observable | Source | 1.31.8 | 1.31.9 |
|---|---|---|---|---|
| **denial of service:** worker crash | nginx master logs a worker exit on a signal | `log` | `16:06:18 [alert] worker process 9 exited on signal 11 (core dumped)` | none |
| | kernel trap in an nginx process | `kernel` | `16:06:18 traps: nginx[371959] general protection fault … in libc.so.6` | none |
| | master respawns a worker outside start-up (privilege drop) | `runtime` (capability) | `CAP_SETUID` at 16:06:18 | only during pod start-up |
| reproduction reached its decision point | the reproduction's own success markers | `probe` | "cleanup over-credit confirmed", then "worker crashed", exit 0 | connection reset by nginx after ~17 s, before the overflow; exit 1 (2 of 2) |
| unusually large single HTTP/2 flow (tens of GB inbound, minutes long) | bytes and duration per connection | `wire` | not evaluable: the loopback connection was seen, its bytes were not | not evaluable |
| **code execution:** worker starts a program | process launched by an nginx worker | `runtime` | none during the trigger (start-up `sh`/`openssl` only) | same |
| worker writes outside its directories | file write | `runtime` | none during the trigger | none |
| worker connects somewhere new | egress | `runtime` / `wire` | none during the trigger (DNS at start-up only) | same |
| **host takeover:** SCTP use from the worker | SCTP socket, `sctp` module load | `runtime` | not reached | not reached |

| Impact | 1.31.8 | 1.31.9 |
|---|---|---|
| denial of service | **VIOLATED** | **COMPLIANT** |
| code execution | NOT_OBSERVED (not reached) | NOT_OBSERVED |
| host takeover | NOT_OBSERVED | NOT_OBSERVED |

## Reading the evidence

- **Three independent sources agree on the crash:** nginx's log, the kernel, and the runtime sensor's view of the respawn. Any one could have another cause; all three in the same second, during the reproduction, on the affected build only, are a crash caused by the reproduction.
- **The crash leaves no code-execution traces.** During the trigger no program was launched, no file written and no connection opened. That separates "a worker died" (a restart, a short outage) from "a worker was taken over" (an attacker inside the cluster). It is also why code execution stays NOT_OBSERVED instead of COMPLIANT: it was never reached, so nothing about it is proven.
- **Start-up noise is separated by time.** Both builds show the same start-up behaviour (`sh`, `openssl`, config reads, DNS, the privilege drop). Only events after start-up count. A profile learned before the reproduction makes that automatic.

## Limits of this run

- **Traffic volume wasn't measurable.** The reproduction only reached the bug over loopback inside the pod. Over a NodePort, a pod IP or a client pod it stalled before the faulty code. Loopback traffic was visible as a connection, but its byte counts and HTTP/2 content were not, so the "huge single flow" indicator is not evaluable here.
- **No core dump was kept**, because the node has no core-dump collector.
- **No CPU or memory series**: the cluster keeps no metrics history.

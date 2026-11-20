<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# nginx2root: before/after evidence

Worked example for [`docs/proposals/sbob-coverage.md`](../../docs/proposals/sbob-coverage.md). The requirement is in the proposal; this page has the evidence behind each status.

## Result

On nginx 1.31.8, an unauthenticated HTTP/2 client made the nginx worker run a program inside a Kubernetes pod, and the runtime sensor saw it. On 1.31.9, nothing of that happened.

| Impact | nginx 1.31.8 | nginx 1.31.9 |
|---|---|---|
| code execution | **VIOLATED**: worker started `sh` → `touch`, uid 101; caught by Kubescape | **COMPLIANT**: the published reproduction recognises the fixed build and does not start |
| information disclosure | **VIOLATED**: worker memory leaked, enough to defeat ASLR | COMPLIANT |
| denial of service | **VIOLATED**: workers abort or segfault | **COMPLIANT**: the crash reproduction is refused before the overflow |
| host reach | **VIOLATED**: a compromised pod read a canary file on the node; detected | not reachable |

## What must not be seen again after the patch

These are the observations from the affected build. They are what the requirement keeps watching for on every later build.

| Observation on 1.31.8 | Source | Evidence |
|---|---|---|
| **a program started by an nginx worker** | runtime (Kubescape R0001) | `Unexpected process launched: touch`, 22:16:31.804Z, profile `completed` before the attempt. Process tree: `nginx` master (uid 0) → `nginx` worker → `/bin/sh -c -- touch /tmp/sbob-proof-A-plain-1` (uid 101) → `/usr/bin/touch` (uid 101) |
| **a file created by the worker outside its directories** | runtime (Kubescape R0002) + marker | `touch` opened `/tmp/sbob-proof-A-plain-1` with `O_WRONLY\|O_CREAT` at 22:16:31.806Z; independent `stat`: `101:101 644` |
| **worker memory sent to the client** | reproduction | 14,393-byte disclosure, from which ASLR was resolved |
| **heap corruption** | nginx log | `double free or corruption (!prev)` |
| **a worker dying** | nginx log, kernel | `worker process 15 exited on signal 6 (core dumped)` (22:16:34); other runs: `signal 11`, with a kernel general-protection fault in `libc.so.6` |
| new egress from the worker | runtime | none: the payload ran a local command only |

The sensor alert came 1.8 ms before the marker file's timestamp, against a profile learned before the attempt. No other alert on the nginx container came from the attack. Our own `kubectl exec` marker checks raised alerts too (`stat`, `runc` init, `CAP_SETUID`); the requirement discounts processes started by `exec`.

## How it was run

| | Code-execution run | Crash run |
|---|---|---|
| cluster | kind, one node, Intel Xeon with AVX-512 | three-node k3s, AMD EPYC-Rome (no AVX-512) |
| sensor | Kubescape, chart from `soc` `lts` | Kubescape and Pixie |
| nginx | Rapid7's reference 1.31.8 image / 1.31.9 amd64; Rapid7's config | 1.31.8 / 1.31.9; config with `location /argocd/` → Argo CD API server |
| reproduction | Rapid7's code-execution PoC, marker `touch /tmp/sbob-proof-<run>` | Rapid7's crash trigger |
| attempts | 1.31.8: 1 of 1 succeeded; 1.31.9: refused 2 of 2 | 1.31.8: crash; 1.31.9: reset 2 of 2 |

Both used the published code unmodified ([sfewer-r7/CVE-2026-123007](https://github.com/sfewer-r7/CVE-2026-123007)), over loopback from a sidecar in the nginx pod. The nginx profile was learned before each attempt, and the attempt ran against a freshly started pod.

## What it took to reproduce

- **Hardware.** The published code-execution path needs AVX-512 on the CPU running nginx.
- **Loopback.** Through a NodePort, a pod IP or a client pod the reproduction stalled before the bug.
- **A pod that looks like the reference container.** Two earlier attempts in Kubernetes reached the memory leak but not code execution: the leak matched none of the PoC's heap-layout candidates. The same host reproduced it in plain Docker on the first try. In Kubernetes it worked once three differences were removed: two requests sent to the fresh worker before the attempt, a long pod hostname (nginx keeps it on its heap), and service-link environment variables.

For a maintainer this also means: a failed reproduction proves little. The requirement reports a reproduction that didn't reach its decision point as NOT_OBSERVED, never as COMPLIANT.

## Limits

- The advisory's full SCTP-kernel escape to host *root* was not run (we don't build a working kernel escape). Instead we proved the consequence that matters — a compromised pod reading a file on the node — by giving the pod one declared host mount and a canary: the read succeeded and fired a runtime alert. The escape's own indicators (namespace/trace syscalls, SCTP module autoload) are detectable, one already, the other once a sensor fix lands.
- On the fixed build, the code-execution reproduction declines to start, so its negative is "recognised as fixed". The crash reproduction gives the behavioural negative: nginx resets the connection before the overflow.
- Traffic volume per connection was not measurable over loopback.

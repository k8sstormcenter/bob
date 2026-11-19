<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# nginx2root: before/after evidence

Worked example for [`docs/proposals/sbob-coverage.md`](../../docs/proposals/sbob-coverage.md). The requirement is in the proposal; this page has the setup and every piece of evidence behind each status.

## Result

| Impact | nginx 1.31.8 | nginx 1.31.9 |
|---|---|---|
| denial of service | **VIOLATED**: worker killed in both environments | **COMPLIANT**: the crash reproduction is refused before the overflow |
| information disclosure | **VIOLATED**: 14,393 bytes of worker memory leaked to an unauthenticated client | not engaged |
| code execution | **NOT_OBSERVED**: attempted twice on AVX-512 hardware, did not complete | not engaged |
| host takeover | NOT_OBSERVED | NOT_OBSERVED |

For a maintainer: on the affected build, any client could crash workers and read worker memory. Code execution was not reproduced here, which is not the same as impossible. The upgrade removed the crash.

## Two environments

| | Environment 1 | Environment 2 |
|---|---|---|
| cluster | three-node k3s, AMD EPYC-Rome (no AVX-512) | kind, Intel Xeon with AVX-512 |
| nginx | `1.31.8` / `1.31.9`, config with `location /argocd/` → Argo CD API server | Rapid7's reference image digest for 1.31.8 / amd64 1.31.9, Rapid7's config verbatim |
| reproduction | Rapid7's crash trigger | Rapid7's code-execution PoC, marker command `touch /tmp/sbob-proof-<run>` |
| baseline | none (pods younger than the learning window) | nginx profile learned before each attempt, then a freshly started pod |

Both used the published code unmodified ([sfewer-r7/CVE-2026-123007](https://github.com/sfewer-r7/CVE-2026-123007)), over loopback from a sidecar in the nginx pod. Over a NodePort, a pod IP or a client pod, it stalled before reaching the bug.

## Indicators → evidence

Neither the vendor nor the researchers publish hashes, domains or IPs for this one. The attack is protocol-driven, so the indicators are behavioural.

| Indicator | Observable (source) | 1.31.8 | 1.31.9 |
|---|---|---|---|
| **denial of service** | worker exit on a signal (`log`) | env 1: `worker process 9 exited on signal 11 (core dumped)`; env 2: `worker process 17 exited on signal 6 (core dumped)`, twice | none |
| | heap corruption detected by glibc (`log`) | env 2: `double free or corruption (!prev)`, twice | none |
| | kernel trap in nginx (`kernel`) | env 1: `nginx[371959] general protection fault … in libc.so.6`. env 2: none, because an abort is not a kernel fault | none |
| | master respawning a worker outside start-up (`runtime`, capability) | env 1: `CAP_SETUID` at the crash second | none |
| **information disclosure** | the reproduction reports leaked memory (`probe`) | env 2: `captured 14393-byte memory disclosure`, twice | — |
| reproduction reached the bug | the reproduction's own markers (`probe`) | env 1: "cleanup over-credit confirmed"; env 2: "vulnerable cleanup observed", twice | env 1: connection reset by nginx after ~17 s, 2 of 2; env 2: the PoC refused to start (its fingerprint doesn't match 1.31.9), 2 of 2 |
| **code execution** | marker file written by the worker, uid 101 (`probe`, independent `stat`) | absent in both env 2 attempts: the PoC's leak did not match its heap profile ("0 candidates") | — |
| | program launched by a worker; write outside its directories; new egress (`runtime`) | none from the worker in any run | none |
| **host takeover** | SCTP use from the worker (`runtime`) | not reached; `sctp` module not loaded on either host | — |

## What the sensors did and didn't see

- **Crash and corruption are visible only in nginx's own log, plus the kernel when the fault is a trap.** In-process heap corruption, and a worker aborting on it, trigger no runtime-sensor rule. That's expected: nothing new is executed, opened or connected. The requirement therefore reads the `log` and `kernel` sources for denial of service.
- **Every runtime alert on the nginx container in environment 2 came from the harness itself**: the `kubectl exec` used for the marker checks (`stat`, `runc` init, its capability set). The requirement must discount processes started by `exec`, as the evaluator already does for architecture checks.
- **The memory disclosure is visible only to the reproduction.** No sensor sees bytes leaving in an HTTP/2 response as a leak. That makes `probe` the source for it.
- **Code-execution indicators were silent in every run, which matches the outcome.** They would be the decisive ones if the final stage had succeeded.

## Limits

- Code execution was not reproduced. The PoC's final stage depends on a heap profile from its authors' test host, and the leak on our hosts matched no candidate. A different host, or the PoC's standalone Docker recipe, may behave differently.
- On 1.31.9 the code-execution PoC doesn't engage, so the fixed-build negative comes from the crash reproduction in environment 1.
- Traffic volume per connection was not measurable over loopback.

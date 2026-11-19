<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# Case study: proving an nginx patch with a coverage requirement

This is the worked example for [`docs/proposals/sbob-coverage.md`](../../docs/proposals/sbob-coverage.md). It shows a before/after check: one requirement, evaluated against an affected and a fixed build, gives a maintainer evidence that an upgrade removed the effect of a published vulnerability on the path their tests exercise.

## The advisory

On 2026-11-18 nginx fixed five vulnerabilities in its HTTP/2 implementation that allow unauthenticated remote code execution (CVE-2026-123007 and four related CVEs; fixed in 1.31.9 and 1.30.7). Rapid7 published a reproduction: a crash-level trigger and a full code-execution proof of concept ([sfewer-r7/CVE-2026-123007](https://github.com/sfewer-r7/CVE-2026-123007)).

## Setup

| | A (affected) | B (fixed) |
|---|---|---|
| Namespace | `argocd-nginx-a` | `argocd-nginx-b` |
| Application | Argo CD v3.6.1 (namespace install) | Argo CD v3.6.1 (namespace install) |
| Reverse proxy | `nginx:1.31.8@sha256:165ddde8…` | `nginx:1.31.9@sha256:08f354a3…` |
| nginx config | 4 workers, `listen 443 ssl`, `http2 on`, static root, `location /argocd/` → Argo CD API server | identical |

- **Cluster:** a three-node k3s lab cluster (AMD EPYC-Rome), with Kubescape for runtime observation and Pixie for protocol tracing.
- **Reproduction:** Rapid7's published crash trigger, unmodified. It runs from a sidecar container inside the nginx pod and talks to nginx over loopback (`https://127.0.0.1:443/`). A and B use the same method.
- **Why the crash trigger, not RCE:** the full code-execution path needs AVX-512 on the CPU running nginx, and the lab CPUs don't have it. The success indicator is therefore an nginx worker exiting on a signal.

## The requirement

```yaml
requirements:
  - id: COV-0101
    summary: the HTTP/2 path is exercised and the published reproduction has no effect
    observed:
      - source: wire
        dst_workload: nginx
        proto: http2
        encrypted: 1
        what: requests reached nginx over HTTP/2 with TLS
      - source: probe
        reproduce: CVE-2026-123007
        what: the published reproduction ran against this build
    violated:
      - source: probe
        reproduce: CVE-2026-123007
        succeeded: true
        broken: the reproduction reached its success indicator
        fix: upgrade nginx to 1.31.9 or 1.30.7
      - source: log
        workload: nginx
        message: {regex: 'worker process [0-9]+ exited on signal'}
        broken: an nginx worker died on a signal while the reproduction ran
        fix: upgrade nginx to 1.31.9 or 1.30.7
```

## Results (2026-11-19)

| | A, nginx 1.31.8 | B, nginx 1.31.9 |
|---|---|---|
| HTTP/2 path exercised (`curl --http2`, direct and via `/argocd/`) | yes | yes |
| Reproduction ran | yes, 1 attempt | yes, 2 attempts |
| Reproduction's own success markers | both reported | none |
| nginx error log | `worker process 9 exited on signal 11 (core dumped)` | no worker exit |
| Client outcome | trigger completed | connection reset after about 17 s, before the faulty accounting is reached |
| Pod restarts | 0 (nginx respawned the worker) | 0 |
| **COV-0101** | **VIOLATED** | **COMPLIANT** |

The requirement draws one statement from both runs: the HTTP/2 path was exercised, the published reproduction worked on the affected build, and it has no effect on the fixed build. Kept in CI, the same requirement is a regression check for every later nginx bump.

## What this proves, and what it doesn't

- It proves the upgrade removed the crash on the exercised HTTP/2 path, with the same configuration and the same reproduction on both builds.
- It doesn't prove code execution was possible before the patch. That needs the full proof of concept on AVX-512 hardware, which is the next run.
- It doesn't replace the vendor advisory. It shows that this deployment, as tested, no longer behaves as the advisory describes.

## Lessons for the harness

1. **The delivery path matters.** Through a NodePort, to a pod IP over the cluster network, and from a client pod, the reproduction stalled in all three cases before reaching nginx's faulty code. Only loopback inside the pod reproduced it. A reproduction that never reaches the code proves nothing either way, so the `observed` predicate on the probe has to check that it ran to its decision point.
2. **Crash and code execution need different indicators.** A crash leaves a worker exit in nginx's own log and no new process. Code execution leaves a process started by the worker and file writes, which the runtime sensor sees directly. The requirement lists both.
3. **Learn the baseline before probing.** Runtime detections only separate the two builds once the proxy's normal behaviour is learned. In this run the nginx pods were younger than the sensor's learning window, so their detections reflected start-up and test traffic on both builds alike, and they aren't used as evidence here. The next run learns the baseline first.

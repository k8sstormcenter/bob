<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# Proposal: SBoB Coverage

Status: draft · Pilot: Argo CD

## What this is

Maintainers write **requirements** about what their software does at runtime. Their own tests run on a throwaway k3s, observed from the outside by Kubescape and Pixie. Each requirement comes back with one status:

- **VIOLATED**: something ruled out happened;
- **NOT_OBSERVED**: the tests never exercised it, so nothing is proven;
- **COMPLIANT**: exercised, and nothing ruled out happened.

The evidence that decided each status comes with it. A green run leaves the component's SBoB behind.

## Example: did the nginx upgrade actually close nginx2root?

On 2026-11-18 nginx fixed five HTTP/2 vulnerabilities that allow unauthenticated code execution in the worker process (CVE-2026-123007 and four related CVEs). Rapid7 published a reproduction. This is the requirement the advisory turns into:

```yaml
- id: CVE-2026-123007
  container: nginx
  observed:                                   # must all hold, or the result is NOT_OBSERVED
    - wire:    { proto: http2, tls: true }    # the tests used the vulnerable path
    - probe:   { reproduce: CVE-2026-123007, reached: decision-point }
    - profile: { baseline: learned }          # normal behaviour known before the probe
  violated:                                   # any match is a finding
    - spec:    { version: '>=1.9.5 <1.30.7 || >=1.31.0 <1.31.9' }  # affected build running
    - probe:   { reproduce: CVE-2026-123007, succeeded: true }
    - log:     { message: 'exited on signal' }                    # worker crashed
    - runtime: { exec: {not: [/usr/sbin/nginx]} }                 # worker started a program
    - runtime: { write: {not: ['/var/cache/nginx/*', '/var/log/nginx/*']} }
    - runtime: { egress: {not: [backends]} }                      # talked to anything but its upstreams
    - runtime: { socket: AF_SCTP }                                # the advisory's step to host root
  host:                                       # the advisory's mitigations, checked on the node
    - aslr: full
    - kernel_module: { sctp: not-loadable }
    - spec: { run_as: {not: root} }
```

First lab run: two Argo CD instances, each behind an nginx HTTP/2 reverse proxy, one on 1.31.8 and one on 1.31.9. The same tests and the same published crash trigger ran against both.

| Check | 1.31.8 | 1.31.9 |
|---|---|---|
| affected version running | **yes** | no |
| HTTP/2 path exercised | yes | yes |
| reproduction reached its decision point | yes | yes |
| reproduction succeeded | **worker crash (signal 11)** | no, connection reset |
| program started, writes, egress, SCTP | not evaluable: baseline not yet learned | not evaluable: baseline not yet learned |
| **Status** | **VIOLATED** | **NOT_OBSERVED** until the baseline rerun |

The fixed build isn't COMPLIANT yet, on purpose. Without a learned baseline, the runtime checks can't tell normal start-up from a compromised worker, so the result says so instead of passing. Code execution itself needs AVX-512 hardware, which the lab doesn't have; that run comes next. Details: [`example/nginx2root-patch-proof`](../../example/nginx2root-patch-proof/README.md).

## How an advisory becomes a requirement

1. **Match.** The advisory names a component and version range. The project's image digests and loaded libraries show whether it ships that component.
2. **Extract the facts.**

   | From the advisory | Becomes |
   |---|---|
   | affected and fixed versions | the version check |
   | preconditions (here: HTTP/2 on a TLS listener) | `observed`: the tests must exercise exactly that path, or the result is NOT_OBSERVED |
   | impact (here: code execution as the worker user) | `violated`: what that process must never do (start programs, write outside its directories, connect anywhere new, crash) |
   | known chains (here: SCTP to reach root) | `violated`: the chain's first step |
   | mitigations (here: ASLR) | `host`: checked on the node |
   | published reproduction | `probe`: run before and after, with its own success indicator |

3. **Draft, then review.** The harness drafts the block from these fields. The maintainer reviews it and commits it next to the tests.
4. **Run before and after the fix.** VIOLATED on the affected build, COMPLIANT on the fixed one, with the evidence for both.
5. **Keep it.** The requirement stays in CI as a regression check for every later bump.

## What else a requirement can check

| `source` | Examples | Observed by |
|---|---|---|
| `profile` / `runtime` | programs started, files and shared libraries opened (e.g. "the affected libxml2 is no longer loaded"), capabilities, network neighbours | Kubescape |
| `wire` | endpoints, methods and status codes inside TLS; WebSockets; PII in bodies; JWT scopes; TLS version and key-exchange group; resets and retries | Pixie |
| `k8sapi` | which component calls which Kubernetes API verb, read from the traffic, not an audit log | Pixie |
| `spec` / `rbac` | image digests, security context, granted vs. used permissions | cluster API |
| `probe` / `log` | the harness's own requests and reproductions; container log lines | harness |

## How it runs

```yaml
- uses: k8sstormcenter/sbob-coverage-action@v0
  with:
    requirements: .sbob/requirements.yaml
    install: ./hack/install-for-coverage.sh
    test: ./test/remote/run-e2e-remote.sh make test-local
    fail-on: VIOLATED
```

The action installs k3s natively with Kubescape and Pixie, lets the project install and test itself, learns a baseline before probes run, and reports per requirement. The same commit run ten times must produce the same report. The evaluator is the one already used to check architecture decisions at runtime ([commons-grid-dynamics-manifest `compliance/`](https://github.com/k8sstormcenter/commons-grid-dynamics-manifest/tree/kcna26/compliance)).

## Pilot: Argo CD

Argo CD has a broad e2e suite, already runs it on k3s, and ships a supported in-cluster test mode (`test/remote`). In the first lab run, that mode exercised `helm`, `kustomize` and `git` in the repo-server. No fork is needed.

The first run of this example, with setup, requirement, results and lessons, is in [`example/nginx2root-patch-proof`](../../example/nginx2root-patch-proof/README.md).

## Milestones

| | Deliverable |
|---|---|
| M0 | Argo CD e2e under observation (done) |
| M1 | Requirements file + evaluator; draft-from-advisory; baseline-before-probe |
| M2 | nginx example complete: baseline rerun, and code execution on AVX-512 hardware |
| M3 | GitHub Action; `k8sapi` and `wire` checks |
| M4 | Pull-request reports on a fork |

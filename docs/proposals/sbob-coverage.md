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

On 2026-11-18 nginx fixed five memory-safety bugs. The headline one, CVE-2026-123007, is an HTTP/2 flow-control overflow that an unauthenticated client can use to crash a worker or, under harder conditions, run code as the worker user. A second bug, CVE-2026-123633, affects HTTP/2 reverse proxies. Fixed in 1.31.9 and 1.30.7.

A crash and code execution are different outcomes for a maintainer: a restarting worker versus an attacker inside the cluster. The requirement keeps them apart, and each line is something observable at runtime:

```yaml
- id: CVE-2026-123007
  container: nginx
  applies:                                  # the advisory's preconditions, seen on the live system
    - spec:    { version: '>=1.9.5 <1.30.7 || >=1.31.0 <1.31.9' }
    - wire:    { proto: http2, tls: true }  # the tests used the vulnerable path
  observed:
    - probe:   { reproduce: CVE-2026-123007, reached: decision-point }
  violated:
    denial-of-service:                      # the worker dies
      - log:     { message: 'worker process .* exited on signal' }
      - log:     { message: 'double free or corruption' }          # glibc caught heap corruption
      - kernel:  { trap: [segfault, general protection], process: nginx }
      - runtime: { capability: CAP_SETUID, outside: startup }      # the master respawning a worker
    information-disclosure:                 # worker memory reaches the client
      - probe:   { reproduce: CVE-2026-123007, stage: memory-disclosure }
    code-execution:                         # the worker does what nginx never does
      - runtime: { exec: {not: [/usr/sbin/nginx]}, parent: nginx }
      - runtime: { write: {not: ['/var/cache/nginx/*', '/var/log/nginx/*']} }
      - runtime: { egress: {not: [upstreams, dns]} }
    host-takeover:                          # the advisory's chain to root
      - runtime: { socket: AF_SCTP }
      - runtime: { kernel_module: sctp }
```

Two lab environments ran it: a k3s cluster with the published crash trigger, and an AVX-512 host with the published code-execution proof of concept.

| Impact | 1.31.8 | 1.31.9 |
|---|---|---|
| denial of service | **VIOLATED**: workers killed (signal 11, signal 6 after glibc detected heap corruption) | **COMPLIANT**: the crash reproduction is refused before the overflow |
| information disclosure | **VIOLATED**: 14,393 bytes of worker memory leaked | not engaged |
| code execution | **NOT_OBSERVED**: attempted twice, the final stage did not complete on our hosts | not engaged |
| host takeover | NOT_OBSERVED | NOT_OBSERVED |

So the maintainer learns what an attacker would have had on the old build (crash any worker, read worker memory) and what the upgrade removed. Code execution stays NOT_OBSERVED, not COMPLIANT: nothing about it is proven either way. The crash and the leak show up in nginx's log and the reproduction's own report; the code-execution signals (a program started by the worker, writes, new connections) stayed silent, as they should when that stage isn't reached. Evidence, line by line: [`example/nginx2root-patch-proof`](../../example/nginx2root-patch-proof/README.md).

## How an advisory becomes a requirement

1. **Match.** The advisory names a component and version range. The project's image digests and loaded libraries show whether it ships that component.
2. **Extract the facts.**

   | From the advisory | Becomes |
   |---|---|
   | affected and fixed versions | the version check |
   | preconditions (here: affected version, HTTP/2 on a TLS listener) | `applies`: checked on the live system; the tests must exercise exactly that path, or the result is NOT_OBSERVED |
   | impact, split by outcome (here: crash, memory disclosure, code execution as the worker user) | `violated`, one group per outcome: what is observable when it happens (worker dies and is respawned; memory reaches the client; worker starts programs, writes outside its directories, connects anywhere new) |
   | known chains (here: SCTP to reach root) | `violated`: the chain's first step |
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
| `probe` / `log` / `kernel` | the harness's own requests and reproductions; container log lines; kernel traps on the node | harness |

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

## Milestones

| | Deliverable |
|---|---|
| M0 | Argo CD e2e under observation (done) |
| M1 | Requirements file + evaluator; draft-from-advisory; baseline-before-probe |
| M2 | nginx example complete: baseline rerun, and code execution on AVX-512 hardware |
| M3 | GitHub Action; `k8sapi` and `wire` checks |
| M4 | Pull-request reports on a fork |

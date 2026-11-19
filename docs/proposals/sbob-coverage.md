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

The maintainer writes two lines — a CVE and a before/after check:

```yaml
verify:
  - cve: CVE-2026-123007      # the fragment comes from the corpus; you don't write it
    component: nginx
```

The watch-list is **not hand-written**. It is a *subtract fragment* that we distilled once, from running the published exploit on the vulnerable build. The SBoB already has a broad allow-list learned from the tests (nginx serving traffic); the fragment is subtracted from it, across every tracer an SBoB++ carries — processes and files, plus the L7 tracers for HTTP, HTTPS, WebSocket and DNS:

```yaml
# subtract: behaviours seen while CVE-2026-123007 compromised nginx 1.31.8.
# Alerts only when one recurs inside the allow envelope — i.e. under compromise.
subtract:
  exec:  any                 # a reverse-proxy worker starts no program   (seen: worker → sh → touch)
  files: creates-outside-own # a write outside nginx's own dirs            (seen: /tmp marker, uid 101)
  http:  response-leaks-memory | single-flow-oversized   # the ASLR leak; the ~120 GiB one-connection flood
  dns:   name-not-in-baseline            # a lookup the app never makes    (C2 / exfil)
  ws:    peer-or-message-not-in-baseline # (none for this CVE; the slot exists)
  egress: peer-not-upstream              # a connection to anywhere new
  dies:  worker-exits-on-signal          # the crash / DoS outcome, kept separate from compromise
```

In a Kubernetes lab, the published exploit ran against both builds, nginx profile learned first:

| Outcome | 1.31.8 | 1.31.9 |
|---|---|---|
| code execution | **FIRES**: worker started `sh` → `touch` as uid 101, caught 1.8 ms before the file appeared | silent: the exploit won't engage the fixed build |
| information disclosure | **FIRES**: worker memory left in a response, enough to defeat ASLR | silent |
| denial of service | **FIRES**: worker aborts after heap corruption | silent: the connection is reset before the overflow |
| host reach | **FIRES**: a compromised pod read a canary on the node | not reachable |

That is what the maintainer needs to know: on the old build, any client could run commands inside the pod; after the upgrade, nothing in the list happens. The 1.31.8 observations (a program started by the worker, a file it wrote, heap corruption, a dying worker) are exactly what the requirement keeps watching for on every later build. Evidence, line by line: [`example/nginx2root-patch-proof`](../../example/nginx2root-patch-proof/README.md).

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

<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# Proposal: SBoB Coverage

**A GitHub Action that tells maintainers, on every pull request, whether their integration tests exercised the runtime behaviour they care about, and whether the behaviour they ruled out stayed out.**

A green run leaves behind the component's SBoB, ready to ship with the release.

Status: draft · Pilot: Argo CD

---

## What we are doing

1. The maintainer states **requirements** about runtime behaviour: what the tests must exercise, and what must never happen.
2. The project's own tests run on a throwaway k3s, observed from the outside by Kubescape (processes, files, network, syscalls) and Pixie (protocols, including inside TLS).
3. A generic evaluator turns the observations into **evidence events** and checks every requirement against them.
4. Each requirement gets one status (**COMPLIANT**, **VIOLATED** or **NOT_OBSERVED**) with the evidence that decided it.

There is no new detector here. The evaluator is the one already used to check architecture decision records (ADRs) at runtime ([commons-grid-dynamics-manifest `compliance/`](https://github.com/k8sstormcenter/commons-grid-dynamics-manifest/tree/kcna26/compliance)). A coverage spec is just another requirements file for it.

## Why

**Line coverage says which code ran. It does not say what the software did to its environment while the tests ran:**

- which programs it executed, which files and shared libraries it opened;
- which hosts it talked to, over which protocol, and whether the traffic was encrypted;
- which Linux capabilities and Kubernetes API permissions it actually used.

That is the security-relevant part of a component. It is rarely measured, because it used to be hard to observe without changing the software under test. A runtime sensor observes it from the outside, with no rebuild and no instrumentation.

**Grants are decided without measurements.** A Helm chart has to grant whatever its users might need, and maintainers rarely have data on which grants their own tests exercise. A run that passes without using a grant gives them that data.

## Requirements: how a maintainer writes them

One block per requirement. Nothing requirement-specific lives in code.

- `observed:` predicates must **all** hold for COMPLIANT. Each one yields a proof line, and an unmet one is named in the result.
- `violated:` predicates: every matching event is a finding, carrying `broken` and `fix`.

```yaml
requirements:
  - id: COV-0001
    summary: the tests drive manifest rendering in the repo-server
    observed:
      - source: profile
        container: argocd-repo-server
        execs: {regex: '/(helm|kustomize|git)$'}
        what: helm, kustomize and git ran during the tests
      - source: wire
        src_workload: argocd-repo-server
        dst_workload: argocd-e2e-server
        what: the repo-server fetched from the test repositories

  - id: COV-0002
    summary: the repo-server never starts a shell or a downloader
    violated:
      - source: runtime
        container: argocd-repo-server
        exec: {regex: '/(sh|bash|curl|wget)$'}
        broken: the repo-server started a shell or a downloader
        fix: render through the configured tools only

  - id: COV-0003
    summary: a library version named in an earlier advisory is no longer loaded
    violated:
      - source: profile
        opens: {regex: 'libxml2\.so\.2\.9\.13$'}
        broken: the affected libxml2 build is still mapped at runtime
        fix: rebuild on the fixed base image
    observed:
      - source: profile
        container: argocd-repo-server
        what: the repo-server profile was read back after the tests

  - id: COV-0004
    summary: only the application controller lists Secrets cluster-wide
    violated:
      - source: k8sapi
        resource: secrets
        verb: list
        scope: cluster
        workload: {not: [argocd-application-controller]}
        broken: a component listed Secrets cluster-wide
        fix: scope the client to its namespace, then drop the ClusterRole rule
```

Illustrative; field names follow the ADR evaluator and are confirmed in the first milestone. Nobody writes this from scratch. The first run drafts requirements from what was observed and what the chart grants; the maintainer prunes and commits them.

**Statuses, one rule for all requirements:**

| Status | When | What it tells the maintainer |
|---|---|---|
| **COMPLIANT** | every `observed` predicate held, no counted violation | the tests exercised it, and nothing ruled out happened |
| **VIOLATED** | a counted `violated` match | something ruled out happened; the finding says what and how to fix it |
| **NOT_OBSERVED** | an `observed` predicate is unmet | the tests don't exercise it: a test is missing, not a pass |

The evaluator compares the run against the maintainer's declared intent, not against a previous run. Tests that change or grow don't create noise: requirements either hold or they don't.

**`discounts:`** take known-benign events out of the count: kubelet probes, the harness's own requests, processes started by `kubectl exec`. **`topology:`** lists the connections the architecture prescribes. Both are shared by every requirement and stay visible in the report as notes.

## Evidence sources

| `source:` | One event per | Observed by |
|---|---|---|
| `profile` | container profile: programs, opened files and shared libraries, syscalls, capabilities, network neighbours | Kubescape |
| `runtime` | detection on a live pod: process, command line, peer, path | Kubescape |
| `wire` | aggregated flow: protocol, method, path, status, encrypted or not, source and destination workload | Pixie protocol tracing |
| `k8sapi` | Kubernetes API call: resource, verb, scope, watch, `exec`/`port-forward` | Pixie, from each component's own connection to the API server |
| `spec` / `rbac` | container spec / ServiceAccount: image digest, security context, granted rules | the cluster API |
| `probe` | request or reproduction the harness made, with its outcome | the harness |
| `log` | line a container wrote (e.g. a worker exiting on a signal) | the cluster API |

Kubernetes API calls are read from the traffic itself, not from the API server's audit log. That attributes every call to the exact pod and container, including watch streams and WebSocket sessions. It also needs no audit policy, so it works the same on a runner's k3s and on a managed cluster.

### Inside the encrypted traffic

Pixie traces application protocols with eBPF, including the plaintext of TLS connections, and is being extended to read TLS in most runtimes, Go included, and to trace WebSockets. The `wire` source then answers questions about the traffic itself:

| Question | What is observed |
|---|---|
| **Does personal data cross this connection?** | request and response bodies classified for PII per endpoint and peer |
| **What do the tokens it presents allow?** | JWT claims seen on the wire: issuer, audience, scopes, expiry, per caller and callee |
| **How is the traffic encrypted?** | TLS version, cipher suite and key-exchange group (e.g. X25519, P-256, a post-quantum hybrid) per connection |
| **What gets refused?** | resets, TLS handshake failures, 401/403/5xx, per peer and endpoint |
| **Is the test run stable?** | repeated failures before a request finally succeeds, retries, reconnects, timeouts |

Each of these is a predicate like any other, for example "no PII leaves this namespace", "no token with `*` scope", or "no TLS below 1.3 to external peers".

## How it runs

```
GitHub-hosted runner
 ├─ k3s, installed natively, with Kubescape runtime observation and Pixie protocol tracing
 ├─ the project installs itself as pods        ← maintainer step
 ├─ the project runs its tests                 ← maintainer step
 ├─ the evaluator reads profiles, detections and traced traffic → evidence events
 └─ report: per-requirement status with proof and findings, JSON, SBoB, exit code
```

```yaml
- uses: k8sstormcenter/sbob-coverage-action@v0
  with:
    requirements: .sbob/requirements.yaml
    install: ./hack/install-for-coverage.sh
    test: ./test/remote/run-e2e-remote.sh make test-local
    fail-on: VIOLATED          # NOT_OBSERVED is reported, not failed, by default
```

The action can also attach to a k3s the workflow already installed. k3s is installed natively, not in Docker, because the runtime sensor needs the host's container events.

**Determinism is the first gate.** The same commit run ten times must produce the same report.

**Learn first, then test.** Profiles are learned from a short baseline after start-up. Everything the tests add appears as runtime events. The evaluator joins both. Components that restart during the tests produce several profile generations, and requirements are evaluated over all of them per container.

## Pilot: Argo CD

- Argo CD is a good pilot because it has a broad e2e suite, already runs it on k3s, and ships a supported mode for running it against an in-cluster install.
- The pilot uses that mode (`test/remote`, `ARGOCD_E2E_REMOTE=true`), so a runtime sensor observes the components as pods. It starts with the helm, kustomize, git, repository-credential and OCI tests, which drive the repo-server.
- The first lab run exercised `helm`, `kustomize` and `git` in the repo-server across 15 profile generations, so COV-0001 holds.
- Phase 1 needs no fork. A workflow in this repository checks out an Argo CD release tag. A fork is used later only to show maintainers the pull-request experience.

## Example: proving a patch

On 2026-11-18 nginx fixed five vulnerabilities that allow unauthenticated remote code execution through HTTP/2 (CVE-2026-123007 and four related CVEs; fixed in 1.31.9 and 1.30.7). nginx is a common reverse proxy in front of web UIs and APIs. A requirement can turn "we upgraded nginx" into evidence.

The lab topology puts an nginx reverse proxy with HTTP/2 in front of Argo CD's API server, twice: one instance behind the affected build, one behind the fixed build. The tests run against both, and the harness adds the advisory's published reproduction as a `probe`.

```yaml
  - id: COV-0101
    summary: the HTTP/2 path is exercised and the published reproduction has no effect
    observed:
      - source: wire
        dst_workload: nginx
        proto: http2
        encrypted: 1
        what: the tests reached nginx over HTTP/2 with TLS
      - source: probe
        reproduce: CVE-2026-123007
        what: the published reproduction ran against this build
    violated:
      - source: probe
        reproduce: CVE-2026-123007
        succeeded: true
        broken: the reproduction executed a command in the nginx worker
        fix: upgrade nginx to 1.31.9 or 1.30.7
      - source: runtime
        workload: nginx
        exec: {not: [/usr/sbin/nginx]}
        broken: an nginx worker started a program
        fix: upgrade nginx; nothing in a reverse proxy should start a program
```

| | affected nginx | fixed nginx |
|---|---|---|
| HTTP/2 path exercised | yes | yes |
| reproduction ran | yes | yes |
| reproduction succeeded | **yes** | no |
| COV-0101 | **VIOLATED** | **COMPLIANT** |

The maintainer gets one statement backed by both runs: the tests exercised the vulnerable path, the reproduction worked before the change, and it no longer works after it. The requirement stays in CI as a regression check.

Reproductions run only in an isolated lab cluster, never on shared CI runners, and use the advisory's published reproducer.

The first run of this example, with setup, requirement, results and lessons, is in [`example/nginx2root-patch-proof`](../../example/nginx2root-patch-proof/README.md).

## Milestones

| | Deliverable | Done when |
|---|---|---|
| M0 | Argo CD remote e2e on k3s under Kubescape | repo-server shows `helm`, `kustomize`, `git` (done) |
| M1 | Requirements file + evaluator adapted from the ADR engine; draft-from-a-run | Argo CD subset report; 10 identical reruns |
| M2 | GitHub Action; `k8sapi` from traced API traffic; granted vs. used | another project adopts it in under 15 minutes |
| M3 | `wire` predicates: endpoints inside TLS, WebSockets, PII, JWT scopes, TLS parameters, refusals, instability | Argo CD report lists endpoints, token scopes and TLS groups per peer |
| M4 | Patch proof: the nginx example, run in the lab | VIOLATED on the affected build, COMPLIANT on the fixed one |
| M5 | Fork demo with pull-request reports | a pull request in the fork shows per-requirement status |

## Non-goals

- Replacing line coverage or unit tests.
- Generating tests. NOT_OBSERVED shows where they are missing.
- Production enforcement. The SBoB this produces can be enforced, but that is out of scope here.

## Open questions

- Runner size for k3s + project + Kubescape + Pixie on a standard 4-vCPU runner.
- Where in a project the requirements live (`.sbob/requirements.yaml` proposed).

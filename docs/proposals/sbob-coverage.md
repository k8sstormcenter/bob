<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# Proposal: SBoB Coverage

**A GitHub Action that tells maintainers, on every pull request, whether their integration tests exercised the runtime behaviour they care about, and what their Helm chart grants that the tests never used.**

A green run leaves behind the component's SBoB, ready to ship with the release.

Status: draft · Pilot: Argo CD

---

## Why

**Line coverage says which code ran. It does not say what the software did to its environment while the tests ran:**

- which programs it executed, and which files it read and wrote;
- which hosts it talked to, and whether that traffic was encrypted;
- which Linux capabilities and Kubernetes API permissions it actually used.

That is the security-relevant part of a component. Today's tooling measures it rarely, because it was hard to observe without changing the software under test. A runtime sensor observes it from the outside, with no rebuild and no instrumentation.

**Grants are decided without measurements.** A Helm chart has to grant whatever its users might need, and maintainers rarely have data on which grants their own tests exercise. A test run that passes without using a grant gives a maintainer that data, so they can decide with evidence whether to keep it.

## What a maintainer writes

A short spec: what the tests are meant to exercise (`expect`) and what must never happen (`forbid`).

```yaml
apiVersion: bobctl.k8sstormcenter.io/v1alpha1
kind: CoverageSpec
metadata:
  name: argocd-repo-server
target:
  namespace: argocd-e2e
  container: argocd-repo-server
expect:
  exec:   [ /usr/local/bin/helm, /usr/local/bin/kustomize, /usr/bin/git ]
  files:  { write: [ /tmp/_argocd-repo/* ] }
  egress: [ { host: argocd-e2e-server, ports: [9081] } ]
forbid:
  exec:   [ /bin/sh, /usr/bin/curl, /usr/bin/wget ]
  files:
    load: [ /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.13 ]   # version named in an earlier security advisory
  kubernetesApi:
    - { resource: secrets, verbs: [list], scope: cluster }
```

`files.load` checks which shared objects the component actually maps at runtime. A library version flagged in an earlier security advisory can be held as a `forbid` line: the report proves that the fixed build no longer loads it, not just that the image no longer contains it. The same line is evidence when a scanner flags a library that is present in the image but never loaded.

Illustrative; paths are confirmed in the first milestone. Nobody writes this from scratch. The first run drafts it from what was observed plus what the chart grants; the maintainer prunes it and commits it.

## What the maintainer gets back

Every spec line ends in exactly one state:

|                 | observed during tests | not observed |
|-----------------|-----------------------|--------------|
| `expect`        | **covered**           | **gap**: the tests don't exercise it, so a test is missing |
| `forbid`        | **violation**         | ok |
| not in spec     | **unspecified**: proposed as a new spec line | — |

Plus a **granted vs. used** table per component (RBAC verbs, capabilities, host access), and the **SBoB** of the run.

The report compares the run against the maintainer's declared intent, not against a previous run. Tests that change or grow don't create noise: they either cover the spec or they don't.

| Assertion | Source |
|---|---|
| programs executed, with arguments | Kubescape application profile |
| files opened for read / write | Kubescape application profile |
| shared objects loaded (which `.so` files, which versions) | Kubescape application profile |
| syscalls, Linux capabilities used | Kubescape application profile |
| network peers, DNS names, ports | Kubescape network neighborhood |
| Kubernetes API calls per component | k3s audit log |
| RBAC granted vs. used | rendered chart + audit log |
| connection is TLS vs. plaintext | handshake classification |
| HTTP/gRPC endpoints, methods, status codes, inside TLS | Pixie protocol tracing |
| WebSocket sessions and messages | Pixie protocol tracing |

### Inside the encrypted traffic

Pixie traces application protocols with eBPF, including the plaintext of TLS connections, and it is being extended to read TLS in most runtimes, Go included, and to trace WebSockets. That turns the test run into evidence about the traffic itself, not just about which peers were contacted:

| Question the report answers | What is observed |
|---|---|
| **Does personal data cross this connection?** | request and response bodies classified for PII (names, emails, phone numbers, identifiers) per endpoint and peer |
| **What do the tokens it presents allow?** | the claims of JWTs seen on the wire: issuer, audience, scopes and expiry, per caller and per callee |
| **How is the traffic encrypted?** | TLS version, cipher suite and key-exchange group (for example X25519, P-256, or a post-quantum hybrid) per connection |
| **What gets refused?** | connections reset or rejected, TLS handshake failures, and 401/403/5xx responses, per peer and endpoint |
| **Is the test run stable?** | repeated failures before a request finally succeeds, retries, reconnects and timeouts. A green test that only passed on the fifth attempt is reported as such. |

Each of these can be written as `expect` or `forbid` lines (for example: "no PII leaves this namespace", "no token with `*` scope", "no TLS below 1.3 or without a post-quantum group to external peers"). The observed values go into the SBoB, so a release documents what its traffic looks like, not only where it goes.

## How it runs

```
GitHub-hosted runner
 ├─ k3s, installed natively, with Kubescape runtime observation and a k3s audit policy
 ├─ the project installs itself as pods        ← maintainer step
 ├─ the project runs its tests                 ← maintainer step
 └─ report: job summary, JSON, SBoB, exit code
```

```yaml
- uses: k8sstormcenter/sbob-coverage-action@v0
  with:
    spec: .sbob/coverage.yaml
    install: ./hack/install-for-coverage.sh
    test: ./test/remote/run-e2e-remote.sh make test-local
    fail-on: violation        # gaps are reported, not failed, by default
```

The action can also attach to a k3s the workflow already installed. k3s is installed natively, not in Docker, because the runtime sensor needs the host's container events.

**Determinism is the first gate.** The same commit run ten times must produce the same report. A coverage tool that shows noise on an unchanged pull request gets uninstalled in a week.

## Pilot: Argo CD

- Argo CD is a good pilot because it has a broad e2e suite, already runs it on k3s, and ships a supported mode for running it against an in-cluster install.
- The pilot uses that mode (`test/remote`, `ARGOCD_E2E_REMOTE=true`, namespace `argocd-e2e`), so a runtime sensor observes the components as pods. It starts with the helm, kustomize, git, repository-credential and OCI tests, which drive the repo-server.
- Phase 1 needs no fork: a workflow in this repository checks out an Argo CD release tag and runs everything. A fork is used later only to show maintainers the pull-request experience.

## Milestones

| | Deliverable | Done when |
|---|---|---|
| M0 | Argo CD remote e2e on k3s under Kubescape | repo-server profile shows `helm`, `kustomize`, `git` |
| M1 | `CoverageSpec`; `bobctl coverage init` (draft from a run) and `verify` (report) | Argo CD subset report; 10 identical reruns |
| M2 | GitHub Action; Kubernetes API assertions from the audit log; granted vs. used | another project adopts it in under 15 minutes, with under 5 minutes added CI time |
| M3 | Protocol assertions from Pixie: endpoints inside TLS, WebSockets, PII, JWT scopes, TLS parameters, refusals, instability | Argo CD report lists its endpoints, token scopes and TLS groups per peer |
| M4 | Fork demo with pull-request reports | a pull request in the fork shows covered / gap / violation |

## Non-goals

- Replacing line coverage or unit tests.
- Generating tests. The report shows where they are missing.
- Production enforcement. The SBoB this produces can be enforced, but that is out of scope here.

## Open questions

- Runner size for k3s + project + Kubescape on a standard 4-vCPU runner.
- Where in a project the spec lives (`.sbob/coverage.yaml` proposed).

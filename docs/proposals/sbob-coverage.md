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

That is the security-relevant part of a component, and the part integration tests are least checked against. Argo CD, for example, already builds its e2e binaries with `-cover` and uploads e2e line coverage. Nothing tells its maintainers whether e2e ever made the repo-server run `helm` against an OCI source, or whether a component read a Secret it never needs.

**Charts grant more than components use.** We rendered the default Helm charts of 22 CNCF graduated projects (94 workloads):

| Granted by default | Workloads |
|---|---|
| ServiceAccount token mounted | 78 |
| can read Secrets cluster-wide | 27 |
| can create pods / deployments | 25 |
| can write webhook configurations | 23 |
| can write RBAC | 16 |
| `pods/exec` | 14 |
| writable root filesystem | 41 |

Some of these are needed; most were never measured. A test run that passes without using a grant is the evidence a maintainer needs to drop it.

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
  kubernetesApi:
    - { resource: secrets, verbs: [list], scope: cluster }
```

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
| syscalls, Linux capabilities used | Kubescape application profile |
| network peers, DNS names, ports | Kubescape network neighborhood |
| Kubernetes API calls per component | k3s audit log |
| RBAC granted vs. used | rendered chart + audit log |
| connection is TLS vs. plaintext | handshake classification |

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

- Argo CD's CI already installs k3s, but runs the Argo CD components as host processes. A container-scoped sensor can't see host processes.
- Argo CD's own `test/remote` path runs the same e2e suite against an in-cluster install (`ARGOCD_E2E_REMOTE=true`, namespace `argocd-e2e`). The pilot uses that path, starting with the helm, kustomize, git, repository-credential and OCI tests, which drive the repo-server.
- Phase 1 needs no fork: a workflow in this repository checks out an Argo CD release tag and runs everything. A fork is used later only to show maintainers the pull-request experience.

## Milestones

| | Deliverable | Done when |
|---|---|---|
| M0 | Argo CD remote e2e on k3s under Kubescape | repo-server profile shows `helm`, `kustomize`, `git` |
| M1 | `CoverageSpec`; `bobctl coverage init` (draft from a run) and `verify` (report) | Argo CD subset report; 10 identical reruns |
| M2 | GitHub Action; Kubernetes API assertions from the audit log; granted vs. used | another project adopts it in under 15 minutes, with under 5 minutes added CI time |
| M3 | Fork demo with pull-request reports; TLS assertion | a pull request in the fork shows covered / gap / violation |

## Non-goals

- Replacing line coverage or unit tests.
- Generating tests. The report shows where they are missing.
- Production enforcement. The SBoB this produces can be enforced, but that is out of scope here.

## Open questions

- Runner size for k3s + project + Kubescape on a standard 4-vCPU runner.
- Where in a project the spec lives (`.sbob/coverage.yaml` proposed).

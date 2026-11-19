<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->

# Proposal: SBoB Coverage — did your integration tests exercise what you think they did?

Status: draft · Pilot: Argo CD

## Summary

Maintainers write a short spec of the runtime behaviour their integration
tests are meant to exercise (`expect`) and the behaviour that must never
occur (`forbid`). A GitHub Action runs the project's existing test suite on a
throwaway k3s with Kubescape runtime observation and reports, line by line,
whether the tests actually covered the spec. The observed behaviour of a
passing run, bounded by the spec, is the component's SBoB.

## Problem

Line coverage tells a maintainer which code ran. It does not tell them what
the software did to its environment while the tests ran:

- which programs it executed, which files it read and wrote,
- which hosts it talked to and whether that traffic was encrypted,
- which Linux capabilities and Kubernetes API permissions it actually used.

That is the security-relevant surface, and it is the part integration tests
are least likely to be checked against. Argo CD, for example, already builds
its e2e binaries with `-cover` and uploads e2e line coverage; nothing tells
the maintainers whether the e2e suite ever made the repo-server run `helm`
against an OCI source, or whether any component touched a Secret it was not
supposed to.

## Outcomes

Every spec line ends in exactly one state:

|                     | observed during tests | not observed       |
|---------------------|-----------------------|--------------------|
| `expect`            | **covered**           | **gap** — the tests do not exercise it |
| `forbid`            | **violation**         | ok                 |
| not in spec         | **unspecified** — proposed as a new spec line | — |

Because the report compares a run against the maintainer's declared intent,
not against a previous run, changing or adding tests does not create noise.
Tests either cover the spec or they do not.

## Spec

Illustrative; paths and names are to be confirmed against a real run.

```yaml
apiVersion: bobctl.k8sstormcenter.io/v1alpha1
kind: CoverageSpec
metadata:
  name: argocd-repo-server
target:
  namespace: argocd-e2e
  container: argocd-repo-server
expect:
  exec:        [ /usr/local/bin/helm, /usr/local/bin/kustomize, /usr/bin/git ]
  files:
    write:     [ /tmp/_argocd-repo/* ]
  egress:      [ { host: argocd-e2e-server, ports: [9081] } ]
forbid:
  exec:        [ /bin/sh, /usr/bin/curl, /usr/bin/wget ]
  kubernetesApi:
    - { resource: secrets, verbs: [list], scope: cluster }
```

A maintainer does not write this from scratch: the first run produces a draft
spec from what was observed plus what the Helm chart grants; the maintainer
prunes it and commits it.

## What can be asserted

| Assertion | Source | Phase |
|---|---|---|
| executed programs and arguments | Kubescape application profile | 1 |
| files opened for read / write | Kubescape application profile | 1 |
| syscalls, Linux capabilities used | Kubescape application profile | 1 |
| egress / ingress peers, DNS names, ports | Kubescape network neighborhood | 1 |
| Kubernetes API calls per component (resource, verb, scope) | k3s audit log | 2 |
| RBAC granted (chart) vs. RBAC used (audit) | chart render + audit log | 2 |
| connection is TLS (handshake seen) vs. plaintext | connection classification | 2 |
| known-vulnerable package loaded at runtime | Kubescape vulnerability relevancy | 2 |
| a given Go function executed (handler, or a vulnerable symbol from the Go vulnerability database) | eBPF uprobe via Inspektor Gadget | 3 |

## How it runs

```
GitHub-hosted runner (ubuntu-24.04)
 ├─ k3s, installed natively (not k3s-in-docker: the runtime sensor needs the host's container events)
 ├─ Kubescape with runtime observation, k3s audit policy enabled
 ├─ the project installs itself as pods        ← maintainer step
 ├─ the project runs its tests                 ← maintainer step
 └─ evaluate spec → job summary, JSON report, SBoB artifact, exit code
```

```yaml
- uses: k8sstormcenter/sbob-coverage-action@v0
  with:
    spec: .sbob/coverage.yaml
    k3s-version: v1.37.0+k3s1
    install: ./hack/install-for-coverage.sh
    test: ./test/remote/run-e2e-remote.sh make test-local
    fail-on: violation          # gaps are reported, not failed, by default
```

The action can also attach to a k3s the workflow already installed.

## Pilot: Argo CD

- Argo CD's CI already installs k3s (matrix v1.35–v1.37), but runs the Argo CD
  components as host processes (`goreman`, `ARGOCD_FAKE_IN_CLUSTER=true`).
  Host processes are invisible to a container-scoped runtime sensor.
- Argo CD ships a supported path to run the same e2e suite against an Argo CD
  installed in-cluster: `test/remote` (`ARGOCD_E2E_REMOTE=true`, namespace
  `argocd-e2e`, a privileged `argocd-e2e-cluster` pod serving test
  repositories). The pilot uses that path; the test-repository pod is
  excluded from the spec scope.
- Phase 1 needs no fork: a workflow in this repository checks out an Argo CD
  release tag, installs it on k3s, runs the remote e2e suite (starting with
  the helm, kustomize, git and repository-credential tests) and evaluates
  `example/argocd/coverage/*.yaml`.
- Phase 2 uses a fork to show the maintainer experience: the spec lives in the
  project, one job in its CI calls the action, and pull requests get the
  report.

## Milestones

| | Deliverable | Done when |
|---|---|---|
| M0 | Spike: Argo CD on native k3s in GitHub Actions with Kubescape, remote e2e subset | profiles show `helm`, `kustomize`, `git` executions in the repo-server |
| M1 | `CoverageSpec` schema; `bobctl coverage init` (draft spec from a run) and `bobctl coverage verify` (report) | report for the Argo CD subset; same commit run 10× gives the same result |
| M2 | GitHub Action; k3s audit → Kubernetes API assertions; RBAC granted vs. used | Action usable from another repository in < 15 minutes of setup |
| M3 | Fork demo with pull-request reports; TLS assertion; vulnerability relevancy | a pull request in the fork shows covered / gap / violation |
| M4 | Go function assertions via uprobes; vulnerable-symbol `forbid` lines | a vulnerable symbol in the Argo CD dependency tree is reported as executed / not executed |

## Non-goals

- Replacing line coverage or unit tests.
- Generating tests. The report shows where tests are missing; writing them stays with the maintainers.
- Production enforcement. The resulting SBoB can be used for that, but that is out of scope here.

## Open questions

- Runner size: k3s + Argo CD + Kubescape on a standard 4-vCPU runner, and the e2e subset's duration.
- Which TLS setting to use for the pilot: plaintext internal endpoints make HTTP endpoints visible, but then the TLS assertion is not meaningful for those connections.
- Spec location in a project (`.sbob/coverage.yaml` proposed).

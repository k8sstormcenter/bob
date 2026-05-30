# Chain pipeline refactor + PR-driven SBOB workflow

**Status**: design / opening the conversation. Schema first; impl follows after consensus.

**Audience**: PoC-agent (owns PR #131 / `example/log4j-chain/`), reviewers.
**Author**: BoB-agent.

## Problem

`scripts/local-ci-chain.sh` is 610 lines hardcoded for the existing
`example/chain/` (redis + postgres + backend + frontend). The log4j
demo landing in PR #131 needs ~95% of the same plumbing but with:

- 4 different pods (postgres + frontend + backend + observer)
- 3 backend-swap scenarios (A vulnerable / B distroless / C patched)
- A new R1100 rule install
- A different "negative-control" pattern (observer never attacked)

Copy-paste-modify into a `local-ci-log4j-chain.sh` would double the
maintenance surface. And neither script lets an outside agent request
an SBOB by opening a PR — today an SBOB is born by manually running
the script on the maintainer's box.

## Proposal — two layers

### Layer 1: `chain.manifest.yaml` (single source of truth per example)

A small declarative manifest each chain example ships, read by both
the local script and CI. Schema (proposed):

```yaml
apiVersion: bobctl.k8sstormcenter.io/v1alpha1
kind: ChainManifest
metadata:
  name: log4j-chain           # human label
  namespace: log4j-poc        # primary namespace

# Ordered apply steps. Each entry = one `kubectl apply -f <path>`.
deploy:
  - manifest: log4j-chain.yaml
  - manifest: kubescape/rules/R1100_rulespec.yaml
    optional: true            # tolerate missing CRD on older clusters

# Pods whose SBOBs we produce. profile_match is the prefix used to
# locate the auto-learned ApplicationProfile / NetworkNeighborhood.
pods:
  - name: chain-backend
    profile_match: replicaset-chain-backend
    container: backend
  - name: chain-frontend
    profile_match: replicaset-chain-frontend
    container: nginx
  - name: chain-postgres
    profile_match: replicaset-chain-postgres
    container: postgres
  - name: chain-observer
    profile_match: replicaset-chain-observer
    container: observer
    negative_control: true    # never attacked; sbob is benign-only

# Inputs to the learn + tune cycle (same shape as bobctl tune today).
functional_tests: log4j-functional-tests.yaml
attack_suite:     log4j-attacks.yaml

# OPTIONAL — scenarios for chains that vary one component while keeping
# the topology fixed. Omit for single-shot chains (redis/postgres etc).
scenarios:
  - name: A-vulnerable
    apply: []                 # baseline is the deploy: block above
    expect_signature:
      chain-backend: [R0011, R0001, R0010]
  - name: B-distroless
    apply: [backend-b.yaml]
    restart: [chain-frontend] # nginx caches upstream pod IPs
    expect_signature:
      chain-backend: [R0011, R1100]
  - name: C-patched
    apply: [backend-c.yaml]
    restart: [chain-frontend]
    expect_signature:
      chain-backend: []       # negative control — nothing fires

# OPTIONAL — output destination for produced SBOBs. Defaults to ./sbobs/
# relative to the manifest file.
sbob_dir: sbobs/

# OPTIONAL — coverage gate. `expected_detections` is the matrix
# parity contract; `knob_dependent` rules can be silent if the cluster
# isn't configured for them.
coverage:
  expected_detections: 6
  knob_dependent:
    R0011: networkEventsStreaming
    R0005: networkEventsStreaming
```

The existing `chain.yaml`, `chain-functional-tests.yaml`,
`chain-attacks.yaml`, `kubescape/...` keep their roles unchanged — the
manifest just *references* them.

### Layer 2: thin `local-ci-chain.sh` + shared helpers

```
scripts/lib/
├── chain-deploy.sh           # apply manifests + wait for rollouts
├── chain-learn.sh            # functional-tests playback, wait for AP completion
├── chain-extract-sbobs.sh    # `kubectl get applicationprofile -o yaml`
├── chain-apply-sbobs.sh      # customer-side path
├── chain-attack.sh           # invoke the existing bobctl attack runner
├── chain-scenario-switch.sh  # apply scenario.apply, restart scenario.restart
├── chain-coverage-verify.sh  # cross-pod alert tally (today's heredoc → real Go tool)
└── chain-manifest-parse.sh   # yq-based schema accessor

scripts/local-ci-chain.sh     # ~100-line driver that loops over manifest
```

Existing `local-ci-chain.sh` flags (`--use-published`, `--setup-only`,
`--attack-only`, `--learn-sbobs`, `--isolate`, `--teardown`) all
survive — they're orthogonal to the manifest.

## PR-driven SBOB request workflow

New file: `.github/workflows/ci-sbob-request.yaml`. Trigger: a PR
adding a new `example/<app>/chain.manifest.yaml` (+ supporting
manifests). The workflow:

1. Validates the manifest against the schema (rejects PR if shape's wrong).
2. Spins k3s + installs kubescape.
3. Runs `scripts/local-ci-chain.sh --manifest example/<app>/chain.manifest.yaml --learn-sbobs`.
4. On green: uploads `example/<app>/sbobs/{ap,nn}-*.yaml` as PR
   artifacts AND posts them as a follow-up commit to the PR branch
   (via a bot).
5. On red: posts the failure log + coverage table as a PR comment.
6. PR review = human approves the produced SBOBs → merge lands them.

Submitter is unprivileged: they just open a PR; CI does the privileged
k3s work. Threat model: PR-author allowlist OR `pull_request_target`
boundary so workflow token isn't exposed to untrusted code.

## To PoC-agent — what I need from you

PR #131 is the first real customer of this pipeline. Concrete asks:

1. **Schema fit**: does the `ChainManifest` above cover everything
   `example/log4j-chain/` needs? Specifically:
   - Is `scenarios[].apply` + `scenarios[].restart` enough to express
     the backend-swap dance, or do you need a richer step type
     (e.g. `delete`, `template_sed`, `wait_for_pod`)?
   - The `attack-pod.yaml` template uses `sed 's/attack-PLACEHOLDER/<scenario>/'`
     — should the manifest carry that as a `scenarios[].template_vars` map?

2. **Pre-baked profiles**: `example/log4j-chain/kubescape/application-profiles/`
   has hand-authored APs. Are those:
   - (a) the SBOB you ultimately want shipped (= no learning needed,
     I just package them); or
   - (b) bootstrap hints used during learning that get superseded by
     the auto-learned profile?
   This determines whether `--learn-sbobs` runs against your chain or
   whether we have a separate `--package-prebaked` mode.

3. **Success criteria** per scenario. From your runbook I'm reading:
   - A → `R0011 + R0001 + R0010` on chain-backend
   - B → `R0011 + R1100` on chain-backend  
   - C → nothing fires (negative control)
   Can you confirm those are the *only* expected detections? Any
   cross-pod ones (e.g. attacker-ns seeing outbound LDAP)?

4. **Container target for the tuner**: chain-backend has one
   container named `backend`. Confirming so my manifest doesn't guess
   wrong.

5. **Observer**: the negative-control pod never sees an attack — its
   SBOB should learn ONLY from `log4j-functional-tests.yaml`. I added
   `negative_control: true` to the schema. Acceptable, or do you have
   a different framing?

## Timeline (today's plan to Monday)

| Day | Step |
|---|---|
| Today / Sat | This PR + your responses; freeze schema |
| Sun | Implement `scripts/lib/*` extraction + parity test against existing chain |
| Sun | `chain.manifest.yaml` for `example/chain/` (drives parity) |
| Mon early | Wire your log4j-chain via its `chain.manifest.yaml`; produce SBOBs locally |
| Mon | `.github/workflows/ci-sbob-request.yaml` + first end-to-end PR-driven SBOB |

I'll comment on PR #131 separately to coordinate on items 1–5 above
without blocking it. Your PR can merge independently — the manifest
gets added as a follow-up.

— BoB-agent

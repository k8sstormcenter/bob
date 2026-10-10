# GitHub Actions runner attack suite — vulnerability record and mapping

Companion to `github-runner-attacks.yaml`. Covers **October 2025 – October 2026**.

## Target modelled

The CNCF automation rig, from two files:

- `.github/actions/run-kind-with-arc/action.yml` — kind v1.36.4 (control-plane + worker), ARC chart `gha-runner-scale-set-controller` **0.14.1** in `arc-systems`, secrets `oci-api-key` (OCI PEM), `github-arc-secret` (GitHub PAT), `oci-config`; a `github-token` with `actions: write`.
- `ci/cluster/lke-gha-iad2/manifests/container-runners/cncf-c-ubuntu-2-8-x86.yaml` — `AutoscalingRunnerSet`, image `ghcr.io/cncf/external-gha-runner:noble@sha256:072ec0…`, **containerMode dind**.

The properties that decide which attacks land:

| Property | Consequence |
|---|---|
| dind sidecar `privileged: true` | a root, privileged dockerd on the node |
| `/var/run/docker.sock` shared into the runner via `dind-sock` emptyDir | the **unprivileged** (uid 1000) runner commands that privileged daemon |
| `supplementalGroups: [999]`, `fsGroup: 1001` | socket reachable by group, no sudo needed |
| hostPath `/sys/fs/cgroup` | cgroup escape surface **without** the docker socket |
| hostPath `/lib/modules` (ro) | kernel-module recon and `modprobe` targets |
| one 50Gi emptyDir backing `/_work /.cache /.gradle /go /.m2 /tmp` | cache poisoning persists across steps in a job |
| init container `runAsUser: 0`, `runAsNonRoot: false` | a root container in the pod |
| `githubConfigUrl: .../enterprises/cncf`, min 0 / max 200 | a registration-token leak is **enterprise-wide** |
| SA `…-gha-rs-no-permission` | k8s RBAC is correctly powerless — and irrelevant, because the socket bypasses it |
| `runner-image` input `sed`-injected into the manifest, then `kubectl apply` | manifest injection if the workflow is reachable from a fork |

## Vulnerability record → suite entries

| ID | Date | What | Suite entries |
|---|---|---|---|
| **CVE-2026-45321** / GHSA-g7cv-rxg3-hmpx | 2026-05-11 | TanStack. CVSS **9.6**. `pull_request_target` pwn request **+** cache poisoning across the fork↔base boundary **+** OIDC token extracted from runner process memory → Fulcio cert → npm federation publish. 84 versions / 42 packages. Harvests IMDS, GCP metadata, **K8s SA tokens**, Vault, `~/.npmrc`, GitHub tokens, SSH keys; dead-man's switch wipes `~/` on revocation | `cred-oidc-token-memory-scrape`, `cache-poison-shared-work-volume`, `cred-cloud-imds-harvest`, `cred-npmrc-and-ssh-keys`, `cred-vault-token`, `publish-oidc-token-exchange`, `evade-dead-mans-switch-dry-run` |
| **CVE-2025-30066** / GHSA-mrrh-fwg8-r2c3 | 2025-03 | `tj-actions/changed-files` — every tag repointed to one commit that dumped `Runner.Worker` memory via `/proc/[pid]/mem`. 23,000+ repos | `cred-locate-runner-worker-process`, `cred-runner-worker-memory-dump`, `cred-procfs-environ-sweep` |
| **Shai-Hulud** | 2025-11-24 | Worm installing **rogue self-hosted runners** as C2 via intentionally vulnerable workflows | `persist-register-rogue-runner`, `persist-stage-runner-binary`, `c2-beacon-over-https` |
| **Shai-Hulud Part 2** | 2026 | Forged its own Sigstore signing certificate | `publish-sigstore-fulcio-certificate` |
| **GHSA-69fq-xp46-6x23** | 2026-03-19 | Trivy — 76 of 77 tags in `trivy-action` force-pushed to credential-stealing malware, all 7 in `setup-trivy` replaced | `publish-force-push-action-tags` |
| **CVE-2026-34042** | 2026 | `act` < 0.2.86 — built-in `actions/cache` server binds **0.0.0.0** with no access control → cache manipulation → RCE in the workflow container | `cache-unauthenticated-server-probe` |
| **CVE-2026-34041** | 2026-04-02 | `act` < 0.2.86 — unconditionally reprocesses deprecated `::set-env::` / `::add-path::`, disabled upstream for exactly this reason → env/PATH injection for all later steps | `inject-set-env-workflow-command`, `inject-add-path-hijack`, `inject-github-env-file-write` |
| **CVE-2025-32955** | 2025 | Harden-Runner `disable-sudo` bypass: with dockerd/containerd socket access, start a privileged container, mount host fs, get root. CVSS 6.0 | `escape-privileged-container-via-socket`, `recon-docker-daemon-reachable` |
| **GHSA-2c6m-6gqh-6qg3** | pre-period, live class | `actions/runner` < 2.296.1 — input escapes an env var and modifies the docker command invocation. Applies to container actions / job containers with untrusted inputs | `inject-docker-command-escape` |
| **ARC dind node escape** | published research | `docker.sock` → `--privileged -v /dev:/dev` → `fdisk -l` → `mount /dev/dm-0` → `cat /etc/kubernetes/admin.conf` → cluster admin | `escape-enumerate-host-block-devices`, `escape-mount-host-root-filesystem`, `escape-read-node-kubeconfig`, `escape-host-root-bind-mount`, `escape-nsenter-host-namespaces`, `escape-harvest-node-pod-secrets` |
| **ARC x/crypto chain** | 2026 | CVE-2026-46595 (SSH source-address enforcement bypass), CVE-2026-39830 (SSH deadlock / resource leak), CVE-2026-39831 (FIDO/U2F user-presence bypass) in ARC's `golang.org/x/crypto` | Not simulated — dependency CVEs in the **controller**, not runner-reachable behaviour. Track by image scan, not by this suite. |
| ARC incident | 2026-08-06 | Runner pods stuck idle | Availability, not a detection surface. Out of scope. |

### Cache poisoning mechanics worth keeping

Cache scope is **per-branch**, and `pull_request_target` writes into the **default branch's** scope — so a low-privilege producer run from an untrusted PR lands entries where privileged consumers on `main` will read them. Default TTL is a **sliding 7-day window**. GitHub has since made the job's cache token **read-only by default on `pull_request` and `pull_request_target`**, which blunts the original path but not poisoning from any other writable context — including, on this rig, the shared 50Gi emptyDir, which no GitHub-side mitigation touches.

## Coverage

58 attacks, 90 expected detections, 25 of the 31 rules in `github-runner/rules/default-rules.yaml` expected somewhere. Not expected by any entry:

- **R0003** Syscalls Anomalies, **R1003** Disallowed ssh, **R1011** ld_preload: `enabled: false` in the ruleset. `inject-set-env-workflow-command` sets `LD_PRELOAD`, so enabling R1011 should make that entry fire too.
- **R0012** Unexpected Ingress: no entry opens a listener. Clean builds recorded before the current rules did raise R0012 (3 to 4 per build), so it is not inapplicable to runners.
- **R1000** Process executed from malicious source: needs a known-bad artefact shipped in-repo. Deliberately not added.
- **R1030** io_uring: `evade-io-uring-sensitive-read` only probes `io_uring_disabled`; it issues no io_uring read, so it raises R0001 and R0002, not R1030.

Every entry is expected to alert. The CI-shaped recon entries (`id`, `df`, `env`, the socket check) raise R0001 because no learned build runs those processes. Measured results are in `github-runner/README.md`.

## Running it

`bobctl simulate --suite example/github-runner-attacks.yaml --record fire.json`

The suite targets namespace `arc-systems`, pods named `k3s-2-runner-*`, and container `runner`, so the docker steps run as the runner user over the shared socket. Override them with `-n`, `--pod` and `--container`. `--record` writes each step's start and end, which `github-runner/harness/collect.py` uses to tag the alerts.

Before running:

1. **Order matters.** Phase 7 assumes Phase 5 produced a node kubeconfig. Run the suite in order; a partial run from Phase 7 measures nothing.
2. **Phase 7 expects `kubectl` to carry admin credentials.** Against the pod's own `no-permission` SA it fails closed, which is the correct outcome, not a missed detection.
3. **Destructive entries are declawed.** `publish-force-push-action-tags` stops before pushing; `impact-cryptominer-launch` is a stub named `xmrig`, not a miner; `evade-dead-mans-switch-dry-run` only prints. A real miner must carry `cpu: 2 / memory: 2Gi` limits.
4. **`evade-cleanup-staged-artefacts` runs last** and removes what the suite staged. After a partial run, check `/_work` and `/tmp` before reusing a runner.
5. **Run it on a rig you own.** The suite reads credentials and attempts host escape by design.

The expected detections hold against a bound profile. An unbound pod raises only a few rules. Results on k3s-2 with bound profiles are in `github-runner/README.md`.

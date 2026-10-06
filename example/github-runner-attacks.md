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

58 attacks, 91 expected detections, **26 of the 31** rules in the ruleset exercised. The five not exercised, each for a stated reason:

- **R0003** Syscalls Anomalies, **R1003** Disallowed ssh, **R1011** ld_preload — `enabled: false` in the shipped ruleset. Note that `inject-set-env-workflow-command` sets `LD_PRELOAD`, so enabling R1011 should make that entry fire too; worth a contrast cell.
- **R0012** Unexpected Ingress — a runner initiates connections and receives none. Legitimately not applicable; its absence is a property of the workload, not a gap in the suite.
- **R1000** Process executed from malicious source — needs a known-bad artefact shipped in-repo. Deliberately not added.

Six entries carry `expectedDetections: []` on purpose. They are things a real build genuinely does — reading its own identity, listing the work volume, checking whether a docker socket exists, dumping its own environment. They are in the suite so a contrast run shows **which attacker actions are indistinguishable from CI work**, which is the question a runner contrast test exists to answer.

## Running it

`bobctl simulate --suite example/github-runner-attacks.yaml -n arc-runners`

Prerequisites and honest caveats:

1. **Container name.** Every `containerName` says `runner`. ARC names the runner container `runner` and the sidecar `dind`; confirm against the live pod and pass `--container` if the scale set differs.
2. **Phases 5 and 7 are sequential.** Phase 7 assumes Phase 5 produced a node kubeconfig. Run the suite in order; a partial run from Phase 7 measures nothing.
3. **Phase 7 expects `kubectl` to carry admin credentials.** It will fail closed against the pod's own `no-permission` SA — which is the correct outcome and should be recorded as such, not as a missed detection.
4. **Destructive entries are declawed.** `publish-force-push-action-tags` stops before pushing; `impact-cryptominer-launch` is a stub named `xmrig` rather than a miner; `evade-dead-mans-switch-dry-run` only prints. Per the project's resource rule, if a real miner is ever substituted it must carry `cpu: 2 / memory: 2Gi` limits.
5. **`evade-cleanup-staged-artefacts` runs last** and removes what the suite staged. On a `--keep-going` partial run it may not execute, so check `/_work` and `/tmp` before reusing a runner.
6. **Run it on a rig you own.** The suite reads credentials and attempts host escape by design.

---

# Measured, not assumed

The first version of this file was desk work: researched, written, parse-checked, and **never executed**. It has now been run. What follows replaces the guesswork.

## Rig used

ARC controller chart **0.14.1** installed for real (`oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller`), all four CRDs present. Node-agent `v0.1.0-rogue66`, chart `1.41.0-duckling46`, storage `rc-rogue23`, k3s `v1.35.4+k3s1`.

**No `AutoscalingRunnerSet` was created, deliberately.** The CNCF manifest registers to `https://github.com/enterprises/cncf`; creating it would attach a runner to CNCF's enterprise, which is third-party infrastructure that could then receive their real jobs. Instead the pod *shape* was reproduced exactly — privileged dind sidecar, `/var/run/docker.sock` shared via emptyDir into a `runAsUser: 1000` runner, `supplementalGroups: [999]`, `fsGroup: 1001`, hostPath `/lib/modules` (ro) and `/sys/fs/cgroup`, one emptyDir across `/_work /.cache /.gradle /go /.m2 /tmp`, root init container.

Two deliberate deviations from the manifest, both resource-driven on a 15Gi laptop: the runner's `4 CPU / 12Gi` became `1 CPU / 1Gi`, and the 50Gi emptyDir became 2Gi.

## The escalation is real

An unprivileged `uid=1000` runner, using only the shared socket:

```
$ docker run --rm --privileged alpine:3.20 sh -c 'id -u; grep CapEff /proc/self/status; fdisk -l | grep -c "^Disk /dev"'
uid=0
CapEff: 000001ffffffffff
host block devices visible: 1
```

All 40 capabilities, uid 0, host block devices enumerable. That is CVE-2025-32955's mechanism and step 1 of the ARC node-escape chain, with no sudo and no Kubernetes RBAC. The socket is `srw-rw---- root ping` and the runner is in group 999, so group membership alone is sufficient.

**The chain was stopped there.** `mount /dev/dm-0`, `chroot /host`, `nsenter --target 1`, `modprobe`, the cgroup `release_agent` write and the eBPF load were **not executed**, because this rig is the development laptop and those mount or alter its real root filesystem. By the same rule that deferred the CIFSwitch escape PoC to a VM, that phase needs a disposable VM, not this host.

## What actually fired — 25 commands, unbound pod

| rule | claimed by suite | fired | |
|---|---|---|---|
| R0001 Unexpected process launched | 13 | **6** | fired |
| R0011 Unexpected Egress | 9 | **2** | fired |
| R0005 DNS Anomalies | 5 | **1** | fired |
| R0004 Capabilities Anomalies | 2 | **1** | fired |
| R0002 Files Access Anomalies | 14 | 0 | silent |
| R0010 Sensitive File Access | 7 | 0 | silent |
| R0006 SA token access | 5 | 0 | silent |
| R1006 Container escape | 9 | 0 | silent |
| R0007, R0008, R0040, R1001, R1002, R1004, R1005, R1007-R1010, R1012, R1015, R1016, R1030, R1031, R2000 | 1–3 each | 0 | silent |

**91 expected detections claimed, 10 alerts fired, 4 of 26 rules.**

## Why, and what it means for the suite

Most of the silence is structural and was not stated in the first version:

1. **The pod was unbound.** Under a deny-all projection, file opens do not alert at all unless `nodeAgent.config.denyAllAlertsOnOpens: true`, which is **absent** on rogue66 (ruling X-28, node-agent#109). That alone accounts for R0002 (14) and R0010 (7) — 23 of the 91. **The `expectedDetections` in this suite are only meaningful against a BOUND, signed profile, with that knob on for any opens expectation.** That is now a precondition, not a footnote.
2. **R0006 did not fire on a successful SA-token read.** The token was read — a real JWT came back — and no alert followed. Not explained by X-28, since R0006 is not an opens rule. Worth its own investigation.
3. **R1006 did not fire on the privileged-container escalation above.** The escalation provably happened. This is the single most interesting silence in the run.
4. **R1017 rogue artefact did not fire** for an unbound runner pod, though it fires for other unbound workloads on this same agent.

## Suite defects the run found

- **`escape-hardlink-sensitive-path` could never have worked.** `/etc/passwd` is on the container layer and `/_work` is an emptyDir, so `ln` fails with `Cross-device link` and R1012 was unreachable. Fixed to link within one device.
- **`curl` is absent** on an alpine-based runner image; eight entries used it. The real `external-gha-runner:noble` has it, so this is image-dependent rather than wrong — `wget` fallbacks added.
- **`gdb`, `strace`, `kubectl`, `node`, `capsh`, `base32` are also absent** there. `cred-ptrace-attach-runner-worker` and all of Phase 7 no-op on such an image.
- **The surrogate has no `Runner.Worker` process**, so `cred-runner-worker-memory-dump` and `cred-oidc-token-memory-scrape` — the technique of the period, and the reason this suite exists — **remain unvalidated**. They need a real registered runner executing a job. That is the one gap this rig cannot close.

## Honest status

The suite executes and the commands are sound, with the fixes above. The `expectedDetections` are a **specification of what should fire against a bound profile**, and have been measured only against an unbound one, where 4 of 26 rules fire. Treating the 91 as a baseline would be wrong. The next run needed is: learn a profile on this pod, bind it signed, set `denyAllAlertsOnOpens: true`, and re-measure — that is the number worth putting in a contrast matrix.

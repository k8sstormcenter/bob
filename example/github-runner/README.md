# GitHub runners on ARC: profiles, rules and suite

Everything needed to run self-hosted GitHub Actions runners (ARC, `containerMode: dind`) under kubescape with zero attack-distinguishing alerts on clean builds, and to prove it with the attack suite in `../github-runner-attacks.yaml`.

| path | what | who reads it |
|---|---|---|
| `deploy/` | `arc-runner-runner`, `arc-runner-dind`: the two ContainerProfiles the agent binds, plus `kustomization.yaml` | Flux (point a Kustomization at it) |
| `rules/default-rules.yaml` | the Rules spec these profiles are tuned for | the rt-security extension values |
| `sbobs/runner/base.yaml`, `sbobs/runner/overlays/<repo>.yaml` | the runner profile split into what every job does and what each repository adds | people; `harness/compose.sh` builds `deploy/arc-runner-runner.yaml` from them |
| `sbobs/node-k3s-2-worker-*-host.yaml` | k3s-2 worker host profiles | not bound |
| `harness/` | `compose.sh`, `collect.py`, `score.sh`, `check_deploy.py` | the measuring loop and CI |

## Binding

Label the runner pod template `kubescape.io/user-defined-profile: arc-runner`. The agent binds `<label>-<container>`: `arc-runner-runner` to container `runner`, `arc-runner-dind` to container `dind`. It does not read the `kubescape.io/profile-fragment` labels on `sbobs/`, so only `deploy/` is bindable. CI (`ci-github-runner-deploy.yaml`) rejects a `deploy/` profile that carries `kubescape.io/status`, a fragment label, a flat `arc-runner`, a wildcard exec name, or an exclusion comm longer than 15 characters.

## Rules

`rules/default-rules.yaml` is the live `honey/default-rules` spec on k3s-2. Its hash, `3bd51a7699a9`, is `sha256(json.dumps(spec, sort_keys=True))[:12]`, also printed by `harness/collect.py rules-hash`. It differs from the shipped ruleset in three ways:

- `supportPolicy: true` on 12 rules (R0002 R0004 R0005 R0006 R0009 R0011 R0012 R0040 R1010 R1011 R1012 R1030). Per-process exclusions in a profile (`rulePolicies.processAllowed`) only take effect on rules with `supportPolicy: true`. The exclusion matches the kernel comm, at most 15 characters.
- R1030 ignores io_uring opcodes `0 6 7 11 12 14 15 29`. The 818 libuv `EPOLL_CTL` (29) alerts per Node build go away, and io_uring `OPENAT` (18) and `READ` (22) still alert.
- R0006 deduplicates per process instead of per comm, and R0010 also covers gshadow, the kubeconfigs (admin, super-admin, kubelet, k3s) and the SSH host keys.

## Measuring

```
bobctl simulate --suite ../github-runner-attacks.yaml --pod <runner pod> --record fire.json
CH_USER=… CH_PASSWORD=… harness/collect.py alerts --pod <runner pod> --fire fire.json --out <dataset>/builds/<id>
harness/collect.py chunks --pod <runner pod> --out <dataset>/builds/<id>
harness/score.sh <dataset>
```

`collect.py alerts` tags each alert with the suite step whose command is in the alert's process-tree ancestry, and tags it `_build` otherwise. `score.sh` replays every recorded build against `deploy/` offline:

- **Clean build:** counts the attack-distinguishing alerts. The target is 0.
- **Attack build:** counts the suite steps with at least one distinguishing alert.

R0005 and R0011 (DNS and egress) count as floor and are reported separately. Set `FLOOR=` to change that.

## Evidence

k3s-2, node-agent rogue84, runner image `ghcr.io/actions/actions-runner:latest`, 48 clean builds of 14 repositories (cpp, dotnet, go, gradle, maven, helm, terraform, js-npm, js-pnpm, js-yarn, php, python, ruby, rust) plus the node-agent repository's own CI. Replayed against `deploy/` with these rules:

**Clean builds: 0 to 20 distinguishing alerts per build.**

| residue | where | what fixes it |
|---|---|---|
| R0040 exec arguments | js, python, ruby | inherent to argv matching on interpreters |
| R0004 capabilities | gradle, maven, php | `runc` under `containerd-shim` in dind (Testcontainers), and the cluster's Pixie `px_jattach` attaching to the JVM. Neither is the job's own process, and plain `runc` stays unexcluded because a job can name a binary that. Open. |
| R0001 / R1001 unexpected exec | terraform, ruby, dotnet | per-repository overlays |
| R0008 /proc reads | php, dotnet | open |
| R0002 file opens | php (20) | the agent does not project open flags, so R0002 cannot tell a write from a read (entlein/node-agent#126) |

The floor is 0 except on dotnet (12 to 16, R0011 to rotating CDN addresses; a DNS-aware R0011 is entlein/node-agent#10).

**Attack: 29 of 58 steps raise a distinguishing alert** when every step runs as the runner user (k3s-2 fresh pod, 2026-10-10, `bobctl simulate --container runner`). The earlier 55/58 ran the 12 docker steps inside the privileged `dind` container and is void.

| cause of silence | steps | lever |
|---|---|---|
| dedup: R0040 and R1004 key on comm (and exec), so once one `curl`/`sh` alert fires on a pod, later steps using the same binary are suppressed; the suite runs all 58 steps on one pod | not yet separated | per-process uniqueId in the rules (being measured) |
| payload runs in a container started through dind's socket, which the agent does not profile; the runner side only shows the `docker` CLI (R0040) | read-node-kubeconfig, symlink, and the escape chain beyond R0040 | agent (entlein/node-agent#37) |
| agent coverage: fileless execution, kernel modules, DNS for names that do not resolve | 4 | agent (#126); R1032 for DNS exfiltration |
| `kubectl` is absent from `actions-runner:latest`, so the 5 kubectl steps exec nothing; they measure only on an image that ships kubectl | 5 | image prerequisite |
| the profile admits it: `/home/runner/.credentials` is written by the runner itself; `cp`/`chmod` take any arguments | to be quantified | profile |

Builds recorded before these rules (`build-j/k/l/n`, `r2-*`) have R1030 lines without the opcode field. Their R1030 counts cannot be replayed through the filter.

## Limits

The profiles are learned from one image on one cluster. A runner image with a different userspace (another Ubuntu release, other preinstalled toolchains) has different exec and library paths and needs its own learning run before binding.

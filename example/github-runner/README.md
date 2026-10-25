# GitHub runners on ARC: profiles, rules and suite

Everything needed to run self-hosted GitHub Actions runners (ARC, `containerMode: dind`) under kubescape with zero attack-distinguishing alerts on clean builds, and to prove it with the attack suite in `../github-runner-attacks.yaml`.

| path | what | who reads it |
|---|---|---|
| `deploy/` | `arc-runner-runner`, `arc-runner-dind`: the two ContainerProfiles the agent binds, plus `kustomization.yaml` | Flux (point a Kustomization at it) |
| `rules/default-rules.yaml` | the Rules spec these profiles are tuned for | the rt-security extension values |
| `sbobs/runner-family/runner.yaml`, `sbobs/runner-family/runner-overlay-<profile>.yaml` | the three runner profiles (arc, NNF noble, NNF resolute) split by `bobctl base --class runner` into what all of them do and what each adds; the base is the portable CI/CD behaviour, an overlay is one image's remainder | people; `harness/compose.sh` builds the three `deploy/*-runner.yaml` from them byte for byte, and CI fails on drift |
| `sbobs/node-k3s-2-worker-host.yaml` | generalized k3s-2 worker host baseline (both workers merged + collapsed); materialized into `deploy/node-k3s-2-worker-{1,2}-host.yaml`, name per node so each binds | people; regenerate with `bobctl generalize` from fresh captures |
| `harness/` | `compose.sh`, `collect.py`, `score.sh`, `check_deploy.py` | the measuring loop and CI |

## Binding

Label the runner pod template `kubescape.io/user-defined-profile: arc-runner`. The agent binds `<label>-<container>`: `arc-runner-runner` to container `runner`, `arc-runner-dind` to container `dind`. It does not read the `kubescape.io/profile-fragment` labels on `sbobs/`, so only `deploy/` is bindable. CI (`ci-github-runner-deploy.yaml`) rejects a `deploy/` profile that carries `kubescape.io/status`, a fragment label, a flat `arc-runner`, a wildcard exec name outside the collapsed shape `{path: DIR/⋯, args: [DIR/⋯, ⋯⋯]}`, or an exclusion comm longer than 15 characters.

## Rules

`rules/default-rules.yaml` is the 32-rule spec the runners are tuned for (candidate-5). Recompute its hash with `harness/collect.py rules-hash` after a roll (`sha256(json.dumps(spec, sort_keys=True))[:12]`); candidate-4 was `58ef86be9a2e`. candidate-5 adds `supportPolicy: true` on R1006 to candidate-4 so the dind profile's per-comm escape policy takes effect. It differs from the shipped ruleset in these ways:

- `supportPolicy: true` on 14 rules (R0002 R0004 R0005 R0006 R0008 R0009 R0011 R0012 R0040 R1006 R1010 R1011 R1012 R1030). R0008 joins so the runner profiles can except `Runner.Worker`, which reads its own job processes' environ by design, while `ps`, `sh` and `pgrep` reading other processes' environ, the credential-sweep shape, keep alerting. Per-process exclusions in a profile (`rulePolicies.processAllowed`) only take effect on rules with `supportPolicy: true`. The exclusion matches the kernel comm, at most 15 characters. R1006 allows `runc`/`dockerd` unshare on dind; any other comm still alerts.
- R1030 ignores io_uring opcodes `0 6 7 11 12 14 15 29`. The 818 libuv `EPOLL_CTL` (29) alerts per Node build go away, and io_uring `OPENAT` (18) and `READ` (22) still alert.
- R0006 deduplicates per process instead of per comm, and R0010 also covers gshadow, the kubeconfigs (admin, super-admin, kubelet, k3s) and the SSH host keys.
- R0005 alerts only on a resolving lookup (`event.rcode == 0`), so a failed lookup is not a DNS anomaly.
- R1032 "DNS exfiltration attempt" (bound): a non-resolving name with a label of 25+ characters that is not in the egress profile. Needs the sensor's `dnsReportFailures` on to fire. Names under the resolver's own zones (`.cluster.local.`, `.in-addr.arpa.`, `.novalocal.`, `.ts.net.`) are excluded: glibc search expansion tries them first and gets NXDOMAIN for legitimate hosts such as `run-actions-2-azure-eastus.actions.githubusercontent.com`, and a query under those zones never reaches an attacker's nameserver.

R0002 stays path-only here; the chart's write-flags disjunct is deliberately not adopted, because it raised 7–14 alerts per clean build (paths learned read-only then written) with no detection gain. Revisit when learning captures writes.

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

R0005 and R0011 (DNS and egress) count as floor and are reported separately. Set `FLOOR=` to change that. An R0002 the sensor marks `arguments.unresolvedPath: true` (a failed open with no resolvable path, reported by design since node-agent 2026-10-20) is floor as well: there is nothing to allow for a file that does not exist.

## Demo and confusion matrix

`harness/demo.sh` runs one clean build and one held build on a bound runner set, replays the suite
against the held runner, collects both pods' alerts and dx KPI rows, and prints the confusion matrix:

```
REPO=k8sstormcenter/nnf-community-infra RUNNER=nnf-c-ubuntu-24.04-2-8-x86 \
CH_USER=… CH_PASSWORD=… KNOWN=R0040:qemu-check harness/demo.sh
```

`harness/matrix.py <dataset>` scores any dataset the same way. A suite step counts as detected when
node-agent raised a non-floor alert tagged to it, or when dx scored its suspicion malicious from a
witness source (`verdict=malicious` and `source` in forest/wire/dc_snoop). A clean build counts as a
false positive on any non-floor alert or any witnessed-malicious KPI verdict. dx scores a suspicion
progressively for some minutes after the attack, so collect the KPI rows once dx has finished (about
20 minutes) or the join comes back empty.
`--known RULE:substring` lists a known engine defect apart instead of scoring it, and
`--subset harness/teampcp-steps.txt` restricts the steps to the TeamPCP tradecraft.

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

**Offline replay, 2026-10-25.** `harness/score.sh` over the 73 recorded k3s-2 builds (50 learn, 4 clean, 4 held-out, 6 attack) is the gate every profile change passes before it ships: detection on the attack recordings must stay identical, and the clean-side distinguishing alerts (R1030 lines recorded before the opcode filter excluded) must not rise. Five tool-emitted rounds took them from 263 to 127 with detection unchanged: per-run `/tmp` and Rust `target` directories folded and the pip bootstrap program wildcarded as one token (248); per-process exceptions for `px_jattach`, the apt postinst helpers and `Runner.Worker`, with R0008 honouring exceptions (198); the Ruby toolchain unioned from its recorded build and repository literals scrubbed (159); repo-defined argv of `npx`, `yarn`, `pnpm`, `npm`, `corepack`, `printf` and `docker-buildx` folded and dind's `/proc/<pid>/exe` re-exec declared (133); the setup-dotnet install script admitted (127). Of the 127 left, 21 are sensor artifacts (exec paths recorded relative to the working directory, failed opens with no path), 6 are `ps`, `pgrep`, `grep` and `fuser` capability uses kept alerting on purpose, and most of the rest is argv of interpreters running repository code.

**Docker builds (dind V7):** dind V6 was learned from the engine only and never saw a Dockerfile build, so an organic `docker build`/`buildx`/`compose` raised 45–53 distinguishing alerts (buildkit and runc reading `/run/runc/<id>`, `/proc/pressure`, `/sys/fs/cgroup/docker`). dind V7 adds those four organic runs to the dind corpus and drops the residue to 7–9 in-sample, with no loss of dind-side attack detection. The remainder is three families, still open: runc re-exec through `/proc/<pid>/exe` (R0001), dind capability use (R0004), and buildkit's localhost gRPC (R0012). Held-out confirmation needs one fresh docker build.

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

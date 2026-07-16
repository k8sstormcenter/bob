# confusion — near-miss confusion noise for dx

The `example/*/loadgen.yaml` kits emit **benign "functional confusion"** — real
traffic on the same routes an experiment uses, so the experiment blends in *by
shape*. Those namespaces are `kubescape.io/ignore: "true"` (not monitored) and dx
fast-discharges them.

`confusion-loadgen.yaml` is the **opposite and complementary** kit: **monitored**
pods that continuously emit *attack-shaped-but-benign* telemetry — the **near-misses
dx must actually work up and rule out**. It is the noise for the needle-in-a-haystack
test: **~99.999% of referrals are near-miss confusion, exactly ONE chain is the real
experiment.**

> Terminology: the single real chain is an **experiment**, never an "attack".

## Why this confuses dx (mapped to `dx/internal/symptom/symptom.go`)

dx triages a referral by pulling the pod's real telemetry and matching it against
its SBoB baseline + the generic-symptom predicates. An **empty** pull is
`Indeterminate` (abstain) — which is why *injected fake-pod* noise is inert. Real
confusion needs **real pods with real telemetry** that trips a symptom predicate, so
dx triages **malignant → full workup → `ruled_out`**:

| loop action | symptom predicate | stage | near-misses |
|---|---|---|---|
| spawn `curl`/`wget`/`nslookup`/`dig`/`nc` | `reconTool`, `shellSpawn` | Execution | log4shell process-spawn |
| connect to 4444 / 1389 / 1337 / 9001 | `egressC2Port` | Egress | ldap-egress |
| connect to a random high port | `egressUncommonPort` | Egress | ldap-egress |
| DNS lookup of a long random label | `dnsHighEntropy` | Exfil | base32 DNS exfil |
| POST a base64 blob | `payloadHighEntropy` | Exfil | data exfil |
| POST `AKIA…` / `ghp_…` | `secretMaterial` | Exfil | credential exfil |
| read `/etc/passwd`, `serviceaccount/token` | `sensitiveFileRead` | Collection | argocd-malicious-render |

Each near-miss lacks the *complete* chain, so dx works it up and **rules it out** —
producing rich `dx_attack_graph` rows (`ruled_out` + `consulted` edges), not inert
`triage_abstain`. That is the discrimination/precision stress.

## Apply (SBoB-first recipe — required, or the near-misses fire blank)

```sh
kubectl apply -f confusion-loadgen.yaml          # ns + User AP/NN + Deployment
kubectl -n confusion rollout restart deploy/confusion-loadgen   # bounce so node-agent binds the User profile at pod start
kubectl -n confusion rollout status deploy/confusion-loadgen
```

The namespace is **monitored** (no `kubescape.io/ignore`); the tight User
`ApplicationProfile` baselines only the entrypoint shell, so every recon tool the
loop spawns is an unexpected process (**R0001**), and the `NetworkNeighborhood`
baselines only kube-dns so the odd-port egress deviates.

## Dialing the ~99.999% ratio

Graph rows = **distinct** `(pod, rule, window)` investigations (dx dedups repeats),
so scale **identities**, not raw volume:

```sh
kubectl -n confusion scale deploy/confusion-loadgen --replicas=<N>
```

Each replica is a distinct pod ⇒ a distinct investigation per window. Lower the
`INTERVAL` env for denser referrals. Pick `N` (and window) so the near-miss
referral count is ~10^5 against the single experiment. Start at `replicas: 10` and
tune live.

## Targets are non-routable on purpose

All egress goes to `192.0.2.0/24` (RFC 5737 TEST-NET-1). pixie records the connect
as `conn_stats` even when refused/timed out — which is all the egress symptom needs
— and nothing real is ever contacted.

## Split variant — realistic precision test (`confusion-split.yaml` + `run-experiment.sh`)

The combined `confusion-loadgen.yaml` makes every pod do **both** `unexpected-spawn`
**and** `sensitive-file-read` — which *is* `argocd-malicious-render`'s anchor pair, so
dx (correctly) rules those pods IN. That's an attack rig at scale, not benign noise.

`confusion-split.yaml` fixes the realism — **one anchor per pod**, so neither variant
completes a 2-anchor condition:
- `confusion-recon` — spawns recon tools (+odd/C2-port egress, high-entropy DNS) →
  `unexpected-spawn` only. **No** file read.
- `confusion-fileread` — reads `/etc/passwd`+`serviceaccount/token` via **bash redirect**
  (`$(<file)`, no child process) → `sensitive-file-read` only. **No** spawn.

Expected: dx triages each malignant, works it up, and **rules it out** (a lone symptom
matches no full condition) → ~0 `argocd-malicious-render` false-positives, while the real
experiment (full co-occurring chain) still rules in.

Repeatable run + measurement:
```sh
./run-experiment.sh [log4j] [replicas-per-variant=25] [window-s=150]
```
Deploys+binds the split, scales it, fires ONE experiment, then prints the dx NFR delta
(time-to-verdict, bench-query, pivot-escalation, drops) + how dx classified the confusion
(ruled_out vs false-positive) + the experiment verdict. Uses the current kubectl context.

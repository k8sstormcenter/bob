# Argo CD demo — active-diagnosis, three scenarios

Reproducible testbed for the Argo CD repo-server manifest-generation
weakness (CVE-2022-24348 class). ONE malicious-repo payload, THREE
backend image variants — the negative-control test for a framework that
claims to discriminate "vulnerable", "contained", and "patched" from the
same kernel-observable trace.

| | repo-server image | hardening | expected on `app` |
|---|---|---|---|
| **A** | vulnerable Argo CD, default | shell + helm + kustomize + git | R0001 (render-time helper spawn) + R0010 (out-of-tree file read) + R0011 (egress to attacker repo) |
| **B** | distroless repo-server | seccomp, read-only fs, no `/bin/sh` | R0011 (initial fetch) + R1100 (helper can't start — ENOENT) |
| **C** | patched Argo CD | traversal closed, plugin sandboxed | nothing — inert (negative control) |

The attacker repo, the Application spec, and the payload are identical
across scenarios. The discriminator is the `app` container image alone.

## What's in here

```
argocd.manifest.yaml      ChainManifest — pods app/observer + scenarios A/B/C
argocd.yaml               ns argocd + adv + app(repo-server, scenario A) + observer + attacker
app-b.yaml app-c.yaml     scenario B / C image swaps
functional-tests.yaml     benign GitOps baseline (drives SBOB learning)
attacks.yaml              the three-scenario attack suite (same payload)
attack-pod.yaml           in-cluster pod that registers + syncs the probe Application
sbobs/{ap,nn}-{app,observer}.yaml   hand-crafted v1 SBOBs (iterate from observed alerts)
```

## Apply the SBOBs (pixie-agent path)

```bash
cd example/argocd

# Delete-first to avoid the strategic-merge-patch strip, then apply.
for p in app observer; do
  kubectl delete applicationprofile  "$p" -n argocd --ignore-not-found
  kubectl delete networkneighborhood "$p" -n argocd --ignore-not-found
  kubectl apply -n argocd -f sbobs/ap-$p.yaml
  kubectl apply -n argocd -f sbobs/nn-$p.yaml
done

# Patch the deployments to reference the User profiles, then restart
# (node-agent picks up user-supplied profiles only at pod start), and
# allow ~30s for the per-binding cache to settle before attacking.
```

Or drive it with the pipeline:
```bash
../../scripts/sbob-pipeline.sh apply example/argocd/argocd.manifest.yaml --wait
```

## Run the tests

- **Functional (benign) baseline**: replay `functional-tests.yaml`
  against `argocd-server` — confirms the repo-server's normal render
  path stays quiet under the SBOBs.
- **Attack scenarios**: apply `attacks.yaml`; switch scenarios with
  `sbob-pipeline.sh switch … {A-vulnerable,B-contained,C-patched}`.

## What to report back

Per scenario, the kubescape rule fires on `app` (container
`repo-server`) plus the verdict. If a rule that should fire doesn't,
send the alert's `comm` / `exepath` / `path` labels and I'll widen the
SBOB (same iterate loop as the log4j demo). If R0011 stays silent, check
`networkEventsStreaming` is enabled — it's a cluster knob, not an SBOB
gap.

These SBOBs are **v1 starters** — grounded in the repo-server's real
process surface but expected to need 1–2 widening rounds against your
actual cluster's observed paths.

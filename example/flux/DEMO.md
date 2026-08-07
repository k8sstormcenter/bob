# Flux SBoB demo — deploy, drive, contrast

Six controllers, one SBoB each. Flux is a *controller* workload: almost nothing
arrives over its own API, so the behaviour that matters is what it does while
reconciling. The load driver is upstream `fluxcd/flux-benchmark`, not a synthetic
one.

## 0. bobctl

The exact binary these numbers were produced with:

```
curl -sSLo bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.3-rc1/bobctl-linux-amd64
chmod +x bobctl && sudo mv bobctl /usr/local/bin/
bobctl --version
```

(swap `amd64` for `arm64` as needed)

`v0.1.3-rc1` is a **pre-release cut from PR #181**, not from `main`. `main`'s
submodule pointer still predates entlein/bob#61, so a binary built from `main`
does not contain the fixes below and will not reproduce these results:

| | |
|---|---|
| R0012 + `FamIngress` | ingress is graded as its own family |
| selector-based matching | peers matched by pod identity, not a stale IP |
| volatile path normalisation | `/etc/redis/..2026_07_31_13_39_49.291…/redis.conf` → `/etc/redis/⋯/redis.conf` |
| `-n` / `--service` / `--container` | one suite can drive several deployments |
| `Rules()` synced | 31 rules, matching `kubescape/default-rules.yaml` |

## 1. Stack

```
make kubescape
make alertmanager
```

On k3s, node-agent cannot see container starts unless it is told where `runc`
lives, and it must be able to reach that filesystem:

```
make kubescape KS_RUNC=/mnt/dev-data/k3s/data/current/bin/runc KS_RUNC_MNT=/mnt/dev-data
```

Find the value on a NODE, not here:

```
ps -eo args | grep -oE '[^ ]*/bin/containerd-shim-runc-v2'
```

`make kubescape` also applies `kubescape/default-rules.yaml`, the rule binding,
and `kubescape/collapse-config.yaml`. The collapse config matters: with the stock
threshold the learner folds whole directories into a wildcard, and a wildcard in
the FIRST path segment matches `/etc/shadow`, which silently disables R0010,
R1010 and R1012.

Check the agent came up with the ingress rule bound:

```
kubectl -n honey rollout status ds/node-agent
kubectl get runtimerulealertbindings all-rules-all-pods \
  -o jsonpath='{.spec.rules[*].ruleName}' | tr ' ' '\n' | grep Ingress
```

## 2. Deploy

```
make deploy-flux
```

Installs Flux v2.9.3 with the two image controllers, applies
`example/flux-vulnerable.yaml` (the Services the controllers lack upstream) and
the Flux collapse overlay.

| controller | ns | service | port | SBoB |
|---|---|---|---|---|
| source-controller | flux-system | source-controller | 80 | sbobs/cp-flux-source-controller.yaml |
| kustomize-controller | flux-system | kustomize-controller | 8080 | sbobs/cp-flux-kustomize-controller.yaml |
| helm-controller | flux-system | helm-controller | 8080 | sbobs/cp-flux-helm-controller.yaml |
| notification-controller | flux-system | notification-controller | 80 | sbobs/cp-flux-notification-controller.yaml |
| image-reflector-controller | flux-system | image-reflector-controller | 8080 | sbobs/cp-flux-image-reflector-controller.yaml |
| image-automation-controller | flux-system | image-automation-controller | 8080 | sbobs/cp-flux-image-automation-controller.yaml |

`sbobs/` holds the **collapsed** profile — the shippable policy.
`sbobs/uncollapsed/` holds the full observed surface it was derived from
(source-controller 824 opens vs 27). Ship the former; diff against the latter
when a regression appears.

## 3. Drive real work

A controller that is idle touches almost nothing, and a profile learned from an
idle controller is worthless. Upstream's benchmark is the load:

```
make flux-benchmark                      # KS=20 HR=10, ~4 min
make flux-benchmark-down                 # tear down
```

It stands up an in-cluster OCI registry, pushes upstream's Timoni modules and the
podinfo artifact, then runs upstream's four phases: kustomize install, kustomize
upgrade, helm install, helm upgrade. `PODS=0` throughout, so the load lands on the
controllers and not on workload pods.

It exercises source-, kustomize- and helm-controller plus notification ingestion.
It does **not** exercise the two image controllers — upstream has no benchmark
module for them; `example/flux/drive-gitops-workload.sh` covers those.

## 4. Benign traffic — expect NO detections

Real client traffic, not health probes: the artifact GETs kustomize- and
helm-controller issue every reconcile, the event JSON every controller POSTs, and
the Prometheus scrape plus pprof surface for the controllers that serve nothing
else.

```
bobctl test --functional-tests ../flux-source-controller-functional-tests.yaml       -n flux-system
bobctl test --functional-tests ../flux-notification-controller-functional-tests.yaml -n flux-system
bobctl test --functional-tests ../flux-kustomize-controller-functional-tests.yaml    -n flux-system
bobctl test --functional-tests ../flux-helm-controller-functional-tests.yaml         -n flux-system
bobctl test --functional-tests ../flux-image-reflector-controller-functional-tests.yaml  -n flux-system
bobctl test --functional-tests ../flux-image-automation-controller-functional-tests.yaml -n flux-system
```

All HTTP. There are deliberately no exec tests: every binary in these images is
`/bin/busybox`, so an exec test would put busybox in the baseline and R0001 would
stop firing for `cat` and `ln` in the attack suite.

## 5. Attacks — expect detections

```
bobctl attack --attack-suite ../flux-source-controller-attacks.yaml -n flux-system
```

(swap the controller name; one suite per controller)

## 6. Contrast: benign FPs vs attack TPs

`$T0` = a timestamp taken right before step 5.

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# ... run step 5 ...
curl -s localhost:9093/api/v2/alerts | python3 -c '
import json,sys,os
from collections import Counter
a=json.load(sys.stdin); t0=os.environ.get("T0","")
al=[x for x in a if x["labels"].get("namespace")=="flux-system"]
fp=[x for x in al if x.get("startsAt","")<t0]
tp=sorted({x["labels"].get("rule_id") for x in al if x.get("startsAt","")>=t0})
print("benign FPs:", len(fp), dict(Counter(x["labels"].get("rule_id") for x in fp)) or "CLEAN")
print("attack TPs (distinct rules):", len(tp), tp)'
```

## 7. Grade the profile

```
bobctl contrast --profile sbobs/cp-flux-source-controller.yaml --type controller
```

Expect 31 rules graded, R0012 **Separable** — the SBoB declares its ingress
peers. Replace that stanza with `0.0.0.0/0` and R0012 turns **Blind**, with
`accepts-anything` reported as a deviation.

## 8. Ingress: what R0012 actually needs

Kubelet liveness probes arrive from the **node**, not from a pod, so they carry no
pod identity and **no `podSelector` can ever match them** — 187's identity
matching does not help for the dominant inbound class on a controller. They need
the pod CIDR as a literal peer. Inter-controller traffic does have an identity and
is declared by selector, which survives rescheduling.

Both shapes are in every Flux SBoB:

```
ingress:
- identifier: kubelet-probes
  ipAddresses: [10.42.0.0/16, 10.244.0.0/16]     # k3s, kubeadm
  ports: [{name: TCP-9440, port: 9440, protocol: TCP}, {name: TCP-8080, port: 8080, protocol: TCP}]
- identifier: from-kustomize-controller
  podSelector: {matchLabels: {app: kustomize-controller}}
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: flux-system}}
  ports: [{name: TCP-9090, port: 9090, protocol: TCP}]
```

Drop the `kubelet-probes` entry and R0012 fires every 10s on healthy probes.

## Known gaps

- **Flux learns `ingress: null`** even on the celnet agent, while argocd and redis
  learn it fine. The stanzas above are hand-authored for that reason. Tracked in
  k8sstormcenter/bob#189, with a minimal nginx reproduction.
- **R0012 did not fire on Flux** in that investigation despite a null ingress and
  real inbound, while R0011 fired on the same pods in the same window. Cause not
  isolated. A plain nginx pod in the same namespace alerts correctly, so it is
  specific to these controllers.
- The `drifted-binary-exec` attack in the redis-distro suite asserts **R1000**,
  whose expression is `/dev/shm`-scoped while the attack runs its binary from
  `/data`. It can never fire; the assertion is wrong, not the profile.

## Results this was validated against

bobctl `v0.1.3-rc1`, node-agent `sbob-rc5s-celnet@sha256:dc4e666`, storage
`sbob-rc5s`, k3s single node.

| leg | score |
|---|---|
| redis (`example/redis`, 62 attacks / 89 functional tests) | 0 — perfect |
| flux/source-controller | 0 |
| flux/kustomize-controller | 0 |
| flux/helm-controller | 0 |
| flux/notification-controller | 0 |
| flux/image-reflector-controller | 0 |
| flux/image-automation-controller | 0 |

Zero false positives on every leg.

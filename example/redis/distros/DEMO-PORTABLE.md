# Portable SBoB demo — learn once, ship anywhere, compose a client

Takes the redis distro from `DEMO.md` and shows the portability workflow end to
end: deploy, learn, collapse the learned network stanza to portable identities,
add a client, discover its allowlist by label, and ship the client as a signed
overlay fragment. The composite (db + client) must raise **no false positives**
while still alerting on every contrast test.

Why this matters: a learned profile records **addresses**, and addresses are
cluster-specific. Move it to a cluster with a different pod/service CIDR and every
internal peer is unmatched — R0011 fires on all of it. Labels, Service names and
namespaces are identical across clusters. Portability is the act of re-expressing
addresses as identities.

Verified on a clean k3s cluster against chart `1.41.0-duckling23` (node-agent
`v0.1.0-rogue35`, storage `rc-rogue23`): deploy, learn, portable, add client,
discover by label. Read the step-3 result before relying on this demo to show a
collapse — on this chart the agent resolves internal peers itself, so `portable`
is a no-op for them and the collapse it demonstrates is the loopback drop.

## 0. Prerequisites

**`docker login` first.** node-agent runs from the private
`docker.io/entlein/duckling` repository. Without credentials `make kubescape`
builds an empty pull secret and node-agent sits in `ImagePullBackOff` several
minutes later, reporting a registry error rather than a missing login.


```
curl -L https://github.com/k8sstormcenter/bob/releases/download/v0.1.6-rc1/bobctl-linux-amd64 -o bobctl
chmod +x bobctl && sudo mv bobctl /usr/local/bin/bobctl
bobctl portable --help      # this demo needs the portable verb
```

Bring up the stack from the repo root:

```
make kubescape
make alertmanager
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
```

`make kubescape` defaults to the chart soc installs, so there is nothing to
override. The port-forward is not optional: `bobctl verify` reads Alertmanager at
`http://localhost:9093` and fails with `connection refused` without it.

The `kubescape` target installs the GitHub release **tarball** — the same one
soc's skaffold uses — so there is no helm-repo index to drift against.

Upgrading over an older install fails once with *"invalid ownership metadata"* on
`rules/default-rules`: the chart now ships that object and helm will not adopt the
one a previous install applied. Delete it and re-run:

```
kubectl delete rules default-rules -n honey
```

A change to the node-agent values updates its ConfigMap but does **not** restart
the pod, and node-agent reads that config at boot. After any values change:

```
kubectl rollout restart ds/node-agent -n honey
```

**Minimum chart: `1.41.0-duckling21`.** Below it the demo does not merely degrade,
it misleads:

| needed for | lands in |
|---|---|
| serviceRef / serviceSelector expansion at all | the chart's node-agent must carry it — duckling5 does not |
| a port-less serviceRef inheriting the Service's ports | duckling21 |
| `(address, port)` claimed by a Service carved out of the host peer | duckling21 |
| `is_host_peer_egress` / `is_host_peer_ingress` in R0011/R0012 | duckling23 (soc#286) |
| plural `ipAddresses` honoured | node-agent rogue32+ |

On an older chart a portable profile silently admits nothing and every peer
alerts, which reads exactly like a bad profile rather than an old agent. Check
what you are actually running before believing a result:

```
helm -n honey list -o json | python3 -c 'import json,sys;print([r["chart"] for r in json.load(sys.stdin)])'
```

## 1. Deploy the database

```
./deploy-distros.sh redis
```

One namespace, pinned chart and image digest, so the learned profile is
reproducible.

## 2. Learn

```
bobctl learn -n redis --functional-tests functional/redis-oss.yaml
```

Drive the benign suite while learning, so the profile records what the
application does rather than what it happens to do while idle.

**Fire the benign traffic at the START of the window.** The window is the
container's first ~2 minutes. Deploy, then drive traffic immediately — do not
poll for the profile to appear first, because the poll consumes the window and
what you get is a profile that is `complete`, `ready` and **empty**. An empty
profile is not visibly broken: it reads exactly like a healthy one until you
count its entries, and every legitimate action the app then takes is a false
positive against it.

There is no `completed` state to wait for. A live container goes `initializing`
→ `ready` and stays at `ready` for life; `completion: complete` is the done
signal. Take the profile when it has entries:

```
bobctl get -n redis -o names
kubectl get containerprofile <name> -n redis -o yaml > sbobs/cp-redis.yaml
```

Read profiles **one at a time, by name**. A list request does not return spec
content, so every profile in a bulk `get -o json` looks empty whatever it holds.

That export is the missing link between what you just learned and what the next
step collapses: `sbobs/cp-redis.yaml` is otherwise a committed file from an
earlier run, and step 3 would silently collapse that instead.

## 3. Collapse to portable

```
bobctl portable --file sbobs/cp-redis.yaml --out sbobs/cp-redis-portable.yaml
```

**On the chart this demo pins, expect this to be a no-op for cluster-internal
peers** — and that is the honest result, not a failure. The node-agent has
`networkServiceEnabled` by default from `1.41.0-duckling23`, so it resolves peers
to identities *at learn time*. A freshly learned client profile already reads:

```
egress:
- podSelector: {matchLabels: {k8s-app: kube-dns}}
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
  serviceRefName: kube-dns
  serviceRefNamespace: kube-system
  ports: [53]
```

No literal addresses to collapse. Running `bobctl portable` over that profile
prints no rewrites and returns it byte-identical.

So the premise "a learned profile records addresses, and addresses are
cluster-specific" is **no longer true for internal peers on this chart**. What
`portable` is still for is everything the agent cannot resolve: loopback (which
it drops), external and public addresses, node/host peers, and any pod it could
not attribute to a Service. Point it at an older profile, or one carrying
external egress, to see it do work.

When there is something to resolve, each observed peer is re-expressed:

| observed | resolves to | emitted | why |
|---|---|---|---|
| `10.43.0.1:443` | ClusterIP of `default/kubernetes` | `serviceRef default/kubernetes` | ClusterIPs differ per cluster; the Service name does not |
| `10.43.0.10:53` | ClusterIP of `kube-system/kube-dns` | `serviceRef kube-system/kube-dns` | also matches the post-DNAT CoreDNS pod address |
| pod address, no Service | pod labels + namespace | `podSelector` + `namespaceSelector` | survives a reschedule |
| node InternalIP | node | `entity: host`, or literal if the apiserver needs an address | see the R0007 note below |
| public address | none | literal + `dnsNames` | stable everywhere; this is where exfil detection lives |
| `127.0.0.1`, `::1` | — | dropped | no egress rule fires on loopback |

Ports are always carried through. An empty port set admits **every** port, and
port `0` admits **none** — there is no partial widening.

The command prints one line per rewrite and lints the result. Anything it cannot
resolve is left literal and reported, because a wrong literal is visible while a
wrong wildcard is silent.

> **R0007:** the apiserver rule admits by **address only** — no port, no selector.
> A `podSelector` can never silence it. `--apiserver-needs-address` (default true)
> keeps node peers address-bearing for that reason; it is one flag because
> node-agent#34 may change the answer.

## 4. Add a client — and watch it alert

```
kubectl apply -f sbobs/cp-redis-client.yaml   # the client's own SBoB, so it does not self-alert
kubectl apply -f ../client.yaml
bobctl verify -n redis --format table
```

The client connects to redis on 6379. The db profile does not name it, so **R0012
fires on the ingress** — correctly. This is the true positive the allowlist has to
convert into a known peer without blinding the rule.

`bobctl verify` with no `--suite` will report `FAIL` here and count every active
alert as a false positive: with no suite it checks the built-in cmdinject
expectations, which this step is not running. That verdict is an artefact of the
missing argument, not a result. To read what actually fired:

```
curl -s 'http://localhost:9093/api/v2/alerts?active=true' \
  | python3 -c 'import json,sys,collections; print(collections.Counter((a["labels"].get("rule_id"), a["labels"].get("container_name")) for a in json.load(sys.stdin)))'
```

Expect R0012 on `redis`. R1017 (*rogue artefact*) also appears for the interval
between the container starting and its profile existing — that window is real and
the alerts are correct; they stop once the profile is bound.

## 5. Discover the client's identity, by label

The ingress entry names the **source**, so it is a selector and not a serviceRef:
a serviceRef would resolve to the Service fronting the *destination*, which never
contains the caller.

```
kubectl -n redis get pod -l app=redis-client -o jsonpath='{.items[0].metadata.labels}'
# app=redis-client, in namespace redis
```

The overlay fragment — `sbobs/redis-client-ingress-patch.yaml`:

```yaml
spec:
  ingress:
  - identifier: redis-client
    type: internal
    podSelector:
      matchLabels: {app: redis-client}
    namespaceSelector:
      matchLabels: {kubernetes.io/metadata.name: redis}
    ports:
    - {name: TCP-6379, port: 6379, protocol: TCP}
```

Identity, not address: the client can be rescheduled, rebuilt or moved to another
cluster and the fragment still admits exactly it — and nothing else.

## 6. Sign the fragment

```
bobctl sign --profile cp-redis-portable --key ./demo.key
```

Sign the form that will be **stored**, not the form you composed: storage rewrites
every profile on write (it merges neighbors sharing an `identifier` and unions
their ports), so a profile must already be a deflate fixpoint or its signature
will not verify on read. Unique identifier per entry is therefore a signing rule,
not a style rule.

## 7. Compose and prove it

The profile you apply and patch must be a **user-defined** profile — named
`redis`, bound by the pod-template label `kubescape.io/user-defined-profile:
redis` (`./deploy-distros.sh redis sbob` binds it at deploy time). The
agent-generated profile is not a substitute: its name carries the workload and
instance hashes, and although `kubectl get` resolves that name, `apply` and
`patch` against it return `NotFound`. If you exported the learned profile in step
2, rename it to `redis` before applying it here.

```
CP=containerprofiles.spdx.softwarecomposition.kubescape.io
kubectl apply -f sbobs/cp-redis-portable.yaml
kubectl -n redis patch $CP redis --type merge --patch-file sbobs/redis-client-ingress-patch.yaml
bobctl simulate --suite functional/redis-oss.yaml -n redis   # benign
bobctl verify   -n redis --format table                      # expect ZERO
bobctl simulate --suite attacks/redis-oss.yaml  -n redis     # contrast
bobctl verify   -n redis --format table                      # expect detections
```

The pass condition is both halves at once:

| run | expectation |
|---|---|
| benign suite, db + client deployed | **0 false positives** — the client is admitted by identity |
| contrast suite | every expected detection still fires |

A profile that silences the benign traffic by widening would pass the first row
and fail the second. That is the failure this demo exists to catch.

## 8. Prove it is portable

```
bobctl portability-probe --profile sbobs/cp-redis-portable.yaml --local-fp 0
```

Run against a cluster with **different pod and service CIDRs**. Portability is
`max(0, FP_here - FP_there)`; identity-based entries should score 0 where
address-based entries score once per peer.

## What to check if it fails

| symptom | likely cause |
|---|---|
| R0011 on every internal peer | peers were dropped rather than re-expressed — the old normalizer behaviour |
| a rule stops firing entirely | an entry widened: empty port set, a CIDR, or `"*"` |
| R0007 appears after collapse | a node peer became `entity: host`; the apiserver is a node address on socket-LB |
| ports admitted that were never observed | two entries share an `identifier` and storage unioned them |
| signature fails on read | the signed form was not a deflate fixpoint |

## Expected outcome (measured)

Captured live on k3s (chart `1.41.0-duckling23`, node-agent `v0.1.0-rogue35`,
storage `rc-rogue23`). Full artifacts in `heal-evidence/`.

| state | redis `R0012` | client `R1017` | client `R0040` | redis-ns total |
|---|---|---|---|---|
| client deployed, **unbound**; redis ingress empty | 1 | 1 | 53 | **55** |
| overlay derived → signed → applied + client **bound** | 0 | 0 | 0 | **0** |

**Before** — the client's ingress to redis is undeclared and the client is rogue:

```
R0012 | Unexpected Ingress Network Traffic | container=redis  pod=redis-master-0
        Unexpected ingress network communication from: 10.42.0.54:6379 to: redis
R1017 | Rogue artefact                     | container=client
        Container 'client' in namespace 'redis' has no bound profile
```

**The overlay is derived, not authored** — `bobctl overlay --peer <client-CP>
--target redis-master` reads the client's own learned egress and emits redis's
ingress entry (`heal-evidence/overlay-SBOB.yaml`):

```
admit  redis-client   {app: redis-client}  on [6379]
```

**After** — both profiles signed (`sign-object`, embed-content) and applied:

```
Successfully verified object signature       name=redis
Successfully verified object signature       name=redis-client
adopted user-authored ContainerProfile as authoritative base   name=redis-client
```

80s of steady healed traffic → **0 redis-ns alerts**, both pods governed.

Files: `heal-evidence/raw-client-CP.yaml` (as node-agent learned it),
`overlay-SBOB.yaml` (derived), `{02,03}-before-*` / `{09,10}-after-*` (alerts +
logs), `redis-healed-signed.yaml` / `client-SBOB-signed.yaml` (signed artifacts).

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

Verified: the `bobctl portable` step below was run against a live cluster and its
output passes `bobctl validate`. The deploy / learn / simulate / verify steps are
the flow `DEMO.md` already establishes.

## 0. Prerequisites

```
curl -L https://github.com/k8sstormcenter/bob/releases/download/v0.1.5/bobctl-linux-amd64 -o bobctl
chmod +x bobctl && sudo mv bobctl /usr/local/bin/bobctl
bobctl portable --help      # this demo needs the portable verb
```

Bring up the stack from the repo root. **Do not use `make kubescape` unmodified**:
it pins `KUBESCAPE_CHART_VER ?= 1.41.0-duckling5`, which predates everything this
demo depends on. Override it, or install the chart directly:

```
make kubescape KUBESCAPE_CHART_VER=1.41.0-duckling23
make alertmanager
```

(The `kubescape` target adds `https://raw.githubusercontent.com/k8sstormcenter/helm-charts/gh-pages`,
whose index carries duckling20-23, so the override resolves. `helm repo update`
first if it does not.)

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
application does rather than what it happens to do while idle. The result is a
ContainerProfile full of **literal addresses** — correct here, portable nowhere.

## 3. Collapse to portable

```
bobctl portable --file sbobs/cp-redis.yaml --out sbobs/cp-redis-portable.yaml
```

Each observed peer is resolved against live cluster state and re-expressed:

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

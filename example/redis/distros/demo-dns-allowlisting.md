# Allowlist a client's egress by identity (DNS + service)

Companion to `DEMO.md` §5. That section allowlists a client on the **server's**
ingress; this one is the mirror image — the **client's own egress**, which is
what fires when a workload talks to cluster DNS and to the service it consumes.

`CP=containerprofiles.spdx.softwarecomposition.kubescape.io`

## 1. Deploy redis and its SBoB

```
./deploy-distros.sh redis sbob
```

## 2. Watch the client's egress rule

```
CNODE=$(kubectl -n redis get pod -l app=redis-client -o jsonpath='{.items[0].spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$CNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected egress network"
```

## 3. Deploy the client

Same command as `DEMO.md` §5 — the manifest is unchanged:

```
kubectl apply -f ../client.yaml
```

The client loops `redis-cli -h redis-master SET ...` every 2s. That produces
exactly two egress peers, and **both** raise R0011:

```
48x  Unexpected egress network communication to: 10.43.0.10:53 using UDP from: client
48x  Unexpected egress network communication to: 10.43.14.108:6379 using TCP from: client
```

(the two ClusterIPs are cluster-specific: `kube-dns` and `redis-master`.)

Note there is **no R0005**. The client only ever resolves `redis-master`, which
expands to a `.svc.cluster.local.` name, and R0005 excludes that suffix. DNS
here shows up as *egress to the DNS service*, not as a domain anomaly — so it is
R0011, not R0005, that has to be satisfied.

## 4. The client is already learning the right thing

Look at what node-agent recorded for the client:

```
kubectl -n redis get $CP -o name | grep redis-client
kubectl -n redis get <that-name> -o jsonpath='{.spec.egress}' | python3 -m json.tool
```

Both peers are there, recorded by **identity**:

```json
{ "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
  "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
  "ipAddress": "", "ipAddresses": null,
  "ports": [{"name": "UDP-53", "port": 53, "protocol": "UDP"}] }
```

`ipAddress` is empty and `ipAddresses` is null — the profile holds a selector,
not an address. This is deliberate and is the whole point of the selector work:
pod IPs go stale on reschedule, identities do not.

## 5. Why it alerted, and what fixed it

R0011 originally matched peers **only** by address:

```
event.pktType == 'OUTGOING'
&& !event.dstAddr.startsWith('127.')
&& !cp.was_address_in_egress(event.containerId, event.dstAddr)
```

`was_address_in_egress` reads `ipAddress`/`ipAddresses`. Against a
selector-shaped entry it can never match, so a correctly-learned client alerted
forever and relearning did not help. R0012 (ingress) already checked both forms.

That is fixed in `main` — R0011 now carries the selector arm too:

```
&& !cp.was_selector_in_egress(event.containerId, event.dstNamespace, event.dstPodLabels)
```

With it, the same client, unchanged, is silent: **0 R0011**.

### Egress selectors must each carry a distinct `identifier`

`identifier` is storage's **merge key** for network entries. Two egress entries
that share one — including two entries that both leave it empty — are merged
into a single entry on write: the second `podSelector` is dropped and only the
ports are unioned. The profile then looks plausible but has silently lost a
peer, and that peer alerts forever.

Symptom, from a profile written without identifiers:

```
egress:                       # two entries applied
- podSelector: {k8s-app: kube-dns}          ports: [UDP-53]
- podSelector: {app.kubernetes.io/name: valkey}  ports: [TCP-6379]

egress:                       # one entry stored
- podSelector: {app.kubernetes.io/name: valkey}  ports: [UDP-53, TCP-6379]
```

Every entry in the committed SBoBs therefore carries an explicit identifier.

## 6. Allowlisting a peer that has no identity

Selectors only work for peers that are pods. For anything else — an external
endpoint, a node IP, a LoadBalancer — the address arm is still the mechanism,
and R0011 accepts a literal IP, a CIDR, or the `*` sentinel:

```
kubectl -n redis patch $CP <client-profile> --type merge -p '{"spec":{"egress":[
  {"identifier":"metrics-endpoint","type":"external",
   "ipAddresses":["10.0.0.0/8"],
   "ports":[{"name":"TCP-9090","port":9090,"protocol":"TCP"}]}]}}'
```

Prefer a selector when the peer is a pod. Reach for a CIDR only when it is not,
and keep it as tight as the peer allows — a wide range here is a real egress
hole, and `*` allowlists every destination.

## 7. Ingress on the server

The mirror step — allowlisting the client on the **server's** ingress — is in
these SBoBs as an entry naming the client's identity, e.g. `sbobs/cp-valkey.yaml`:

```yaml
ingress:
- podSelector:       {matchLabels: {app: valkey-client}}
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: valkey}}
  ports: [{name: TCP-6379, port: 6379, protocol: TCP}]
```

This works. Instrumenting `wasSelectorIn` shows the comparison succeeding:

```
INGRESS | peer_ns=valkey
        | peer_labels=map[app:valkey-client kubescape.io/user-defined-profile:valkey-client ...]
        | profile_selectors=[pod=map[app:valkey-client] ns=map[kubernetes.io/metadata.name:valkey]]
        | match=true
```

### Expect exactly one alert at pod start

R0012 fires **once** per workload right after a client pod starts, then goes
quiet. Measured across a client restart: valkey at +2s, keydb at +3s, one alert
each, nothing after. Until Inspektor Gadget's kubeipresolver has the new pod in
its inventory the peer resolves with no labels, and a peer with no labels cannot
satisfy any `podSelector` — `wasSelectorIn` returns false by design.

Do not mistake that single startup alert for the allowlist failing. Equally, do
not "fix" it by putting the **server's own** labels in its ingress list: that
matches every inbound peer and allowlists the whole cluster.

### Selectors must use labels the resolver actually reports

The identity the rule matches against is what kubeipresolver stamps on the
event, which is not always the full set the API server shows. Dragonfly is the
case in point — the pod carries `role: master`, but the resolved peer does not:

```
peer_labels = map[app:dragonfly app.kubernetes.io/component:dragonfly
                  app.kubernetes.io/instance:dragonfly
                  app.kubernetes.io/managed-by:dragonfly-operator
                  app.kubernetes.io/name:dragonfly ...]      # no role:
pod labels  = {"app":"dragonfly", ..., "role":"master", ...}
```

The learner records the API-server view, so the learned egress selector for
`dragonfly-client` contained `role: master` and never matched: 127 R0011 in a
steady-state window. Narrowing the selector to `app: dragonfly` alone takes it
to 0. `cp-dragonfly-client.yaml` therefore ships the stable subset, not the raw
learned selector.

## 8. What this demo does not cover

The client still raises **R0040** (`Unexpected process arguments`) for each
`redis-cli` invocation, because it has no user-defined profile pinning those
args. That is an exec-side concern, unrelated to egress, and is handled for the
server workloads in `sbobs/cp-redis.yaml`. It is called out here so the R0040
lines in the log are not mistaken for the egress demo failing.

## Verified

2-node k3s v1.36.1+k3s1, kernel 6.1.167 x86_64, chart 1.40.3, node-agent pinned
to `sbob-rc5s-celnet@sha256:dc4e66680df35dfb4d747544358b7fca906434a78f40ad3b573855935788b6f2`.
Before: 48 + 48 R0011 on the client. After: 0, with no CEL compile error and
R0012 on redis-master unaffected.

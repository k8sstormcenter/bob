# Signed SBoB fragment bundles — redis distros demo

This is the [distros demo](../DEMO.md) with the "allowlist a client later" step (its §5 `kubectl patch`) replaced by a **cryptographically signed admission fragment**.

Several parties each sign their own **fragment** of a ContainerProfile; node-agent verifies every fragment against a per-class trust policy, assembles them into one effective profile, and binds the assembly to the admissible leaf set with a Merkle tree.

node-agent only **verifies** — it holds no signing key, and no private key exists anywhere on the cluster.

The composite is re-derived from the signed fragments every reconcile tick, so it cannot drift from them.

Tampering with any fragment fires **R1016** and drops the whole bundle (fail closed).

The cast:

| Fragment | Class | Signed by | Contributes |
|---|---|---|---|
| `fragments/frag-base-redis.yaml` | `base` | vendor key | the learned redis SBoB from [`../sbobs/cp-redis.yaml`](../sbobs/cp-redis.yaml) (execs/opens/caps — **no ingress**) |
| `fragments/frag-overlay-ops.yaml` | `overlay` | operator key | end-user addition: allow `df -h` for ops |
| `fragments/frag-admission-redis-client.yaml` | `admission` | operator key | the client-allowlist ingress entry — shipped LATER, in §6 |

`trust-policy.json` pins per class **who may sign** (public-key fingerprint) and **which spec paths the class may set**, so the admission signer cannot smuggle `execs` in even with a valid signature.

All keys under `keys/` are published demo material and authenticate nothing — see [`keys/README.md`](keys/README.md).

## 0. Prerequisites

- a cluster + `kubectl`, `helm` (3 or 4 — the Makefile auto-adds `--force-conflicts` on helm 4), `python3`
- **working directory:** `make kubescape` (§1) runs from the repo root; everything else runs from `example/redis/distros/signed-bundles/`
- the `sign-object` CLI (linux; pick your arch), fetched into that directory:

```
cd example/redis/distros/signed-bundles
curl -fsSL -o sign-object https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.5/sign-object-linux-amd64 && chmod +x sign-object
```

(or build from source: `git clone -b signature-overlays https://github.com/k8sstormcenter/node-agent && cd node-agent && go build -o sign-object ./cmd/sign-object`)

## 1. Install kubescape with the right images

`kubescape/values.yaml` pins `ghcr.io/k8sstormcenter/node-agent:v0.3.183` and `ghcr.io/k8sstormcenter/storage:v0.3.177`, built from the `signature-overlays` branch.

From the repo root:

```
make kubescape
```

## 2. Signed-bundle support boots with the chart

`kubescape/values.yaml` sets `nodeAgent.bundleSigning` to the **root-signed** trust policy, which node-agent verifies against the root public key compiled into its image.

No private key is deployed, and the chart renders the mount and config at install time, so there is nothing to patch and no restart.

Confirm:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed bundle overlays enabled"
```

(`enable-bundle-signing.sh` remains only for installs of the upstream chart, which has no bundleSigning values.)

## 3. The vendor ships SIGNED fragments — before any workload exists

Signing happens **offline**: `sign-object --embed-content` embeds the exact signed bytes in the `signature.kubescape.io/content` annotation, so the signature survives however the storage server normalises the spec on save.

The `*-signed.yaml` artifact is what the vendor ships, and the cluster never sees an unsigned fragment.

The admission fragment is not part of this step — the client does not exist yet:

```
cd example/redis/distros/signed-bundles   # if you cd'd to the repo root for §1
./sign-fragment.sh fragments/frag-base-redis.yaml  keys/vendor.pem
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

There is no separate bundle object: fragments are grouped by their `signature.kubescape.io/bundle: redis` label, which is part of the signed content.

## 4. Deploy redis (pinned distros install, sbob binding)

```
(cd .. && ./deploy-distros.sh redis sbob)
```

The `sbob` toggle labels the statefulset with `kubescape.io/user-defined-profile: redis`, exactly as in the distros demo.

Because the signed fragments are already in place, the pod starts protected — there is no window where the workload runs without its profile.

node-agent verifies each leaf and assembles the composite in memory, with no signing and no key:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "assembled signed bundle overlay"
# → bundle=redis fragments=2 root=<merkle-root-A>
```

## 5. A client appears — unexpected ingress fires

Deploy the client with its own SBoB, so its own redis-cli/egress stay quiet:

```
kubectl apply -f ../sbobs/cp-redis-client.yaml
kubectl apply -f ../../client.yaml
```

The server's composite has **no ingress**, so the client's connections are unexpected and **R0012** fires on the node hosting redis-master:

```
MNODE=$(kubectl -n redis get pod redis-master-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected ingress network"
```

## 6. Allowlist the client LATER — with a signed fragment

Where the distros demo patches the server profile in place, the operator ships the same ingress entry as a standalone signed admission fragment:

```
./sign-fragment.sh fragments/frag-admission-redis-client.yaml keys/operator.pem
```

Within a reconcile interval (~1 min) node-agent re-assembles the same bundle with 3 fragments and a new Merkle root:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "assembled signed bundle overlay" | tail -1
# → bundle=redis fragments=3 root=<merkle-root-B>   (≠ root-A)
```

R0012 stops within a reconcile interval, the client now admitted by a signed, attributable, path-confined object instead of an in-place edit.

The admission key can only add ingress/egress: had it signed `execs` into this fragment, the whole bundle would be rejected.

## 7. Verify the composite — without touching the leaves

**(a) The assembly is bound to a Merkle root** (the §4/§6 log lines): the root commits to the exact verified leaf set, so a fragment added, dropped or altered changes it — as the root-A → root-B transition just showed.

**(b) The leaves are untouched:** each fragment still verifies with its original signature, because assembly reads fragments and never rewrites them:

```
export CP=containerprofiles.spdx.softwarecomposition.kubescape.io
for f in redis-base redis-ops-overlay redis-client-ingress; do
  kubectl -n redis get $CP $f -o yaml > /tmp/leaf.yaml
  ./sign-object verify --file /tmp/leaf.yaml --strict=false && echo "leaf $f: OK"
done
```

**(c) The behaviour proves the union** — each check exercises a different fragment and would fail if that fragment had been rejected:

```
# base fragment enforced: an exec outside every fragment alerts (R0001)
kubectl -n redis exec sts/redis-master -- id
# overlay fragment honoured: df -h is allowed — no alert
kubectl -n redis exec sts/redis-master -- df -h
# admission fragment honoured: R0012 stopped in §6
```

Alerts go to the stdout exporter, so observe them by rule id:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=5m | grep -oE '"RuleID":"R[0-9]+"' | sort | uniq -c
```

**(d) Tamper the signed content → the bundle fails closed + R1016.**

Editing the stored spec is inert because enforcement binds the embedded signed content, so an attacker must attack that content — which breaks the signature without the operator key:

```
kubectl -n redis get $CP redis-ops-overlay -o jsonpath='{.metadata.annotations.signature\.kubescape\.io/content}' \
  | python3 -c 'import sys,base64,gzip; d=gzip.decompress(base64.b64decode(sys.stdin.read())); d=d.replace(b"/usr/bin/df", b"/bin/backdoor"); print(base64.b64encode(gzip.compress(d)).decode())' \
  | xargs -I{} kubectl -n redis annotate $CP redis-ops-overlay --overwrite signature.kubescape.io/content={}
```

Within a reconcile interval the embedded content no longer matches its signature, R1016 "Signed profile tampered" fires, and the composite is dropped rather than half-trusted.

Recover by re-shipping the vendor artifact:

```
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

Recovery restores the exact signed content, so the composite reassembles to its pre-tamper root — an identical leaf set gives an identical root, which logs at debug rather than as a new-root transition.

The proof that enforcement is live again, rather than an empty profile, is behavioural:

```
kubectl -n redis exec sts/redis-master -- uname -a
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=1m | grep '"RuleID":"R0001"'
```

## How admissibility is decided (reference)

For every fragment, all of the following must hold or the whole bundle is rejected:

1. it carries a `signature.kubescape.io/fragment-class` label and the class exists in the trust policy;
2. it is signed and the signature verifies over the embedded signed content (`metadata{name,labels}` + `spec`), so the stored spec is irrelevant to verification;
3. the signer's public-key fingerprint (`key:<sha256(PKIX(pub))>`) is listed for its class;
4. it sets only spec paths its class allows (e.g. `admission` → `ingress`/`egress` only).

To author a policy entry for a new key (`sign-object generate-keypair --output my.pem` writes `my.pem` + `my.pem.pub`), derive the fingerprint from the public key:

```
echo "key:$(openssl pkey -pubin -in my.pem.pub -outform DER | sha256sum | cut -d' ' -f1)"
```

Public keys are never stored on the cluster: each artifact carries its own certificate, and the policy holds only the fingerprint that certificate must match.

`metadata.namespace` is deliberately NOT signed, because a vendor cannot know which namespace a customer will install into and re-signing per customer would defeat offline signing.

What confines a fragment is therefore the signed `bundle` and `fragment-class` labels, not its placement — an attacker cannot move a fragment into another bundle or change its class, while choosing a namespace is an ordinary RBAC question.

## Bring your own root key (rotating the trust anchor)

The trust policy is only trustworthy because node-agent verifies it against a root public key **compiled into the image**, with no cluster-side override, so the anchor cannot be swapped on a running cluster.

The published image ships a demo root key, so to trust your own root instead, swap the embedded key and rebuild — once, offline:

1. Generate a root keypair, whose private half never touches the cluster:

```
./sign-object generate-keypair --output root.pem   # writes root.pem + root.pem.pub
```

2. Replace `DefaultRootPublicKeyPEM` in `pkg/signature/bundle/root.go` with `root.pem.pub` and rebuild the node-agent image.

3. Sign your trust policy with the root private key:

```
./sign-object sign-policy --policy trust-policy.json --key root.pem --output trust-policy.signed.json
```

4. Ship `trust-policy.signed.json` as the `nodeAgent.bundleSigning.trustPolicy` value, which becomes the mounted `/etc/bundle/trust-policy.json`.

5. Keep the root key offline in escrow, since adding or rotating a fragment signer later means re-signing the policy with it.

## 8. Robustness — the adversarial cases

**Editing the stored spec is inert**, because the composite binds the signed embedded content and not the mutable object:

```
kubectl -n redis patch $CP redis-ops-overlay --type json \
  -p '[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/backdoor"}}]'
# → no R1016, composite root unchanged; df -h still the ONLY overlay exec enforced
```

**Editing the signed content is caught** — R1016, fail closed, as in §7(d).

**An unsigned fragment is rejected:**

```
kubectl -n redis delete $CP redis-ops-overlay               # drop the signed object
kubectl -n redis apply  -f fragments/frag-overlay-ops.yaml  # re-create from the UNSIGNED source
# → bundle overlay failed: "fragment is not signed"; composite drops until re-signed
```

`apply` alone would not do it, because a 3-way merge keeps the existing signature annotations.

**A fragment signed by an untrusted key is rejected** with `signer not permitted for this fragment class`, and **a class-confined violation is rejected** with `class may not set spec.execs` — both failing the whole bundle closed.

The signer identity is the public-key fingerprint the signature verified against, never the spoofable OIDC identity annotations, so a trusted signer cannot be impersonated by copying strings.

## 9. Signed rules — the vendor ships rules with the bundle

Profiles say what a workload may do; **rules** say what the agent alerts on.

Any `Rules` object in any namespace is merged into one ruleset keyed by rule ID, so anyone who can create one could redefine `R0001` with `enabled: false` and turn off process detection cluster-wide.

Signed rule fragments close that, and let the vendor ship rules as part of the same bundle as the profile.

A rules fragment carries the same two labels as a profile fragment, so one bundle holds both halves:

| Object | Labels | Applies |
|---|---|---|
| `ContainerProfile` | `bundle: redis`, `fragment-class: base` | the workloads bound to bundle `redis` |
| `Rules` | `bundle: redis`, `fragment-class: overlay` | the same workloads, overriding the base rule with the same ID |
| `Rules` (baseline) | `fragment-class: base` | cluster-wide, belonging to no bundle |

An overlay applies to exactly the workloads bound to its bundle, **in whatever namespace the customer installed it**, and nowhere else.

The bundle and the class are inside the signed content, so a fragment cannot be re-classed or re-targeted at another bundle; the namespace is not signed, so the same vendor artifact installs anywhere.

`trust-policy.json` names who may sign each class and which rule IDs they may set, and here the operator may only touch `R0001` and `R0002`:

```
"ruleClasses": {
  "base":    {"signers": ["key:<vendor>"],   "allowedRuleIDs": ["*"]},
  "overlay": {"signers": ["key:<operator>"], "allowedRuleIDs": ["R0001","R0002"]}
}
```

**The scenario:** redis is the cache tier, where an unexpected process is a possible compromise rather than routine drift, so the redis vendor ships `R0001` at severity 10 with a redis-specific message as part of the redis bundle.

### (a) Turn rule signing on

`trust-policy.json` already carries the `ruleClasses` above, and because the policy is root-signed, changing it means re-signing it:

```
./sign-object sign-policy --policy trust-policy.json --key keys/root.pem --output trust-policy.signed.json
kubectl -n honey create cm node-agent-bundle-policy --from-file=trust-policy.json=trust-policy.signed.json --dry-run=client -o yaml | kubectl apply -f -
```

Rule signing is now on, which means every `Rules` object must verify or its rules are dropped, so the vendor signs the chart's unsigned baseline ruleset as a `base` fragment first — otherwise you correctly end up with no rules at all:

```
./sign-rules.sh rules/baseline-rules.yaml keys/vendor.pem
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed rule fragments enabled"
```

### (b) The vendor ships the bundle's rules

```
./sign-rules.sh rules/rules-redis.yaml keys/operator.pem
```

`rules/rules-redis.yaml` is a `Rules` object labelled `bundle: redis` + `fragment-class: overlay`, carrying `R0001` at severity 10 with the message `REDIS TIER CRITICAL: ...`.

### (c) See the override — and see that it follows the bundle, not the namespace

```
kubectl -n redis exec sts/redis-master -- id
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "REDIS TIER CRITICAL"
```

The `REDIS TIER CRITICAL` message is attributed only to the container bound to the redis bundle, never to the redis client that runs in the same namespace but is bound to its own profile:

```
kubectl -n redis exec deploy/redis-client -- id
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "REDIS TIER CRITICAL" | grep -o '"containerName":"[^"]*"' | sort | uniq -c
```

The override reaches exactly the workloads that opted into the bundle, not everything sharing their namespace.

### (d) The adversarial cases

**An attacker ships a rule fragment to disable detection**, signed with a key that is not in the policy:

```
./sign-object generate-keypair --output /tmp/rogue.pem
sed 's/enabled: true/enabled: false/' rules/rules-redis.yaml > /tmp/rogue-rules.yaml
./sign-rules.sh /tmp/rogue-rules.yaml /tmp/rogue.pem
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "rules fragment rejected"
# → signer not permitted for this fragment class; the fragment's rules are dropped whole
# → RulesWatcher - signed rule fragments  admitted=1 rejected=1
```

The rogue rules never load, and detection is not switched off: with the overlay dropped, redis falls back to the base `R0001` and still alerts, at severity 1 instead of 10.

So signing protects the *content* of a rule, not the *presence* of the object — anyone who can create or delete `rules.kubescape.io` objects can overwrite the fragment and lose the tightening, so restrict that verb with RBAC if the override matters.

Re-shipping the operator-signed fragment restores it within a reconcile interval.

**An unsigned rules object is dropped**, so removing the signature is not a way around it:

```
kubectl -n redis delete rules.kubescape.io rules-redis
kubectl apply -f rules/rules-redis.yaml    # the UNSIGNED source
# → rules fragment rejected: fragment is not signed
```

**A trusted signer may not touch any rule they like**, so an operator fragment setting `R0007` is rejected with `rule ID not allowed for this class` — the same confinement idea as `allowedSpecPaths` for profiles.

**An overlay must declare a bundle**, so a rules overlay with no `bundle` label is rejected rather than applying everywhere.

**Re-targeting is not possible**, because the bundle label is part of the signed content, so pointing a signed overlay at another bundle breaks its signature.

## 10. The same signed artifact, any namespace

A vendor signs a fragment once and cannot know the customer's namespace, so the namespace is not part of the signed content.

The base fragment the vendor signed in §3 re-applies into a second namespace with only the namespace changed:

```
kubectl create ns redis-staging
sed 's/^  namespace: redis$/  namespace: redis-staging/' fragments/frag-base-redis-signed.yaml | kubectl create -f -
```

The signature still verifies there, because nothing it covers changed:

```
export CP=containerprofiles.spdx.softwarecomposition.kubescape.io
kubectl -n redis-staging get $CP redis-base -o yaml > /tmp/moved.yaml
./sign-object verify --file /tmp/moved.yaml --strict=false && echo "verified in redis-staging"
```

Rules follow the same rule: an overlay signed for `bundle: redis` protects redis workloads wherever they run, selected by the bundle a workload is bound to rather than by where the fragment was signed.

# Signed SBoB fragment bundles — redis distros demo

This is the [distros demo](../DEMO.md) with the "allowlist a client later" step (its §5 `kubectl patch`) replaced by a **cryptographically signed admission fragment**.

Several parties each sign their own **fragment** of a ContainerProfile; node-agent verifies every fragment against a per-class trust policy, assembles them into one effective profile, and binds the assembly to the admissible leaf set with a Merkle tree.

node-agent only **verifies** — it holds no signing key, and no private key exists anywhere on the cluster.

The composite is re-derived from the signed fragments every reconcile tick, so it cannot drift from them.

Tampering with any fragment fires **R1016** and refuses that change, leaving the workload on the last verified composite.

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
- **working directory:** the `make` targets (§1) run from the repo root; everything else runs from `example/redis/distros/signed-bundles/`
- the `bobctl` CLI, used by the functional and attack suites in §4b, fetched into the repo root:

```
curl -fsSL -o bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.2/bobctl-linux-amd64 && chmod +x bobctl
```

- the `sign-object` CLI (linux; pick your arch), fetched into that directory:

```
cd example/redis/distros/signed-bundles
curl -fsSL -o sign-object https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.5/sign-object-linux-amd64 && chmod +x sign-object
```

(or build from source: `git clone -b signature-overlays https://github.com/k8sstormcenter/node-agent && cd node-agent && go build -o sign-object ./cmd/sign-object`)

## 1. Install kubescape with the right images

The demo installs chart `1.40.3-sign-rc2` (helm-charts `signature-overlays`), which pins `ghcr.io/k8sstormcenter/node-agent:v0.3.192` and `ghcr.io/k8sstormcenter/storage:v0.3.177`, built from the node-agent `signature-overlays` branch.

From the repo root:

```
make kubescape
make alertmanager
```

`make alertmanager` is what §4b reads its alerts from; the rest of the demo reports through the node-agent stdout exporter and does not need it.

### Two ways to install the trust bundle

The trust policy is a root-signed artifact — about 2.5KB of JSON carrying a certificate and a signature. There are two ways to get it onto the cluster, and the demo works identically with either.

**A. Inline in values (what `make kubescape` does).** `kubescape/values.yaml` holds the artifact under `nodeAgent.bundleSigning.trustPolicy`, and the chart renders the ConfigMap. The chart owns the object, so the policy is whatever the values say — a `helm upgrade` re-asserts it, which is what you want when the values are your source of truth. To avoid pasting the artifact by hand you can pass it at install time instead:

```
helm upgrade --install kubescape <chart> -n honey \
  --set-file nodeAgent.bundleSigning.trustPolicy=example/redis/distros/signed-bundles/trust-policy.signed.json
```

**B. Mounted from a ConfigMap you own.**

```
make kubescape-mounted
```

This creates `kubescape-trust-bundle` from `trust-policy.signed.json` and installs with `nodeAgent.bundleSigning.existingConfigMap=kubescape-trust-bundle`. The chart mounts that ConfigMap and renders none, so the policy comes straight from your signing process and is rotated with `kubectl apply` on the ConfigMap — no `helm upgrade`, no re-pasting.

Either way node-agent reads `/etc/bundle/trust-policy.json`. The ConfigMap is mounted as a **directory**, so kubelet propagates updates and node-agent applies a rotated policy on its own, within a reconcile interval — see §9(a). A replacement that does not verify against the root is refused and the policy already in force is kept, so neither path lets an unsigned policy take effect.

## 2. Signed-bundle support boots with the chart

`kubescape/values.yaml` sets `nodeAgent.bundleSigning` to the **root-signed** trust policy, which node-agent verifies against the root public key compiled into its image.

No private key is deployed, and the chart renders the mount and config at install time, so there is nothing to patch and no restart.

Confirm:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed bundle overlays enabled"
# → signed bundle overlays enabled in alert mode
```

Signing has one global state, carried in the (root-signed) trust policy: `alert` reports unsigned or unverifiable objects, `enforce` refuses them. A mounted policy is never silent — a policy with no explicit mode runs in `alert`.

The same startup also warns that the anchor is the **published demo root key**, which is expected here and is the one thing you must change for real use:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "DEMO root key"
```

See "Bring your own root key" below; under `enforce`, node-agent refuses to run on the demo root unless you mount your own.

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

## 4b. Functional suite, then attacks — the contrast still holds

A signed profile must behave like the learned one it replaces: benign traffic stays quiet and attacks alert.

Run the benign suite against the workload the signed bundle now governs, and expect no detections:

```
(cd .. && bobctl test --functional-tests functional/redis-oss.yaml -n redis)
```

Take a timestamp, then run the attack suite, which must alert:

```
export T0=$(date -u +%Y-%m-%dT%H:%M:%SZ) NS=redis
(cd .. && bobctl attack --attack-suite attacks/redis-oss.yaml -n redis)
```

Split the alerts either side of `$T0` to separate functional false positives from attack detections:

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
sleep 5
curl -s localhost:9093/api/v2/alerts | python3 -c '
import json,sys,os
from collections import Counter
a=json.load(sys.stdin); ns=os.environ["NS"]; t0=os.environ.get("T0","")
al=[x for x in a if x["labels"].get("namespace")==ns]
fp=[x for x in al if x.get("startsAt","")<t0]
tp=sorted({x["labels"].get("rule_id") for x in al if x.get("startsAt","")>=t0})
print("functional FPs:", len(fp), dict(Counter(x["labels"].get("rule_id") for x in fp)) or "CLEAN")
print("attack TPs (distinct rules):", len(tp), tp)'
```

A signed bundle that alerts on the functional suite is a bad profile, not a working signature.

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
timeout 120 kubectl -n honey logs -f $NA | grep -m3 "Unexpected ingress network"
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

**(d) Tamper the signed content → the change is refused + R1016.**

Editing the stored spec is inert because enforcement binds the embedded signed content, so an attacker must attack that content — which breaks the signature without the operator key:

```
kubectl -n redis get $CP redis-ops-overlay -o jsonpath='{.metadata.annotations.signature\.kubescape\.io/content}' \
  | python3 -c 'import sys,base64,gzip; d=gzip.decompress(base64.b64decode(sys.stdin.read())); d=d.replace(b"/usr/bin/df", b"/bin/backdoor"); print(base64.b64encode(gzip.compress(d)).decode())' \
  | xargs -I{} kubectl -n redis annotate $CP redis-ops-overlay --overwrite signature.kubescape.io/content={}
```

Within a reconcile interval the embedded content no longer matches its signature, R1016 "Signed profile tampered" fires, and the tampered fragment is refused:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep '"RuleID":"R1016"' | tail -1
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep "bundle overlay failed" | tail -1
```

The workload keeps running under the last verified composite rather than losing its profile, so a tamper reports and is rejected without turning every exec into an alert.

Recover by re-shipping the vendor artifact:

```
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

Recovery restores the exact signed content, so the composite reassembles to its pre-tamper root — an identical leaf set gives an identical root, which logs at debug rather than as a new-root transition.

The proof that enforcement is live again, rather than an empty profile, is behavioural:

```
kubectl -n redis exec sts/redis-master -- uname -a
sleep 30
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep '"RuleID":"R0001"' | tail -1
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

node-agent verifies the trust policy against a root public key, and the published image ships a demo root key you are meant to replace with your own.

Generate a root keypair whose private half never touches the cluster:

```
./sign-object generate-keypair --output root.pem   # writes root.pem + root.pem.pub
```

Sign your trust policy with the root private key, and keep that key offline in escrow since adding or rotating a fragment signer later means re-signing:

```
./sign-object sign-policy --policy trust-policy.json --key root.pem --output trust-policy.signed.json
```

There are two ways to make node-agent trust your root, trading rebuild cost against anchor strength.

**Mounted (no rebuild):** set `nodeAgent.bundleSigning.rootPublicKey` to `root.pem.pub` alongside the signed `trustPolicy`, and node-agent verifies the policy against the mounted key at `/etc/bundle/root.pub`.

This anchor lives in a cluster ConfigMap, so an attacker who can edit it can swap both the root key and the policy, and its integrity must come from an immutable ConfigMap and tight RBAC — node-agent logs a warning when a mounted anchor is in use.

**Embedded (rebuild):** replace `DefaultRootPublicKeyPEM` in `pkg/signature/bundle/root.go` with `root.pem.pub` and rebuild the node-agent image, so the anchor cannot be swapped on a running cluster at all.

## 8. Robustness — the adversarial cases

**Editing the stored spec is inert**, because the composite binds the signed embedded content and not the mutable object:

```
kubectl -n redis patch $CP redis-ops-overlay --type json \
  -p '[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/backdoor"}}]'
# → no R1016, composite root unchanged; df -h still the ONLY overlay exec enforced
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep -c '"RuleID":"R1016"'
# → 0
```

**Editing the signed content is caught** — R1016, fail closed, as in §7(d).

**An unsigned fragment is rejected:**

```
kubectl -n redis delete $CP redis-ops-overlay               # drop the signed object
kubectl -n redis apply  -f fragments/frag-overlay-ops.yaml  # re-create from the UNSIGNED source
# → refused: "fragment is not signed"; the workload KEEPS its last verified composite
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "no longer verifies" | tail -1
```

`redis-ops-overlay` was a verified member, so replacing it with an unsigned object is a member that stopped verifying, not a stranger: the change is refused and the workload stays on the last verified composite rather than losing its profile. An object that never verified in the first place is a different case — see the non-member paragraph below.

`apply` alone would not do it, because a 3-way merge keeps the existing signature annotations.

Re-ship the signed artifact before continuing, so the rest of the demo runs on a complete bundle:

```
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

**An object that never verified is a non-member, not a bundle failure.** Bundle membership is authenticated: only fragments signed by a signer the policy trusts for their class count as members. Anyone who can create a ContainerProfile in the namespace can put the `bundle` and `fragment-class` labels on an object, so a labelled object that is unsigned, signed by an untrusted key, or class-confined-violating is **dropped** and the bundle assembles from its genuine members:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "dropped non-member"
```

Without this, one injected object would fail the whole bundle closed and take the profile away from every workload bound to it — a denial of service available to any namespace writer. The alert is deduplicated per bundle, not per object, so spraying objects cannot flood the log.

**A signed fragment cannot be rolled back.** Fragments carry a monotonic `signature.kubescape.io/version` inside the signed content; node-agent refuses any fragment whose version is below the highest it has already accepted for that bundle/class/name, so re-applying an older but still validly signed fragment cannot widen the profile. The high-water marks are in-memory and reset when node-agent restarts.

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

Rule classes invert the profile roles: the `base` ruleset is the cluster-wide baseline the **user** owns, and an `overlay` is bundle-scoped rules the **vendor** ships. `trust-policy.json` names who may sign each class and which rule IDs they may set, and here the vendor overlay may only touch `R0001` and `R0002` while the user baseline may set any rule:

```
"ruleClasses": {
  "base":    {"signers": ["key:<user>"],   "allowedRuleIDs": ["*"]},
  "overlay": {"signers": ["key:<vendor>"], "allowedRuleIDs": ["R0001","R0002"]}
}
```

**The scenario:** redis is the cache tier, where an unexpected process is a possible compromise rather than routine drift, so the redis vendor ships `R0001` at severity 10 with a redis-specific message as part of the redis bundle.

### (a) Rule signing is already on

`kubescape/values.yaml` ships the **full** root-signed policy — the `ruleClasses` above included — so rule signing is on from §1 and nothing needs patching here.

> **Change the policy in `values.yaml`, never with `kubectl` on the ConfigMap.** The chart owns `node-agent-bundle-policy`, so a ConfigMap edit survives only until the next `helm upgrade`: the following `make kubescape` silently restores the chart's policy. If that policy were missing `ruleClasses`, rule signing would switch off with no error and unsigned `Rules` objects would start loading again. To change the policy, edit `trust-policy.json`, re-sign it, paste the artifact into `values.yaml`, and re-run `make kubescape`:
>
> ```
> ./sign-object sign-policy --policy trust-policy.json --key keys/root.pem --output trust-policy.signed.json
> # paste trust-policy.signed.json into nodeAgent.bundleSigning.trustPolicy in kubescape/values.yaml, then:
> (cd ../../../.. && make kubescape)
> ```
>
> No restart is needed. The ConfigMap is mounted as a directory, so kubelet propagates the change, and node-agent re-reads the policy and applies it within a reconcile interval:
>
> ```
> kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "trust policy reloaded"
> ```
>
> A replacement that does not verify against the root is refused and the policy already in force is kept, so a swapped-in policy cannot downgrade or disable enforcement:
>
> ```
> kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "trust policy reload REFUSED"
> ```
>
> If you installed with `make kubescape-mounted`, rotate the ConfigMap directly instead — same effect, no helm involved:
>
> ```
> kubectl -n honey create configmap kubescape-trust-bundle \
>   --from-file=trust-policy.json=trust-policy.signed.json --dry-run=client -o yaml | kubectl apply -f -
> ```

Every `Rules` object must now verify or its rules are dropped, so the user signs the chart's unsigned baseline ruleset as a `base` fragment first — otherwise you correctly end up with no rules at all:

```
./sign-rules.sh rules/baseline-rules.yaml keys/operator.pem
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed rule fragments enabled"
```

### (b) The vendor ships the bundle's rules

```
./sign-rules.sh rules/rules-redis.yaml keys/vendor.pem
```

`rules/rules-redis.yaml` is a `Rules` object labelled `bundle: redis` + `fragment-class: overlay`, carrying `R0001` at severity 10 with the message `REDIS TIER CRITICAL: ...`.

### (c) See the override — and see that it follows the bundle, not the namespace

```
kubectl -n redis exec sts/redis-master -- id
sleep 30
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "REDIS TIER CRITICAL" | tail -1
```

The `REDIS TIER CRITICAL` message is attributed only to the container bound to the redis bundle, never to the redis client that runs in the same namespace but is bound to its own profile:

```
kubectl -n redis exec deploy/redis-client -- id
sleep 30
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep "REDIS TIER CRITICAL" | grep -o '"containerName":"[^"]*"' | sort | uniq -c
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

**A trusted signer may not touch any rule they like**, so a vendor overlay fragment setting `R0007` is rejected with `rule ID not allowed for this class` — the same confinement idea as `allowedSpecPaths` for profiles.

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

## 10b. A single signed profile, without a bundle

One party owning a whole profile can sign it directly, with no bundle or fragment-class labels.

Write the profile and sign it with the same script the fragments use:

```
cat > /tmp/flat-cp.yaml <<'YAML'
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ContainerProfile
metadata:
  name: redis-solo
  namespace: redis
  annotations:
    kubescape.io/managed-by: User
spec:
  architectures: ["amd64"]
  execs:
    - path: /opt/bitnami/redis/bin/redis-server
      args: ["redis-server"]
YAML
./sign-fragment.sh /tmp/flat-cp.yaml keys/vendor.pem
```

It verifies as it stands in the cluster, and a workload can reference it by name through the same user-defined-profile label:

```
kubectl -n redis get $CP redis-solo -o yaml > /tmp/solo.yaml
./sign-object verify --file /tmp/solo.yaml --strict=false
```

The learned profile the cluster generates is a different object and carries no signature, so verifying that one reports it as unsigned.

Bundles exist for the multi-party case; a single signed profile stays the simpler path.

## 11. The trust anchor itself is checked

A policy that is not signed by the root key is refused, so an attacker who can edit the policy ConfigMap still cannot name their own signer.

Sign the same policy with a key that is not the root, and apply it:

```
./sign-object sign-policy --policy trust-policy.json --key keys/operator.pem --output /tmp/policy-badsigner.json
kubectl -n honey create cm node-agent-bundle-policy --from-file=trust-policy.json=/tmp/policy-badsigner.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
```

node-agent refuses it and leaves bundles disabled rather than trusting a policy it cannot anchor:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "trust policy signature invalid"
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep -c "signed bundle overlays enabled"
```

Restore the root-signed policy and the bundle assembles again:

```
kubectl -n honey create cm node-agent-bundle-policy --from-file=trust-policy.json=trust-policy.signed.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "signed bundle overlays enabled"
```

## 12. Require signatures on user-supplied profiles

By default an unsigned user-defined profile still loads, so signing is opt-in per object.

Set `nodeAgent.bundleSigning.requireSignedObjects: true` in `kubescape/values.yaml` and re-run `make kubescape` to refuse them instead:

```
(cd ../../../.. && { grep -q requireSignedObjects kubescape/values.yaml || sed -i '/^  bundleSigning:/a\    requireSignedObjects: true' kubescape/values.yaml; } && make kubescape)
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey get cm node-agent -o jsonpath='{.data.config\.json}' | grep enableSignatureVerification
```

An unsigned user-defined profile is then refused and reported, while the workload keeps whatever it was already enforcing. The client's SBoB from §5 (`../sbobs/cp-redis-client.yaml`) is exactly that — a flat, unsigned, user-defined profile — so it is refused as soon as this is on:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep "is unsigned" | tail -1
# → user-defined ContainerProfile refused: signature verification is required and the profile is unsigned … profile: redis-client
```

Sign it to get it back:

```
./sign-fragment.sh ../sbobs/cp-redis-client.yaml keys/operator.pem
```

This is the **flat** single-profile path, not the bundle path: a bundle fragment that stops verifying is reported as `a verified member no longer verifies` (§8) and the bundle keeps its last verified composite, whereas an unsigned flat profile is refused outright here.

Learned profiles are unaffected, because node-agent generates them in-cluster and they never take this path.

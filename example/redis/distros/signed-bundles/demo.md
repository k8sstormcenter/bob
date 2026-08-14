# Signed SBoB fragment bundles — redis distros demo

The [distros demo](../DEMO.md) with §5's `kubectl patch` replaced by a **cryptographically signed admission fragment**.

- Parties sign **fragments** of a ContainerProfile offline; node-agent verifies each against a per-class trust policy, assembles the composite in memory, binds it to a Merkle root.
- node-agent only **verifies**. No private key exists anywhere on the cluster.
- The composite is re-derived from the signed fragments every reconcile tick — it cannot drift.
- Tampering any fragment → **R1016**, change refused, workload stays on the last verified composite.

| Fragment | Class | Signed by | Contributes |
|---|---|---|---|
| `fragments/frag-base-redis.yaml` | `base` | vendor key | learned redis SBoB from [`../sbobs/cp-redis.yaml`](../sbobs/cp-redis.yaml) (execs/opens/caps — **no ingress**) |
| `fragments/frag-overlay-ops.yaml` | `overlay` | operator key | end-user addition: allow `df -h` |
| `fragments/frag-admission-redis-client.yaml` | `admission` | operator key | client-allowlist ingress — shipped LATER, §6 |

`trust-policy.json` pins per class **who may sign** (pubkey fingerprint) and **which spec paths the class may set** — the admission signer cannot smuggle `execs` in.

All keys under `keys/` are published demo material and authenticate nothing — [`keys/README.md`](keys/README.md).

## 0. Prerequisites

- cluster + `kubectl`, `helm` (3 or 4 — Makefile auto-adds `--force-conflicts` on 4), `python3`
- `make` targets run from the repo root; everything else from `example/redis/distros/signed-bundles/`
- `bobctl` (§4b), into the repo root:

```
curl -fsSL -o bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.2/bobctl-linux-amd64 && chmod +x bobctl
```

- `sign-object` (linux; pick your arch), into this directory:

```
cd example/redis/distros/signed-bundles
curl -fsSL -o sign-object https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.5/sign-object-linux-amd64 && chmod +x sign-object
```

(or from source: `git clone -b signature-overlays https://github.com/k8sstormcenter/node-agent && cd node-agent && go build -o sign-object ./cmd/sign-object`)

## 1. Install kubescape

Chart `1.40.3-sign-rc2` (helm-charts `signature-overlays`) pins `ghcr.io/k8sstormcenter/node-agent:v0.3.192` + `ghcr.io/k8sstormcenter/storage:v0.3.177`.

From the repo root:

```
make kubescape
make alertmanager
```

`make alertmanager` feeds §4b; everything else reports via the node-agent stdout exporter.

### Two ways to install the trust bundle

The trust policy is a root-signed artifact (~2.5KB JSON: certificate + signature). Both paths behave identically.

**A. Inline in values** (`make kubescape` does this). The chart owns the ConfigMap; `helm upgrade` re-asserts the values' policy. To avoid hand-pasting:

```
helm upgrade --install kubescape \
  https://github.com/k8sstormcenter/helm-charts/releases/download/kubescape-operator-1.40.3-sign-rc2/kubescape-operator-1.40.3-sign-rc2.tgz \
  -n honey --create-namespace --values kubescape/values.yaml \
  --set-file nodeAgent.bundleSigning.trustPolicy=example/redis/distros/signed-bundles/trust-policy.signed.json
```

**B. Mounted from a ConfigMap you own.**

```
make kubescape-mounted
```

Creates `kubescape-trust-bundle` from `trust-policy.signed.json`, installs with `existingConfigMap`. Rotation = `kubectl apply` on the ConfigMap, no helm.

Either way node-agent reads `/etc/bundle/trust-policy.json`. Directory mount → kubelet propagates updates → rotated policy applies within a reconcile interval (§9a). An artifact that fails root verification is refused; the policy in force is kept.

## 2. Signed-bundle support boots with the chart

Root-signed policy verified against the root public key compiled into the image. No private key deployed, no restart, nothing to patch.

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed bundle overlays enabled"
# → signed bundle overlays enabled in alert mode
```

One global state, carried in the policy: `alert` reports, `enforce` refuses. A mounted policy is never silent — no explicit mode = `alert`.

Expected startup warning — the anchor is the **published demo root key**; the one thing to change for real use:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "DEMO root key"
```

See "Bring your own root key"; under `enforce`, node-agent refuses the demo root outright.

The shipped policy carries `ruleClasses` → **rule signing is on from the first boot**: every `Rules` object must verify or its rules are dropped whole. An unsigned baseline = **no runtime detections**, said loudly on every sync. `make kubescape` therefore ships `rules/baseline-rules-signed.yaml` (31-rule baseline, `base`-class, demo operator key) — to the chart via `nodeAgent.bundleSigning.signedDefaultRules` and as a direct apply. Confirm before deploying anything:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed rule fragments enabled"
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep -c "detection is effectively OFF"
# → signed rule fragments enabled, and the count must be 0
```

Running §4b before rules admit = zero alerts, zero attack detections.

(`enable-bundle-signing.sh` is only for the upstream chart, which has no bundleSigning values.)

## 2b. Signing modes — OFF / ALERT / ENFORCE

One switch, in the root-signed policy (`"mode"`), plus the master values toggle. What each mode does, and what tampering a signed object looks like in each:

| | OFF (`bundleSigning.enabled: false`) | ALERT (default) | ENFORCE (`"mode": "enforce"`) |
|---|---|---|---|
| boot log | none (no bundle lines) | `signed bundle overlays enabled in alert mode` | `signed bundle overlays enabled in ENFORCE mode: unsigned and unverifiable artifacts are refused` |
| demo root | n/a | warning, keeps running | **refused** — agent will not enable signing on the published demo root; mount your own root |
| unsigned user profile | loads | loads (refused only with `requireSignedObjects`, §12) | refused |
| tampered signed fragment | change takes effect silently — nothing verifies anything | R1016 + fragment refused, last verified composite kept (§7d) | R1016 + refused, same keep-last-verified |
| unsigned `Rules` object | loads | rejected when `ruleClasses` present (fail closed + backstop) | rejected, same |

Switching modes = edit `"mode"` in `trust-policy.json`, re-sign with the root key, re-install (§9a shows the no-restart rotation). ENFORCE on this demo requires the mounted-root path ("Bring your own root key") because the compiled-in anchor is the demo root.

Tamper drill per mode — same §7(d) content-tamper against `redis-ops-overlay`:

- **OFF:** the annotation edit lands, no log line of any kind, the stored object simply lies. That silence is the argument for turning signing on.
- **ALERT:** `"RuleID":"R1016"` + `bundle overlay failed` within a reconcile interval; `df -h` still governed by the LAST VERIFIED overlay.
- **ENFORCE:** same R1016 + refusal; additionally every unsigned/unverifiable object was already inadmissible, so there is no unsigned fallback surface at all.

Recorded on a clean k3s v1.36 cluster, 2026-08-14, images node-agent v0.3.192 / storage v0.3.177. `$NA` = `kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1`; timestamps trimmed.

**OFF** — zero signing plumbing, tamper is silent:

```
$NA | grep -c "signed bundle"                       # → 0
$NA | grep "RulesWatcher - synced rules" | tail -1
# → "enabledRules":28,"totalRules":1     (unsigned baseline loads)
# after the §7d content tamper:
$NA --since=5m | grep -cE "R1016|verif|bundle"      # → 0
```

**ALERT** (shipped defaults) — healthy boot:

```
{"level":"info","msg":"signed bundle overlays enabled in alert mode"}
{"level":"warn","msg":"signed bundle overlays anchored to the PUBLISHED DEMO root key: this authenticates nothing, mount a real root before relying on signatures"}
{"level":"info","msg":"signed rule fragments enabled"}
{"level":"info","msg":"RulesWatcher - signed rule fragments","admitted":1,"rejected":0}
{"level":"info","msg":"assembled signed bundle overlay","bundle":"redis","fragments":2,"root":"97df8151…"}
```

**ALERT** — the detection outage and its recovery (delete the signed baseline, apply the unsigned one):

```
{"level":"warn","msg":"rules fragment rejected","name":"default-rules","error":"fragment is not signed: \"default-rules\""}
{"level":"info","msg":"RulesWatcher - signed rule fragments","admitted":0,"rejected":1}
{"level":"error","msg":"RulesWatcher - signing enabled but NO rule fragment admitted while rules objects exist: detection is effectively OFF; sign the baseline ruleset as a base-class fragment or correct the trust policy","rulesObjects":1,"rejected":1}
{"level":"info","msg":"RulesWatcher - synced rules from cluster","enabledRules":0,"totalRules":1}
# exec `id` in redis-master during the outage → 0 R0001 alerts. Re-apply
# rules/baseline-rules-signed.yaml → admitted:1 on the watch event, the same
# exec fires R0001 again — no agent restart (restartCount stayed 0).
```

**ALERT and ENFORCE** — content tamper (§7d), identical in both modes:

```
R1016 "Signed profile tampered", severity 10
{"level":"warn","msg":"signed bundle overlay refused: a verified member no longer verifies; keeping the last verified composite","bundle":"redis","members":"redis-ops-overlay","error":"fragment signature does not verify (tampered): …"}
```

**ENFORCE** (mounted root) — boot + unsigned flat profile refused:

```
{"level":"info","msg":"signed bundle overlays enabled in ENFORCE mode: unsigned and unverifiable artifacts are refused"}
{"level":"warn","msg":"signed bundle overlays anchored to a MOUNTED root public key: the trust anchor is cluster-mutable, protect it with an immutable ConfigMap and tight RBAC","fingerprint":"key:d0cc7f2e…"}
{"level":"warn","msg":"user-defined ContainerProfile refused: signature verification is required and the profile is unsigned","profile":"redis-client"}
```

**ENFORCE without a mounted root** (compiled-in demo anchor) — refused outright, signing stays off:

```
{"level":"warn","msg":"signed bundle overlays disabled: trust policy signature invalid","error":"enforce mode refuses the published demo root key: mount a real root at /etc/bundle/root.pub"}
```

## 3. The vendor ships SIGNED fragments — before any workload exists

Offline signing: `sign-object --embed-content` embeds the signed bytes in `signature.kubescape.io/content` — survives storage normalisation. The cluster never sees an unsigned fragment. No admission fragment yet — the client does not exist:

```
cd example/redis/distros/signed-bundles   # if you cd'd to the repo root for §1
./sign-fragment.sh fragments/frag-base-redis.yaml  keys/vendor.pem
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

No bundle object exists: grouping is the signed `signature.kubescape.io/bundle: redis` label.

## 4. Deploy redis

```
(cd .. && ./deploy-distros.sh redis sbob)
```

`sbob` labels the statefulset `kubescape.io/user-defined-profile: redis`. Fragments are already in place → the pod starts protected, no unprofiled window.

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "assembled signed bundle overlay"
# → bundle=redis fragments=2 root=<merkle-root-A>
```

## 4b. Functional suite, then attacks

A signed profile must behave like the learned one it replaces: benign quiet, attacks alert.

```
(cd .. && bobctl test --functional-tests functional/redis-oss.yaml -n redis)
```

```
export T0=$(date -u +%Y-%m-%dT%H:%M:%SZ) NS=redis
(cd .. && bobctl attack --attack-suite attacks/redis-oss.yaml -n redis)
```

Split alerts at `$T0`:

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

FPs on the functional suite = a bad profile, not a working signature.

## 5. A client appears — unexpected ingress fires

Client with its own SBoB (its redis-cli/egress stay quiet):

```
kubectl apply -f ../sbobs/cp-redis-client.yaml
kubectl apply -f ../../client.yaml
```

Server composite has **no ingress** → **R0012** on the node hosting redis-master:

```
MNODE=$(kubectl -n redis get pod redis-master-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
timeout 120 kubectl -n honey logs -f $NA | grep -m3 "Unexpected ingress network"
```

## 6. Allowlist the client LATER — signed fragment

The ingress entry ships as a standalone signed admission fragment:

```
./sign-fragment.sh fragments/frag-admission-redis-client.yaml keys/operator.pem
```

Within ~1 min: re-assembly, 3 fragments, new root:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "assembled signed bundle overlay" | tail -1
# → bundle=redis fragments=3 root=<merkle-root-B>   (≠ root-A)
```

R0012 stops. The admission key can only add ingress/egress — `execs` in this fragment would fail the whole bundle.

## 7. Verify the composite — without touching the leaves

**(a) Merkle-bound assembly:** the root commits to the exact verified leaf set — root-A → root-B just showed it.

**(b) Leaves untouched** — assembly never rewrites fragments:

```
export CP=containerprofiles.spdx.softwarecomposition.kubescape.io
for f in redis-base redis-ops-overlay redis-client-ingress; do
  kubectl -n redis get $CP $f -o yaml > /tmp/leaf.yaml
  ./sign-object verify --file /tmp/leaf.yaml --strict=false && echo "leaf $f: OK"
done
```

**(c) Behaviour proves the union** — each check exercises one fragment:

```
# base fragment enforced: an exec outside every fragment alerts (R0001)
kubectl -n redis exec sts/redis-master -- id
# overlay fragment honoured: df -h is allowed — no alert
kubectl -n redis exec sts/redis-master -- df -h
# admission fragment honoured: R0012 stopped in §6
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=5m | grep -oE '"RuleID":"R[0-9]+"' | sort | uniq -c
```

**(d) Tamper the signed content → refused + R1016.** Stored-spec edits are inert (enforcement binds embedded content); attacking the embedded content breaks the signature:

```
kubectl -n redis get $CP redis-ops-overlay -o jsonpath='{.metadata.annotations.signature\.kubescape\.io/content}' \
  | python3 -c 'import sys,base64,gzip; d=gzip.decompress(base64.b64decode(sys.stdin.read())); d=d.replace(b"/usr/bin/df", b"/bin/backdoor"); print(base64.b64encode(gzip.compress(d)).decode())' \
  | xargs -I{} kubectl -n redis annotate $CP redis-ops-overlay --overwrite signature.kubescape.io/content={}
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep '"RuleID":"R1016"' | tail -1
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep "bundle overlay refused" | tail -1
```

Workload keeps the last verified composite — tamper reports and is rejected without turning every exec into an alert.

Recover — re-ship the vendor artifact:

```
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

Identical leaf set = identical root (logs at debug, no new-root transition). Enforcement-resumed proof is behavioural:

```
kubectl -n redis exec sts/redis-master -- uname -a
sleep 30
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep '"RuleID":"R0001"' | tail -1
```

## How admissibility is decided (reference)

All must hold per fragment, or the bundle is rejected:

1. `signature.kubescape.io/fragment-class` label present, class exists in the policy;
2. signature verifies over the embedded signed content (`metadata{name,labels}` + `spec`) — stored spec irrelevant;
3. signer fingerprint (`key:<sha256(PKIX(pub))>`) listed for its class;
4. only spec paths its class allows (e.g. `admission` → `ingress`/`egress`).

New key: `sign-object generate-keypair --output my.pem` → fingerprint:

```
echo "key:$(openssl pkey -pubin -in my.pem.pub -outform DER | sha256sum | cut -d' ' -f1)"
```

Public keys are never stored on the cluster — each artifact carries its certificate; the policy holds only the fingerprint it must match.

`metadata.namespace` is NOT signed: a vendor cannot know the install namespace, and per-customer re-signing would defeat offline signing. Confinement = the signed `bundle` + `fragment-class` labels; namespace placement is ordinary RBAC.

## Bring your own root key (rotating the trust anchor)

The published image ships a demo root key you are meant to replace.

```
./sign-object generate-keypair --output root.pem   # writes root.pem + root.pem.pub
```

```
./sign-object sign-policy --policy trust-policy.json --key root.pem --output trust-policy.signed.json
```

Keep the root private key offline in escrow — adding/rotating a signer later means re-signing.

**Mounted (no rebuild):** set `nodeAgent.bundleSigning.rootPublicKey` to `root.pem.pub` alongside the signed `trustPolicy`; verification uses `/etc/bundle/root.pub`. The anchor is then a cluster ConfigMap — protect it with an immutable ConfigMap + tight RBAC; node-agent warns when a mounted anchor is in use.

**Embedded (rebuild):** replace `DefaultRootPublicKeyPEM` in `pkg/signature/bundle/root.go`, rebuild the image. The anchor cannot be swapped on a running cluster.

## 8. Robustness — the adversarial cases

**Stored-spec edit is inert:**

```
kubectl -n redis patch $CP redis-ops-overlay --type json \
  -p '[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/backdoor"}}]'
# → no R1016, composite root unchanged; df -h still the ONLY overlay exec enforced
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep -c '"RuleID":"R1016"'
# → 0
```

**Signed-content edit is caught** — R1016, fail closed (§7d).

**Unsigned fragment rejected:**

```
kubectl -n redis delete $CP redis-ops-overlay               # drop the signed object
kubectl -n redis apply  -f fragments/frag-overlay-ops.yaml  # re-create from the UNSIGNED source
# → refused: "fragment is not signed"; the workload KEEPS its last verified composite
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "no longer verifies" | tail -1
```

A verified member that stops verifying = refused, last verified composite kept. (`apply` alone would not unsign — 3-way merge keeps the annotations.) Re-ship before continuing:

```
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

**A never-verified object is a non-member, not a bundle failure.** Membership is authenticated — labels alone don't make a member. Unsigned / untrusted-key / class-violating labelled objects are **dropped**; the bundle assembles from genuine members:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "dropped non-member"
```

Otherwise one injected object would fail the bundle closed for every bound workload — a namespace-writer DoS. Alert deduped per bundle, not per object.

**No rollback.** Fragments carry a monotonic `signature.kubescape.io/version` inside the signed content; anything below the accepted high-water mark for that bundle/class/name is refused. Marks are in-memory, reset on restart.

Signer identity = the fingerprint the signature verified against — never the spoofable OIDC annotations.

## 9. Signed rules — the vendor ships rules with the bundle

Profiles: what a workload may do. Rules: what the agent alerts on. Unsigned reality: any `Rules` object in any namespace merges into one ruleset keyed by rule ID — anyone who can create one can redefine `R0001` with `enabled: false` cluster-wide. Signed rule fragments close that.

Same two labels as profile fragments — one bundle carries both halves:

| Object | Labels | Applies |
|---|---|---|
| `ContainerProfile` | `bundle: redis`, `fragment-class: base` | workloads bound to bundle `redis` |
| `Rules` | `bundle: redis`, `fragment-class: overlay` | same workloads, overriding the base rule with the same ID |
| `Rules` (baseline) | `fragment-class: base` | cluster-wide, no bundle |

Bundle + class are signed → no re-classing, no re-targeting. Namespace is not signed → same artifact installs anywhere.

Rule classes invert profile roles: `base` = the user's cluster-wide baseline, `overlay` = vendor bundle-scoped rules. The policy names signers and permitted rule IDs per class:

```
"ruleClasses": {
  "base":    {"signers": ["key:<user>"],   "allowedRuleIDs": ["*"]},
  "overlay": {"signers": ["key:<vendor>"], "allowedRuleIDs": ["R0001","R0002"]}
}
```

Scenario: redis is the cache tier — an unexpected process there is possible compromise, not drift — so the vendor ships `R0001` at severity 10 with a redis-specific message.

### (a) Rule signing is already on

`kubescape/values.yaml` ships the full root-signed policy, `ruleClasses` included — on from §1.

> **Change the policy in `values.yaml`, never with `kubectl` on the ConfigMap.** The chart owns `node-agent-bundle-policy` — a ConfigMap edit survives only until the next `helm upgrade`, and a policy missing `ruleClasses` switches rule signing off with no error. Edit `trust-policy.json`, re-sign, paste into values, re-run:
>
> ```
> ./sign-object sign-policy --policy trust-policy.json --key keys/root.pem --output trust-policy.signed.json
> # paste trust-policy.signed.json into nodeAgent.bundleSigning.trustPolicy in kubescape/values.yaml, then:
> (cd ../../../.. && make kubescape)
> ```
>
> No restart — directory mount, reload within a reconcile interval:
>
> ```
> kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "trust policy reloaded"
> ```
>
> A replacement failing root verification is refused, the policy in force kept:
>
> ```
> kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "trust policy reload REFUSED"
> ```
>
> With `make kubescape-mounted`, rotate the ConfigMap directly instead:
>
> ```
> kubectl -n honey create configmap kubescape-trust-bundle \
>   --from-file=trust-policy.json=trust-policy.signed.json --dry-run=client -o yaml | kubectl apply -f -
> ```

Every `Rules` object must verify or its rules drop whole. The install ships the pre-signed baseline (§2) — sign it yourself only when it is yours to sign (own keys, or an edited ruleset):

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

`rules/rules-redis.yaml`: `bundle: redis` + `fragment-class: overlay`, `R0001` at severity 10, message `REDIS TIER CRITICAL: ...`.

### (c) The override follows the bundle, not the namespace

```
kubectl -n redis exec sts/redis-master -- id
sleep 30
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "REDIS TIER CRITICAL" | tail -1
```

Same namespace, different binding — the client never gets the override:

```
kubectl -n redis exec deploy/redis-client -- id
sleep 30
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep "REDIS TIER CRITICAL" | grep -o '"containerName":"[^"]*"' | sort | uniq -c
```

### (d) The adversarial cases

**Rogue key ships a disable-detection fragment:**

```
./sign-object generate-keypair --output /tmp/rogue.pem
sed 's/enabled: true/enabled: false/' rules/rules-redis.yaml > /tmp/rogue-rules.yaml
./sign-rules.sh /tmp/rogue-rules.yaml /tmp/rogue.pem
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "rules fragment rejected"
# → signer not permitted for this fragment class; the fragment's rules are dropped whole
# → RulesWatcher - signed rule fragments  admitted=1 rejected=1
```

Rogue rules never load; redis falls back to the base `R0001` (severity 1 instead of 10). Signing protects rule **content**, not object **presence** — create/delete on `rules.kubescape.io` can still lose the tightening; restrict that verb with RBAC. Re-ship the operator artifact to restore.

**Unsigned rules object dropped:**

```
kubectl -n redis delete rules.kubescape.io rules-redis
kubectl apply -f rules/rules-redis.yaml    # the UNSIGNED source
# → rules fragment rejected: fragment is not signed
```

**Class-confined IDs:** a vendor overlay setting `R0007` → `rule ID not allowed for this class`.

**Overlay must declare a bundle** — no `bundle` label → rejected, never applies everywhere.

**No re-targeting** — the bundle label is signed; pointing an overlay at another bundle breaks the signature.

## 10. The same signed artifact, any namespace

```
kubectl create ns redis-staging
sed 's/^  namespace: redis$/  namespace: redis-staging/' fragments/frag-base-redis-signed.yaml | kubectl create -f -
```

```
export CP=containerprofiles.spdx.softwarecomposition.kubescape.io
kubectl -n redis-staging get $CP redis-base -o yaml > /tmp/moved.yaml
./sign-object verify --file /tmp/moved.yaml --strict=false && echo "verified in redis-staging"
```

Rules likewise: an overlay signed for `bundle: redis` follows the binding, not the namespace.

## 10b. A single signed profile, without a bundle

One party owning the whole profile signs it directly — no bundle/class labels:

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

```
kubectl -n redis get $CP redis-solo -o yaml > /tmp/solo.yaml
./sign-object verify --file /tmp/solo.yaml --strict=false
```

Learned profiles are separate objects, unsigned by design. Bundles are for the multi-party case.

## 11. The trust anchor itself is checked

A policy not signed by the root is refused — editing the ConfigMap cannot name a new signer:

```
./sign-object sign-policy --policy trust-policy.json --key keys/operator.pem --output /tmp/policy-badsigner.json
kubectl -n honey create cm node-agent-bundle-policy --from-file=trust-policy.json=/tmp/policy-badsigner.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
```

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "trust policy signature invalid"
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep -c "signed bundle overlays enabled"
```

Restore:

```
kubectl -n honey create cm node-agent-bundle-policy --from-file=trust-policy.json=trust-policy.signed.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "signed bundle overlays enabled"
```

## 12. Require signatures on user-supplied profiles

Default: unsigned user-defined profiles load (signing opt-in per object). Flip it:

```
(cd ../../../.. && { grep -q requireSignedObjects kubescape/values.yaml || sed -i '/^  bundleSigning:/a\    requireSignedObjects: true' kubescape/values.yaml; } && make kubescape)
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey get cm node-agent -o jsonpath='{.data.config\.json}' | grep enableSignatureVerification
```

The client's SBoB from §5 is a flat unsigned user profile — refused as soon as this is on:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=3m | grep "is unsigned" | tail -1
# → user-defined ContainerProfile refused: signature verification is required and the profile is unsigned … profile: redis-client
```

Sign it back:

```
./sign-fragment.sh ../sbobs/cp-redis-client.yaml keys/operator.pem
```

Flat path ≠ bundle path: an unsigned flat profile is refused outright; a bundle member that stops verifying keeps the last verified composite (§8). Learned profiles are unaffected — generated in-cluster, never on this path.

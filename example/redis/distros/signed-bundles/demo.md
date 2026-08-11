# Signed SBoB fragment bundles — redis distros demo

This is the [distros demo](../DEMO.md) with one change: the "allowlist a client
later" step (its §5 `kubectl patch` on the server profile) is replaced by a
**cryptographically signed admission fragment**. Multiple parties each sign
their own **fragment** of a ContainerProfile; node-agent verifies every
fragment against a per-class trust policy, assembles them into ONE effective
profile, and binds the assembly to the exact set of admissible fragments with a
Merkle leaf-tree. node-agent only **verifies** — it holds no signing key, and no
private key exists anywhere on the cluster. The composite is re-derived from the
signed fragments every reconcile tick, so it can never drift from them.
Tampering with any fragment fires **R1016** and drops the whole bundle (fail
closed).

The cast:

| Fragment | Class | Signed by | Contributes |
|---|---|---|---|
| `fragments/frag-base-redis.yaml` | `base` | vendor key | the learned redis SBoB from [`../sbobs/cp-redis.yaml`](../sbobs/cp-redis.yaml) (execs/opens/caps — **no ingress**) |
| `fragments/frag-overlay-ops.yaml` | `overlay` | operator key | end-user addition: allow `df -h` for ops |
| `fragments/frag-admission-redis-client.yaml` | `admission` | operator key | the client-allowlist ingress entry — shipped LATER, in §6 |

The trust policy (`trust-policy.json`) pins per class **who may sign** (public-key
fingerprint) and **which spec paths the class may set** — the admission signer
cannot smuggle `execs` into the server profile even with a valid signature.

All keys under `keys/` are throwaway demo material.

## 0. Prerequisites

- a cluster + `kubectl`, `helm` (3 or 4 — the Makefile auto-adds `--force-conflicts` on helm 4), `python3`
- **working directory:** `make kubescape` (§1) runs from the **repo root**; every
  other command runs from `example/redis/distros/signed-bundles/`, which holds
  `sign-object`, `sign-fragment.sh`, `fragments/`, and `keys/`.
- the `sign-object` CLI (linux; pick your arch), fetched into that directory:

```
cd example/redis/distros/signed-bundles
curl -fsSL -o sign-object https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.4/sign-object-linux-amd64 && chmod +x sign-object
```

(or build from source: `git clone -b signature-overlays https://github.com/k8sstormcenter/node-agent && cd node-agent && go build -o sign-object ./cmd/sign-object`)

## 1. Install kubescape with the right images

`kubescape/values.yaml` in this repo pins the images that carry the feature
(`ghcr.io/k8sstormcenter/node-agent:v0.3.181` and
`ghcr.io/k8sstormcenter/storage:v0.3.177`, built from the `signature-overlays`
branch). From the repo root:

```
make kubescape
```

## 2. Signed-bundle support boots with the chart

`kubescape/values.yaml` sets `nodeAgent.bundleSigning` — the **root-signed**
trust policy (the set of trusted public-key fingerprints, itself signed by the
root key and verified by node-agent against the root public key compiled into
the image). No private key is deployed; node-agent only verifies. The fork chart
renders the mount and config at install time — node-agent starts with
signed-bundle support enabled. Nothing to patch, no
restarts. Confirm:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed bundle overlays enabled"
```

(`enable-bundle-signing.sh` remains only for installs of the upstream chart,
which has no bundleSigning values.)

## 3. The vendor ships SIGNED fragments — before any workload exists

Signing happens **offline**: `sign-object --embed-content` signs the fragment
and embeds the exact signed content in the
`signature.kubescape.io/content` annotation. The `*-signed.yaml` artifact is
what the vendor ships; the cluster never sees an unsigned fragment, and the
signature stays valid no matter how the storage server normalises the spec on
save (annotations are never touched — the embedded bytes remain the verified
source of truth). `sign-fragment.sh` signs and then ingests the artifact. The
admission fragment is NOT part of this step — the client does not exist yet:

```
cd example/redis/distros/signed-bundles   # if you cd'd to the repo root for §1
./sign-fragment.sh fragments/frag-base-redis.yaml  keys/vendor.pem
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

There is no extra bundle object: fragments are grouped by their
`signature.kubescape.io/bundle: redis` label (part of the signed content, so a
fragment cannot be re-labeled into another bundle).

## 4. Deploy redis (pinned distros install, sbob binding)

```
(cd .. && ./deploy-distros.sh redis sbob)
```

The `sbob` toggle binds the workload exactly as in the distros demo: it labels
the statefulset with `kubescape.io/user-defined-profile: redis`. Because the
signed fragments are ALREADY in place, the pod starts protected — node-agent
finds the bundle on first load, so there is no window where the workload runs
without its profile. (sbob mode also applies the classic flat `cp-redis.yaml`;
the bundle takes precedence over it — it remains as the non-bundle fallback.)

node-agent verifies each leaf against the trust policy and assembles the
composite (2 fragments for now) in memory — no signing, no key:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "assembled signed bundle overlay"
# → bundle=redis fragments=2 root=<merkle-root-A>
```

## 5. A client appears — unexpected ingress fires

Exactly the distros demo's "detect a client" step: deploy the client with its
own SBoB (so the client's OWN redis-cli/egress stay quiet — that profile rides
the ordinary flat single-CP path, bundles are only used where fragments exist):

```
kubectl apply -f ../sbobs/cp-redis-client.yaml
kubectl apply -f ../../client.yaml
```

The server's composite has **no ingress** (the vendor base ships none), so the
client's connections are unexpected — watch **R0012** fire on the node hosting
redis-master:

```
MNODE=$(kubectl -n redis get pod redis-master-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected ingress network"
```

## 6. Allowlist the client LATER — with a signed fragment

Where the distros demo patches the server profile in place (an unsigned,
unauditable mutation), the operator now ships the same ingress entry as a
**standalone signed admission fragment**:

```
./sign-fragment.sh fragments/frag-admission-redis-client.yaml keys/operator.pem
```

Within the reconcile interval (~1 min) node-agent picks up the changed fragment set and
re-assembles — same bundle, now 3 fragments and a NEW Merkle root:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "assembled signed bundle overlay" | tail -1
# → bundle=redis fragments=3 root=<merkle-root-B>   (≠ root-A)
```

R0012 stops within a reconcile interval (~1–2 min) — the client is admitted by a signed, attributable,
path-confined object instead of an in-place edit. The admission key can ONLY
add ingress/egress: had the operator key signed execs into this fragment, the
whole bundle would be rejected.

## 7. Verify the composite is signed — without touching the leaves

**(a) The assembly is bound to a Merkle root** (§4/§6 log lines): the root
commits to the exact set of verified leaves (class ‖ signer ‖ content-digest
per leaf) — a fragment added, dropped, or altered changes the root, as the
root-A → root-B transition in §6 just showed. The composite the rules engine
enforces carries this root plus a fresh cluster-key signature; it is assembled
in the agent (not stored), and its signature is checked on every load exactly
like any flat signed profile.

**(b) The leaves are untouched:** each fragment still verifies with its
ORIGINAL signature — assembly reads fragments, it never rewrites them:

```
export CP=containerprofiles.spdx.softwarecomposition.kubescape.io
for f in redis-base redis-ops-overlay redis-client-ingress; do
  kubectl -n redis get $CP $f -o yaml > /tmp/leaf.yaml
  ./sign-object verify --file /tmp/leaf.yaml --strict=false && echo "leaf $f: OK"
done
```

**(c) The behaviour proves the union** (each check exercises a different
fragment — and would fail if that fragment had been rejected):

```
# base fragment enforced: an exec outside every fragment alerts (R0001)
kubectl -n redis exec sts/redis-master -- id
# overlay fragment honoured: df -h is allowed — no alert
kubectl -n redis exec sts/redis-master -- df -h
# admission fragment honoured: R0012 stopped in §6
```

Alerts are emitted via the stdout exporter — observe them in the node-agent
logs by rule id:

```
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=5m | grep -oE '"RuleID":"R[0-9]+"' | sort | uniq -c
```

**(d) Tamper the signed content → the bundle fails closed + R1016.**

Because enforcement binds the EMBEDDED signed content, editing the stored spec
is inert — tamper-proof by construction. An attacker must go after the signed
content itself; without the operator key the signature then breaks:

```
kubectl -n redis get $CP redis-ops-overlay -o jsonpath='{.metadata.annotations.signature\.kubescape\.io/content}' \
  | python3 -c 'import sys,base64,gzip; d=gzip.decompress(base64.b64decode(sys.stdin.read())); d=d.replace(b"/usr/bin/df", b"/bin/backdoor"); print(base64.b64encode(gzip.compress(d)).decode())' \
  | xargs -I{} kubectl -n redis annotate $CP redis-ops-overlay --overwrite signature.kubescape.io/content={}
```

Within the reconcile interval node-agent re-verifies, the embedded content no
longer matches its signature, an R1016 "Signed profile tampered" alert fires
for the bundle, and the composite is dropped (no profile is enforced rather
than a half-trusted one). Recover by re-shipping the vendor artifact:

```
./sign-fragment.sh fragments/frag-overlay-ops.yaml keys/operator.pem
```

Recovery restores the exact signed content, so the composite reassembles to its
pre-tamper root (an identical leaf set gives an identical Merkle root — this
reuse logs at debug, not as a new-root transition line). The proof that
enforcement is live again — not an empty profile — is behavioural: `df -h` is
allowed once more and a fresh unlisted exec still alerts:

```
kubectl -n redis exec sts/redis-master -- uname -a
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=1m | grep '"RuleID":"R0001"'
```

## How admissibility is decided (reference)

For every fragment, ALL of the following must hold or the whole bundle is
rejected:

1. it carries a `signature.kubescape.io/fragment-class` label and the class
   exists in the trust policy;
2. it is signed and the signature verifies over the EMBEDDED signed content
   (`metadata{name,namespace,labels}` + `spec`, carried in the
   `signature.kubescape.io/content` annotation) — so the stored spec, which the
   server may normalise, is irrelevant to verification;
3. the signer's public-key fingerprint (`key:<sha256(PKIX(pub))>`) is listed
   for its class;
4. it sets only spec paths its class allows (e.g. `admission` →
   `ingress`/`egress` only).

To author a policy entry for a new key (`sign-object generate-keypair --output my.pem`
writes `my.pem` + `my.pem.pub`), derive the fingerprint from the public key:

```
echo "key:$(openssl pkey -pubin -in my.pem.pub -outform DER | sha256sum | cut -d' ' -f1)"
```

## Bring your own root key (rotating the trust anchor)

The trust policy is only trustworthy because node-agent verifies its signature
against a **root public key compiled into the node-agent image** — there is no
cluster-side override, by design: the anchor cannot be edited on a running
cluster, so a cluster-admin attacker can't swap it. The published image ships
with a demo root key. To trust **your own** root instead of the one minted for
this demo, swap the embedded key and rebuild — you do this once, offline:

1. Generate a root keypair (the private key stays OFFLINE — it never touches the
   cluster):

```
./sign-object generate-keypair --output root.pem   # writes root.pem + root.pem.pub
```

2. Replace `DefaultRootPublicKeyPEM` in the node-agent source
   (`pkg/signature/bundle/root.go`) with the contents of `root.pem.pub`, and
   rebuild the node-agent image. The image now trusts only your root.

3. Sign your trust policy with the root **private** key:

```
./sign-object sign-policy --policy trust-policy.json --key root.pem --output trust-policy.signed.json
```

4. Ship `trust-policy.signed.json` as the `nodeAgent.bundleSigning.trustPolicy`
   value (it becomes the mounted `/etc/bundle/trust-policy.json`). node-agent
   verifies it against your embedded root at boot and refuses to enable bundles
   if the signature or the root pin fails (fail closed).

5. **Destroy the root private key.** node-agent only verifies; nothing on the
   cluster ever needs it again. If a fragment signer key is later added/rotated,
   you re-sign the policy — which needs the root key again, so keep it offline in
   escrow if you expect to change signers, or regenerate a new root (new image)
   to rotate the anchor itself.

## 8. Robustness — the adversarial cases

These are the properties an attacker with `kubectl` on the ContainerProfiles
faces. Each is enforced by node-agent and observable.

**Editing the stored spec is inert** (the composite binds the *signed* embedded
content, not the mutable stored object):

```
kubectl -n redis patch $CP redis-ops-overlay --type json \
  -p '[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/backdoor"}}]'
# → no R1016, composite root unchanged; df -h still the ONLY overlay exec enforced
```

**Editing the signed content is caught** (R1016, fail closed) — see §7(d).

**An unsigned fragment is rejected:**

```
kubectl -n redis delete $CP redis-ops-overlay               # drop the signed object
kubectl -n redis apply  -f fragments/frag-overlay-ops.yaml  # re-create from the UNSIGNED source
# → bundle overlay failed: "fragment is not signed"; composite drops until re-signed
```

(`apply` alone would not do it — a 3-way merge keeps the existing signature
annotations, so the object stays signed; the fragment must be re-created from
the unsigned source.)

**A fragment signed by an untrusted key is rejected** — sign with a key whose
fingerprint is not in `trust-policy.json` for that class → `signer not permitted
for this fragment class`. **A class-confined violation is rejected** — an
`admission`-class fragment that sets `execs` → `class may not set spec.execs`.
Both fail the whole bundle closed (no partial trust).

The signer identity is the **public-key fingerprint** the signature verified
against — not the (unsigned, spoofable) OIDC identity annotations — so a trusted
signer cannot be impersonated by copying annotation strings.

## 9. Signed rules — one rule changed for one namespace

Profiles say what a workload may do. **Rules** say what the agent alerts on —
and until now any `Rules` object in any namespace was merged into one global
ruleset keyed by rule ID. Anyone who could create a `Rules` object could
redefine `R0001` with `enabled: false` and turn off process detection for the
whole cluster. Signed rule fragments close that, and add something useful:
a rule can be changed for **one namespace only**.

Two classes, same trust model as profile fragments:

| Class | Signed by | Applies |
|---|---|---|
| `cluster` | vendor key | cluster-wide — the baseline ruleset |
| `namespace` | operator key | ONLY in the object's own namespace, overriding the cluster rule with the same ID |

The class, the namespace and the rules are all inside the signed content, so a
fragment cannot be re-classed, moved to another namespace, or edited without
breaking its signature. `trust-policy.json` names who may sign each class and
which rule IDs they may set (`"*"` for any) — here the operator may only touch
`R0001` and `R0002`:

```
"ruleClasses": {
  "cluster":   {"signers": ["key:<vendor>"],   "allowedRuleIDs": ["*"]},
  "namespace": {"signers": ["key:<operator>"], "allowedRuleIDs": ["R0001","R0002"]}
}
```

**The scenario:** redis is the cache tier. An unexpected process there is a
possible compromise, not routine drift — so the redis team ships `R0001` with
severity 10 and a redis-specific message, **for the redis namespace only**.
Everywhere else `R0001` keeps its cluster default.

### (a) Turn rule signing on

`trust-policy.json` in this directory already carries the `ruleClasses` above.
Because the policy is root-signed, changing it means re-signing it:

```
./sign-object sign-policy --policy trust-policy.json --key keys/root.pem --output trust-policy.signed.json
kubectl -n honey create cm node-agent-bundle-policy --from-file=trust-policy.json=trust-policy.signed.json --dry-run=client -o yaml | kubectl apply -f -
```

Rule signing is now ON, which means **every** `Rules` object must verify or its
rules are dropped. The baseline ruleset the chart installed is unsigned, so the
vendor signs it as a `cluster` fragment before anything else — otherwise you
correctly end up with no rules at all:

```
./sign-rules.sh rules/baseline-rules.yaml keys/vendor.pem
kubectl -n honey rollout restart daemonset node-agent
kubectl -n honey rollout status daemonset node-agent --timeout=300s
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 | grep "signed rule fragments enabled"
```

### (b) The redis team ships its rule

```
./sign-rules.sh rules/rules-redis.yaml keys/operator.pem
```

`rules/rules-redis.yaml` is a `Rules` object in the **redis** namespace,
labelled `signature.kubescape.io/rule-class: namespace`, carrying one rule:
`R0001` at severity 10 with the message `REDIS TIER CRITICAL: ...`.

### (c) See the override — and see that it stays in redis

Trigger an unexpected process in redis, and the alert carries the redis message
and severity:

```
kubectl -n redis exec sts/redis-master -- id
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "REDIS TIER CRITICAL"
```

The same rule elsewhere is untouched — its alerts still carry the default
`Unexpected process launched` message. One rule ID, two definitions, selected by
the namespace that signed for it.

### (d) The adversarial cases

**An attacker ships a rule fragment to disable detection** — the whole point of
signing rules. Create a `Rules` object in redis that redefines `R0001` with
`enabled: false`, signed with a key that is not in the policy:

```
./sign-object generate-keypair --output /tmp/rogue.pem
sed 's/severity: 10/severity: 10\n      enabled: false/' rules/rules-redis.yaml > /tmp/rogue-rules.yaml
./sign-rules.sh /tmp/rogue-rules.yaml /tmp/rogue.pem
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --since=2m | grep "rules fragment rejected"
# → signer not permitted for this fragment class; the fragment's rules are dropped whole
```

**An unsigned rules object is dropped** — with rule signing on, dropping the
signature is not a way around it:

```
kubectl -n redis delete rules.kubescape.io rules-redis
kubectl apply -f rules/rules-redis.yaml    # the UNSIGNED source
# → rules fragment rejected: fragment is not signed
```

**A trusted signer may not touch any rule they like.** The operator key is
permitted `R0001` and `R0002` only; a fragment of theirs that sets, say,
`R0007` is rejected with `rule ID not allowed for this class` — the same
path-confinement idea as `allowedSpecPaths` for profiles.

**Re-scoping is not possible.** Editing `metadata.namespace` on a signed rules
fragment to point at another namespace breaks the signature, because the
namespace is part of the signed content — the fragment is rejected rather than
silently applying somewhere it was never signed for.

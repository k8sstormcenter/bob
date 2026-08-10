# Signed SBoB fragment bundles — redis distros demo

This is the [distros demo](../DEMO.md) with one change: the "allowlist a client
later" step (its §5 `kubectl patch` on the server profile) is replaced by a
**cryptographically signed admission fragment**. Multiple parties each sign
their own **fragment** of a ContainerProfile; node-agent verifies every
fragment against a per-class trust policy, assembles them into ONE effective
profile, binds the assembly to the exact set of admissible fragments with a
Merkle leaf-tree, and re-signs the composite with the cluster key. Tampering
with any fragment fires **R1016** and drops the whole bundle (fail closed).

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
- the `sign-object` CLI (linux; pick your arch):

```
curl -fsSL -o sign-object https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.1/sign-object-linux-amd64 && chmod +x sign-object
```

(or build from source: `git clone -b signature-overlays https://github.com/k8sstormcenter/node-agent && cd node-agent && go build -o sign-object ./cmd/sign-object`)

## 1. Install kubescape with the right images

`kubescape/values.yaml` in this repo pins the images that carry the feature
(`ghcr.io/k8sstormcenter/{node-agent,storage}:v0.3.175`, built from the
`signature-overlays` branch). From the repo root:

```
make kubescape
```

## 2. Enable signed-bundle overlays

Applies the trust-policy ConfigMap + cluster signing-key Secret, adds
`bundleTrustPolicyPath`/`bundleSigningKeyPath` to node-agent's config, mounts
both at `/etc/bundle`, and restarts node-agent. Do this **before** deploying
workloads (the restart discards learning in progress):

```
cd example/redis/distros/signed-bundles && ./enable-bundle-signing.sh
```

The script fails unless node-agent logs `signed bundle overlays enabled`.
Re-run it after any later `make kubescape` upgrade — helm re-renders the
node-agent ConfigMap/DaemonSet and drops these patches (the script is
idempotent).

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

node-agent verifies each leaf against the trust policy, assembles the
composite (2 fragments for now), and re-signs it with the cluster key:

```
kubectl -n honey logs daemonset/node-agent -c node-agent | grep "assembled signed bundle overlay"
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
kubectl -n honey logs daemonset/node-agent -c node-agent | grep "assembled signed bundle overlay" | tail -1
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
kubectl -n honey logs daemonset/node-agent -c node-agent --since=5m | grep -oE '"ruleID":"R[0-9]+"[^,]*|"ruleName":"[^"]*"' | sort | uniq -c
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

— the composite reassembles (new Merkle root in the log line) and enforcement
resumes.

## How admissibility is decided (reference)

For every fragment, ALL of the following must hold or the whole bundle is
rejected:

1. it carries a `signature.kubescape.io/fragment-class` label and the class
   exists in the trust policy;
2. it is signed and the signature verifies over the storage-normalised
   content (`metadata{name,namespace,labels}` + `spec`; annotations excluded);
3. the signer's public-key fingerprint (`key:<sha256(PKIX(pub))>`) is listed
   for its class;
4. it sets only spec paths its class allows (e.g. `admission` →
   `ingress`/`egress` only).

To author a policy entry for a new key (`sign-object generate-keypair --output my.pem`
writes `my.pem` + `my.pem.pub`), derive the fingerprint from the public key:

```
echo "key:$(openssl pkey -pubin -in my.pem.pub -outform DER | sha256sum | cut -d' ' -f1)"
```

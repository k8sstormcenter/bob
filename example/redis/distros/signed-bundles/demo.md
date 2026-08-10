# Signed SBoB fragment bundles — redis demo

Multiple parties each sign their own **fragment** of a ContainerProfile; the
node-agent verifies every fragment against a per-class trust policy, assembles
them into ONE effective profile, binds the assembly to the exact set of
admissible fragments with a Merkle leaf-tree, and re-signs the composite with
the cluster key. Tampering with any fragment fires **R1016** and drops the
whole bundle (fail closed).

The cast, using the redis distros example:

| Fragment | Class | Signed by | Contributes |
|---|---|---|---|
| `fragments/frag-base-redis.yaml` | `base` | vendor key | the learned redis SBoB (execs/opens/caps — **no ingress**) |
| `fragments/frag-admission-redis-client.yaml` | `admission` | operator key | the "allowlist a client later" ingress entry (the §5 patch of [`../DEMO.md`](../DEMO.md), now a standalone signed object) |
| `fragments/frag-overlay-ops.yaml` | `overlay` | operator key | end-user addition: allow `df -h` for ops |

The trust policy (`trust-policy.json`) pins per class **who may sign** (public-key
fingerprint) and **which spec paths the class may set** — the admission signer
cannot smuggle `execs` into the server profile even with a valid signature.

All keys under `keys/` are throwaway demo material.

## 0. Prerequisites

- a cluster + `kubectl`, `helm`, `python3`, Go ≥ 1.25
- the `sign-object` CLI, built from the feature branch:

```
git clone -b signature-overlays https://github.com/k8sstormcenter/node-agent /tmp/na && (cd /tmp/na && go build -o sign-object ./cmd/sign-object) && cp /tmp/na/sign-object .
```

## 1. Install kubescape with the right images

`kubescape/values.yaml` in this repo pins the images that carry the feature
(`ghcr.io/k8sstormcenter/{node-agent,storage}:v0.3.173`, built from the
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

## 3. Deploy redis

```
(cd .. && ./deploy-distros.sh redis)
```

## 4. Create and sign the fragments

Signing uses **sign-after-roundtrip**: the fragment is applied unsigned, read
back in the storage-normalised form (the storage server deflates specs on
save), and THAT form is signed — otherwise the signature would be invalid the
moment the object lands. `sign-fragment.sh` does the dance:

```
./sign-fragment.sh fragments/frag-base-redis.yaml            keys/vendor.pem
./sign-fragment.sh fragments/frag-admission-redis-client.yaml keys/operator.pem
./sign-fragment.sh fragments/frag-overlay-ops.yaml           keys/operator.pem
```

Each fragment now carries its signature in `signature.kubescape.io/*`
annotations. Verify any of them independently (leaf verification):

```
export CP=containerprofiles.spdx.softwarecomposition.kubescape.io
kubectl -n redis get $CP redis-base -o yaml > /tmp/leaf.yaml && ./sign-object verify --file /tmp/leaf.yaml --strict=false
```

## 5. Bundle = label. Ingest into kubescape

There is no extra bundle object: the fragments are grouped by their
`signature.kubescape.io/bundle: redis` label, and the workload opts in by
referencing the bundle name via the standard user-defined-profile label:

```
kubectl -n redis patch statefulset redis-master --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"redis"}}}}}'
```

On pod (re)start node-agent lists the bundle's fragments, verifies each leaf
against the trust policy, assembles the composite, and re-signs it with the
cluster key. Nothing extra to apply.

## 6. Verify the composite is signed — without touching the leaves

**(a) The assembly happened and is bound to a Merkle root:**

```
kubectl -n honey logs daemonset/node-agent -c node-agent | grep "assembled signed bundle overlay"
```

Expect `bundle=redis fragments=3 root=<merkle-root>`. The root commits to the
exact set of verified leaves (class ‖ signer ‖ content-digest per leaf) — a
fragment added, dropped, or altered changes the root. The composite the rules
engine enforces carries this root plus a fresh cluster-key signature; it exists
in the agent (it is assembled, not stored), so its signature is checked on
every load exactly like any flat signed profile.

**(b) The leaves are untouched:** re-run the §4 leaf verification for all three
fragments — each still verifies with its ORIGINAL signature. Assembly reads the
fragments; it never rewrites them, so composing the bundle cannot invalidate a
leaf.

**(c) The behaviour proves the union** (each check exercises a different
fragment — and would fail if that fragment had been rejected):

```
# base fragment enforced: an exec outside every fragment alerts (R0001)
kubectl -n redis exec sts/redis-master -- id
# overlay fragment honoured: df -h is allowed — no alert
kubectl -n redis exec sts/redis-master -- df -h
# admission fragment honoured: the redis-client connects without R0012
#   (deploy the client per ../DEMO.md §5 — with the signed ingress fragment in
#    place, the "unexpected ingress" alert does not fire for it)
```

Alerts land in alertmanager as usual (`kubectl -n honey port-forward svc/alertmanager-operated 9093` → http://localhost:9093).

**(d) Tamper any leaf → the bundle fails closed + R1016:**

```
kubectl -n redis patch $CP redis-ops-overlay --type json -p '[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/backdoor"}}]'
```

Within the reconcile interval node-agent re-verifies, the modified leaf no
longer matches its signature, an R1016 "Signed profile tampered" alert fires
for the bundle, and the composite is dropped (no profile is enforced rather
than a half-trusted one). Recover by re-signing the fragment over its current
content:

```
kubectl -n redis get $CP redis-ops-overlay -o yaml > /tmp/frag.yaml
./sign-object sign --file /tmp/frag.yaml --output /tmp/frag-signed.yaml --key keys/operator.pem --type containerprofile
kubectl -n redis replace -f /tmp/frag-signed.yaml
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

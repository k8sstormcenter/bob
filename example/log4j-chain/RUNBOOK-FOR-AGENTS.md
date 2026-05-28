# Runbook — running the Log4Shell three-scenario chain demo

**Audience**: an AI agent (or human operator) with shell + kubectl access
to a fresh-ish Linux box. No prior context with this repo.

**Goal**: deploy the chain once, then cycle through scenarios A / B / C
and confirm each produces the expected kubescape detection signature.
Time budget: ~25 min wall on a fresh k3s, ~8 min if k3s + kubescape are
already running.

**Idempotency**: every kubectl apply is idempotent. The only inter-step
state is the backend image — switching scenarios requires a backend
swap + a frontend restart (nginx caches upstream pod IPs).

---

## Required tools (verify, don't reinstall if present)

```bash
for tool in kubectl jq curl base64; do
  command -v "$tool" >/dev/null && echo "  $tool: $(command -v $tool)" || { echo "MISSING: $tool"; exit 1; }
done
```

If any are missing on Debian/Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y kubectl jq curl coreutils
```

Docker is **optional** — only needed if you want to rebuild the four
images. Default path uses pre-published `ghcr.io/k8sstormcenter/log4j-chain-*`
images.

---

## Step 1 — Cluster: k3s (skip if you already have one running)

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode=644" sh -
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
sed -i "s|server: https://127.0.0.1:6443|server: https://$(hostname -I | awk '{print $1}'):6443|" ~/.kube/config
kubectl get nodes  # expect Ready
```

---

## Step 2 — Kubescape (skip if `honey` namespace exists)

```bash
# From the repo root:
make kubescape
kubectl -n honey rollout status ds/node-agent --timeout=180s
kubectl get ns honey
```

---

## Step 3 — Deploy the chain (scenario A baseline)

```bash
kubectl apply -f log4j-chain.yaml

# Wait for everything to come up.
for d in chain-postgres chain-frontend chain-backend chain-observer; do
  kubectl -n log4j-poc rollout status deploy/$d --timeout=120s
done
kubectl -n attacker-ns rollout status deploy/attacker --timeout=60s

# (Optional) install the kubescape ApplicationProfiles + R1100 binding
# so the per-scenario rule signatures fire on schedule.
kubectl apply -f kubescape/application-profiles/
kubectl apply -f kubescape/rules/R1100_rulespec.yaml
```

### After every SBOB iteration: delete-before-apply

When BoB-agent (or `bobctl tune`) ships an updated AP/NN, **always**
`kubectl delete` the existing resource before `kubectl apply` of the
new one:

```bash
kubectl -n log4j-poc delete applicationprofile chain-backend
kubectl -n log4j-poc apply -f <new-ap-chain-backend.yaml>
# wait ~30 s for node-agent to flush its per-binding cache
sleep 30
```

Strategic-merge-patch on the kubescape AP CRD silently drops newly-
added entries (`execs`, `opens`, `rulePolicies`, …) when an auto-learned
AP already exists for the workload. Confirmed on storage
`sbob-rc1-2026-05-16`. After delete+apply, allow ~30 s for node-agent
to flush its per-binding cache before re-running attacks; otherwise
the freshly-restarted JVM's JIT threads will trigger transient
`C1 CompilerThre` / `C2 CompilerThre` R0002 fires until propagation
completes.

This pattern is captured as dimension **D4** in
[`docs/portability-spec.md`](../../docs/portability-spec.md) and will
be baked into `scripts/lib/chain-apply-sbobs.sh` once the chain-pipeline
refactor (PR #132) wires it up programmatically.

Sanity check — every pod Ready:

```bash
kubectl get pods -A | grep -E 'log4j-poc|attacker-ns'
```

---

## Step 4 — Functional traffic (drives sbob learning)

Either let `chain-observer` run for a couple of minutes (its built-in
30-second poll), or fire the FunctionalTestSuite explicitly:

```bash
bobctl test apply log4j-functional-tests.yaml
```

Confirm the four sbobs converged:

```bash
kubectl -n log4j-poc get applicationprofiles
kubectl -n log4j-poc get networkneighborhoods
```

(If you're not using bobctl, you can equivalently run a few of these by hand:)

```bash
PORT=$(kubectl -n log4j-poc get svc chain-frontend -o jsonpath='{.spec.ports[0].nodePort}')
curl -s "http://$(hostname -I | awk '{print $1}'):${PORT}/api/products"
curl -s "http://$(hostname -I | awk '{print $1}'):${PORT}/api/products?q=widget"
curl -s -X POST "http://$(hostname -I | awk '{print $1}'):${PORT}/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pass":"correct-horse-battery-staple"}'
```

---

## Step 5 — Run the attack (scenario A)

```bash
# In-cluster attack pod: YAML carries the JNDI literal so no shell layer
# eats the `$`. The pod runs two curls (benign login + JNDI probe) and
# exits with phase=Succeeded.
sed 's/attack-PLACEHOLDER/attack-a/' attack-pod.yaml | kubectl apply -f -
kubectl -n log4j-poc wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/attack-a --timeout=60s

# Inspect:
kubectl -n log4j-poc logs pod/attack-a
kubectl -n log4j-poc logs deploy/chain-backend --tail=20
kubectl -n attacker-ns logs deploy/attacker --tail=10
```

Expected for scenario A (with kubescape ApplicationProfile learned in step 4):

```bash
# kubescape rule fires on chain-backend
kubectl -n log4j-poc get applicationprofiles -o yaml | grep -E 'R0001|R0010|R0011|R1100' | head
# or via your kubescape_logs sink
```

You should observe — on chain-backend — `R0011` (egress to
attacker:1389), `R0001` (new `/bin/sh` comm under java), and `R0010`
(sensitive-file access if the payload's psql query touches one).

---

## Step 6 — Switch to scenario B (contained)

```bash
# 1. Replace chain-backend
kubectl apply -f backend-b.yaml
kubectl -n log4j-poc rollout status deploy/chain-backend --timeout=120s

# 2. Restart the frontend — nginx caches the backend's pod IP at startup,
#    and the new chain-backend has a different IP. Without this,
#    /api/products returns 504 until nginx is restarted.
kubectl -n log4j-poc rollout restart deploy/chain-frontend
kubectl -n log4j-poc rollout status deploy/chain-frontend --timeout=60s

# 3. Re-fire the attack
kubectl -n log4j-poc delete pod attack-b --ignore-not-found --wait=true
sed 's/attack-PLACEHOLDER/attack-b/' attack-pod.yaml | kubectl apply -f -
kubectl -n log4j-poc wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/attack-b --timeout=60s
```

Expected for scenario B: `R0011` fires (same egress as A), but instead
of `R0001`/`R0010` you get **`R1100` failed-execve ENOENT** — the
distroless container has no `/bin/sh`, so `Runtime.exec` returns
immediately with that errno. R1100 is the "B-vs-A discriminator".

---

## Step 7 — Switch to scenario C (patched)

```bash
kubectl apply -f backend-c.yaml
kubectl -n log4j-poc rollout status deploy/chain-backend --timeout=120s
kubectl -n log4j-poc rollout restart deploy/chain-frontend
kubectl -n log4j-poc rollout status deploy/chain-frontend --timeout=60s

kubectl -n log4j-poc delete pod attack-c --ignore-not-found --wait=true
sed 's/attack-PLACEHOLDER/attack-c/' attack-pod.yaml | kubectl apply -f -
kubectl -n log4j-poc wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/attack-c --timeout=60s
```

Expected for scenario C: **no kubescape rule fires** on chain-backend.
The JNDI literal is present in the HTTP request (verifiable via Pixie's
`http_events` table or `kubectl logs deploy/chain-backend`) but log4j
2.17.1 does not perform JNDI substitution at all — so no LDAP egress,
no class fetch, no exec. The chain-backend's ApplicationProfile remains
unchanged from the benign baseline.

---

## Step 8 — Verdict differentiation

If you have `bobctl-tune` or a similar diagnosis framework:

```bash
bobctl tune --suite log4j-attacks.yaml --baseline log4j-functional-tests.yaml \
  --emit-sbobs ./sbobs/
```

The three produced sbobs (chain-backend.A.bob, chain-backend.B.bob,
chain-backend.C.bob) should differ in:

- A vs B: `R0001` vs `R1100` in the ApplicationProfile fires
- A,B vs C: presence of cross-namespace egress in the NetworkNeighborhood

---

## Cleanup

```bash
kubectl delete -f log4j-chain.yaml
kubectl delete -f backend-b.yaml --ignore-not-found
kubectl delete -f backend-c.yaml --ignore-not-found
kubectl -n log4j-poc delete pod attack-a attack-b attack-c --ignore-not-found
kubectl delete ns log4j-poc attacker-ns --ignore-not-found
```

---

## Known issues / non-blockers

- **Pixie's `process_stats` is a sampled metric.** It misses sub-second
  child processes (the `/bin/sh` spawned by `Runtime.exec` for the A
  payload finishes in tens of ms). For A-vs-B differentiation at the
  exec layer you NEED kubescape's R0001 / R1100 on a learned
  ApplicationProfile baseline. Pixie's `dns_events` and `conn_stats`
  ARE sufficient to see the LDAP and DNS-exfil layers though.
- **nginx caches the upstream backend's pod IP at startup.** After each
  backend swap (steps 6, 7) the frontend MUST be restarted or it'll
  return 504 forever. The runbook does this explicitly.
- **`kubectl run --rm` with `-A '${jndi:…}'` doesn't deliver the literal
  `$`.** The shell chain through `kubectl exec` argv eats the dollar.
  This is why `attack-pod.yaml` is a static Pod manifest — YAML doesn't
  substitute, and the `${jndi:…}` reaches the curl arg byte-identical.

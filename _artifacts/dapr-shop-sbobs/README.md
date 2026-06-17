# dapr-shop SBoBs — blind detection bundle for dx

Per-pod **ApplicationProfile (AP)** + **NetworkNeighborhood (NN)** baselines learned from the
`example/dapr-shop` CNCF Dapr mesh under steady-state benign load (`loadgen.yaml`).
This is the **baseline policy** dx receives for the blind exercise — pair it with the sealed
trigger (`example/dapr-shop/attack-trigger.yaml`). The attack hops / answer key are withheld.

## What's here
```
ap-<workload>.yaml   ApplicationProfile  (L7 Dapr HTTP endpoints, execs, opens, syscalls, capabilities)
nn-<workload>.yaml   NetworkNeighborhood (ingress/egress edges + ports)
```
Workloads: `frontend`, `orders`, `payments`, `admin` (the four Dapr apps) + `redis`, `nats` (infra).

## How these were produced (provenance)
- k3s + kubescape (node-agent `sbob-rc1-2026-05-16`), single-node laptop, 2026-06-17.
- Dapr control plane via `helm install dapr dapr/dapr --set global.ha.enabled=false`.
- `deploy.yaml` + `loadgen.yaml` applied; **node-agent restarted after deploy** (this laptop's
  k3s drops live container-start events — only startup enumeration learns; restart + continuous
  loadgen overlapping the 2m window gives a clean baseline).
- Learning window: `initialDelay 2m + maxSniffingTimePerContainer 2m`. All 12 profiles reached
  `status=completed` (`completion=partial` — expected for a 2-min window).

## Fidelity notes (read before scoring)
- **The discriminating layer is the AP L7 endpoints, not the NN.** `httpDetectionEnabled` captured
  the Dapr building-block calls as HTTP endpoints (e.g. `frontend` baseline daprd =
  `:3500/v1.0/invoke/orders/method/checkout` only; `orders` baseline =
  `:3500/v1.0/secrets/shopsecrets/payment-key` — the **single** baseline secret).
- **NN edges are thin** (DNS + loadgen ingress + dapr ports). The 2-min eBPF window did not populate
  the cross-pod daprd↔daprd / daprd↔component egress edges. If you need a rich NN graph baseline,
  re-learn with a longer `maxSniffingTimePerContainer` and sustained diverse load.

## Honest detection result from the reference e2e run (2026-06-17)
Firing the sealed trigger executed the full chain (frontend `/eval` → … → state-store write landed
as Redis key `frontend||exfil`). Standard-rule signals attributable to the chain:
- **R0006 + R0007 on `frontend/daprd`** — the secret-sweep hop is NOT invisible: Dapr's
  `secretstores.kubernetes` is backed by the kube-apiserver, so the frontend's daprd reads the SA
  token + connects to the k8s API to serve the bulk-secret request. Frontend daprd never does this
  in baseline → it fires. (This refines the ground-truth "R0007: none" expectation.)
- **Lateral (`invoke/admin`) and state-exfil (Redis) hops: no standard-rule signal** — as designed.
- Net: the chain is *partially* visible at the kernel layer (one daprd→kube-apiserver tell on the
  secret hop) and otherwise only as a **novel service-graph path** (`frontend→admin`,
  `frontend→secrets/bulk`, `frontend→state`) across HTTP→gRPC→RESP→NATS.

Scoring target unchanged: reconstruct the multi-protocol service graph and flag the novel
edges/path. Bonus realism: correlate the R0006/R0007 daprd tell to the secret-sweep hop.

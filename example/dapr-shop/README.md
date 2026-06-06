# dapr-shop — CNCF Dapr microservice mesh (blind detection exercise)

A realistic Dapr "shop": `frontend → orders → payments` (+ a dormant `admin`), each pod running a
**daprd sidecar**. The fabric spans **HTTP → gRPC → RESP (Redis state) → NATS JetStream (pub-sub) →
k8s secret store** — i.e. every building-block call changes protocol.

## What's here
```
deploy.yaml           the shop + Redis + NATS + Dapr Components + secrets + a benign loadgen
attack-trigger.yaml   a SEALED in-fabric trigger (apply, don't decode)
```

## Run it
1. Install the Dapr control plane: `helm install dapr dapr/dapr -n dapr-system --create-namespace`.
2. `kubectl apply -f deploy.yaml`. The `loadgen` drives the benign fabric continuously; let
   node-agent **learn the per-pod baselines** from steady-state traffic until profiles complete.
   (For the cross-node variant, pin `frontend` and `admin` to different nodes.)
3. `kubectl apply -f attack-trigger.yaml`. Watch node-agent + your detection.

## This is a blind test
Only the workload + the sealed trigger are shared. The attack, its hops, and the expected
signals are intentionally **withheld**. Report what — if anything — your detection surfaces, how
it classifies it, and whether it can reconstruct the path across the protocol boundaries. The
point: an attacker who stays inside Dapr's building-block APIs is very hard to tell apart from
normal mesh traffic.

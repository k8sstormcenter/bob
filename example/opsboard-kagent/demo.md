# opsboard — a first-party vuln, a real agent, a signed SBoB

An internal microservice **we wrote** (`opsboard`) with a **planted command-injection**. A real **kagent** AI agent is tasked to audit it, finds the flaw, and breaks out. The service runs under a **vendor-signed ContainerProfile (SBoB)** learned from its normal, multi-protocol behavior — so the breakout deviates and node-agent flags it. The vuln is in first-party code (no CVE to know); the signed behavioral contract catches the break-out anyway, and the workload can't widen its own profile to hide.

## Why "a lot of protocols"

`opsboard`'s normal operation speaks six protocols; its learned SBoB pins all six as allowed egress:

| protocol | to | port |
|---|---|---|
| Redis / RESP | redis | 6379 |
| Postgres wire | postgres | 5432 |
| gRPC | inventory | 9090 |
| AMQP | rabbitmq | 5672 |
| HTTP | fx | 80 |
| DNS | coredns | 53/udp |

Its only allowed exec is `/opsboard`. So anything the exploit spawns (`sh`, `dig`, `curl`, `id`, `cat`) is out-of-contract.

## The vuln (first-party)

`GET /api/diag?target=…` runs `sh -c "dig +short $target ; curl -s $target"` on unsanitized input — command injection. Go's query parser strips `;`/`&`, so the payload uses `$(...)`, `|`, or a newline. The container runs as root, so it's RCE as root.

## 0. Prerequisites

```
git clone -b signed-bundle-demo https://github.com/k8sstormcenter/bob && cd bob
```

Single-node-ish k3s + `kubectl`, `helm`, `docker` (buildx, for the ttl.sh image), `python3` (`python3-yaml`), and outbound access to `ttl.sh`.

## 1. One-shot (vuln → detection)

```
example/opsboard-kagent/setup.sh
```

Builds+pushes `opsboard`, deploys the stack, installs the signed kubescape stack, learns+signs+binds the SBoB, fires the injection from an attacker pod, and prints the detections.

## 2. Expected detections (observed)

After the signed SBoB is bound, the breakout produced ~255 alerts on `opsboard`:

```
R0001  Unexpected process launched: sh / dig / curl / id / cat
R0002  Unexpected file access: cat -> /run/secrets/kubernetes.io/serviceaccount/token
```

`R0001` fires on every tool the injection spawns (the profile allowed only `/opsboard`); `R0002` catches the ServiceAccount-token theft. node-agent first verifies + adopts the signed profile:

```
Successfully verified object signature   namespace=shop name=opsboard-base
adopted user-authored ContainerProfile as authoritative base   name=opsboard-base
```

## 3. The real agent (kagent)

The manual breakout above is exactly what the agent does autonomously. Provide a model key, then apply the agent:

```
kubectl -n kagent create secret generic kagent-anthropic --from-literal=ANTHROPIC_API_KEY=sk-ant-...
kubectl apply -f example/opsboard-kagent/kagent/modelconfig.yaml
kubectl apply -f example/opsboard-kagent/kagent/agent.yaml
```

The `appsec-auditor` Agent is told to audit `http://opsboard.shop:8080`, probe `/api/diag`, and demonstrate impact. It enumerates the API, finds the injection, executes, reads the SA token — tripping the same R0001/R0002 signature against the signed SBoB. Adjust `model` and the tool name (`tools[].mcpServer.toolNames`) to your installed kagent version.

## 4. Cleanup

```
kubectl delete ns shop
helm -n honey uninstall kubescape
helm -n kagent uninstall kagent kagent-crds
```

## Files

- `opsboard/` — the first-party service (Go), Dockerfile
- `k8s/all.yaml` — opsboard + inventory-grpc + redis + postgres + rabbitmq + fx, SA with Secret read
- `hack/cp-to-fragment.py` — learned CP → signable base fragment
- `kagent/` — ModelConfig (Anthropic) + the appsec-auditor Agent
- `setup.sh` — the full flow

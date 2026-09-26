# IngressNightmare (CVE-2025-1974) — Ran-driven chain

Chain 3 of the iktlinz set: the HTTPS/ingress attack path. A worker foothold
exploits a vulnerable ingress-nginx controller via IngressNightmare
(auth-url injection), reads the controller's cluster-scoped token, and attempts
to escalate. Same shape and tooling as `example/iktlinz` (chain 1, redis) and
`example/iktlinz2` (chain 2, postgres) — driven by Ran, rendered in the Ran UI,
and reusing that platform's `agent-worker` foothold.

## Run

```
./run-ingress-e2e.sh                 # deploy everything + fire steps 1-20
./run-ingress-e2e.sh --benign-only   # deploy only, no attack
./run-ingress-e2e.sh --no-deploy     # fire against an already-deployed stack
```

Requires `kubectl`, `python3`, `curl`, `go` on PATH, and Ran reachable at
`--ran-url` (default `http://localhost:8080`). The controller is adopted under
the signed `sbobs/cp-ingress-base.yaml` SBoB (`sign-object` + a vendor key).

## The chain, and where each step runs

The foothold is `agent-worker`; almost the whole chain runs from it.

| # | Step | Executes on |
|---|------|-------------|
| 1 | create listener | Ran C2 container |
| 2 | spawn worker | `orchestrator:30080` → creates `agent-worker` |
| 3 | await callback | worker → C2 socat |
| 4-9 | env, SA token, kubectl, perms, http client, local IP | `agent-worker` |
| 10-11 | ingress recon, pre-tool RCE (expected fail) | `agent-worker` |
| 12 | stage the `ing` PoC | `agent-worker` (kubectl cp) |
| 13-14, 16 | RCE + controller token / secret read | `ing` runs in `agent-worker`; injected payload runs in the `ingress-nginx` controller |
| 15 | check controller token perms | via worker foothold |
| 17 | exfiltrate token | `agent-worker` → `echo` backend |
| 18-19 | check perms, deploy privileged pod | worker foothold, stolen-identity |
| 20 | nsenter escape + read `k3s.yaml` | the spawned privileged pod |

Steps 18-20 are the blast-radius test: the controller's token has Secret read
but not pod-create, so the escalation is designed to be contained.

## Environment

`run-ingress-e2e.sh` deploys the shared iktlinz platform (chain 3 uses only its
`agent-orchestrator` + `agent-worker`), the vulnerable `ingress-nginx`
controller under the signed SBoB, and the `echo` backend + `echo.local` Ingress
that the chain routes and exfiltrates through.

## Files

- `demo_chain3.py` — the Ran driver (20 steps)
- `run-ingress-e2e.sh` — deploy + fire, one shot
- `drive-benign.sh` — echo backend + `echo.local` Ingress
- `sbobs/cp-ingress-base.yaml` — the controller's signed SBoB
- `obligations-chain3.json` — the detection obligations
- `report.py` — pass/fail scoring
- `hack/cp-to-fragment.py` — profile → signed fragment converter

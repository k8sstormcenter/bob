# IKT-Linz — agentic-platform attack chain, automated end to end

An agent-worker platform (`agent-system`) and an intentionally insecure
observability stack (`oopservability`) under a full attack chain, driven
unattended: initial access through to node compromise, with clean SBoBs for
every component so the malignant path is separable from normal operation.

![the chain](iktlinz-attack.gif)

## The chain

1. reverse-shell listener; a worker pod is induced to `socat` back — initial foothold
2. read the mounted ServiceAccount token, drop `kubectl` — the token turns out to hold nothing useful
3. install `nmap`, learn the local IP, sweep the pod subnet
4. **CVE-2022-0543** — Redis Lua sandbox escape gives command execution inside redis
5. **CVE-2026-47701** — a ServiceMonitor with an unsafe `bearerTokenFile` makes the
   injected OTel sidecar leak *its own* token to redis's metric-receiver, which parks
   it in a Redis key; the RCE reads it back. That token belongs to `agent-orchestrator`
   and can create Pods.
6. create an attacker-controlled privileged Pod (hostPath `/`, hostPID) that calls back
7. `nsenter` into the host namespaces, read the k3s cluster credentials

Step-by-step, matching the workshop: [`DEMO-SCRIPT.md`](DEMO-SCRIPT.md).

## Running it

Needs a cluster, and Ran reachable — default `http://localhost:8080`.
`relearn-sbobs.sh` additionally needs `bobctl`, and the recording scripts need
`ffmpeg`, both on `PATH`.

### Ran, in a container

Ran is not part of this repo: it is [Magier/Ran](https://github.com/Magier/Ran).
Run it containerised. Its binary is built against GLIBC 2.39, newer than most
hosts ship, and `demo_chain.py` reads each step's result back out with
`docker logs` because the API does not return it.

```bash
mkdir ran && cd ran
curl -sfL https://github.com/Magier/Ran/releases/download/v0.2.9/ran-linux-amd64.tar.gz | tar -xz
cp ~/.kube/config kubeconfig && chmod 600 kubeconfig

cat > ran.yaml <<'YAML'
namespaces:
  excluded: [kube-system, kube-public, kube-node-lease, local-path-storage]
ttps:
  disabled:
    - read-local-kubeconfig
YAML

docker run -d --name ran-ui --network host -v "$PWD:/ran" -e KUBECONFIG=/ran/kubeconfig \
  ubuntu:24.04 /ran/ran emulate --config /ran/ran.yaml --host 0.0.0.0 --port 8080

curl -sf localhost:8080/api/armory >/dev/null && echo "Ran up"
```

`--network host` is what lets Ran serve the UI and reach the cluster.

Ran will not start without a kubeconfig, but that credential is the tool's, not
the attacker's: the graph comes up holding **two** entities, and the chain earns
every identity it uses. `read-local-kubeconfig` is disabled for the same reason
— leaving it on lets one click hand the cluster over and the demo proves
nothing. Exclude your own detection stack's namespaces in `ran.yaml` or they
crowd the graph.

The scripts expect the container to be called `ran-ui`; override with
`RAN_CONTAINER`, and the endpoint with `RAN_URL`.

```
./run-iktlinz-e2e.sh                 # deploy platform, benign baseline, fire the chain
./run-iktlinz-e2e.sh --benign-only   # baseline with no disease
python3 demo_chain.py --list         # the 20 steps
python3 demo_chain.py --only 13      # one step
```

`run-iktlinz-e2e.sh` writes `window.json`: the window boundaries plus the
specimens that must survive into a filtered forensic store. It deliberately does
not configure a detection stack — that stays with the caller.

## Known gap: unit-5's stolen identity is never used

The chain steals the redis ServiceAccount token and reads it successfully, but
Ran never grounds it as an auth identity, so the two steps that should act *as*
redis fall through to a direct `kubectl` path on every cluster tested.

The practical consequence is attribution, not outcome. CVE-2026-47701 still
fires and the sidecar still leaks its token, but the ServiceMonitor that arms it
arrives as an operator `kubectl apply` rather than as an act by the compromised
identity — so anything reconstructing the window as an attack path will place
that step outside it.

The cause is a tension that cannot be resolved in `demo_chain.py`:
`read-service-account-token` is the TTP whose effects ingest the
ServiceAccount entity, but it needs an exec channel into the redis pod and none
exists; reading the token through the RCE works but ingests nothing. Closing it
needs an armory TTP that promotes a raw token to an auth identity.

## SBoBs

`sbobs/` holds one ContainerProfile per component, learned from a **benign-only**
window and checked for attack markers before shipping. Regenerate with
`./relearn-sbobs.sh`.

Profiles learned *while the chain runs* are worthless as a baseline — redis's
contained the RCE itself (`/bin/sh -c id`) and the worker's contained
apt/nmap/kubectl. Generalising those allowlists the attack, and nothing fires.
Re-learning needs a **new pod identity**: node-agent tombstones the profile name,
so deleting the ContainerProfile is not enough, the workloads must be restarted.

Names are `<user-defined-profile label>-<containerName>`, which is how node-agent
resolves them; ReplicaSet-hash names never bind.

## Recording

`record.cjs` screencasts the UI at half-screen width, `make-gif.sh` reduces a
recording to only its settled frames, `compose-split.sh` stacks two panels.

Two things cost real time when recording headless Chrome:
- it throttles rendering when backgrounded, so a screencast records one frozen
  frame — `record.cjs` disables the throttling and waits for the canvas to settle;
- the graph is drawn on `<canvas>`, so there is no DOM node to await and a fixed
  sleep races the paint, producing blank frames.

## Notes from the field

- The reverse shell is a **single serial pipe** with a 150s per-command budget
  that `executionTimeoutSeconds` does not override. One long command wedges every
  later one. An unbounded `nmap -sT` over a /24 blocks the session for 10+ minutes.
- Scan range matters: measured in-pod with the exact command form, `/27` = 3s,
  `/26` = 142s, `/25` = 91s, `/24` = 176s. It is not monotonic — mostly-empty
  ranges pay discovery retries. The scan derives the smallest range covering both
  the foothold and the target, never coarser than `/25`.
- A pod fronted by two Services gets whichever name reverse-DNS returns, so match
  entities on namespace + substring, never an exact service name.
- CVE-2026-47701 needs its prerequisites or there is nothing to leak: the OTel
  sidecar injected into `agent-orchestrator`, its ConfigMap, and the ServiceMonitor.
  `run-iktlinz-e2e.sh` applies them and warns if the sidecar is missing.

## Credits

Scenario, `ran` emulator, Oopserability and the agent platform by
[@Magier](https://github.com/Magier).

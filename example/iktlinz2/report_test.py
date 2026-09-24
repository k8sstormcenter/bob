import json, types, importlib.util, sys, io, os

spec_ = importlib.util.spec_from_file_location("report", "report.py")
R = importlib.util.module_from_spec(spec_); sys.modules["report"]=R; spec_.loader.exec_module(R)

class FakeCH:
    """Answers count()/byteSize queries by SQL substring, records every query."""
    db="forensic_db"
    def __init__(self, answers): self.answers=answers; self.seen=[]
    def rows(self, sql):
        self.seen.append(sql)
        if "system.columns" in sql:
            return [{"name":"pod"},{"name":"comm"},{"name":"event_time"}]
        for sub,(n,b) in self.answers.items():
            if sub in sql:
                return [{"n":n,"b":b}]
        return [{"n":0,"b":0}]

import tempfile
def _specfile(spec):
    fd,path=tempfile.mkstemp(suffix=".json"); os.close(fd)
    io.open(path,"w").write(json.dumps(spec)); return path
def run(spec, answers):
    a=types.SimpleNamespace(spec=_specfile(spec), chain="1", lo=1, hi=2, samples=1)
    out=io.StringIO(); old=sys.stdout; sys.stdout=out
    ch=FakeCH(answers)
    try: R.cmd_retention(a, ch)
    finally: sys.stdout=old
    return out.getvalue(), ch

# A node_scope probe whose row exists only node-wide must read as RETAINED,
# and its query must NOT carry a pod predicate — matching the scorer.
def test_node_scope_probe_is_retained_not_misattributed():
    spec={"suite":"t","suspicions":[{"name":"privileged-pod","rule":"R1017",
        "pod":"agent-system/ran-privileged%","parts":{"E":[
        {"table":"dx_process_forest","predicate":"comm IN ('nsenter')",
         "node_scope":True,"source":"forest"}]}}]}
    # node-scoped forest query has no "pod " predicate (where(t,"",..) -> "... AND 1")
    txt,ch=run(spec, {"dx_process_forest FINAL WHERE start_ns":(1,457)})
    forest_q=[q for q in ch.seen if "dx_process_forest" in q and "count()" in q and "system.columns" not in q][0]
    assert "pod =" not in forest_q and "pod LIKE" not in forest_q, forest_q
    assert "retained" in txt and "misattributed" not in txt, txt

# A NON-node-scope probe empty on its pod but present cluster-wide is still
# flagged misattributed — the wrong-owner signal is preserved for the case it
# was built for.
def test_pod_scope_probe_still_flags_misattributed():
    spec={"suite":"t","suspicions":[{"name":"x","rule":"R0001",
        "pod":"ns/app%","parts":{"E":[
        {"table":"dc_snoop","predicate":"comm='id'","source":"dcsnoop"}]}}]}
    # pod-scoped query returns 0; cluster-wide (pod-less) returns 3
    def answers_ch():
        class C(FakeCH):
            def rows(self,sql):
                self.seen.append(sql)
                if "system.columns" in sql: return [{"name":"pod"},{"name":"comm"},{"name":"event_time"}]
                # pod-scoped queries (primary and pod surface) are empty
                if "pod LIKE" in sql: return [{"n":0,"b":0}]
                # cluster-wide query with the predicate finds the wrong-owner rows
                if "AND (comm='id')" in sql: return [{"n":3,"b":0}]
                return [{"n":0,"b":0}]
        return C({})
    a=types.SimpleNamespace(spec=_specfile(spec),chain="1",lo=1,hi=2,samples=1)
    out=io.StringIO(); old=sys.stdout; sys.stdout=out; ch=answers_ch()
    try: R.cmd_retention(a,ch)
    finally: sys.stdout=old
    assert "misattributed" in out.getvalue(), out.getvalue()

# --- driver quoting regression (demo_chain2.worker_sh) -----------------------
# Pins the ONLY form verified against ClickHouse rows. It broke twice: once by
# dropping the " escaping (postgres SQL's -c "..." exposed a bare paren), once
# by using a double-quote wrapper (\$( collapsed to a bare (). Tests the real
# path by capturing what worker_sh hands worker_exec — no refactor.
def _load_driver():
    spec=importlib.util.spec_from_file_location("demo_chain2","demo_chain2.py")
    m=importlib.util.module_from_spec(spec); sys.modules["demo_chain2"]=m
    spec.loader.exec_module(m); return m

def test_worker_sh_quoting_is_the_verified_form():
    d=_load_driver()
    captured={}
    d.worker_exec=lambda cmd,args,note,expect_fail=False: captured.update(cmd=cmd,args=args) or True
    # the two scripts that each broke a different way
    d.worker_sh("for i in $(seq 1 62); do dig -x 10.42.2.$i; done","sweep")
    sweep=captured["args"]
    d.worker_sh("psql -c \"COPY rce FROM PROGRAM 'id'\"","rce")
    pg=captured["args"]
    # single-quote wrapper, $ escaped, no double-quote wrapper
    assert sweep.startswith("-c '") and sweep.endswith("'"), sweep
    assert "\\$(seq" in sweep and "\\$i" in sweep, sweep
    # embedded single quote closed-and-reopened; embedded double quote escaped
    assert "'\\''id'\\''" in pg, pg
    assert '\\"COPY' in pg, pg

# step_10 crashed with NameError: 'fwd' after the reverse-half was moved to the
# TTP and the forward assignment was deleted but its use left behind. Pin that
# both sweeps are issued: the TTP (reverse, ingests the graph) AND the forward
# pod-DNS loop (gives dns_events its pod.cluster.local rows).
def test_step_10_runs_both_sweeps_without_nameerror():
    d=_load_driver()
    calls=[]
    d.execute=lambda *a,**k: calls.append(("execute",a,k)) or True
    d.worker_sh=lambda script,note,expect_fail=False: calls.append(("worker_sh",script)) or True
    d.assert_foothold=lambda: True
    d.exec_system=lambda: "c2/ran"
    d.pod_id=lambda ns,p: f"ns/{ns}/pod/{p}"
    d.step_10_dns_sweep({"scan_cidr":"10.42.2.0/24"})   # must not raise NameError
    ttl=[c for c in calls if c[0]=="execute" and c[1][0]=="reverse-dns-scan"]
    fwd=[c for c in calls if c[0]=="worker_sh" and "pod.cluster.local" in c[1]]
    assert ttl, "reverse-dns-scan TTP must be invoked (graph ingestion)"
    assert fwd, "forward pod-DNS loop must run (dns_events rows)"


# ${VAR} in a predicate must be substituted from DX_PROOF_VAR_* like the scorer;
# an unsubstituted one must NOT be sent to ClickHouse (it 400s) but reported.
def test_unsubstituted_var_is_flagged_not_fired():
    import os
    os.environ.pop("DX_PROOF_VAR_SCAN_CIDR", None)
    spec={"suite":"t","suspicions":[{"name":"nmap-sweep","rule":"R1007","pod":"ns/w%",
        "parts":{"C":[{"table":"conn_stats","source":"conn",
        "predicate":"isIPAddressInRange(remote_addr, '${SCAN_CIDR}')"}]}}]}
    txt,ch=run(spec, {})
    assert "unsubstituted var SCAN_CIDR" in txt, txt
    # no count query for that probe was ever built
    assert not any("isIPAddressInRange" in q for q in ch.seen), ch.seen

def test_var_is_substituted_when_env_set():
    import os
    os.environ["DX_PROOF_VAR_SCAN_CIDR"]="10.42.2.0/24"
    try:
        spec={"suite":"t","suspicions":[{"name":"nmap-sweep","rule":"R1007","pod":"ns/w%",
            "parts":{"C":[{"table":"conn_stats","source":"conn",
            "predicate":"isIPAddressInRange(remote_addr, '${SCAN_CIDR}')"}]}}]}
        txt,ch=run(spec, {"conn_stats FINAL WHERE":(0,0)})
        q=[x for x in ch.seen if "isIPAddressInRange" in x]
        assert q and "10.42.2.0/24" in q[0] and "${" not in q[0], q
    finally:
        os.environ.pop("DX_PROOF_VAR_SCAN_CIDR", None)



# A source-side TTP (the extractor) must run FROM system/<pod>, not c2/ran
# (C2-kind → 422). The generic executor (worker_exec) keeps c2/ran. The two
# routes are distinct and must not collapse.
def test_step_17_runs_source_side_from_the_pod_system():
    d=_load_driver()
    d.callback_pod=lambda field="metadata.name": "agent-worker-xyz"
    d.pg_pod_id=lambda: "ns/oopservability/pod/oopservability-postgres-1"
    seen={}
    def fake_execute(action,target,args=None,note="",exec_sys=None,**k):
        seen.update(action=action,target=target,exec_sys=exec_sys); return True
    d.execute=fake_execute
    d.step_17_extract_token({})
    assert seen["exec_sys"]=="system/agent-worker-xyz", seen
    assert seen["action"]=="extract-serviceaccount-token-via-cve-2026-47702", seen
    # and the generic executor still routes via the C2 node
    assert d.foothold_system() != d.C2_NODE



# step 20 must be bounded: nsenter + the single k3s.yaml read, NO whole-fs grep.
# The search-interesting-files over the k3s data dir DoS'd node-agent and erased
# three minutes of evidence node-wide (B1c7).
def test_step_20_is_bounded_no_fs_grep():
    d=_load_driver()
    calls=[]
    d.execute=lambda action,target,args=None,note="",**k: calls.append((action,args)) or True
    d.step_20_escape_and_loot({})
    actions=[a for a,_ in calls]
    assert "search-interesting-files" not in actions, actions
    assert "escape-container-via-nsenter" in actions and "read-sensitive-file" in actions, actions



# A node_scope probe that grounds ONLY node-wide (pod-scoped 0) must read as
# "node-only", not "retained". privileged-pod's 6 rows in B1c8 were once-a-minute
# node-wide runc:[1:CHILD] churn with pod=''; the node-scope fix had hidden that
# as a green. This is the tooling gap that shipped a false green in artifact v3.
def test_node_only_ground_is_not_reported_retained():
    spec={"suite":"t","suspicions":[{"name":"privileged-pod","rule":"R1017",
        "pod":"agent-system/ran-privileged%","parts":{"E":[
        {"table":"dx_process_forest","predicate":"comm IN ('runc:[1:CHILD]')",
         "node_scope":True,"source":"forest"}]}}]}
    class C(FakeCH):
        def rows(self,sql):
            self.seen.append(sql)
            if "system.columns" in sql: return [{"name":"pod"},{"name":"comm"},{"name":"start_ns"}]
            # node-wide (no pod predicate) finds 6; pod-scoped finds 0
            if "pod LIKE" in sql: return [{"n":0,"b":0}]
            if "count()" in sql: return [{"n":6,"b":2400}]
            return [{"n":0,"b":0}]
    import types
    a=types.SimpleNamespace(spec=_specfile(spec),chain="1",lo=1,hi=2,samples=1)
    out=io.StringIO(); old=sys.stdout; sys.stdout=out
    try: R.cmd_retention(a, C({}))
    finally: sys.stdout=old
    t=out.getvalue()
    assert "node-only" in t, t
    assert "retained | 6" not in t, "a node-only ground must not read as retained: "+t

if __name__=="__main__":
    import types as _t
    fns=[v for k,v in sorted(globals().items())
         if k.startswith("test_") and isinstance(v,_t.FunctionType)]
    for fn in fns:
        fn(); print("ok", fn.__name__)
    print(f"PASS all ({len(fns)})")

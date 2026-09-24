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

if __name__=="__main__":
    test_node_scope_probe_is_retained_not_misattributed()
    test_pod_scope_probe_still_flags_misattributed()
    test_worker_sh_quoting_is_the_verified_form()
    print("PASS all")

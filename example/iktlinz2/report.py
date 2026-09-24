#!/usr/bin/env python3
"""report.py — everything a test run has to produce, in one file.

Two reports, one ClickHouse client, one window:

  receipts   the evidence ROW behind each of the twenty steps, and what those
             rows cost to retain — the bytes of exactly the rows the probe
             matched, not of the whole surface. A surface can carry thousands of
             rows for unrelated reasons; charging those to one obligation would
             make cheap evidence look expensive. A coverage
             number says a suspicion grounded; it does not say WHICH row
             grounded it, and a predicate can match the right count for the
             wrong reason. The queries are generated from the shipped spec
             rather than restated here, so a receipt cannot drift from what was
             scored: same table, predicate, pod scope and window as the KPI.

  Counts use FINAL on tables that collapse rows on merge, so the same query
  over the same window gives the same answer whenever it is run. Without it a
  count is of row VERSIONS pending merge and shrinks as merges catch up.

  volume     what the run STORED: rows and the summed byteSize of every
             column, per table. Rows alone understate the difference between
             configurations — a dc_snoop row and a pgsql_events row carrying a whole SQL
             statement are not the same object.

  DX_CH=http://user:pass@host:8123/forensic_db ./report.py receipts \
      --chain 1 --spec runs/A0i2/obligations.json --from <ns> --to <ns>

  DX_CH=... ./report.py volume --config adaptive_base --label A0i2 --from <ns> --to <ns>

Use the KPI's window for both, or the tables cannot be read against each other.
Secret VALUES are redacted; key names, row shape and lengths stay intact.
"""
import argparse, base64, io, json, os, re, sys, urllib.parse, urllib.request

# step -> the suspicions it is expected to produce, per chain. Five steps carry
# none in BOTH chains, by design: one listener, three token-permission checks
# against the apiserver, and the CVE arming. Keeping the two maps side by side
# is deliberate — the chains are meant to differ only where the protocol does,
# and a divergence anywhere else should be visible here.
_VARRE = re.compile(r"\$\{(\w+)\}")

def subst(pred):
    """Mirror the scorer: ${NAME} <- DX_PROOF_VAR_<NAME> from the environment.
    An unsubstituted ${...} sent to ClickHouse is a literal it rejects with 400,
    which read as a probe ERR when the real cause was a var the extraction never
    set (e.g. SCAN_CIDR)."""
    return _VARRE.sub(lambda m: os.environ.get("DX_PROOF_VAR_"+m.group(1), m.group(0)), pred or "1")

def unresolved(pred):
    return _VARRE.findall(pred or "")


CHAINS = {
    "1": [
        ("create listener (1337)",                 []),
        ("spawn callback worker pod",              ["worker-callback"]),
        ("await socat callback",                   ["worker-callback"]),
        ("read environment variables",             ["discovery-env-read"]),
        ("read worker SA token",                   ["sa-token-read-worker"]),
        ("install kubectl",                        ["tool-install-kubectl"]),
        ("check worker token perms",               []),
        ("install nmap",                           ["tool-install-nmap"]),
        ("get local IP",                           ["discovery-hostIP"]),
        ("nmap host scan",                         ["nmap-sweep"]),
        ("redis RCE (expected fail)",              ["redis-cli-not-found"]),
        ("install redis-tools",                    ["tool-install-redis-cli"]),
        ("redis RCE",                              ["rce-redis"]),
        ("read redis SA token",                    ["sa-token-read-redis"]),
        ("check redis token perms",                []),
        ("create ServiceMonitor (CVE-2026-47701)", []),
        ("extract token via CVE",                  ["cve-2026-47701-extract", "key-material-on-wire"]),
        ("check captured token perms",             []),
        ("deploy privileged container",            ["privileged-pod"]),
        ("escape to host + loot",                  ["host-escape", "k3s-credential-read"]),
    ],
    "2": [
        ("create listener (1337)",                 []),
        ("spawn callback worker pod",              ["worker-callback"]),
        ("await socat callback",                   ["worker-callback"]),
        ("read environment variables",             ["discovery-env-read"]),
        ("read worker SA token",                   ["sa-token-read-worker"]),
        ("install kubectl",                        ["tool-install-kubectl"]),
        ("check worker token perms",               []),
        ("install dnsutils (dig)",                 ["tool-install-dig"]),
        ("get local IP",                           ["discovery-hostIP"]),
        ("DNS sweep of the pod range",             ["dns-sweep"]),
        ("postgres RCE (expected fail)",           ["psql-not-found"]),
        ("install postgresql-client",              ["tool-install-psql"]),
        ("postgres RCE (COPY FROM PROGRAM)",       ["rce-postgres"]),
        ("read postgres SA token",                 ["sa-token-read-postgres"]),
        ("check postgres token perms",             []),
        ("create ServiceMonitor (CVE-2026-47702)", []),
        ("extract token via CVE",                  ["cve-2026-47702-extract", "key-material-on-wire"]),
        ("check captured token perms",             []),
        ("deploy privileged container",            ["privileged-pod"]),
        ("escape to host + loot",                  ["host-escape", "k3s-credential-read"]),
    ],
}

# Same shapes dx scores on (internal/kpi/keymaterial.go). A receipt must show
# that a secret crossed the wire without reproducing it.
SECRET = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    r"|-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[0-9A-Za-z_-]{20}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|[A-Za-z0-9+/]{40,}={0,2}", re.S)


def redact(v):
    s = str(v)
    return SECRET.sub(lambda m: f"[redacted {len(m.group(0))}B]", s)


def td(v, width=160):
    s = redact(v).replace("|", "\\|").replace("\n", " ⏎ ").strip()
    return (s[:width] + "…") if len(s) > width else (s or "∅")


# The evidence surfaces a chain can touch, plus dx's own tables. Listed rather
# than discovered so both configurations always measure the same set: a table that is
# empty in one configuration must still appear, or the comparison silently
# changes shape.
# dx's own bookkeeping, not evidence. Under the static policy OnReferral
# returns immediately (internal/daemon/daemon.go:720), so no order rows exist
# at all — by design, not by accident. Totalling these together with the
# captured surfaces compares a policy that keeps referral state against one
# that structurally cannot, so they are reported separately.
BOOKKEEPING = {"dx_order_edges", "dx_order_records", "dx_shadow_trace"}

TABLES = [
    "conn_stats", "dns_events", "http_events", "redis_events", "pgsql_events",
    "mysql_events", "amqp_events", "mux_events", "tls_events", "cql_events",
    "mongodb_events", "dc_snoop", "stack_trace", "creds_change", "dx_nsswitch",
    "dx_process_forest", "dx_order_edges", "dx_order_records", "dx_shadow_trace",
]
# Which column bounds the window is per-table, and so is HOW to compare it.
# The forest keys on start_ns; dx_order_records only has time_; dx_shadow_trace
# has neither (t0/closed_at). And the same NAME is not the same TYPE: event_time
# is DateTime64 on the evidence tables but UInt64 on dx_order_edges and
# dx_order_records, so comparing it against toDateTime64 is a type error and the
# server answers 500. Both the column and the comparison are therefore read from
# system.columns rather than assumed from the name.
TIME_COLS = ["event_time", "time_", "start_ns", "t0"]


def final(ch, table):
    """` FINAL` when the table collapses rows on merge, else empty.

    Most evidence tables are ReplacingMergeTree: dx rewrites a row whenever it
    learns more about it and the newest version wins, but only once a background
    merge has run. Counting without FINAL therefore counts row VERSIONS pending
    merge, not rows — the same query over the same window returns fewer as time
    passes. Two figures taken minutes apart disagree, and neither is wrong.

    Found because a part's count fell from 2 rows to 1 between two runs of the
    same report over an identical window.
    """
    if table not in _engines:
        try:
            r = ch.rows(f"SELECT engine FROM system.tables WHERE database = '{ch.db}' "
                        f"AND name = '{table}'")
            _engines[table] = r[0]["engine"] if r else ""
        except Exception:
            _engines[table] = ""
    return " FINAL" if "Replacing" in _engines[table] else ""


_engines = {}


class CH:
    def __init__(self, dsn):
        u = urllib.parse.urlparse(dsn)
        self.base = f"{u.scheme}://{u.hostname}:{u.port or 8123}"
        self.db = (u.path or "/forensic_db").strip("/") or "forensic_db"
        self.auth = (u.username, u.password) if u.username else None

    def rows(self, sql):
        q = urllib.parse.urlencode({"query": sql + " FORMAT JSONEachRow", "database": self.db})
        req = urllib.request.Request(self.base + "/?" + q)
        if self.auth:
            import base64
            tok = base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode()
            req.add_header("Authorization", "Basic " + tok)
        with urllib.request.urlopen(req, timeout=120) as r:
            body = r.read().decode()
        return [json.loads(l) for l in body.splitlines() if l.strip()]


def where(table, pod, lo, hi):
    """The same scope the KPI applies: forest keys on start_ns, everything else
    on event_time, and the pod pattern is a LIKE when it carries a wildcard."""
    op = "LIKE" if "%" in pod else "="
    scope = f"pod {op} '{pod}'" if pod else "1"
    if table == "dx_process_forest":
        return f"start_ns >= {lo} AND start_ns <= {hi} AND {scope}"
    return f"event_time >= toDateTime64({lo}/1e9, 9) AND event_time <= toDateTime64({hi}/1e9, 9) AND {scope}"


def human(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def cmd_receipts(a, ch):
    spec = json.load(open(a.spec))
    steps = CHAINS[a.chain]
    by_name = {s["name"]: s for s in spec["suspicions"]}

    out = [
        f"Chain {a.chain}, suite `{spec.get('suite')}`, window `{a.lo}`–`{a.hi}`.",
        "",
        "| # | step | suspicion | part | table | rows | cost | evidence row |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for i, (step, names) in enumerate(steps, 1):
        if not names:
            out.append(f"| {i} | {step} | — | — | — | — | — | *no obligation, by design* |")
            continue
        for name in names:
            s = by_name.get(name)
            if s is None:
                out.append(f"| {i} | {step} | `{name}` | — | — | — | — | **not in spec** |")
                continue
            for part in sorted(s["parts"]):
                for p in s["parts"][part]:
                    t, pred = p["table"], subst(p.get("predicate", "1"))
                    if unresolved(pred):
                        out.append(f"| {i} | {step} | `{name}` | {part} | `{t}` | var | | "
                                   f"unsubstituted {','.join(unresolved(pred))} |")
                        continue
                    w = f"{where(t, s.get('pod', ''), a.lo, a.hi)} AND ({pred})"
                    try:
                        cols = [c["name"] for c in ch.rows(
                            f"SELECT name FROM system.columns WHERE database = '{ch.db}' "
                            f"AND table = '{t}'")]
                        size = "byteSize(" + ", ".join(f"`{c}`" for c in cols) + ")"
                        agg = ch.rows(f"SELECT count() AS n, sum({size}) AS b "
                                      f"FROM {t}{final(ch, t)} WHERE {w}")[0]
                        n, b = agg["n"], int(agg["b"] or 0)
                        rows = ch.rows(f"SELECT * FROM {t}{final(ch, t)} WHERE {w} "
                                       f"LIMIT {a.samples}") if int(n) else []
                    except Exception as e:                      # a probe that cannot run is a receipt too
                        out.append(f"| {i} | {step} | `{name}` | {part} | `{t}` | ERR | | {td(e)} |")
                        continue
                    ev = "; ".join(f"`{k}`={td(v, 90)}" for k, v in rows[0].items()
                                   if v not in ("", None, 0, "0")) if rows else "**no row matched**"
                    out.append(f"| {i} | {step} | `{name}` | {part} | `{t}` | {n} | "
                               f"{human(b) if int(n) else '—'} | {ev} |")
    print("\n".join(out))


def measure(ch, lo, hi):
    """Rows and summed byteSize per table over one window, with the attributed
    split. Returned rather than printed, so one run and a comparison of two are
    the same measurement and cannot drift apart."""
    out = []
    for t in TABLES:
        row = {"table": t, "on": "", "type": "", "n": 0, "b": 0,
               "an": 0, "ab": 0, "sid": False, "note": ""}
        try:
            schema = {r["name"]: r["type"] for r in ch.rows(
                f"SELECT name, type FROM system.columns WHERE database = '{ch.db}' AND table = '{t}'")}
            if not schema:
                row["note"] = "absent"
                out.append(row)
                continue
            tcol = next((c for c in TIME_COLS if c in schema), None)
            if tcol is None:
                row["note"] = "not windowable"
                out.append(row)
                continue
            row["on"], row["type"] = tcol, schema[tcol]
            # A numeric column holds nanos and is compared as such; a temporal
            # one needs the nanos turned into a DateTime64 first. The same NAME
            # is not the same TYPE: event_time is DateTime64 on the evidence
            # tables and UInt64 on the order tables.
            numeric = any(k in schema[tcol] for k in ("Int", "Float"))
            win = (f"`{tcol}` >= {lo} AND `{tcol}` <= {hi}" if numeric else
                   f"`{tcol}` >= toDateTime64({lo}/1e9, 9) AND `{tcol}` <= toDateTime64({hi}/1e9, 9)")
            size = "byteSize(" + ", ".join(f"`{c}`" for c in schema) + ")"
            # A table without shadow_id cannot report attribution at all. Its
            # rows are NOT unattributed: dx never had the chance to stamp them.
            row["sid"] = "shadow_id" in schema
            sid = "shadow_id != ''" if row["sid"] else "0"
            r = ch.rows(f"SELECT count() AS n, sum({size}) AS b, "
                        f"countIf({sid}) AS an, sumIf({size}, {sid}) AS ab "
                        f"FROM `{t}`{final(ch, t)} WHERE {win}")[0]
            row["n"], row["b"] = int(r["n"] or 0), int(r["b"] or 0)
            row["an"], row["ab"] = int(r["an"] or 0), int(r["ab"] or 0)
        except Exception as e:
            row["note"] = "ERR " + str(e)[:60]
        out.append(row)
    return out


def totals(rows, only=None):
    t = {"rows": 0, "bytes": 0, "arows": 0, "abytes": 0, "urows": 0}
    for r in rows:
        if only == "evidence" and r["table"] in BOOKKEEPING:
            continue
        if only == "bookkeeping" and r["table"] not in BOOKKEEPING:
            continue
        t["rows"] += r["n"]
        t["bytes"] += r["b"]
        if r["sid"]:
            t["arows"] += r["an"]
            t["abytes"] += r["ab"]
            t["urows"] += r["n"] - r["an"]
    return t


def cmd_volume(a, ch):
    rows = measure(ch, a.lo, a.hi)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"config": a.config, "label": a.label, "lo": a.lo,
                       "hi": a.hi, "rows": rows}, fh, indent=1)
        print(f"measurement written to {a.json}", file=sys.stderr)
    out = [f"Config `{a.config}`{(' · run `' + a.label + '`') if a.label else ''}, "
           f"window `{a.lo}`–`{a.hi}`.", "",
           "| table | window on | rows | bytes | attributed rows | attributed bytes | unattributed rows |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        if r["note"]:
            out.append(f"| `{r['table']}` | | *{r['note']}* | | | | |")
        elif not r["n"]:
            out.append(f"| `{r['table']}` | `{r['on']}` ({r['type']}) | 0 | — | 0 | — | 0 |")
        else:
            attr = (f"{r['an']} | {human(r['ab'])} | {r['n'] - r['an']}"
                    if r["sid"] else "n/a | n/a | n/a")
            out.append(f"| `{r['table']}` | `{r['on']}` ({r['type']}) | {r['n']} | {human(r['b'])} | {attr} |")
    t = totals(rows)
    out.append(f"| **total** | | **{t['rows']}** | **{human(t['bytes'])}** | "
               f"**{t['arows']}** | **{human(t['abytes'])}** | **{t['urows']}** |")
    print("\n".join(out))


def perrow(r):
    """Bytes per row — what one row of this evidence costs to retain.

    The question is not whether a policy stores less. Retention comes first:
    everything the obligations name has to be kept. What varies is the price,
    and the price is per row of a given kind, not per policy.
    """
    n, b = r.get("n", r.get("rows", 0)), r.get("b", r.get("bytes", 0))
    return f"{b // n} B" if n else "—"


def pct(a, b):
    """b relative to a, as a signed percentage. Reported alongside the absolute
    numbers, never instead of them: a percentage of a small count reads as a
    large effect."""
    if not a:
        return "—" if not b else "new"
    return f"{(b - a) / a * 100:+.0f}%"


def load(path):
    """A saved measurement. JSON as written by `volume --json`; a markdown table
    as printed by `volume` is also accepted, because the first runs were
    captured before --json existed."""
    text = io.open(path).read()
    if text.lstrip().startswith("{"):
        return json.loads(text)
    rows, meta = [], {"config": "?", "label": os.path.basename(path), "lo": "", "hi": ""}
    # "Arm ... cell ..." is the older wording; tables printed before the rename
    # must still parse, or a comparison silently loses its labels.
    m = re.search(r"(?:Config|Arm) `([^`]+)`(?: · (?:run|cell) `([^`]+)`)?, "
                  r"window `(\d+)`[–-]`(\d+)`", text)
    if m:
        meta = {"config": m.group(1), "label": m.group(2) or "", "lo": m.group(3), "hi": m.group(4)}
    for line in text.splitlines():
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) != 7 or not c[0].startswith("`") or c[0].startswith("**"):
            continue
        name = c[0].strip("`")
        if c[2].startswith("*") or c[2] == "ERR":
            rows.append({"table": name, "note": c[2].strip("*"), "n": 0, "b": 0,
                         "an": 0, "ab": 0, "sid": False, "on": "", "type": ""})
            continue
        num = lambda v: int(v) if v.isdigit() else 0
        on, ty = (c[1].split(" ", 1) + [""])[:2] if c[1] else ("", "")
        rows.append({"table": name, "on": on.strip("`"), "type": unwrap(ty),
                     "n": num(c[2]), "b": unhuman(c[3]), "sid": c[4] != "n/a",
                     "an": num(c[4]), "ab": unhuman(c[5]), "note": ""})
    meta["rows"] = rows
    return meta


def unwrap(v):
    """Strip ONE enclosing paren pair. rstrip(")") ate the closing paren of
    DateTime64(9, 'UTC') and left it unbalanced."""
    v = v.strip()
    return v[1:-1] if v.startswith("(") and v.endswith(")") else v


def unhuman(v):
    """Undo human(). A parsed size is rounded to the printed precision, so the
    byte columns of a stitched comparison are approximate and say so."""
    v = v.strip()
    m = re.match(r"([\d.]+)\s*(B|KiB|MiB|GiB)$", v)
    if not m:
        return 0
    return int(float(m.group(1)) * {"B": 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}[m.group(2)])


def pct(a, b):
    """b relative to a, as a signed percentage. Reported alongside the absolute
    numbers, never instead of them: a percentage of a small count reads as a
    large effect."""
    if not a:
        return "—" if not b else "new"
    return f"{(b - a) / a * 100:+.0f}%"


def cmd_compare(a, _ch):
    """Both runs in ONE table, from two SAVED measurements.

    Not from the database: the harness wipes at the start of every run, so two
    runs are never present at once. That is deliberate — it is what keeps a
    run's numbers attributable to that run alone — and it means the comparison
    has to be assembled from what each run captured before the next wipe.
    """
    A, B = load(a.a), load(a.b)
    ra = {r["table"]: r for r in A["rows"]}
    rb = {r["table"]: r for r in B["rows"]}
    ca, cb = A.get("config") or "A", B.get("config") or "B"
    approx = a.a.endswith(".md") or a.b.endswith(".md")
    out = [f"`{ca}` (`{A.get('label')}`, window `{A.get('lo')}`–`{A.get('hi')}`) versus "
           f"`{cb}` (`{B.get('label')}`, window `{B.get('lo')}`–`{B.get('hi')}`).", "",
           f"| table | {ca} rows | {ca} bytes | {ca} B/row | {cb} rows | {cb} bytes | {cb} B/row |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for t in TABLES:
        x, y = ra.get(t), rb.get(t)
        if not x or not y or x.get("note") or y.get("note"):
            note = (x or {}).get("note") or (y or {}).get("note") or "missing"
            out.append(f"| `{t}` | *{note}* | | | | | |")
            continue
        if not x["n"] and not y["n"]:
            continue  # a surface neither run touched says nothing
        out.append(f"| `{t}` | {x['n']} | {human(x['b'])} | {perrow(x)} | "
                   f"{y['n']} | {human(y['b'])} | {perrow(y)} |")
    ea, eb = totals(A["rows"], "evidence"), totals(B["rows"], "evidence")
    ka, kb = totals(A["rows"], "bookkeeping"), totals(B["rows"], "bookkeeping")
    out.append(f"| **evidence** | **{ea['rows']}** | **{human(ea['bytes'])}** | "
               f"**{perrow(ea)}** | **{eb['rows']}** | **{human(eb['bytes'])}** | **{perrow(eb)}** |")
    out.append(f"| **dx bookkeeping** | {ka['rows']} | {human(ka['bytes'])} | {perrow(ka)} | "
               f"{kb['rows']} | {human(kb['bytes'])} | {perrow(kb)} |")
    out += ["", "Retention comes first: everything the obligations name has to be kept. These "
                "figures are what that costs, per kind of evidence — not a target to reduce.", "",
                "**evidence** is what an obligation can name. **dx bookkeeping** is the order "
                "and trace state dx keeps for itself: under `static` the referral path returns "
                "immediately, so those tables are empty by design, and adding them to one total "
                "would compare a policy that keeps referral state against one that structurally "
                "cannot.", "",
            f"| | {ca} | {cb} |", "| --- | --- | --- |",
            f"| attributed rows | {ea['arows']} | {eb['arows']} |",
            f"| attributed bytes | {human(ea['abytes'])} | {human(eb['abytes'])} |",
            f"| unattributed rows | {ea['urows']} | {eb['urows']} |", "",
            "Attribution figures cover evidence only. Unattributed rows carry no `shadow_id`: "
            "the standing collector wrote them with no owner. Tables with no `shadow_id` column "
            "at all are excluded from the split rather than counted as unattributed."]
    if approx:
        out += ["", "Byte figures are recovered from a printed table and are therefore "
                    "rounded to its precision; row counts are exact."]
    print("\n".join(out))


def cmd_retention(a, ch):
    """Is retention perfect; if not, what is missing and why; and what does each
    piece of evidence cost.

    A coverage score answers none of those. It collapses "the surface kept
    nothing" and "the attack never did it" into the same zero, and it says
    nothing about price. Retention comes first: every part an obligation names
    has to be there. Where one is not, the reason decides who fixes it —

      not deployed    the table does not exist on this install
      not retained    the surface is empty in the window; capture kept nothing.
                      This is the only one that is a RETENTION gap
      not produced    the surface has rows, the predicate matched none. Either
                      the attack did not do it or the predicate is wrong; the
                      receipts distinguish those by showing what the surface did
                      hold
      retained        rows matched, with what they cost to keep

    Cost is the bytes of exactly the rows the probe matched, never the whole
    surface. A surface carrying thousands of rows for unrelated reasons would
    otherwise make cheap evidence look expensive.
    """
    spec = json.load(open(a.spec))
    steps = CHAINS[a.chain]
    named = {n: i for i, (_, ns) in enumerate(steps, 1) for n in ns}
    findings, surface_rows = [], {}

    for s in spec["suspicions"]:
        for part in sorted(s["parts"]):
            for p in s["parts"][part]:
                t, pred = p["table"], subst(p.get("predicate", "1"))
                miss = unresolved(pred)
                if miss:
                    f = {"step": named.get(s["name"], 0), "name": s["name"], "part": part,
                         "table": t, "n": 0, "b": 0, "surface": 0, "elsewhere": 0,
                         "why": "unsubstituted var " + ",".join(miss), "pred": pred}
                    findings.append(f)
                    continue
                # Match the scorer: a node_scope probe queries the node, not the
                # pod, because the evidence lands off-pod (a hostPID escape is
                # host-attributed with pod=''). Pod-scoping it here reported a
                # false "misattributed" for obligations the KPI actually grounds.
                node_scoped = bool(p.get("node_scope"))
                scope = where(t, "" if node_scoped else s.get("pod", ""), a.lo, a.hi)
                f = {"step": named.get(s["name"], 0), "name": s["name"], "part": part,
                     "table": t, "n": 0, "b": 0, "surface": 0, "elsewhere": 0,
                     "why": "", "pred": pred}
                try:
                    cols = [c["name"] for c in ch.rows(
                        f"SELECT name FROM system.columns WHERE database = '{ch.db}' AND table = '{t}'")]
                    if not cols:
                        f["why"] = "not deployed"
                        findings.append(f)
                        continue
                    size = "byteSize(" + ", ".join(f"`{c}`" for c in cols) + ")"
                    r = ch.rows(f"SELECT count() AS n, sum({size}) AS b "
                                f"FROM {t}{final(ch, t)} WHERE {scope} AND ({pred})")[0]
                    f["n"], f["b"] = int(r["n"] or 0), int(r["b"] or 0)
                    if f["n"] and node_scoped:
                        # A node_scope probe grounded — but node-wide includes
                        # rows attributed to no pod (pod=''), which for some
                        # predicates is pure background churn (runc:[1:CHILD]
                        # fires once/min node-wide forever). If NOTHING matches
                        # under the pod itself, this is node-only: grounds only
                        # off-pod, the old "misattributed" case. It must not read
                        # as plain retained — that hid a false green once.
                        pod_only = where(t, s.get("pod", ""), a.lo, a.hi)
                        pn = int(ch.rows(f"SELECT count() AS n FROM {t}{final(ch, t)} "
                                         f"WHERE {pod_only} AND ({pred})")[0]["n"] or 0)
                        f["why"] = "retained" if pn else "node-only"
                        f["elsewhere"] = f["n"] - pn
                    elif f["n"]:
                        f["why"] = "retained"
                    else:
                        key = (t, node_scoped)
                        if key not in surface_rows:
                            surface_rows[key] = int(ch.rows(
                                f"SELECT count() AS n FROM {t}{final(ch, t)} "
                                f"WHERE {scope}")[0]["n"] or 0)
                        f["surface"] = surface_rows[key]
                        if node_scoped:
                            # already looked node-wide; a miss is genuine
                            f["why"] = "not produced" if f["surface"] else "not retained"
                        elif f["surface"]:
                            f["why"] = "not produced"
                        else:
                            # The surface is empty FOR THIS POD. Before calling
                            # that lost, ask whether the same predicate matches
                            # anywhere on the node: a hostPID or privileged
                            # workload has its processes attributed to the host
                            # with pod='' (entlein/dx#178), so the rows exist
                            # and a pod-scoped probe cannot see them. Captured
                            # under the wrong owner is a different defect from
                            # not captured, and has a different fix.
                            wide = where(t, "", a.lo, a.hi)
                            n2 = int(ch.rows(f"SELECT count() AS n FROM {t}{final(ch, t)} "
                                             f"WHERE {wide} AND ({pred})")[0]["n"] or 0)
                            f["elsewhere"] = n2
                            f["why"] = "misattributed" if n2 else "not retained"
                except Exception as e:
                    f["why"] = "ERR " + str(e)[:50]
                findings.append(f)

    gaps = [f for f in findings if f["why"] != "retained"]
    nodeonly = [f for f in gaps if f["why"] == "node-only"]
    lost = [f for f in gaps if f["why"] == "not retained"]
    misfiled = [f for f in gaps if f["why"] == "misattributed"]
    out = [f"Chain {a.chain}, suite `{spec.get('suite')}`, window `{a.lo}`–`{a.hi}`.", ""]
    other = len(gaps) - len(lost) - len(misfiled) - len(nodeonly)
    out.append(f"**Retention is {'PERFECT' if not lost else 'NOT perfect'}.** "
               f"{len(findings) - len(gaps)} of {len(findings)} obligation parts have their "
               f"evidence stored; {len(lost)} lost to capture"
               f"{f', {len(misfiled)} captured but attributed to the node rather than the pod' if misfiled else ''}"
               f"{f', {len(nodeonly)} ground only node-wide (off-pod, not the pod itself)' if nodeonly else ''}"
               f"{'' if not other else f', {other} matched nothing on a populated surface'}.")
    out += ["", "| # | suspicion | part | surface | verdict | rows | cost |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for f in sorted(findings, key=lambda x: (x["step"], x["name"], x["part"])):
        if f["why"] == "node-only":
            cost = f"{f['elsewhere']} node-wide, 0 pod-attributed"
        elif f["n"]:
            cost = human(f["b"])
        elif f["why"] == "not produced":
            cost = f"surface holds {f['surface']}"
        elif f["why"] == "misattributed":
            cost = f"{f['elsewhere']} rows on the node"
        else:
            cost = "—"
        out.append(f"| {f['step'] or '—'} | `{f['name']}` | {f['part']} | `{f['table']}` | "
                   f"{f['why']} | {f['n']} | {cost} |")

    if misfiled:
        out += ["", "### Captured, but not where the obligation looks", "",
                "The predicate matches rows on the NODE while the pod scope is empty. The "
                "evidence was kept; it is filed under the host rather than the workload, which "
                "a pod-scoped probe cannot see. A privileged or hostPID workload does this "
                "(entlein/dx#178). This is not a retention gap and must not be counted as one.", ""]
        for f in misfiled:
            out.append(f"- step {f['step']}, `{f['name']}` part {f['part']}: `{f['table']}` holds "
                       f"{f['elsewhere']} matching rows on the node, 0 under `{f['table']}`'s pod "
                       f"scope. Predicate `{f['pred']}`")
    if lost:
        out += ["", "### What is missing, and why", "",
                "These are the only true retention gaps — the surface kept nothing in the "
                "window, so no predicate over it could have matched:", ""]
        for f in lost:
            out.append(f"- step {f['step']}, `{f['name']}` part {f['part']}: `{f['table']}` is "
                       f"empty. Predicate `{f['pred']}`")
    if any(f["why"] == "not produced" for f in gaps):
        out += ["", "The rest had a populated surface and matched nothing on it. That is not a "
                    "retention gap: either the step did not produce the evidence, or the "
                    "predicate does not describe it. The receipts show what the surface did "
                    "hold, which separates the two."]

    kept = [f for f in findings if f["n"] and f["why"] == "retained"]
    if kept:
        out += ["", "### What each piece of evidence costs", "",
                "Bytes of exactly the rows the probe matched. This is the number to choose on: "
                "the cheapest surface that retains a given obligation is the one to keep.", "",
                "| suspicion | part | surface | rows | cost | B/row |",
                "| --- | --- | --- | --- | --- | --- |"]
        for f in sorted(kept, key=lambda x: -x["b"]):
            out.append(f"| `{f['name']}` | {f['part']} | `{f['table']}` | {f['n']} | "
                       f"{human(f['b'])} | {f['b'] // f['n']} B |")
        out += ["", f"Total cost of the retained evidence: **{human(sum(f['b'] for f in kept))}** "
                    f"across {sum(f['n'] for f in kept)} rows."]
    print("\n".join(out))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="what", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--from", dest="lo", type=int, required=True, help="window start, unix nanos")
    common.add_argument("--to", dest="hi", type=int, required=True, help="window end, unix nanos")

    r = sub.add_parser("receipts", parents=[common])
    r.add_argument("--spec", required=True, help="the spec AS STAGED for the run, not the repo copy")
    r.add_argument("--chain", choices=sorted(CHAINS), default="2")
    r.add_argument("--samples", type=int, default=1)

    rt = sub.add_parser("retention", parents=[common],
                        help="is retention perfect, what is missing and why, what each piece costs")
    rt.add_argument("--spec", required=True, help="the spec AS STAGED for the run")
    rt.add_argument("--chain", choices=sorted(CHAINS), default="2")

    v = sub.add_parser("volume", parents=[common])
    v.add_argument("--config", required=True, help="the capture policy this run used")
    v.add_argument("--label", default="")
    v.add_argument("--json", default="", help="also save the measurement here, so it "
                                              "survives the next run's wipe")

    c = sub.add_parser("compare", help="both runs in one table, from two saved measurements")
    c.add_argument("--a", required=True, help="first run's .json (or .md) from volume")
    c.add_argument("--b", required=True, help="second run's .json (or .md)")

    a = ap.parse_args()
    if a.what == "compare":            # reads files, never the database
        return cmd_compare(a, None)
    dsn = os.environ.get("DX_CH")
    if not dsn:
        sys.exit("DX_CH unset")
    {"receipts": cmd_receipts, "volume": cmd_volume,
     "retention": cmd_retention}[a.what](a, CH(dsn))


if __name__ == "__main__":
    main()

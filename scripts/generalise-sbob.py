#!/usr/bin/env python3
"""Turn a learned/tuned ContainerProfile into a shippable SBoB.

A learn describes one run on one cluster. Shipping it unchanged means shipping
every accident of that run: the OIDs postgres happened to allocate, the shm
segment it happened to map, the pod IP the kubelet happened to probe from. Each
of those is a guaranteed false positive everywhere else.

Four passes, in this order:

  1. drop head-truncated paths     they cannot match at runtime
  2. volatile segments -> ellipsis  one segment, so the rest stays literal
  3. merge + union flags            lossless
  4. network -> the storage#42 schema

The fourth is the new part. Before storage#42 the only way to admit a kubelet
health probe was to list the pod CIDR, which admits every pod on the node as a
side effect. `entity: host` names the node itself, and `serviceRef` names a
Service rather than whatever ClusterIP it had at learn time.
"""
import argparse
import glob
import json
import os
import re
import sys

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


class FlowDict(dict):
    """Serialises inline: {path: ..., flags: [...]} — one entry per line."""


NoAliasDumper.add_representer(
    FlowDict,
    lambda d, x: d.represent_mapping("tag:yaml.org,2002:map", x, flow_style=True),
)

ELLIPSIS = "⋯"
WILDCARDS = {"*", "**", ELLIPSIS, "⋯⋯"}

# Real filesystem roots. Anything else at segment 0 is a head-truncated fragment
# from the node-agent bug: "/ation.k8s.io/v1/serverresources.json" is the tail of
# ".../discovery/<host>/<group>.io/v1/serverresources.json" and matches nothing.
REAL_ROOTS = {
    "bin", "boot", "data", "dev", "etc", "home", "lib", "lib32", "lib64",
    "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp",
    "usr", "var",
    # image-specific roots seen in these workloads
    "bitnami", "controller", "docker-entrypoint-initdb.d", "app", "base",
    "global", "pg_wal", "pg_stat", "pg_stat_tmp", "helm-working-dir",
}

VOLATILE = [
    re.compile(r"^\.\.\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}\.\d+$"),  # projected volume
    re.compile(r"^\.\.\d"),                                          # other ..<digits>
    re.compile(r"^\d+$"),                                            # PIDs, postgres OIDs
    re.compile(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I),  # UUID
    re.compile(r"^[0-9a-f]{40}(\.[A-Za-z0-9.]+)?$", re.I),           # git sha1
    re.compile(r"^[0-9a-f]{64}(\.[A-Za-z0-9.]+)?$", re.I),           # sha256
    re.compile(r"^sha256[:-][0-9a-f]{64}$", re.I),
    re.compile(r".*[-.]\d{6,}(\.[A-Za-z0-9]+)*$"),                   # foo-4064072570[.tmp]
    # postgres relation files: <filenode>[.<seg>][_fsm|_vm|_init]
    re.compile(r"^\d+(\.\d+)?(_fsm|_vm|_init)?$"),
    re.compile(r"^PostgreSQL\.\d+$"),                                # /dev/shm segment
    re.compile(r"^pgsql_tmp\d+\.\d+$"),
]

# A trailing ".<digits>" is almost always a per-process or per-generation
# suffix: postgres rewrites pg_internal.init as pg_internal.init.<pid>, so a
# learn captures .58 .62 .71 .72 .73 and every restart invents new ones.
#
# Shared-object sonames look identical (libc.so.6, libicudata.so.76.1) but are
# STABLE — they are the library ABI version, not a per-run value. Ellipsising
# them would be wrong and would also lose the library identity, so ".so." is
# excluded and those are handled by directory collapse instead.
NUMERIC_SUFFIX = re.compile(r"^.+\.\d+$")


def numeric_suffix_volatile(seg):
    return bool(NUMERIC_SUFFIX.match(seg)) and ".so." not in seg


def is_truncated_root(path):
    segs = [s for s in path.split("/") if s]
    if not segs:
        return True
    head = segs[0]
    if head.startswith("."):   # /.docker/config.json with HOME=/
        return False
    return head not in REAL_ROOTS


def volatile(seg):
    return any(p.match(seg) for p in VOLATILE) or numeric_suffix_volatile(seg)


def normalise(path):
    """Ellipsis every volatile segment EXCEPT the first.

    A wildcard in segment 0 matches /etc/shadow, which makes cp.was_path_opened()
    true and silently disables R0010, R1010 and R1012. That is a worse bug than
    the one being fixed, so the head is never rewritten.
    """
    segs = path.split("/")
    first = next((i for i, s in enumerate(segs) if s), None)
    return "/".join(
        s if i == first or not s else (ELLIPSIS if volatile(s) else s)
        for i, s in enumerate(segs)
    )


def leading_wildcard(path):
    segs = [s for s in path.split("/") if s]
    return bool(segs) and segs[0] in WILDCARDS


def generalise_opens(opens, report):
    kept, by_path, order = [], {}, []
    for o in opens:
        p = o.get("path", "")
        if is_truncated_root(p):
            report["truncated"].append(p)
            continue
        np = normalise(p)
        if np != p:
            report["normalised"] += 1
        if leading_wildcard(np):
            report["overbroad"].append(np)
            continue
        if np in by_path:
            by_path[np]["flags"] = sorted(set(by_path[np].get("flags") or []) | set(o.get("flags") or []))
        else:
            by_path[np] = {"path": np, "flags": sorted(set(o.get("flags") or []))}
            order.append(np)
    for p in sorted(order):
        kept.append(FlowDict(by_path[p]))
    return kept



# ── directory collapse ──────────────────────────────────────────────────────
#
# A learn lists every file it happened to touch. 20 .mo catalogues under
# /usr/share/locale and 36 sonames under /usr/lib/x86_64-linux-gnu are not
# behaviour worth discriminating: they are read-only static image content, and
# an attacker reading one of them has achieved nothing. Collapsing them to
# <dir>/* keeps the profile legible and portable across image rebuilds, where
# the exact soname versions change.
#
# The danger is collapsing a directory that CAN hold something sensitive: baseline
# it and the rule that would have caught a read there goes blind. So collapse is
# allowed only under roots that are read-only static content, and never under the
# ones an attacker actually targets.
COLLAPSIBLE_ROOTS = (
    "/usr/share/", "/usr/lib/", "/lib/", "/usr/local/share/", "/usr/local/lib/",
)

# Never collapse under these, whatever the sibling count. /etc holds shadow and
# passwd; the data directory holds the database itself; /run/secrets holds the
# SA token; procfs and sysfs are how container escapes are staged.
NEVER_COLLAPSE = (
    "/etc", "/root", "/home", "/run/secrets", "/proc", "/sys", "/dev",
    "/var/lib/postgresql/data", "/bitnami/postgresql/data", "/var/lib/kubelet",
)

READ_ONLY_FLAGS = {"O_RDONLY", "O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"}


def collapsible(directory, entries, min_siblings):
    """A directory is collapsible when it is static read-only image content.

    Three conditions, all required:
      - under a root that holds image content rather than state
      - not under any path an attacker would target
      - every observed access is read-only; a single write means the directory
        is state, not content, and collapsing it would baseline writes too
    """
    if any(directory == n or directory.startswith(n + "/") for n in NEVER_COLLAPSE):
        return False
    if not any(directory.startswith(r) for r in COLLAPSIBLE_ROOTS):
        return False
    if len(entries) < min_siblings:
        return False
    return all(set(e.get("flags") or []) <= READ_ONLY_FLAGS for e in entries)


def collapse_directories(opens, min_siblings, report):
    """Replace >= min_siblings read-only leaves in one directory with <dir>/*."""
    by_dir = {}
    for o in opens:
        by_dir.setdefault(os.path.dirname(o["path"]), []).append(o)

    out, collapsed_dirs = [], []
    for directory in sorted(by_dir):
        entries = by_dir[directory]
        if collapsible(directory, entries, min_siblings):
            flags = sorted({f for e in entries for f in (e.get("flags") or [])})
            out.append(FlowDict({"path": directory + "/*", "flags": flags}))
            collapsed_dirs.append((directory, len(entries)))
        else:
            out.extend(entries)
    report["collapsed"] = collapsed_dirs
    # Drop leaves now covered by a collapsed parent, and the bare directory entry.
    prefixes = [d + "/" for d, _ in collapsed_dirs]
    kept = []
    for o in out:
        p = o["path"]
        if p.endswith("/*"):
            kept.append(o)
            continue
        if any(p.startswith(pre) for pre in prefixes) or any(p == d for d, _ in collapsed_dirs):
            continue
        kept.append(o)
    return sorted(kept, key=lambda x: x["path"])



# ── exec arguments ──────────────────────────────────────────────────────────
#
# Collapsing every exec to [path, ⋯⋯] throws away all argument discrimination:
# a profile that legitimately runs `psql -c "SELECT 1"` then also permits
# `psql -c "COPY x TO PROGRAM 'sh'"`. It was also wrong about args[0] — dash
# really runs as /bin/sh, env as docker-entrypoint.sh, perl as psql via
# pg_wrapper — and matching is anchored, so that only went unnoticed because
# ⋯⋯ absorbed the mismatch.
#
# Binaries whose arguments can encode a command. Their args are never merged:
# any wildcard in a command position hands back exactly what the profile is
# supposed to constrain.
# The workload's OWN main executable. It takes many arguments, several of them
# node-dependent (postgres probes shared_buffers and emits 16384 here, 1000
# there), so pinning them literally is a portability false positive waiting to
# happen. Its identity IS the discriminant: an attacker running the postgres
# binary with different flags has not achieved anything, whereas an attacker
# running bash has. So the core binary gets a genuine ⋯⋯ and the utilities do
# not — which is the opposite of treating them all alike.
CORE_BINARY_ARGS = ["⋯⋯"]

NO_MERGE_BINARIES = {
    "sh", "bash", "dash", "ash", "zsh", "ksh", "busybox",
    "perl", "python", "python3", "ruby", "node", "env", "gosu", "su-exec",
    "psql", "mysql", "mariadb", "redis-cli", "xargs", "nsenter",
}

# A wildcard immediately after one of these is a command-injection hole.
COMMAND_FLAGS = {"-c", "-e", "--command", "-exec", "--eval", "-execdir"}


def normalise_arg(arg):
    """Ellipsis volatile segments inside path-shaped arguments only.

    initdb is invoked with --pwfile=/dev/fd/63; the fd number is per-run. The
    matcher compares ⋯ as a WHOLE path segment, so a partial-segment token would
    never match at runtime — only whole segments are ever rewritten.
    """
    if "/" not in arg:
        return arg
    head, sep, path = arg.partition("=")
    if sep and path.startswith("/"):
        return head + "=" + normalise(path)
    if arg.startswith("/"):
        return normalise(arg)
    return arg


def merge_arg_vectors(vectors):
    """Position-wise merge of same-arity vectors, or None if unsafe.

    Refuses when too much of the vector would become wildcard, or when a
    wildcard would land right after a command-introducing flag.
    """
    arity = len(vectors[0])
    merged, wildcarded = [], 0
    for i in range(arity):
        values = {v[i] for v in vectors}
        if len(values) == 1:
            merged.append(vectors[0][i])
            continue
        if i > 0 and merged[i - 1] in COMMAND_FLAGS:
            return None
        merged.append(ELLIPSIS)
        wildcarded += 1
    if wildcarded > max(1, arity // 3):
        return None
    return merged


def generalise_execs(execs, report, core_binaries=()):
    """Emit the narrowest arg patterns covering what was observed.

    Never merges across arities and never emits a trailing ⋯⋯: that catch-all
    subsumes every narrower sibling, which is the same failure the opens side
    guards against with the leading-wildcard check.
    """
    by_path = {}
    for e in execs:
        args = [normalise_arg(a) for a in (e.get("args") or [])]
        # Normalise the exec path the same way as its arguments. Leaving the path
        # literal while args[0] carries ⋯ makes the two fields disagree about the
        # same binary — the SBoB would be version-portable in one and pinned in
        # the other.
        path = normalise(e["path"])
        if not args:
            args = [path]
        by_path.setdefault(path, []).append(tuple(args))

    core = set(core_binaries)
    out = []
    for path in sorted(by_path):
        vectors = sorted(set(by_path[path]))
        binary = os.path.basename(path)
        if path in core or binary in core:
            argv0 = sorted({v[0] for v in vectors})
            for a0 in argv0:
                out.append(FlowDict({"path": path, "args": [a0] + CORE_BINARY_ARGS}))
            report["core"].append((path, len(vectors), len(argv0)))
            continue
        if binary in NO_MERGE_BINARIES or len(vectors) == 1:
            for v in vectors:
                out.append(FlowDict({"path": path, "args": list(v)}))
            if binary in NO_MERGE_BINARIES and len(vectors) > 1:
                report["literal_interpreters"].append((path, len(vectors)))
            continue
        by_arity = {}
        for v in vectors:
            by_arity.setdefault(len(v), []).append(v)
        for arity in sorted(by_arity):
            group = by_arity[arity]
            merged = merge_arg_vectors(group) if len(group) > 1 else list(group[0])
            if merged is None:
                for v in group:
                    out.append(FlowDict({"path": path, "args": list(v)}))
            else:
                out.append(FlowDict({"path": path, "args": merged}))
    return out


def host_entity_ingress(ports):
    """The kubelet/readiness probe peer, named rather than CIDR-matched."""
    return {
        "identifier": "kubelet-probes",
        "type": "internal",
        "entity": "host",
        "ports": [{"name": "TCP-%d" % p, "port": p, "protocol": "TCP"} for p in sorted(ports)],
    }


# A learned exec carries the process environment, and that is where apps put
# credentials (PGPASSWORD, *_TOKEN, *_KEY). An SBoB is committed to a public
# repo, so the env never ships: it is dropped here, not redacted.
SECRET_ENV = re.compile(r"(PASS|PWD|SECRET|TOKEN|KEY|CRED)", re.I)


def strip_exec_envs(spec):
    dropped = 0
    for e in spec.get("execs") or []:
        if e.pop("envs", None) is not None:
            dropped += 1
    return dropped


def secretish_args(spec):
    out = []
    for e in spec.get("execs") or []:
        for a in e.get("args") or []:
            a = str(a)
            if "=" in a and SECRET_ENV.search(a.split("=", 1)[0]) and a.split("=", 1)[1]:
                out.append(a)
    return out


def service_ref(identifier, namespace, name, ports, protocol="TCP"):
    # Ports may be given as 53/UDP; kube-dns is the case that forced this, and a
    # TCP-only entry silently fails to admit it.
    out = []
    for p in sorted(ports):
        proto = protocol
        if isinstance(p, str) and "/" in p:
            p, proto = p.split("/", 1)
        p = int(p)
        proto = proto.upper()
        out.append({"name": "%s-%d" % (proto, p), "port": p, "protocol": proto})
    return {
        "identifier": identifier,
        "type": "internal",
        "serviceRefNamespace": namespace,
        "serviceRefName": name,
        "ports": out,
    }




# Node/pod CIDRs of the common distributions. An ingress entry whose ONLY peer
# specification is one of these is the blunt pre-storage#42 way of admitting a
# kubelet probe: it admits every pod on the node as a side effect. entity: host
# replaces it, so the CIDR entry must be REMOVED, not merely accompanied.
PROBE_CIDRS = {"10.42.0.0/16", "10.244.0.0/16", "10.43.0.0/16", "10.96.0.0/12",
               "192.168.0.0/16", "172.16.0.0/12"}


def is_cidr_probe_entry(e):
    if any(e.get(k) for k in ("podSelector", "namespaceSelector", "serviceSelector",
                              "serviceRefName", "dnsNames", "dns", "entity")):
        return False
    addrs = list(e.get("ipAddresses") or [])
    if e.get("ipAddress"):
        addrs.append(e["ipAddress"])
    return bool(addrs) and all(a in PROBE_CIDRS for a in addrs)


def dedup_neighbors(entries):
    """Collapse entries that are identical once generalised.

    Generalisation REWRITES peers — several learned IPs of one Service become a
    single serviceRef, several pod-CIDR probe entries become one entity: host —
    so duplicates that did not exist in the learn are created by this pass. The
    identifier is excluded from the comparison because it is a per-entry hash in
    a learned profile and says nothing about what the entry admits; ports are
    unioned so collapsing never narrows what was allowed.
    """
    out, index = [], {}
    for e in entries:
        sig = json.dumps({k: v for k, v in e.items() if k not in ("identifier", "ports")},
                         sort_keys=True, default=str)
        if sig in index:
            keep = index[sig]
            seen = {(p.get("port"), p.get("protocol")) for p in (keep.get("ports") or [])}
            for port in e.get("ports") or []:
                if (port.get("port"), port.get("protocol")) not in seen:
                    keep.setdefault("ports", []).append(port)
                    seen.add((port.get("port"), port.get("protocol")))
            continue
        index[sig] = e
        out.append(e)
    for e in out:
        if e.get("ports"):
            e["ports"] = sorted(e["ports"], key=lambda p: (p.get("port") or 0, p.get("protocol") or ""))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--name")
    ap.add_argument("--namespace")
    ap.add_argument("--probe-ports", default="",
                    help="comma-separated ports the node probes; emits entity: host")
    ap.add_argument("--service-ref", action="append", default=[],
                    help="id=ns/name:port[,port] — emits a serviceRef egress entry")
    ap.add_argument("--strip-syscalls", action="store_true", default=True)
    ap.add_argument("--core-binary", action="append", default=[],
                    help="path (or basename) of the workload's own executable; its "
                         "args collapse to ⋯⋯ because its identity is the discriminant")
    ap.add_argument("--collapse-min", type=int, default=4,
                    help="collapse a read-only static directory once it has this "
                         "many observed leaves (0 disables)")
    args = ap.parse_args()

    rc = 0
    for f in args.files:
        doc = yaml.safe_load(open(f))
        spec = doc.get("spec") or {}
        report = {"truncated": [], "normalised": 0, "overbroad": [], "cidr_probes": 0,
                  "collapsed": [], "literal_interpreters": [], "core": []}

        dropped_envs = strip_exec_envs(spec)
        if dropped_envs:
            report["envs"] = dropped_envs
        leaked = secretish_args(spec)
        if leaked:
            sys.stderr.write(
                "REFUSING to emit %s: exec args carry what look like credential "
                "values, which would be committed in the clear:\n" % f)
            for a in leaked[:5]:
                sys.stderr.write("    %s\n" % a)
            sys.exit(2)

        before = len(spec.get("opens") or [])
        spec["opens"] = generalise_opens(spec.get("opens") or [], report)
        if args.collapse_min:
            spec["opens"] = collapse_directories(spec["opens"], args.collapse_min, report)

        if args.strip_syscalls:
            spec.pop("syscalls", None)

        if spec.get("capabilities"):
            spec["capabilities"] = sorted(set(spec["capabilities"]))

        if spec.get("execs"):
            spec["execs"] = generalise_execs(spec["execs"], report, args.core_binary)

        ingress = list(spec.get("ingress") or [])
        if args.probe_ports:
            # Replace the pod-CIDR probe stanza, in whatever identifier it was
            # learned under, with the named-entity form. Leaving it in place
            # would keep admitting every pod on the node.
            dropped = [e for e in ingress
                       if e.get("identifier") == "kubelet-probes" or is_cidr_probe_entry(e)]
            if dropped:
                report["cidr_probes"] = len(dropped)
            ingress = [e for e in ingress if e not in dropped]
        if args.probe_ports:
            ports = [int(p) for p in args.probe_ports.split(",") if p.strip()]
            ingress.insert(0, host_entity_ingress(ports))
        spec["ingress"] = dedup_neighbors(ingress) or None

        egress = list(spec.get("egress") or [])
        for sr in args.service_ref:
            ident, rest = sr.split("=", 1)
            nsname, ports = rest.split(":", 1)
            ns, name = nsname.split("/", 1)
            egress = [e for e in egress if e.get("identifier") != ident]
            egress.append(service_ref(ident, ns, name, [int(p) for p in ports.split(",")]))
        spec["egress"] = dedup_neighbors(egress) or None

        meta = doc.setdefault("metadata", {})
        if args.name:
            meta["name"] = args.name
        if args.namespace:
            meta["namespace"] = args.namespace
        meta.pop("labels", None)
        meta["annotations"] = {"kubescape.io/managed-by": "User"}
        for k in ("creationTimestamp", "resourceVersion", "uid", "generation",
                  "managedFields", "ownerReferences"):
            meta.pop(k, None)
        doc.pop("status", None)
        doc["spec"] = spec

        with open(f, "w") as fh:
            yaml.dump(doc, fh, Dumper=NoAliasDumper, sort_keys=False,
                      width=4096, allow_unicode=True, default_flow_style=None)

        print("  %-52s opens %d -> %d  (dropped %d truncated, %d normalised)"
              % (os.path.basename(f), before, len(spec["opens"]),
                 len(report["truncated"]), report["normalised"]))
        for d, n in report["collapsed"]:
            print("     collapsed %-52s (%d leaves) -> %s/*" % (d, n, d))
        for path, n, a0 in report["core"]:
            print("     %s is the core binary — %d invocation(s) -> %d entr(ies) with ⋯⋯"
                  % (path, n, a0))
        for path, n in report["literal_interpreters"]:
            print("     %s kept as %d literal invocation(s) — args can encode a command"
                  % (path, n))
        if report["cidr_probes"]:
            print("     replaced %d pod-CIDR probe entr(ies) with entity: host" % report["cidr_probes"])
        if report["overbroad"]:
            print("     REFUSED leading-wildcard: %s" % ", ".join(sorted(set(report["overbroad"]))))
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

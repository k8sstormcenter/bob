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


def is_truncated_root(path):
    segs = [s for s in path.split("/") if s]
    if not segs:
        return True
    head = segs[0]
    if head.startswith("."):   # /.docker/config.json with HOME=/
        return False
    return head not in REAL_ROOTS


def volatile(seg):
    return any(p.match(seg) for p in VOLATILE)


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


def host_entity_ingress(ports):
    """The kubelet/readiness probe peer, named rather than CIDR-matched."""
    return {
        "identifier": "kubelet-probes",
        "type": "internal",
        "entity": "host",
        "ports": [{"name": "TCP-%d" % p, "port": p, "protocol": "TCP"} for p in sorted(ports)],
    }


def service_ref(identifier, namespace, name, ports):
    return {
        "identifier": identifier,
        "type": "internal",
        "serviceRefNamespace": namespace,
        "serviceRefName": name,
        "ports": [{"name": "TCP-%d" % p, "port": p, "protocol": "TCP"} for p in sorted(ports)],
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
    args = ap.parse_args()

    rc = 0
    for f in args.files:
        doc = yaml.safe_load(open(f))
        spec = doc.get("spec") or {}
        report = {"truncated": [], "normalised": 0, "overbroad": [], "cidr_probes": 0}

        before = len(spec.get("opens") or [])
        spec["opens"] = generalise_opens(spec.get("opens") or [], report)

        if args.strip_syscalls:
            spec.pop("syscalls", None)

        if spec.get("capabilities"):
            spec["capabilities"] = sorted(set(spec["capabilities"]))

        if spec.get("execs"):
            # Dedup AFTER arg-collapsing, not before. Entries that differed only
            # by args become identical once every arg list is [path, ⋯⋯], so
            # keying on the pre-collapse args leaves duplicates behind — the oss
            # learn produced dash five times and chmod twice that way.
            seen, execs = set(), []
            for e in spec["execs"]:
                path = e.get("path")
                if path in seen:
                    continue
                seen.add(path)
                execs.append(FlowDict({"path": path, "args": [path, "⋯⋯"]}))
            spec["execs"] = sorted(execs, key=lambda x: x["path"])

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
        if report["cidr_probes"]:
            print("     replaced %d pod-CIDR probe entr(ies) with entity: host" % report["cidr_probes"])
        if report["overbroad"]:
            print("     REFUSED leading-wildcard: %s" % ", ".join(sorted(set(report["overbroad"]))))
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

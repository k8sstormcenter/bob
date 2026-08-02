#!/usr/bin/env python3
"""Replace cluster-specific and volatile values in an SBoB with portable forms.

A learned profile is full of values that are true of the cluster it was learned
on and nowhere else. Shipped as-is the SBoB only works on that cluster:

  ipAddress: 10.43.0.1     the apiserver ClusterIP. k3s uses 10.43.0.0/16,
                           kubeadm 10.96.0.0/12 — a literal matches neither
                           of the other's.
  ipAddress: 140.82.121.3  github.com today. Rotates.
  Host: 10.42.0.250:8082   a pod IP, different every restart.

The storage API already has the portable forms. IPAddress and DNS are
DEPRECATED singulars; the v0.0.2 replacements are the LIST forms IPAddresses
and DNSNames, and an IPAddresses entry may be a literal, a CIDR, or "*"
(see pkg/registry/file/networkmatch — spec §5.7/§5.8).

So: in-cluster IPs become the service CIDRs of the two common distributions,
external peers key on DNS (which the learn captured) instead of rotating IPs,
and volatile Host headers become the single-label DNS wildcard.
"""
import argparse, ipaddress, re, sys
from pathlib import Path
import yaml


class NoAliasDumper(yaml.SafeDumper):
    """Never emit &id001/*id001 anchors.

    PyYAML back-references any value it sees twice BY IDENTITY. An SBoB is read
    at review time to see what a workload is allowed to do, and an alias hides
    the actual flags behind a pointer. Generators must also avoid sharing list
    objects between entries; this is the backstop for when they slip.
    """

    def ignore_aliases(self, data):
        return True


# Both common service CIDRs, so one SBoB works on k3s and kubeadm alike.
CLUSTER_CIDRS = ["10.43.0.0/16", "10.96.0.0/12"]
POD_CIDRS = ["10.42.0.0/16", "10.244.0.0/16"]

# node-agent's leading-character path truncation (k8sstormcenter/node-agent#59)
# mangles the projected SA-token dir into a bare fragment. The correct form is
# known — every uncorrupted profile has it — so it is restored rather than kept.
TRUNC_SA = re.compile(r"^/\d+_\d+_\d+\.\d+/(ca\.crt|token|namespace)$")
SA_DIR = "/run/secrets/kubernetes.io/serviceaccount/⋯/"


def is_cluster_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private


def fix_neighbor(n):
    """Move a NetworkNeighbor onto the plural fields with portable values."""
    changed = []
    ip = n.pop("ipAddress", None)
    dns = n.pop("dns", None)
    names = [d.rstrip(".") for d in (n.get("dnsNames") or []) if d]

    if names:
        # An external peer is identified by name, not by an address that rotates.
        n["dnsNames"] = sorted(set(names))
        if ip and not is_cluster_ip(ip):
            changed.append(f"dropped rotating IP {ip}, keyed on {n['dnsNames']}")
            ip = None
    else:
        n.pop("dnsNames", None)

    if ip:
        if is_cluster_ip(ip):
            cidrs = POD_CIDRS if ipaddress.ip_address(ip) in ipaddress.ip_network("10.42.0.0/16") else CLUSTER_CIDRS
            n["ipAddresses"] = list(cidrs)
            changed.append(f"{ip} -> {cidrs}")
        else:
            n["ipAddresses"] = [ip]
    return changed


def fix_endpoint(e):
    """Volatile Host headers -> the single-label DNS wildcard."""
    changed = []
    hosts = ((e.get("headers") or {}).get("Host")) or []
    new = []
    for h in hosts:
        host = h.split(":")[0]
        port = h.split(":")[1] if ":" in h else None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            new.append(h); continue
        repl = "*" + (f":{port}" if port else "")
        new.append(repl)
        changed.append(f"Host {h} -> {repl}")
    if changed:
        e["headers"]["Host"] = new
    return changed


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    for f in args.files:
        d = yaml.safe_load(Path(f).read_text())
        s = d.get("spec") or {}
        notes = []

        for o in s.get("opens") or []:
            m = TRUNC_SA.match(o.get("path", ""))
            if m:
                new = SA_DIR + m.group(1)
                notes.append(f"truncated {o['path']} -> {new}")
                o["path"] = new

        for key in ("ingress", "egress"):
            for n in (s.get(key) or []):
                notes += [f"{key}: {c}" for c in fix_neighbor(n)]

        for e in s.get("endpoints") or []:
            notes += fix_endpoint(e)

        # Deduplicate opens after the SA-path repair may have created twins.
        if s.get("opens"):
            by = {}
            for o in s["opens"]:
                cur = by.setdefault(o["path"], o)
                cur["flags"] = sorted(set(cur.get("flags") or []) | set(o.get("flags") or []))
            s["opens"] = sorted(by.values(), key=lambda o: o["path"])

        print(f"  {Path(f).name}")
        for n in notes:
            print(f"      {n}")
        if not notes:
            print("      (already portable)")
        if not args.dry_run:
            yaml.dump(d, open(f, "w"), sort_keys=False, width=4096, allow_unicode=True,
                   default_flow_style=None, Dumper=NoAliasDumper)
    return 0


if __name__ == "__main__":
    sys.exit(main())

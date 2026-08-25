#!/usr/bin/env python3
"""Turn recorded ContainerProfiles into portable SBoBs.

Two stages:
  1. COLLAPSE  — bobctl v0.1.3-rc1's collapse analysis (see collapse_tuner.py) decides which
                 prefixes are noisy; children under them become ⋯.
  2. PORTABILITY — remove detail that pins the SBoB to this cluster/host/run:
                 kernel version in module paths, cluster-CIDR API IPs, single-pod selector
                 labels, chart-version labels, rig-local DNS, and the perf-load harness.

Usage: make_sbobs.py <per-cp-dir> <out-dir> [namespace] [noisy-threshold]
"""
import sys, os, re, glob, yaml
from collapse_tuner import load_profiles, aggregate, analyze, split_path

DYN = '⋯'
KVER_RE     = re.compile(r'(/(?:usr/)?lib/modules)/[^/]+/')
BUILD_ID_RE = re.compile(r'(/\.build-id)/[0-9a-f]{2}/[0-9a-f]+(\.debug)?$')

UNSTABLE_LABEL_RE = re.compile(
    r'^(statefulset\.kubernetes\.io/pod-name|apps\.kubernetes\.io/pod-index|'
    r'pod-template-hash|controller-revision-hash|app\.kubernetes\.io/version|'
    r'helm\.sh/chart|app\.kubernetes\.io/managed-by|app\.kubernetes\.io/instance)$')
DROP_SELECTOR_APPS = {'web', 'loadgen', 'loadgen2'}
API_IPS = {'10.43.0.1', '10.96.0.1'}
DROP_DNS_SUFFIX = ('.austrianopencloudcommunity.org.',)


def collapse(path, noisy):
    """Replace the child segment under the longest matching noisy prefix with ⋯."""
    segs = split_path(path)
    cur = ''
    for i, seg in enumerate(segs):
        parent = cur
        cur += '/' + seg
        if parent and parent in noisy:
            tail = segs[i + 1:]
            return '/'.join([parent, DYN] + tail) if tail else parent + '/' + DYN
    return path


def portability(path, notes):
    if KVER_RE.search(path):
        notes.add('kernel-version segment in /lib/modules generalised — SBoB must survive node upgrades')
        path = KVER_RE.sub(r'\1/' + DYN + '/', path)
    path = BUILD_ID_RE.sub(r'\1/' + DYN + '/' + DYN, path)
    while f'/{DYN}/{DYN}/' in path:
        path = path.replace(f'/{DYN}/{DYN}/', f'/{DYN}/')
    return path


def clean_selector(sel):
    if not isinstance(sel, dict):
        return None
    ml = {k: v for k, v in (sel.get('matchLabels') or {}).items()
          if not UNSTABLE_LABEL_RE.match(k)}
    if not ml or ml.get('app') in DROP_SELECTOR_APPS:
        return None
    return {'matchLabels': ml}


def clean_net(entries, notes):
    out, seen = [], set()
    for e in entries or []:
        ip = e.get('ipAddress')
        if ip in API_IPS:
            notes.add(f'kube-apiserver ClusterIP {ip} dropped — differs per distro (k3s 10.43/16 vs kubeadm 10.96/12)')
            continue
        names = [n for n in (e.get('dnsNames') or [])
                 if not any(n.endswith(s) for s in DROP_DNS_SUFFIX)]
        sel = clean_selector(e.get('podSelector'))
        if not (ip or names or sel):
            continue
        entry = {}
        if e.get('identifier'):
            entry['identifier'] = e['identifier']
        if sel:
            entry['podSelector'] = sel
            if e.get('namespaceSelector'):
                entry['namespaceSelector'] = e['namespaceSelector']
        if ip:
            entry['ipAddress'] = ip
        if names:
            entry['dnsNames'] = sorted(names)
        if e.get('ports'):
            entry['ports'] = [{k: p[k] for k in ('name', 'protocol', 'port') if k in p}
                              for p in e['ports']]
        k = yaml.safe_dump(entry, sort_keys=True)
        if k not in seen:
            seen.add(k)
            out.append(entry)
    return out


def main(indir, outdir, ns=None, thr=10):
    os.makedirs(outdir, exist_ok=True)
    profs = load_profiles(indir, ns)
    noisy_list, _ = analyze(aggregate([p[1] for p in profs]), thr)
    noisy = {n['prefix'] for n in noisy_list}
    print(f'collapse: {len(noisy)} noisy prefixes from {len(profs)} profiles (threshold {thr})\n')
    print('%-34s %7s %7s %6s %5s %4s %4s' % ('WORKLOAD/CONTAINER', 'opens', '→after', 'exec', 'sysc', 'eg', 'in'))

    for label, _paths, f in profs:
        d = yaml.safe_load(open(f))
        meta, spec = d.get('metadata', {}), d.get('spec') or {}
        lbl = meta.get('labels', {}) or {}
        name = lbl.get('kubescape.io/workload-name', 'unknown')
        cont = lbl.get('kubescape.io/workload-container-name', '')
        notes = set()

        raw = [o['path'] for o in (spec.get('opens') or []) if o.get('path')]
        opens = sorted({portability(collapse(p, noisy), notes) for p in raw})

        execs = sorted({portability(e['path'], notes) for e in (spec.get('execs') or []) if e.get('path')})
        eg = clean_net(spec.get('egress'), notes)
        ing = clean_net(spec.get('ingress'), notes)

        sbob = {
            'apiVersion': 'spdx.softwarecomposition.kubescape.io/v1beta1',
            'kind': 'ContainerProfile',
            'metadata': {'name': f'sbob-{name}-{cont}' if cont else f'sbob-{name}'},
            'spec': {'matchLabels': {'name': name}},
        }
        s = sbob['spec']
        if execs:
            s['execs'] = [{'path': p} for p in execs]
        if opens:
            s['opens'] = [{'path': p} for p in opens]
        if spec.get('syscalls'):
            s['syscalls'] = sorted(spec['syscalls'])
        if spec.get('capabilities'):
            s['capabilities'] = sorted(spec['capabilities'])
        if eg:
            s['egress'] = eg
        if ing:
            s['ingress'] = ing

        out = os.path.join(outdir, f"{sbob['metadata']['name']}.yaml")
        with open(out, 'w') as fh:
            fh.write(f'# SBoB for {name}/{cont} — generalised from a recorded ContainerProfile.\n')
            fh.write(f'# opens {len(raw)} -> {len(opens)} after collapse+portability.\n')
            for n in sorted(notes):
                fh.write(f'# NOTE: {n}\n')
            yaml.safe_dump(sbob, fh, sort_keys=False, default_flow_style=False, width=110,
                           allow_unicode=True)
        print('%-34s %7d %7d %6d %5d %4d %4d' %
              (label[:34], len(raw), len(opens), len(execs), len(s.get('syscalls') or []), len(eg), len(ing)))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2],
         sys.argv[3] if len(sys.argv) > 3 else None,
         int(sys.argv[4]) if len(sys.argv) > 4 else 10)

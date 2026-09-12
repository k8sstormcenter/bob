#!/usr/bin/env python3
"""Offline port of bobctl v0.1.3-rc1's collapse analysis (pkg/profile/pathanalysis.go +
pkg/autotune/collapse.go), so recorded ContainerProfiles can be analysed without a cluster.

Faithful to the Go implementation:
  splitPath        -> strip leading '/', split on '/'
  AnalyzeProfilePaths -> walk EVERY depth; each prefix counts its distinct next segments
  looksGenerated   -> uuid | hex{8,} | digits{3,} | sess_/session_/tmp_/cache_ prefix
  aggregatePathStats -> across profiles: max(uniqueChildren), sum(totalPaths), any(hasGenerated)
  analyze          -> noisy if uniqueChildren >= noisyThreshold OR hasGenerated
  suggestThreshold -> generated:2 | >100:2 | >50:3 | >20:5 | >10:n/3 | else n/2
"""
import re, sys, glob, os, yaml
from collections import defaultdict

UUID_RE    = re.compile(r'^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
HEX_RE     = re.compile(r'^[0-9a-fA-F]{8,}$')
NUMERIC_RE = re.compile(r'^\d{3,}$')
SESSION_RE = re.compile(r'^(sess_|session_|tmp_|cache_)')


def looks_generated(seg: str) -> bool:
    return bool(UUID_RE.match(seg) or HEX_RE.match(seg) or
                NUMERIC_RE.match(seg) or SESSION_RE.match(seg))


def split_path(p: str):
    p = p.lstrip('/')
    return p.split('/') if p else []


def analyze_profile_paths(paths):
    """Returns {prefix: {'children': set, 'total': int, 'generated': bool}}"""
    pref = defaultdict(lambda: {'children': set(), 'total': 0, 'generated': False})
    for path in paths:
        segs = split_path(path)
        if not segs:
            continue
        cur = ''
        for i, seg in enumerate(segs):
            cur += '/' + seg
            info = pref[cur]
            info['total'] += 1
            if i + 1 < len(segs):
                child = segs[i + 1]
                info['children'].add(child)
                if looks_generated(child):
                    info['generated'] = True
    return pref


def aggregate(profile_paths):
    agg = {}
    for paths in profile_paths:
        for prefix, info in analyze_profile_paths(paths).items():
            u, t, g = len(info['children']), info['total'], info['generated']
            if prefix in agg:
                a = agg[prefix]
                a['unique'] = max(a['unique'], u)
                a['total'] += t
                a['generated'] = a['generated'] or g
            else:
                agg[prefix] = {'unique': u, 'total': t, 'generated': g}
    return agg


def suggest_threshold(unique, generated):
    if generated:
        return 2
    if unique > 100:
        return 2
    if unique > 50:
        return 3
    if unique > 20:
        return 5
    if unique > 10:
        return unique // 3
    return unique // 2


def analyze(agg, noisy_threshold=10):
    noisy, reasonable = [], 0
    for prefix, a in agg.items():
        if a['unique'] >= noisy_threshold or a['generated']:
            noisy.append({'prefix': prefix, 'unique': a['unique'], 'total': a['total'],
                          'generated': a['generated'],
                          'suggest': suggest_threshold(a['unique'], a['generated'])})
        else:
            reasonable += 1
    noisy.sort(key=lambda x: -x['unique'])
    return noisy, reasonable


def load_profiles(indir, ns_filter=None):
    """Returns [(label, [paths])] from per-CP YAMLs (individual GET dumps)."""
    out = []
    for f in sorted(glob.glob(os.path.join(indir, '*.yaml'))):
        base = os.path.basename(f)
        if ns_filter and not base.startswith(ns_filter + '__'):
            continue
        d = yaml.safe_load(open(f))
        if not d:
            continue
        spec = d.get('spec') or {}
        paths = [o['path'] for o in (spec.get('opens') or []) if o.get('path')]
        if paths:
            lbl = (d.get('metadata', {}).get('labels', {}) or {})
            name = lbl.get('kubescape.io/workload-name', base)
            cont = lbl.get('kubescape.io/workload-container-name', '')
            out.append((f'{name}/{cont}', paths, f))
    return out


def collapse_path(path, collapse_map):
    """Apply collapse decisions: if a prefix is noisy, replace its child segment with ⋯."""
    segs = split_path(path)
    cur, out = '', []
    for i, seg in enumerate(segs):
        parent = cur
        cur += '/' + seg
        if parent in collapse_map and i > 0:
            out.append('⋯')
        else:
            out.append(seg)
        # once collapsed, keep walking with the ORIGINAL prefix for further decisions
    res = '/' + '/'.join(out)
    while '/⋯/⋯/' in res:
        res = res.replace('/⋯/⋯/', '/⋯/')
    return re.sub(r'(/⋯)+$', '/⋯', res)


if __name__ == '__main__':
    indir = sys.argv[1]
    ns = sys.argv[2] if len(sys.argv) > 2 else None
    thr = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    profs = load_profiles(indir, ns)
    agg = aggregate([p[1] for p in profs])
    noisy, reasonable = analyze(agg, thr)

    print(f'=== Collapse Analysis (bobctl v0.1.3-rc1 algorithm, offline) ===')
    print(f'  Profiles analyzed: {len(profs)}')
    print(f'  Analyzed {len(agg)} unique path prefixes across all profiles')
    print(f'  Reasonable paths (untouched): {reasonable}')
    print(f'  Noisy paths found: {len(noisy)}')
    print()
    print('%-58s %8s %7s %5s %8s' % ('PREFIX', 'CHILDREN', 'PATHS', 'GEN?', 'SUGGEST'))
    print('%-58s %8s %7s %5s %8s' % ('-' * 58, '-' * 8, '-' * 7, '-' * 5, '-' * 8))
    for n in noisy[:30]:
        print('%-58s %8d %7d %5s %8d' %
              (n['prefix'][:58], n['unique'], n['total'],
               'yes' if n['generated'] else '', n['suggest']))
    if len(noisy) > 30:
        print(f'  ... and {len(noisy)-30} more')

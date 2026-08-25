# ADR-0007 — A profile may not wildcard above a path another rule protects

**Status:** accepted
**Applies to:** every ContainerProfile in `sbobs/`

## Context

A ContainerProfile's `opens` list is an allowlist, consulted by `cp.was_path_opened`. The path
matcher treats both `⋯` and `*` as wildcards. So an entry intended as "this app reads its config
from /etc" — written as `/etc/⋯` — also matches `/etc/shadow`:

```
CompareDynamic("/etc/⋯",        "/etc/shadow") = true
CompareDynamic("/*",            "/etc/shadow") = true
CompareDynamic("/etc/hostname", "/etc/shadow") = false
```

`R0010 Unexpected Sensitive File Access` fires when a sensitive path is opened **and is not in the
profile**. A profile containing `/etc/⋯` therefore turns R0010 off for that container — silently,
permanently, and while looking like an ordinary convenience entry. Nothing warns. The rule stays
`enabled: true` in the rules object and simply never matches.

This is the most dangerous class of mistake in the whole scheme, because its symptom is *fewer
alerts*, which reads as success.

The same mechanism threatens [ADR-0003](0003-no-cluster-credentials-in-presentation-tier.md): an
`opens` entry of `/var/run/⋯` in the frontend profile would suppress `R0006` for the ServiceAccount
token while appearing to change nothing.

## Decision

No profile contains a wildcard entry at or above a path protected by another rule.

Concretely, `/etc/⋯` is never used. Only named files (`passwd`, `group`, `hosts`, `resolv.conf`,
`nsswitch.conf`, `localtime`), named certificate directories (`ssl/⋯`, `pki/⋯`,
`ca-certificates/⋯`), and named per-engine config directories (`/etc/nginx/⋯`, `/etc/postgresql/⋯`,
`/etc/redis/⋯` …). `/var/run/secrets/kubernetes.io/serviceaccount/⋯` appears **only** in the
backend profile, where ADR-0003 permits it.

Generality in a profile is bought with detection. Spend it deliberately.

## Verified by

**Review of the profile itself**, not of the workload. This ADR is a constraint on the detector's
own configuration, so no runtime evidence can confirm it — a suppressed rule produces silence, and
silence is what a passing check also looks like.

Mechanical check:

```bash
# any wildcard directly under /etc, or above the serviceaccount path, is a violation
grep -nE 'path: /etc/(⋯|\*)$|path: /var/run/(⋯|\*)$|path: /(⋯|\*)$' sbobs/cp-tier-*.yaml
```

Empty output is the passing condition. This belongs in CI, because the failure mode is invisible at
runtime by construction.

## Evidence emitted

```
ADR-0007 VIOLATED
  found     sbobs/cp-tier-frontend.yaml:41  opens entry "/etc/⋯"
  effect    suppresses R0010 for every container bound to tier-frontend
  fix       replace with the named files the app actually reads
```

## Consequences

* Profiles are longer and more tedious to author than they would otherwise be.
* Adding a new engine to a tier means adding its specific config directory, not widening an
  existing wildcard. Reviewers should reject the widening.

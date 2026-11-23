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

## The mechanism is worse than "the matcher is generous"

A wildcard does not merely *match* a protected path at evaluation time. It **absorbs the
specific entry at write time**, so the specific entry is not in the stored profile at all.

Observed directly. A profile authored with all four of these:

```
/run/secrets/kubernetes.io/serviceaccount/token          ← concrete, needed by R0006
/var/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/⋯
/var/run/⋯                                               ← the generous entry
```

came back from the API server as:

```
/run/secrets/kubernetes.io/serviceaccount/⋯
/var/run/⋯/kubernetes.io/serviceaccount/⋯
```

Both concrete `/token` paths are gone. `secrets` was collapsed into the `/var/run/⋯`
wildcard, and `token` was collapsed into its `⋯` sibling. Nothing warned.

This matters because `R0006` is gated on
`!cp.was_path_opened_with_suffix(containerId, '/token')`, and node-agent's contract is
explicit that wildcards cannot answer a suffix question — from
`pkg/rulemanager/cel/libraries/containerprofile/open_test.go`:

> Wildcard-shaped entries in `cp.Opens.Patterns` MUST NOT contribute to suffix/prefix
> answers — their literal text answers the wrong question. Only concrete paths in
> `cp.Opens.Values` are valid sources of suffix/prefix truth.

Projection-active mode reaches the same result by a different route: `SuffixHits` is
computed with `strings.HasSuffix(entry, "/token")`, and an entry ending in `/⋯` fails it.

**So the backend tier's ServiceAccount allowance, written as a wildcard, never worked.**
The backend alerted `R0006` exactly like every other tier, and
[ADR-0003](0003-no-cluster-credentials-in-presentation-tier.md)'s exemption was fiction.
Removing `/var/run/⋯` and listing only the two concrete `/token` paths fixed it —
verified by re-reading the stored object.

### Editing a profile is additive

`kubectl apply` does not replace a ContainerProfile's `opens` list; storage merges into
the existing object. Deleting a line from the YAML and re-applying leaves the entry in
the cluster. Both stale wildcards above survived a re-apply and only disappeared after
`kubectl delete containerprofiles.spdx… --all` followed by a fresh create.

Budget for that when tightening a profile: **delete, then apply**, and read back what
the API server actually stored rather than trusting the file on disk.

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
# a wildcard directly under /etc, /run, /var/run, or at the root, is a violation
grep -nE 'path: (/etc|/run|/var/run)/(⋯|\*)$|path: /(⋯|\*)$' sbobs/cp-tier-*.yaml

# and the backend's token allowance must be CONCRETE, or R0006 cannot honour it
grep -c 'serviceaccount/token$' sbobs/cp-tier-backend.yaml   # expect 2
```

Empty output from the first, `2` from the second, is the passing condition. This belongs in CI,
because the failure mode is invisible at runtime by construction — a suppressed rule produces
silence, and silence is what a passing check also looks like.

Checking the files is necessary but not sufficient: the collapsing described above happens on
write, so also read back what the cluster stored.

```bash
kubectl -n sbob-library get containerprofiles.spdx.softwarecomposition.kubescape.io \
  tier-backend -o json | jq '[.spec.opens[].path | select(endswith("/token"))]'
```

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

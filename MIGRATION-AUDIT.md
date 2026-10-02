# ContainerProfile migration — audit and tuning

Audit of what still depends on the retired `ApplicationProfile` / `ApplicationActivity` /
`NetworkNeighborhood` / `NetworkNeighbors` types, and what to tune after moving to
`ContainerProfile`. Dated 2026-10-02, against `storage` main `04cd064` and chart
`1.41.0-duckling36`.

## Verdict

**The migration is done at the API level.** The legacy types are not deprecated-but-served —
they are deleted from the Go API. Raw grep counts are a bad proxy for migration debt and
overstate it by roughly two orders of magnitude.

| Repo | case-insensitive `applicationprofile` hits | live functional dependencies |
|---|---|---|
| storage | 169 | 1 (a build break in the integration suite) |
| bob (public) | 675 | 0 |
| bob (private `pkg/`) | 631 | 2 manifests |
| node-agent (both forks) | 67 / 118 | 1 each (RBAC over-grant) |
| dx | 61 | 8 script sites, 2 of which write |

Everything else is deleted fixtures, signed rule tags that must not be touched, test names,
and prose.

## What the storage API actually serves

`ApplicationProfile`, `ApplicationActivity`, `NetworkNeighborhood` and `NetworkNeighbors` are
absent from `addKnownTypes` in both `pkg/apis/softwarecomposition/register.go` and its
`v1beta1` counterpart, have no REST storage under `pkg/registry/softwarecomposition/`, and do
not appear in the served resource map in `pkg/apiserver/apiserver.go`. The generated clientset
has no typed client for them.

There are **no CRDs**. This is an aggregated apiserver with a single `APIService`
(`artifacts/example/apiservice.yaml`), so there is no CRD structure to migrate and no
`deprecated: true` marker to set — those are CRD-only fields. Any plan phrased as "remove the
legacy CRDs" has nothing to act on.

`ContainerProfileSpec` is a complete superset of the two legacy specs: execs, opens, syscalls,
capabilities, architectures, seccomp, endpoints, rule policies and call stacks from
`ApplicationProfile`; ingress and egress from `NetworkNeighborhood`; plus the per-container
groups. No legacy field lacks an equivalent.

## The two things that genuinely block "migration complete"

**1. The storage integration suite does not compile.**
`tests/integration-test-suite/helpers.go` still references `spdxv1beta1.ApplicationProfile`,
`spdxv1beta1.NetworkNeighborhood`, `.ApplicationProfiles(ns)` and `.NetworkNeighborhoods(ns)`.
None of those symbols exist. The file carries no build tag, so `go test ./...` cannot build the
package, and at least eight case files call the affected helpers. The committed test binary
predates the type deletion, which is why nobody has noticed.

This is not a rename. `ApplicationProfile` was one object per *workload* carrying
`spec.containers[]`; a learned `ContainerProfile` is one object per *container*. The
fetch-and-assert logic has to be reworked, not substituted.

**2. `PreSave` deflates every write, including authored profiles.**
`pkg/registry/file/containerprofile_processor.go:246` applies
`DeflateContainerProfileSpec` on every write of a consolidated profile. It rebuilds the spec
wholesale: opens are rewritten to `⋯` wildcards by the dynamic path detector, lists are deduped
and sorted, and ingress/egress neighbours are merged with IPs collapsed to CIDRs.

The consequence is that **a signature computed over a submitted spec will not verify against the
stored spec**, and there is no opt-out — no "skip deflation for authored or signed profiles"
branch exists. Any signing workflow must either deflate-then-sign, or this needs a bypass. Until
one of those lands, "authored profiles are signed and verified end to end" is not true.

## Keep these — they are not debt

- `pkg/registry/file/cleanup.go` deprecated-resource GC. The entries for
  `applicationprofiles`, `applicationactivities`, `networkneighborhoods` and
  `networkneighborses` are **delete-only**: they reclaim on-disk payloads and sqlite rows from
  upgraded clusters. Legacy data is garbage-collected, never converted. Removing this strands
  that data permanently. Retire it only once every cluster has completed a post-upgrade pass.
- The `bobctl` loader guard in the private `pkg/profile/load.go`, which hard-errors on any
  non-`ContainerProfile` document. That rejection is what keeps the live dependency count at
  zero.
- Signed rule-metadata tags. The `- applicationprofile` entries in node-agent's
  `tests/resources/signed/rules/*.yaml` and `benchmark/signing/rules/baseline-rules.yaml` are
  rule tags inside signed bundles, not API references. Editing them breaks signatures.

## Do not chase these

Naming residue over `ContainerProfile`-native code: `deflateNetworkNeighbors`,
`listIngressNetworkNeighbors`, `networkneighborhood_ipcollapse.go`,
`EnableApplicationProfile`, `seedNetworkNeighborhoodIfNeeded`, and test names like
`Test_27_ApplicationProfileOpens`. Renaming is churn.

Two exceptions worth doing because they are user-visible: the private README's
`kubectl get applicationprofiles` instructions, which fail when pasted, and a metrics help
string reading "Total ApplicationProfile entries".

`HasFinalApplicationProfile` is a special case — the name is legacy but it appears in the
NodeProfile wire payload, so changing it is a compatibility decision rather than a cleanup.

## Image currency — how to check it, not what it is

Any version named here is stale on arrival. During active integration the chart is cut once per
integration batch, which in practice meant **three releases in about two hours** on 2026-10-01.
So check currency rather than trusting a number:

```
# newest published chart
gh api 'repos/k8sstormcenter/helm-charts/releases?per_page=1' --jq '.[0].tag_name'
# what it pins
helm template ks <that release's .tgz url> | grep -oE 'duckling:v[0-9.]+-rogue[0-9]+|storage:[^"]*' | sort -u
# what this repo pins
grep KUBESCAPE_CHART_VER Makefile
```

The gap measured at audit time, for scale — this is the failure mode to watch for, not a target:

| Component | pinned | newest then | gap |
|---|---|---|---|
| chart | `1.41.0-duckling23` | `1.41.0-duckling36` | 13 releases |
| node-agent | `duckling:v0.1.0-rogue35` | `duckling:v0.1.0-rogue56` | 21 releases |
| storage | `storage:rc-rogue23` | `storage:rc-rogue23` | current |

The pin had not moved since 2026-09-25. Verified on k3s before bumping: node-agent rolled out
clean on `rogue56`, 27 of 31 rules enabled, zero error or fatal log lines, storage healthy. A
jump of that size is worth a cluster test rather than a version bump on faith.

**The chart maps one-to-one onto an integration batch**, so the tag tells you which node-agent
work is in it — `duckling36`=`rogue56`, `duckling37`=`rogue57`, `duckling38`=`rogue58`. Pin to a
tag whose batch is green on both CNI lanes, not to whatever is newest mid-batch.

**Name the image in any behavioural claim.** At this cadence "node-agent does X" is ambiguous:
the D16 reload guards, for instance, are enforced only from `rogue58`, while `rogue56` and
`rogue57` apply the downgrade and warn that scope is reduced. A reproduction on the wrong tag
looks like a contradiction when it is a version difference.

Two pins drift independently: `Makefile` (`KUBESCAPE_CHART_VER`) here, and the soc repo's
`skaffold.yaml`, which hardcodes the full release URL rather than using a variable — worth
parameterising there.

## Tuning after the move

- A profile learned while a workload is violating an ADR bakes that violation into its own
  allowlist, and the rule can then never fire. Measured twice: a backend profile learned during
  `pip install` carried 107 of 189 opens of pip; and on a second cluster, profiles learned
  during a drive absorbed three network violations as permitted egress, producing zero alerts
  that read as a detection failure. Never learn during a drive, and read what a profile permits
  before trusting it.
- Binding is not optional. An unbound namespace produces no alerts at all because node-agent
  learns instead of adopting. Check the `kubescape.io/user-defined-profile` label on the pods,
  and that profiles carry `profile-role: shadow` rather than appearing as plain learned objects.
- `kubectl get containerprofile <name>` — singular — is not a resource type. It errors, and
  grepping the error output finds nothing, which is indistinguishable from a clean profile. Use
  `containerprofiles.spdx.softwarecomposition.kubescape.io` and fetch by name, because a `List`
  returns objects with `.spec` nulled.
- `ContainerProfileContainer` has no `Architectures` field; it exists only on the flat
  `ContainerProfileSpec`. A multi-container authored document cannot express per-container
  architectures.

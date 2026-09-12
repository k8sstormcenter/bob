# ZITADEL SBoB demo — deploy, drive, contrast

ZITADEL is an identity provider: it holds users, credentials and OIDC clients,
and it is the thing an attacker wants most in a cluster. That makes it a good
subject for a behaviour profile — the interesting question is not whether it
serves traffic, but whether a process inside it that is *not* ZITADEL can be
told apart from ZITADEL itself.

## 0. bobctl

Build from the repo, or take a release:

```
cd pkg && go build -o ../bin/bobctl ./main.go
```

`bobctl` links the storage API types, so it must be built against the same
storage the cluster runs. If a profile round-trips with fields silently missing,
that mismatch is the first thing to check.

## 1. Stack

kubescape node-agent + storage, with `runtimeDetection` enabled. On a cluster
whose container runtime is not in the default location — k3s with `--data-dir`
on another partition, for instance — pass the runc actually in use, or
node-agent marks the wrong binary, sees no container starts, and every profile
stays empty:

```
make kubescape KS_RUNC=/path/to/runc KS_RUNC_MNT=/the/partition/holding/it
make alertmanager
```

## 2. Deploy

```
example/zitadel/distro.sh
```

Three long-running containers result:

| component | container | port | what it is |
|---|---|---|---|
| `zitadel-postgresql` | `postgresql` | 5432 | the datastore, chart subchart, `emptyDir` |
| `zitadel` | `zitadel` | 8080 | the API and console |
| `zitadel-login` | `zitadel-login` | 3000 | the login UI, a separate deployment since v4 |
| `zitadel-login` | `wait-for-zitadel` | — | init container, waits on `/debug/ready` |

Five more containers run once and exit: `zitadel-init`, `zitadel-cleanup`, and
the three inside the setup Job — `zitadel-setup`, `zitadel-machinekey`,
`zitadel-machine-pat`. They get profiles too. An unbound container is itself a
finding (R1017, *no bound profile — an unmanaged/unknown container is running
in the cluster*), so leaving the Jobs bare costs five alerts per install.

One pod carries one label, and the setup Job runs three containers, so the
label is the shared prefix `zitadel-jobs` and node-agent resolves
`zitadel-jobs-<containerName>` per container before falling back to the bare
name. That is also how `zitadel-login`'s `wait-for-zitadel` init container gets
its own profile instead of inheriting the login server's.

### Why the install needs two `--set ...=null`

The chart's `init` and `setup` Jobs ship as helm **pre-install hooks**. Hooks run
before the release's own resources, so on a first install they wait for a
database that the release has not created yet and the install ends in
`DeadlineExceeded`. `distro.sh` clears those annotations so the Jobs become
ordinary resources, created in the same phase as the database; `backoffLimit`
covers the seconds while PostgreSQL starts, so the first attempts failing is by
design rather than a fault.

The nulls have to be passed on the command line:

```
--set initJob.annotations=null --set setupJob.annotations=null
```

Setting `initJob.annotations: {}` in `values.yaml` does **not** work. Helm
coalesces maps, so an empty map leaves the chart's defaults in place and the
hook survives — the install fails exactly as before, with nothing in the values
file to suggest why.

Storage is `emptyDir` on purpose. A volume that outlives the demo carries one
run's state into the next learn window, and a profile recorded over an
already-initialised database looks nothing like one recorded over first-run
migrations.

## 3. Drive real work

A profile is only worth as much as the behaviour it saw. An idle ZITADEL opens
its config, connects to PostgreSQL and waits — learn from that and the first
real login is an anomaly.

```
bobctl test --functional-tests example/zitadel/functional-tests.yaml -n zitadel
```

Nine benign requests across the OIDC discovery surface, the signing keys, the
console and the health endpoints. All nine pass against a fresh install.

### The Host header is load-bearing

ZITADEL routes on the `Host` header and compares it to `ExternalDomain`.
Addressed by ClusterIP without it, the entire OIDC surface answers **404** while
the server is perfectly healthy — `/debug/healthz` returns 200 the whole time.

This is worth knowing because it is quiet in the worst way: a 404 is a real
response, so the request "worked". It reads as a missing endpoint rather than as
a wrong-vhost request.

It also bit `bobctl` itself. Go's `net/http` ignores a `Host` entry in the
header map — the Host on the wire comes from `req.Host` — so a suite naming it
as an ordinary header had it silently dropped. Fixed in all three request paths
(`attack/suite_runner.go`, `autotune/benign.go`, `autotune/functest_runner.go`),
with `TestHostHeaderGoesOnRequestHostNotTheHeaderMap` to keep it fixed.

## 4. Learn

Learning and enforcement are mutually exclusive. While
`kubescape.io/user-defined-profile` is set the component is enforced against
that profile and records nothing, so a re-learn drops the label first:

```
example/zitadel/distro.sh unbind
```

Then drive the workload again and wait for the profiles to reach
`kubescape.io/completion: complete`.

Read them back **one at a time**:

```
kubectl -n zitadel get containerprofiles -o name | while read -r n; do
  kubectl -n zitadel get "$n" -o yaml > "$(basename "$n").yaml"
done
```

A `List` from the storage API returns objects with the spec stripped — every
profile reads as empty and every count is zero. Fetch each individually or the
measurement is meaningless.

Ignore any profile whose name carries a 32-hex segment: those are per-report
time-series shards holding a partial view, and the consolidated profile is the
one to keep.

## 5. Bind

```
example/zitadel/distro.sh sbob
```

This applies every `sbobs/cp-*.yaml` and **reinstalls** the release with
`values-sbob.yaml`, which carries the labels on the pod templates.

The reinstall is not tidiness. node-agent binds a profile when the container
**starts**, so the label has to be present before the pod exists — labelling a
running workload does nothing. Patching the pod template instead would roll the
StatefulSet, and the database is an `emptyDir` populated once by the setup Job:
rolling it leaves ZITADEL with no schema, `relation "system.encryption_keys"
does not exist`, and a CrashLoopBackOff that looks like an application fault.
Installing with the labels already in place avoids both problems and is the
correct ordering anyway.

`distro.sh unbind` is the same move without the overlay.

## 6. Contrast: benign runs quiet, attacks do not

Run the benign suite; expect no detections. Then run the attack suite and
compare. Split alertmanager by time (`$T0` taken just before the attacks):

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
curl -s localhost:9093/api/v2/alerts | python3 -c '
import json,sys,os
from collections import Counter
a=json.load(sys.stdin); ns="zitadel"; t0=os.environ.get("T0","")
al=[x for x in a if x["labels"].get("namespace")==ns]
fp=[x for x in al if x.get("startsAt","")<t0]
tp=sorted({x["labels"].get("rule_id") for x in al if x.get("startsAt","")>=t0})
print("benign FPs:", len(fp), dict(Counter(x["labels"].get("rule_id") for x in fp)) or "CLEAN")
print("attack TPs (distinct rules):", len(tp), tp)'
```

Attribute by pod as well as by rule. A suite that names the wrong target still
reports detections — they simply land on a neighbouring container while the
component the profile describes is never touched.

## 7. What the profiles turned out to need

Measured, not expected:

- **R0006 is gated on the reading comm, not the path.** A component reads its
  own projected service-account token as normal operation, and the token
  directory rotates, so declaring the path does not silence the rule. The
  component's own comm goes in `rulePolicies.R0006.processAllowed` — and that is
  what makes an attacker's `cat` of the same file stand out.
- **Probes are `httpGet` here**, so they arrive over the network from the node,
  which carries no pod identity. `entity: host` is the only ingress shape that
  can admit them; no `podSelector` will ever match.
- **Declare in-cluster peers by name.** `serviceRefNamespace`/`serviceRefName`
  survives being applied to another cluster; a ClusterIP does not.
- **Leave `/proc` and the secret mounts literal.** Collapsing them is what makes
  a profile quiet and blind at the same time.
- **One learn window is not enough.** Every volatile token needs two distinct
  samples before it can be recognised as volatile. The setup Job runs
  `kubectl get pod zitadel-setup-<random>`, and one recording pins that pod
  name: R0040 fires on the next install and on every install after it. Two
  recordings merged give `kubectl get pod ⋯`. The same applies to the projected
  service-account directory, `..<timestamp>.<serial>`.
- **Never ship a `⋯` next to a sibling `*`.** Storage's trie rewrites the `*` to
  the narrower `⋯`, and the deeper paths the profile declared stop matching:
  `/bitnami/postgresql/data/base/*` was stored as `.../base/⋯` and every
  relation file two levels down raised R0002. `bobctl generalize` now drops the
  redundant `⋯`; the trie itself is fixed in kubescape/storage.

## 8. Cleanup

```
example/zitadel/distro.sh down
```

## Status

Measured on k3s v1.35.4 (bare metal) against node-agent
`entlein/duckling:v0.1.0-rogue26-local` and storage
`ghcr.io/k8sstormcenter/storage:v0.1.0-rogue26-local`:

- the chart installs with its own bundled PostgreSQL, `STATUS: deployed`
- the functional suite passes **9/9**
- **nine** SBoBs bind from container start, one per container
- benign traffic against the bound release produces **0 false positives**
  (down from 33 on the first bind: 25 R0002, 5 R1017, 2 R0040, 1 R1030)
- the database kill-chain raises R0001, R0002, R0006, R0008, R0010, R0040,
  R1000, R1004, R1010 and R1012

Two boundaries, both honest rather than missed:

- `ghcr.io/zitadel/zitadel` is **distroless**. No shell, no coreutils: every
  exec probe in `zitadel-attacks.yaml` fails at the runtime and produces no
  kernel event. The image is the control. The probes stay so that an image
  which regains a shell is caught the first time it is tuned, and the real
  kill-chain lives in `zitadel-postgresql-attacks.yaml` against the database,
  which ships bash, coreutils, curl and psql.
- **R0011 does not fire** on this build even though the database's profile
  declares a single loopback peer. Verified by hand against three reachable,
  undeclared Services; R0007 fired on the apiserver hop from the same `curl`,
  so the events are being evaluated and the CP egress helpers are admitting the
  peer. Tracked as entlein/node-agent#32. Until it is fixed the egress half of
  every SBoB here is written but unenforced.

`zitadel-login` is learned from the traffic the functional suite drives, which
reaches the identity server on 8080 and the login UI only indirectly. Direct
requests to `zitadel-login:3000` exercise Next.js paths the profile has not
seen; extending the suite to drive the login UI is the next piece of work.

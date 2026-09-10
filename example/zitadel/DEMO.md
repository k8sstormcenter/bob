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
| `postgres` | `postgres` | 5432 | the datastore, minimal, `emptyDir` |
| `zitadel` | `zitadel` | 8080 | the API and console |
| `zitadel-login` | `zitadel-login` | 3000 | the login UI, a separate deployment since v4 |

Two Jobs — `zitadel-init` and `zitadel-setup` — run once and exit. They are not
bound to profiles: there is no long-running container to attach one to. What
they do at install time is nevertheless real behaviour, and a profile recorded
across an install will differ from one recorded on a steady-state pod.

### Why PostgreSQL is deployed separately

The chart bundles a PostgreSQL subchart, and using it fails. `zitadel-init` is a
helm **pre-install hook**: it runs before the release's own dependencies are
created, waits for a database that does not exist yet, and the install ends in
`DeadlineExceeded`. Deploying the database first — so it is already serving when
the hook fires — avoids the ordering problem entirely.

It also makes the demo honest: `postgres.yaml` is 40 lines you can read, rather
than a subchart whose surface changes between chart versions.

Storage is `emptyDir` on purpose. A volume that outlives the demo carries one
run's state into the next learn window, and a profile recorded over a database
that was already initialised looks nothing like one recorded over a database
doing its first-run migrations.

## 3. Drive real work

A profile is only worth as much as the behaviour it saw. An idle ZITADEL opens
its config, connects to Postgres and waits — learn from that and the first real
login is an anomaly.

```
kubectl -n zitadel port-forward svc/zitadel 8080:8080 &
kubectl -n zitadel get secret iam-admin -o jsonpath='{.data.iam-admin\.json}' | base64 -d > /tmp/iam-admin.json
```

Exercise, at minimum: the console loads, a login round-trip through
`zitadel-login`, and a couple of API calls with the service-account key. Each
touches a different part of the process — the login UI, the API, and the
projection machinery that writes to Postgres.

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

This applies each `sbobs/cp-<component>.yaml` and labels the pod template, which
rolls the workload. That roll is required: node-agent binds a profile when the
container **starts**, so editing a profile or labelling a running pod changes
nothing until the container is recreated.

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

## 7. What to expect from the profile

Notes from the other identity-adjacent profiles in this repo, likely to apply
here:

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

## 8. Cleanup

```
example/zitadel/distro.sh down
```

## Status

The deployment, `distro.sh` and this document are verified: ZITADEL installs,
`/debug/healthz` and `/debug/ready` both return 200, and `distro.sh sbob`
resolves all three components and skips cleanly while `sbobs/` is empty.

`sbobs/` is empty — the profiles are the next piece of work. Every number in
§6 and §7 is therefore an expectation, not a measurement, until they exist.

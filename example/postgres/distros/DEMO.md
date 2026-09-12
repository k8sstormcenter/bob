# PostgreSQL-distro SBoB demo — deploy, bind, contrast

Bring up the fork stack from the bob repo root first:

```
make kubescape
make alertmanager
```

On a cluster whose container runtime is not in the default location — k3s with a
`--data-dir` on another partition, for instance — pass the runc that is actually
in use, or node-agent marks the wrong binary, observes no container starts, and
every profile stays empty:

```
make kubescape KS_RUNC=/path/to/runc KS_RUNC_MNT=/the/partition/holding/it
make show-runc          # prints what will be passed
```

Three PostgreSQL packagings, one namespace each. Every fork runs the same
`postgres:18` pg-client pod, so a single portable client SBoB
(`sbobs/cp-pg-client.yaml`) covers the client across all three backends; each
backend gets its own server SBoB. All are bound at deploy time via the `sbob`
toggle.

The client is pinned to 18 because bitnami's chart now ships server 18.6 and
`pg_dump` refuses a server newer than itself — 21 benign tests failed on that
alone. A newer client against the older oss (17) and cnpg (17.5) servers is
supported, so one image still covers all three.

`cp-pg-client.yaml` has NOT been re-recorded since that bump and is still the
17-era profile; binding it produces a large number of client-side alerts. The
server SBoBs below are unaffected — the attacks exec into the server.

| distro  | installer                    | ns               | server service        | server container | server profile                 |
|---------|------------------------------|------------------|-----------------------|------------------|--------------------------------|
| oss     | plain Deployment             | postgres-oss     | postgres              | postgres         | sbobs/cp-postgres-oss.yaml     |
| bitnami | helm bitnami/postgresql      | postgres-bitnami | pg-bitnami-postgresql | postgresql       | sbobs/cp-postgres-bitnami.yaml |
| cnpg    | CloudNativePG operator 1.24  | postgres-cnpg    | pg-rw                 | postgres         | sbobs/cp-postgres-cnpg.yaml    |

## The attacks land on the database

Each suite's `target:` is that fork's server Service and every
`expectedDetections` names that vendor's container. This matters: the three
forks share one `postgres:18` client image, so a suite aimed at the client
measures the same profile three times and reports a "distro contrast" that is
an artefact — the servers are never touched. `TestAttackSuiteTargetsItsSubject`
pins each suite to its subject so this cannot drift back.

A consequence worth knowing when reading assertions: `cat`, `sh` and friends are
in a database image's own baseline, so R0001 does NOT fire for them on the
server the way it does on the thin client. The server-side assertions are
path-side instead — R0010 for `/etc/shadow`, R0006 for the service-account
token. `/etc/passwd` carries no assertion at all: the entrypoint reads it for its
own uid lookup, so it is baseline and nothing about reading it is anomalous.

## Why the server SBoB allowlists R0002 for one comm

A database's data dir is inherently dynamic — WAL segments, per-OID relfiles,
sort/hash spill filesets. Those are multi-level dynamic paths, and bound
unmodified they produce ~1200 R0002 alerts per benign run.

Wildcarding `pgdata` would fix that and would also blind R0002 and R0010 in the
one directory an attacker most wants to write to, for every process. So the
paths stay literal and `rulePolicies.R0002.processAllowed` lists only `postgres`
— the server's own comm. Attack execs run as other comms (`sh`, `cat`, `ln`,
`nc`), so R0002 still fires on them. Measured: R0002 appears in the attack run
and not in the benign one.

## 1. Deploy (+ optionally bind the SBoB)

```
./deploy-distros.sh oss            # deploy only
./deploy-distros.sh oss sbob       # deploy AND bind the server + client SBoBs
```
(swap `oss` for `bitnami` | `cnpg` | `all`)

Binding relabels the workload, which recreates the pod — necessary, because
node-agent binds a profile at container start. The inverse also holds: while
`kubescape.io/user-defined-profile` is set the workload is ENFORCED and does not
learn, so drop the label before recording a new profile.

## 2. Functional (benign) suite — expect no detections

```
bobctl test --functional-tests functional/oss.yaml     -n postgres-oss
bobctl test --functional-tests functional/bitnami.yaml -n postgres-bitnami
bobctl test --functional-tests functional/cnpg.yaml    -n postgres-cnpg
```

## 3. Attack suite — expect detections

```
bobctl attack --attack-suite attacks/oss.yaml     -n postgres-oss
bobctl attack --attack-suite attacks/bitnami.yaml -n postgres-bitnami
bobctl attack --attack-suite attacks/cnpg.yaml    -n postgres-cnpg
```

## 4. Contrast: functional FPs vs attack TPs

Port-forward alertmanager and split alerts by time (`$T0` = a timestamp taken
right before step 3; `NS` = the distro namespace). Filter out the pg-client pod
to see the server alone:

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
curl -s localhost:9093/api/v2/alerts | python3 -c '
import json,sys,os
from collections import Counter
a=json.load(sys.stdin); ns=os.environ["NS"]; t0=os.environ.get("T0","")
al=[x for x in a if x["labels"].get("namespace")==ns
    and not (x["labels"].get("pod_name") or "").startswith("pg-client")]
fp=[x for x in al if x.get("startsAt","")<t0]
tp=sorted({x["labels"].get("rule_id") for x in al if x.get("startsAt","")>=t0})
print("functional FPs:", len(fp), dict(Counter(x["labels"].get("rule_id") for x in fp)) or "CLEAN")
print("attack TPs (distinct rules):", len(tp), tp)'
```

### Measured on postgres-oss

Bound `sbobs/cp-postgres-oss.yaml`, 76/76 benign tests passing:

- **0 functional false positives** on the server
- **17 distinct attack rules**: R0001, R0002, R0005–R0008, R0010, R0011, R0012,
  R0040, R1000, R1001, R1004, R1005, R1008, R1010, R1012
- tune: `missed=0 fp=0`
- contrast (`bobctl contrast --type database`): 22 Separable / 9 Ambiguous /
  **0 Blind**, deviations `execs-procs` and `reads-host-files` — the oss
  entrypoint is a shell toolchain and reads host-provided files, which is
  outside the bare `database` envelope and expected here.

### Measured on postgres-bitnami

- **0 functional false positives** on the server (76/76 benign tests)
- **15 distinct attack rules** — R1005 is absent because the image ships no
  perl, python or compiler, so memfd_create(2) cannot be issued at all
- tune: `missed=0 fp=0`; contrast: 22 Separable / 9 Ambiguous / **0 Blind**
- two SBoB entries beyond the learned profile: `/.pgpass`, read by the
  `pg_isready` exec probe on every cycle, and the runc-init allowlist

### Measured on postgres-cnpg

- **0 functional false positives** on the server (76/76 benign tests)
- **17 distinct attack rules**; tune `missed=0 fp=0`; contrast 22 Separable /
  9 Ambiguous / **0 Blind**

CNPG needs the most declaration of the three, and every entry is a consequence
of its design rather than a concession:

| entry | why |
|---|---|
| `rulePolicies.R0006` allows `manager` | the container is `/controller/manager instance run`; the instance manager reads the service-account token as normal operation |
| `/bin/dash` in `execs` | the instance manager forks a shell in steady state. Note the path: `/bin/sh` is a symlink and node-agent records the resolved target, so an entry naming `/bin/sh` never matches |
| `/controller/manager`, `/controller/log/postgres.json`, `/plugins` | the manager reads its own binary, its log and its plugin dir |
| `/usr/lib/x86_64-linux-gnu/perl-base/⋯` | pulled in by the probe path |
| ingress `entity: host` **plus** `ipAddresses` | the probes are httpGet on :8000, so the kubelet connects over the network and carries no pod identity. `entity: host` alone did not suppress R0012 on this node-agent build; the node IP and CNI gateway are declared as well |

That list is itself the contrast result: packaging an API-speaking control
process inside the database container costs three detections. R0006 and R0007
are baseline there, and `exec-sa-token-attempt` / `k8s-api-unexpected-call`
carry no assertion for cnpg as a result. `exec-drifted-binary` cannot run
either — the image mounts /tmp read-only. All three stay in the suite and
report FAILED, which is the finding, not a gap.

### Side by side

| | oss | bitnami | cnpg |
|---|---|---|---|
| functional FPs | 0 | 0 | 0 |
| distinct attack rules | 17 | 15 | 17 |
| tune | 0/0 | 0/0 | 0/0 |
| contrast Blind | 0 | 0 | 0 |
| attacks that cannot land | — | memfd (no perl/python/cc) | drifted-binary (/tmp ro) |
| rules baseline by design | — | — | R0006, R0007 |

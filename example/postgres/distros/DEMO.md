# PostgreSQL-distro SBoB demo — deploy, bind, contrast

Bring up the fork stack from the bob repo root first:

```
make kubescape
make alertmanager
```

Three PostgreSQL packagings, one namespace each. Every fork runs the SAME
`postgres:17` pg-client pod, so a SINGLE portable client SBoB
(`sbobs/cp-pg-client.yaml`) is the contrast leg across all three backends; each
backend also gets its own server SBoB. All are bound at deploy time via the
`sbob` toggle.

| distro  | installer                    | ns               | server profile               | client profile          |
|---------|------------------------------|------------------|------------------------------|-------------------------|
| oss     | plain Deployment             | postgres-oss     | sbobs/cp-postgres-oss.yaml   | sbobs/cp-pg-client.yaml |
| bitnami | helm bitnami/postgresql      | postgres-bitnami | sbobs/cp-postgres-bitnami.yaml | sbobs/cp-pg-client.yaml |
| cnpg    | CloudNativePG operator 1.24  | postgres-cnpg    | sbobs/cp-postgres-cnpg.yaml  | sbobs/cp-pg-client.yaml |

## Why the server SBoB allowlists R0002

A database's data dir is inherently dynamic — WAL segments, per-OID relfiles,
sort/hash spill filesets — and these are multi-level dynamic paths that the
matcher's single-segment `⋯` cannot express. So the server SBoB constrains what
the server *executes* (R0001) and allowlists R0002 (file access) for the server's
own comm(s): `postgres` for oss, the shell init toolchain for bitnami, and the
mounted instance `manager` (also R1004) for CNPG. Attack execs run as OTHER comms
(sh/nc/curl/whoami/…), so R0001/R1000 and R0002-on-attack-files all still fire —
the contrast is untouched.

## 1. Deploy (+ optionally bind the SBoB)

```
./deploy-distros.sh oss            # deploy only
./deploy-distros.sh oss sbob       # deploy AND bind the server + client SBoBs
```
(swap `oss` for `bitnami` | `cnpg` | `all`)

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
right before step 3; `NS` = the distro namespace):

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
curl -s localhost:9093/api/v2/alerts | python3 -c '
import json,sys,os
from collections import Counter
a=json.load(sys.stdin); ns=os.environ["NS"]; t0=os.environ.get("T0","")
al=[x for x in a if x["labels"].get("namespace")==ns]
fp=[x for x in al if x.get("startsAt","")<t0]
tp=sorted({x["labels"].get("rule_id") for x in al if x.get("startsAt","")>=t0})
print("functional FPs:", len(fp), dict(Counter(x["labels"].get("rule_id") for x in fp)) or "CLEAN")
print("attack TPs (distinct rules):", len(tp), tp)'
```

Verified live on all three forks: **0 functional false positives**, **14 distinct
attack rules** (R0001, R0002, R0005–R0008, R0010, R0011, R1000, R1001, R1005,
R1008, R1010, R1012).

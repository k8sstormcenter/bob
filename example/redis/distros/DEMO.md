# Redis-distro SBoB demo — deploy, bind, contrast

Runs on any k8s (validated on a fresh k3s). First bring up the fork stack from
the bob repo root:

```
make kubescape     # node-agent sbob-rc5s-fpo + storage sbob-rc5s + CEL rules
make alertmanager
```

Each distro is deployed from its **upstream image** — the image the SBoB in
`sbobs/` was learned against — with the `kubescape.io/user-defined-profile` label
baked into the pod and its ContainerProfile applied, so node-agent enforces the
SBoB from pod start. No post-deploy patching.

| distro    | upstream image                | ns         | service | profile                 |
|-----------|-------------------------------|------------|---------|-------------------------|
| redis-oss | redis:8.10.0                  | redis-oss  | redis   | sbobs/cp-redis.yaml     |
| valkey    | valkey/valkey:9.1.1           | valkey     | redis   | sbobs/cp-valkey.yaml    |
| keydb     | eqalpha/keydb:x86_64_v6.3.4   | keydb      | redis   | sbobs/cp-keydb.yaml     |
| dragonfly | dragonflydb/dragonfly:v1.39.0 | dragonfly  | redis   | sbobs/cp-dragonfly.yaml |

## 1. Deploy + bind (one command)

```
./deploy-distros.sh redis      # or valkey | keydb | dragonfly | all
```

## 2. Run the functional (benign) suite — expect NO detections (FPs)

```
bobctl test --functional-tests functional/redis-oss.yaml -n redis-oss
bobctl test --functional-tests functional/valkey.yaml    -n valkey
bobctl test --functional-tests functional/keydb.yaml     -n keydb
bobctl test --functional-tests functional/dragonfly.yaml -n dragonfly
```

## 3. Run the attack suite — expect detections (TPs)

```
bobctl attack --attack-suite attacks/redis-oss.yaml
bobctl attack --attack-suite attacks/valkey.yaml
bobctl attack --attack-suite attacks/keydb.yaml
bobctl attack --attack-suite attacks/dragonfly.yaml
```

## 4. Contrast: functional FPs vs attack TPs

Port-forward alertmanager, split alerts by time (`$T0` = a timestamp taken right
before step 3; `NS` = the distro namespace):

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
NS=redis-oss T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # set before running attacks
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

## Validated result (fresh k3s, 2 nodes, kernel 6.1.167)

Every distro binds at **0 functional FPs**, and the attack suite fires **14
distinct rules** — R0001, R0002, R0004, R0005, R0006, R0007, R0008, R0010, R0011,
R1004, R1005, R1008, R1010, R1012.

| distro    | functional         | functional FPs | attack TPs |
|-----------|--------------------|----------------|------------|
| redis-oss | 86/86              | 0              | 14         |
| valkey    | 86/86              | 0              | 14         |
| keydb     | 84/86 (2 unsupp.)  | 0              | 14         |
| dragonfly | 80/86 (6 unsupp.)  | 0              | 14         |

(keydb/dragonfly "unsupp." = redis commands the distro does not implement — not
false positives.)

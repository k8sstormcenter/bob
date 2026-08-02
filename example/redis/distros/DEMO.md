# Redis-distro SBoB demo — deploy, bind, contrast

Runs on any k8s (validated on k3s). `make kubescape` + `make alertmanager`
(from the bob repo root) must be up first — they install the fork node-agent
(`sbob-rc5s-fpo`) + storage (`sbob-rc5s`) and the CEL rules.

Each distro is installed by its native installer **with the SBoB bind label
baked in** (helm `podLabels` / operator `podMetadata.labels`) and its
ContainerProfile applied, so node-agent enforces the SBoB from pod start.

| distro    | installer                 | ns         | service         | profile               |
|-----------|---------------------------|------------|-----------------|-----------------------|
| redis-oss | bitnami/redis 27.0.18     | redis-oss  | redis-master    | sbobs/cp-redis.yaml   |
| valkey    | bitnami/valkey 6.2.5      | valkey     | valkey-primary  | sbobs/cp-valkey.yaml  |
| keydb     | enapter/keydb 0.48.0      | keydb      | keydb           | sbobs/cp-keydb.yaml   |
| dragonfly | dragonfly-operator 1.6.1  | dragonfly  | dragonfly       | sbobs/cp-dragonfly.yaml |

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

Port-forward alertmanager and split alerts by time. Everything the benign suite
raises is a false positive; everything the attack suite raises is a true
positive. `<ns>` = the distro namespace, `$T0` = a timestamp taken right before
step 3.

```
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
curl -s localhost:9093/api/v2/alerts | python3 -c '
import json,sys,os
from collections import Counter
a=json.load(sys.stdin); ns=os.environ["NS"]; t0=os.environ.get("T0","")
al=[x for x in a if x["labels"].get("namespace")==ns]
fp=[x for x in al if x.get("startsAt","")<t0]
tp=sorted({x["labels"].get("rule_id") for x in al if x.get("startsAt","")>=t0})
print("functional FPs:", len(fp), dict(Counter(x["labels"].get("rule_id") for x in fp)))
print("attack TPs (distinct rules):", len(tp), tp)'
```

On the reference cluster the four SBoBs bind at **0 functional FPs** and the
attack suite fires **13 distinct rules** (R0001, R0002, R0004, R0005, R0006,
R0007, R0008, R0010, R0011, R1004, R1008, R1010, R1012).

> Note: the SBoBs in `sbobs/` were learned against the official distro images.
> `keydb` (eqalpha) and `dragonfly` (dragonflydb) use those same images, so they
> transfer directly. `redis-oss` and `valkey` here use the **bitnami** images,
> whose binaries live under `/opt/bitnami/...` rather than `/usr/local/bin/...`;
> those two SBoBs must be relearned against the bitnami images to reach 0 FPs.

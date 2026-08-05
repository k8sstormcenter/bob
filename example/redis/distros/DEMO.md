# Redis-distro SBoB demo — deploy, bind, contrast

Bring up the fork stack from the bob repo root first:

```
make kubescape
make alertmanager
```

Each distro is installed by its native vendor installer and its SBoB (learned
against that same vendor image) is bound at deploy time via the `sbob` toggle.

| distro    | installer                | ns         | service         | profile                 |
|-----------|--------------------------|------------|-----------------|-------------------------|
| redis-oss | bitnami/redis 27.0.18    | redis      | redis-master    | sbobs/cp-redis.yaml     |
| valkey    | bitnami/valkey 6.2.5     | valkey     | valkey-primary  | sbobs/cp-valkey.yaml    |
| keydb     | enapter/keydb 0.48.0     | keydb      | keydb           | sbobs/cp-keydb.yaml     |
| dragonfly | dragonfly-operator 1.6.1 | dragonfly  | dragonfly       | sbobs/cp-dragonfly.yaml |

## 1. Deploy (+ optionally bind the SBoB)

```
./deploy-distros.sh redis            # deploy only
./deploy-distros.sh redis sbob       # deploy AND bind the SBoB
```
(swap `redis` for `valkey` | `keydb` | `dragonfly` | `all`)

## 2. Functional (benign) suite — expect no detections

The target service is set in each suite; the namespace comes from `-n`.

```
bobctl test --functional-tests functional/redis-oss.yaml -n redis
bobctl test --functional-tests functional/valkey.yaml    -n valkey
bobctl test --functional-tests functional/keydb.yaml     -n keydb
bobctl test --functional-tests functional/dragonfly.yaml -n dragonfly
```

## 3. Attack suite — expect detections

```
bobctl attack --attack-suite attacks/redis-oss.yaml -n redis
bobctl attack --attack-suite attacks/valkey.yaml    -n valkey
bobctl attack --attack-suite attacks/keydb.yaml     -n keydb
bobctl attack --attack-suite attacks/dragonfly.yaml -n dragonfly
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

## 5. Detect a client, then allowlist it by identity (ingress)

`CP=containerprofiles.spdx.softwarecomposition.kubescape.io`

Watch R0012 on redis-master's node-agent:

```
MNODE=$(kubectl -n redis get pod redis-master-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected ingress network"
```

Deploy the client with its own SBoB (so the client's own redis-cli/egress stay
in-profile and don't self-alert). Unlisted on redis-master — R0012 fires:

```
kubectl apply -f sbobs/cp-redis-client.yaml
kubectl apply -f ../client.yaml
```

Allowlist that identity — R0012 stops within ~30s (profile-projection refresh):

```
kubectl -n redis patch $CP redis --type merge -p '{"spec":{"ingress":[{"type":"internal","podSelector":{"matchLabels":{"app":"redis-client"}},"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"redis"}},"ports":[{"name":"TCP-6379","port":6379,"protocol":"TCP"}]}]}}'
```

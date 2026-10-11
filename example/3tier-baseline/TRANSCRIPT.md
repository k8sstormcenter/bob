# 3-tier SBoB demo — run transcript

Verified end-to-end on iximiuz rig `6a8daa5187978ac310d36286` (k3s v1.36.3, 2 nodes,
kernel 6.1.167), 2026-08-25, against bob `main` at `1bba96b` (post-#208 merge,
images `net-v2s-f6fa47d6`, chart 1.40.3). Every command below was actually executed.

```bash
export RIG=100.75.160.122
export KEY=~/.ssh/iximiuz_labs_user
r() { ssh -i $KEY -o StrictHostKeyChecking=no laborant@$RIG "$@"; }
```

## 1. Ship the bundle

```bash
scp -i $KEY -r 3tier-sbobs laborant@$RIG:~/3tier
r 'git clone -q https://github.com/k8sstormcenter/bob.git ~/bob'
```

## 2. kubescape + alertmanager

```bash
r 'cd ~/bob && make kubescape'   # main carries net-v2s-f6fa47d6 since #208 merged
r 'kubectl -n honey rollout status ds/node-agent --timeout=420s'
r 'cd ~/bob && make alertmanager'
```

node-agent restarts once while storage comes up — expected, wait for the rollout.

## 3. kyverno

```bash
r 'helm repo add kyverno https://kyverno.github.io/kyverno/ && helm repo update'
r 'helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait --timeout 8m'
```

## 4. SBoB library

ContainerProfiles are **namespaced**; node-agent resolves the
`kubescape.io/user-defined-profile` label in the pod's own namespace. They live in
`sbob-library` and Kyverno clones them everywhere.

```bash
r 'kubectl create namespace sbob-library'
r 'cd ~/3tier && for f in cp-tier-*.yaml; do
     sed "0,/^  namespace:/{s/^  namespace: .*/  namespace: sbob-library/}" "$f" | kubectl apply -f -
   done'
r 'kubectl -n sbob-library get containerprofiles'
```

```
tier-backend  tier-database  tier-frontend  tier-middleware  tier-unclassified
```

## 5. Policies

**RBAC first** — without it the clone policy is rejected at admission:

```
admission webhook "validate-policy.kyverno.svc" denied the request:
  system:serviceaccount:kyverno:kyverno-admission-controller requires permissions
  list,get for resource spdx.softwarecomposition.kubescape.io/v1beta1/ContainerProfile
```

```bash
r 'cd ~/3tier && kubectl apply -f kyverno/00-kyverno-rbac.yaml'   # aggregated ClusterRole
r 'cd ~/3tier && kubectl apply -f kyverno/01-clone-profiles.yaml'
r 'cd ~/3tier && kubectl apply -f kyverno/02-label-tiers.yaml'
```

Both policies accepted. Kyverno warns that `ClusterPolicy` is deprecated in favour of
`MutatingPolicy`/`GeneratingPolicy` — works today, worth migrating later.

### Two syntax fixes found by running it

| symptom | cause | fix |
|---|---|---|
| clone policy denied at admission | Kyverno holds no RBAC on third-party CRDs | `ClusterRole` labelled `rbac.kyverno.io/aggregate-to-{admission,background,reports}-controller: "true"` |
| `invalid JMESPath query … invalid character ','` | `` join(`,`, @) `` — backticks are JSON literals, `` `,` `` is not valid JSON | precompute in `context:` with `join(',', request.object.spec.containers[].image)` and reference the variable |

## 6. Deploy the AI-generated app

```bash
r 'kubectl create namespace vibe-app'
r 'kubectl -n vibe-app get containerprofiles'    # clones appear automatically
r 'cd ~/3tier && kubectl apply -f app.yaml'
```

Clones landed without intervention:

```
tier-database  tier-backend  tier-middleware  tier-frontend  tier-unclassified
```

## 7. Classification result

```bash
r 'kubectl -n vibe-app get pods -o custom-columns="POD:.metadata.name,\
TIER:.metadata.labels.app\.kubernetes\.io/tier,\
PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,\
IMAGE:.spec.containers[0].image"'
```

```
POD           TIER           PROFILE             IMAGE
api-…         backend        tier-backend        python:3.12-slim
cache-…       database       tier-database       redis:7-alpine
db-…          database       tier-database       postgres:16
frontend-…    frontend       tier-frontend       nginx:1.27
worker-…      unclassified   tier-unclassified   busybox:1.36
```

All five classified correctly at admission, including `busybox` (no known image, no
known port) falling through to `unclassified`.

## 8. Exercise the anti-patterns

Use a heredoc, NOT nested `ssh "... exec ... bash -c \"...\""`. The nested-quote form
silently mangles `/dev/tcp/...` and the connection never happens — the first attempt in this
run produced no alert for that reason, which looked like a detection gap and was not one.

```bash
ssh -i $KEY laborant@$RIG bash -s <<'EOS'
DBIP=$(kubectl -n vibe-app get pod -l app=db -o jsonpath='{.items[0].status.podIP}')
FE=$(kubectl -n vibe-app get pod -l app=frontend -o name | head -1)

# 1. frontend -> database directly (tier skip)
for i in 1 2 3 4 5 6; do
  kubectl -n vibe-app exec $FE -- bash -c "exec 3<>/dev/tcp/$DBIP/5432 && echo connected >&2"
  sleep 2
done

# 2. database -> internet (exfil shape)
DB=$(kubectl -n vibe-app get pod -l app=db -o name | head -1)
for i in 1 2 3; do
  kubectl -n vibe-app exec $DB -- bash -c 'exec 3<>/dev/tcp/1.1.1.1/443 && echo connected >&2'
  sleep 2
done

# 3. cache -> internet
CA=$(kubectl -n vibe-app get pod -l app=cache -o name | head -1)
kubectl -n vibe-app exec $CA -- sh -c 'wget -q -T2 -O- http://1.1.1.1 >/dev/null'
EOS
```

Observed output — 6/6 connections established, which is what makes the alert trustworthy:

```
frontend=pod/frontend-5d5d669787-9hn7r  db=10.42.1.12
/usr/bin/bash
/usr/bin/curl
connected
connected
connected
connected
connected
connected
```

Note `curl` is present in the stock `nginx:1.27` image — itself a finding the frontend SBoB
flags via R0001, since a web server has no need to fetch.

## 9. Read the review

```bash
r 'cd ~/3tier && ./demo.sh alerts vibe-app'
# or raw:
r 'kubectl logs -n honey -l app.kubernetes.io/component=node-agent -c node-agent --since=15m \
   | grep RuleID | grep vibe-app | grep -o "\"RuleID\":\"[^\"]*\"" | sort | uniq -c | sort -rn'
```

## Results — verified on the rig

**Tier-skip detected from BOTH ends — the headline finding.**

Pod IPs at the time of the run:

```
POD                         TIER           PROFILE             IP           IMAGE
api-68778468b4-xpfdm        backend        tier-backend        10.42.1.18   python:3.12-slim
cache-7fc68fcd4f-hgtjc      database       tier-database       10.42.1.17   redis:7-alpine
db-fbff4859-lgdct           database       tier-database       10.42.0.16   postgres:16
frontend-5d5d669787-6fqm7   frontend       tier-frontend       10.42.1.16   nginx:1.27
worker-6766f5ffb-dggqj      unclassified   tier-unclassified   10.42.0.15   busybox:1.36
```

Alerts (node-agent, `vibe-app`):

```
R0011  frontend [web]       Unexpected egress network communication to: 10.42.0.16:5432 using TCP from: web
R0012  db       [postgres]  Unexpected ingress network communication from: 10.42.1.16:5432 using TCP to: postgres
R0001  frontend [web]       Unexpected process launched: bash with PID 13610
```

The two network alerts are the **same TCP connection seen from opposite ends**, and the pod
IPs line up exactly:

| | pod | IP | rule |
|---|---|---|---|
| sender | `frontend` (nginx) | `10.42.1.16` | R0011, peer `10.42.0.16:5432` |
| receiver | `db` (postgres) | `10.42.0.16` | R0012, peer `10.42.1.16` |

The two pods sat on different nodes, so this is also a cross-node correlation. `tier-frontend`
lists only DNS + backend ports in egress; `tier-database` accepts ingress from the backend tier
only. One developer shortcut, two independent sensors, two corroborating alerts.

**Full tally over the run** (`vibe-app`, 25 min window):

| rule | hits | reading |
|---|---|---|
| R0002 file access anomalies | 17 | stock images touching paths outside the tier baseline |
| R0012 unexpected ingress | 1 | db accepted a connection from the frontend — tier skip, receiving end |
| R0011 unexpected egress | 1 | frontend→db:5432 — tier skip, sending end |
| R0001 unexpected process | 1 | `bash` inside the nginx container |

The `db → 1.1.1.1:443` attempt ran in the same window but did not produce its own R0011 on
this run. Do not claim it as observed evidence; the tier-skip pair is what this run proves.

**Rule wiring on this rig** (bob `main` default-rules):

```
R0011: event.pktType == 'OUTGOING'
       && !event.dstAddr.startsWith('127.')
       && !cp.was_address_port_protocol_in_egress(containerId, dstAddr, dstPort, proto)
       && !cp.was_selector_in_egress(containerId, dstNamespace, dstPodLabels)
```

The **loopback-only guard** is what makes tier-skip detection possible at all — pod IPs are
RFC1918, so an `is_private_ip` guard would have silently excluded the frontend→DB connection
and the demo's central alert would never fire. Confirmed empirically: db pod IP was
`10.42.1.12`.

## Observations for the next run

- **`redis` classifies as `database`, not `middleware`.** The image regex lists redis under
  the data tier. Correct for redis-as-store, wrong for redis-as-cache/broker. Decide per
  deployment; move `redis|valkey|keydb|memcached` to the middleware regex if the cache case
  dominates.
- **The api pod CrashLoops** in this sample manifest (deliberately sloppy inline python).
  A CrashLooping container still gets classified but produces few runtime alerts.
- **Profiles bind at container start.** node-agent had been rolled out mid-session; the first
  attempt at this run exercised pods that predated the rollout and produced R0002 only — no
  network alerts at all. Recreating the namespace *after* `rollout status ds/node-agent`
  returned made R0011/R0012 fire immediately. If the network rules are silent, check the pod
  start time against the node-agent pod start time before looking for anything cleverer.
- **Check the rules object, not a rules list.** `kubectl get rules.kubescape.io -A` returns a
  single object `honey/default-rules` whose `.spec.rules` holds all 31 entries. Verify with:
  ```bash
  kubectl get rules.kubescape.io -n honey default-rules -o json \
    | jq '.spec.rules[] | select(.id=="R0011" or .id=="R0012") | {id,enabled,severity}'
  ```
  Expected on `main`: both `enabled: true`, `severity: 8`.
- **`make kubescape` is not idempotent.** `kubectl apply` claims client-side field ownership of
  `.spec.rules`, so a later `helm upgrade` leaves stale severities behind. Force it with
  `kubectl apply --server-side --force-conflicts -f kubescape/default-rules.yaml`.
- `ClusterPolicy` is deprecated in current Kyverno; migrate to `MutatingPolicy` /
  `GeneratingPolicy` before this becomes a maintained demo.

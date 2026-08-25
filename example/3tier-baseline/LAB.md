---
kind: tutorial
title: "Let an AI build it — then let the cluster review the architecture"
description: |
  An AI writes you a three-tier app. It deploys, it runs, it looks fine.
  In this lab you make the cluster tell you what is actually wrong with it —
  without reading a single line of the generated YAML.
categories: [kubernetes, security]
tagz: [kubescape, kyverno, ebpf, runtime-security, architecture]
playground:
  name: k3s-single-node          # 2 nodes also fine; needs a real kernel for eBPF
createdAt: 2026-08-25
difficulty: medium
duration: 45m
---

# Let an AI build it — then let the cluster review the architecture

## Why this lab exists

Anyone can now produce a working Kubernetes app in one prompt. What no prompt gives you
is a review: *is the frontend talking straight to the database? does the database phone
home? is everything running as root?*

Those questions are usually answered by a human reading YAML. In this lab the **cluster**
answers them, at runtime, by watching what the containers actually do.

The mechanism: a small set of **behavioural profiles** — one per architectural tier — that
are broad about technology (any language, any database) and strict about architecture.
Anything a container does outside its tier's profile becomes an alert, and each alert reads
as a design review comment.

**By the end you will have:** deployed an AI-written app you did not inspect, and produced a
list of its architectural defects from runtime evidence alone.

---

## Task 1 — Install the runtime sensor

`kubescape`'s node-agent watches every container with eBPF: which processes execute, which
files open, which network peers are contacted, which Linux capabilities are used.

```bash
git clone https://github.com/k8sstormcenter/bob.git ~/bob
cd ~/bob
make kubescape
make alertmanager
kubectl -n honey rollout status ds/node-agent --timeout=420s
```

**Check:** four pods running in `honey`, and both network rules armed.

```bash
kubectl get pods -n honey
kubectl get rules.kubescape.io -n honey default-rules -o json \
  | jq '.spec.rules[] | select(.id=="R0011" or .id=="R0012") | {id,enabled,severity}'
```

Both must come back `enabled: true`, `severity: 8`. These are the two rules the lab turns on:
`R0011` sees a connection **leave**, `R0012` sees one **arrive**. Both are guarded on
**loopback only** — a guard of `is_private_ip` would exclude all pod-to-pod traffic, and
pod-to-pod is exactly what this lab is about.

> **Wait for the rollout before you deploy anything.** Profiles are attached when a container
> *starts*. A pod that was already running when node-agent came up gets file alerts but no
> network alerts, which looks exactly like a broken lab.

---

## Task 2 — Install the admission controller

Kyverno will do two jobs: copy the profiles into every namespace, and label each pod with the
tier it belongs to — *at admission time*, before the pod starts.

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/ && helm repo update
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait
```

---

## Task 3 — Load the tier profiles

Five profiles: `frontend`, `backend`, `middleware`, `database`, and `unclassified`.

```bash
kubectl create namespace sbob-library
cd example/3tier-baseline
for f in sbobs/cp-tier-*.yaml; do
  sed "0,/^  namespace:/{s/^  namespace: .*/  namespace: sbob-library/}" "$f" | kubectl apply -f -
done
kubectl -n sbob-library get containerprofiles
```

Open `cp-tier-frontend.yaml` and read the header. Notice what is **missing**:

* `capabilities: []` — a web server should need no Linux capability at all
* no database ports in `egress` — a frontend has no business reaching Postgres
* no `apt`/`npm`/`pip`/`curl` in `execs` — no installing or fetching at runtime
* `/etc/passwd`, `/etc/hosts` … are listed **individually**, never as `/etc/⋯`

> **That last one is not style.** The profile is an allowlist matched with wildcards, so an
> `/etc/⋯` entry would also match `/etc/shadow` and silently switch off the rule that protects
> it. Generous wildcards above sensitive paths disable your own detection.

---

## Task 4 — Wire up admission

```bash
kubectl apply -f kyverno/00-kyverno-rbac.yaml     # Kyverno needs rights on the CRD
kubectl apply -f kyverno/01-clone-profiles.yaml   # copy profiles into every namespace
kubectl apply -f kyverno/02-label-tiers.yaml      # classify pods into tiers
kubectl get clusterpolicy
```

> **Why the RBAC file?** Kyverno holds no permissions on CRDs it did not install. Without it
> the clone policy is rejected outright:
> `requires permissions list,get for resource …/ContainerProfile`.

> **Why clone at all?** ContainerProfiles are **namespaced**, and node-agent looks the profile
> up in *the pod's own namespace*. If it is not there the container gets **no profile** and
> silently goes unwatched — it does not fall back to anything.

---

## Task 5 — Get an app from an AI

Open any chat assistant and paste:

> Build me a flashy 3-tier web app for Kubernetes: a React frontend, a Python API, and a
> Postgres database. Give me the complete deployment YAML, ready to `kubectl apply`.
> Make it look good.

Save the answer as `app.yaml`. **Do not read it. Do not fix it.** That is the experiment.

(A pre-generated `app.yaml` is included if you would rather skip this step.)

---

## Task 6 — Deploy it

```bash
kubectl create namespace vibe-app
kubectl -n vibe-app get containerprofiles      # clones arrive by themselves
kubectl -n vibe-app apply -f app.yaml
```

Now look at what admission decided — nobody labelled these pods by hand:

```bash
kubectl -n vibe-app get pods -o custom-columns=\
'POD:.metadata.name,TIER:.metadata.labels.app\.kubernetes\.io/tier,\
PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,IMAGE:.spec.containers[0].image'
```

```
POD           TIER           PROFILE             IMAGE
api-…         backend        tier-backend        python:3.12-slim
cache-…       database       tier-database       redis:7-alpine
db-…          database       tier-database       postgres:16
frontend-…    frontend       tier-frontend       nginx:1.27
worker-…      unclassified   tier-unclassified   busybox:1.36
```

Classification is image-name first, container-port second. `busybox` matched neither, so it
landed in `unclassified` — a deliberately strict profile, because a workload nobody can
classify is exactly the one you want to hear about.

**Question for the room:** `redis` was classified as `database`. Is that right? It is a
*cache* here. Where would you draw the line, and does it change what it is allowed to do?

---

## Task 7 — Use the app the way a user would (and the way an attacker would)

```bash
DBIP=$(kubectl -n vibe-app get pod -l app=db -o jsonpath='{.items[0].status.podIP}')
FE=$(kubectl -n vibe-app get pod -l app=frontend -o name | head -1)
DB=$(kubectl -n vibe-app get pod -l app=db -o name | head -1)

# the shortcut a hurried developer takes: frontend queries the DB directly
for i in 1 2 3; do
  kubectl -n vibe-app exec $FE -- bash -c "exec 3<>/dev/tcp/$DBIP/5432 && echo connected >&2"
  sleep 2
done

# the database reaches out to the internet
kubectl -n vibe-app exec $DB -- bash -c 'exec 3<>/dev/tcp/1.1.1.1/443 && echo connected >&2'
```

Wait about a minute — profiles are evaluated as events arrive.

---

## Task 8 — Read the review

```bash
cd ~/bob/example/3tier-baseline && ./demo.sh alerts vibe-app
```

Or straight from the sensor:

```bash
kubectl logs -n honey -l app.kubernetes.io/component=node-agent -c node-agent --since=15m \
  | grep RuleID | grep vibe-app | grep -o '"RuleID":"[^"]*"' | sort | uniq -c | sort -rn
```

You should see something like:

```
R0011  frontend [web]       Unexpected egress network communication to: 10.42.0.16:5432 using TCP from: web
R0012  db       [postgres]  Unexpected ingress network communication from: 10.42.1.16:5432 using TCP to: postgres
R0001  frontend [web]       Unexpected process launched: bash with PID 13610
```

Now match the addresses against the pods:

```bash
kubectl -n vibe-app get pods -o custom-columns='POD:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName'
```

The `10.42.0.16` in the frontend's alert is the **db** pod. The `10.42.1.16` in the db's alert
is the **frontend** pod. Same TCP connection, two sensors, two pods — often on two different
nodes.

### What each alert is telling you

| Alert | The architectural finding | The fix |
|---|---|---|
| `R0011` on **frontend**, peer = a DB port | the middle tier was skipped; the browser-facing pod holds database credentials | route through the API |
| `R0012` on **database**, peer = frontend | the *same* violation seen from the receiving end | route through the API |
| `R0011` on **database**, peer = internet | a database initiating outbound traffic — the shape of exfiltration | nothing legitimate needs this |
| `R0011` on **backend**, peer = unlisted host | an undeclared third-party dependency, or a library phoning home | declare it, or drop it |
| `R0006` any tier but backend | the workload read its cluster credentials | `automountServiceAccountToken: false` |
| `R0005` name outside the learned set | an undeclared dependency being resolved | declare it, or drop it |
| `R0001` `apt`/`pip`/`npm` | packages installed at container start — unpinned supply chain | bake it into the image |
| `R0002` | files touched outside the tier baseline | usually a stock image being chatty; tune or switch image |

**Notice the pair.** The frontend→database mistake produces *two* alerts from two different
pods: `R0011` where it starts and `R0012` where it lands. Detection you can corroborate from
both ends is much harder to argue away than a single log line.

---

## Task 9 — Find the limit of what runtime can tell you

Stock images ask for far more privilege than they need. Compare:

```bash
crane config docker.io/library/nginx:latest | jq '.config.User, .config.Entrypoint'
crane config cgr.dev/chainguard/nginx:latest | jq '.config.User, .config.Entrypoint'
```

| | stock `nginx` | Chainguard `nginx` |
|---|---|---|
| `User` | *empty* → **root** | `65532` → non-root |
| `Entrypoint` | `/docker-entrypoint.sh` (a shell script) | `/usr/sbin/nginx` (the binary) |
| shell / package manager | present | **absent** |
| files in image | tens of thousands | **203** |

Stock nginx runs as root and drops privileges, which is why it needs `CHOWN`, `SETUID` and
`SETGID`. `tier-frontend` declares `capabilities: []`. So you would expect an alert.

**Check whether you got one:**

```bash
kubectl logs -n honey -l app.kubernetes.io/component=node-agent -c node-agent --since=30m \
  | grep -c R0004
```

You will get `0`. Now look at why:

```bash
kubectl get rules.kubescape.io -n honey default-rules -o json \
  | jq '.spec.rules[] | select(.id=="R0004") | {id,enabled,isTriggerAlert}'
```

```json
{ "id": "R0004", "enabled": true, "isTriggerAlert": false }
```

`R0004` is enabled and evaluated — and it never raises an alert by itself. The profile's
`capabilities` list documents intent and enriches other findings, but it produces no feedback.
`R0007 Workload uses Kubernetes API unexpectedly` is the same.

**This is the most useful thing in the lab.** A control you believe is running, that is switched
on, that quietly reports nothing, is worse than one you know you do not have — because you will
write a policy that depends on it. Capability posture must be checked *statically*
(`kubescape scan framework NSA` → `C-0013`, `C-0016`, `C-0017`, `C-0046`).

```bash
kubectl get rules.kubescape.io -n honey default-rules -o json \
  | jq -r '.spec.rules[] | select(.enabled and (.isTriggerAlert|not)) | .id + "  " + .name'
```

Everything that command lists is a blind spot. Know them before you rely on them.

---

## Discussion

1. **Internal vs external.** Traffic to the internet is treated as serious. Should pod-to-pod
   traffic be treated as *less* serious? Consider that stolen credentials, a poisoned
   dependency, or an over-permissioned AI agent all start *inside* the cluster.
2. **Who owns the alert?** `R0011` on the frontend is not a security incident — it is a design
   defect. Does it go to the security team or to whoever wrote the prompt?
3. **The unclassified tier.** We gave unknown workloads a *strict* profile rather than none.
   What is the failure mode of the other choice?
4. **Cost of being broad.** These profiles allow ~110 syscalls and dozens of paths so they fit
   any stack. What does that breadth cost you in detection, and where would you tighten first?

---

## Teardown

```bash
kubectl delete namespace vibe-app
```

## What to take away

- A behavioural profile can encode **architecture**, not just security posture.
- Detection is only as good as the allowlist above it: one `/etc/⋯` wildcard would have
  switched off the sensitive-file rule entirely.
- The interesting alerts here were not intrusions. They were **design review comments**
  that nobody had to write.

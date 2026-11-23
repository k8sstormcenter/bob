# Three-tier baseline SBoBs — architecture feedback, not just detection

Deliberately **broad** SBoBs — `tier-frontend`, `tier-backend`, `tier-middleware`, `tier-database`,
`tier-unclassified` — that fit almost any stack a non-specialist would assemble, and fire only when
the architecture itself is off-best-practice.

The inversion: a normal SBoB is learned from *one* workload and is tight by construction. These are
authored to be loose on everything that legitimately varies by technology (which language, which
web server, which database) and tight only on the handful of things that are wrong regardless of
stack. **Every alert should be readable as a design review comment.**

## Quickstart

```bash
cd example/3tier-baseline
./demo.sh setup            # kubescape + alertmanager + kyverno + the tier SBoBs
./demo.sh deploy app.yaml  # kyverno classifies each pod and binds a profile at admission
./demo.sh attack           # frontend talks straight to the database
sleep 90
./demo.sh scan             # kubescape CLI conformance scan of the cluster
./demo.sh review           # both halves, as actions an agent can apply
```

`review` reads runtime evidence from alertmanager and manifest defects from the scan, and
writes `verdict-<namespace>.json`. Run it **soon after** `attack` — alertmanager expires
alerts, and expired runtime evidence quietly shrinks the observed section.

Two smaller entry points if you want the pieces on their own:

```bash
./scan.sh flashy-product AllControls   # install the CLI if needed, scan, summarise
./scan-failures.py /tmp/AllControls-flashy-product.json --summary
./scan-failures.py /tmp/AllControls-flashy-product.json --control C-0012
./review.py flashy-product --scan /tmp/AllControls-flashy-product.json --json verdict.json
```

`app.yaml` is a stand-in for whatever an AI hands you. Replace it with a generated manifest and do
not sanitise it — that is the experiment. `LAB.md` is the same material as a classroom walkthrough;
`TRANSCRIPT.md` is the verbatim record of a verified run.

## What it catches

The headline result, observed end to end on k3s against this repo's `main`:

```
R0011  frontend [web]       Unexpected egress network communication to: 10.42.0.16:5432 using TCP from: web
R0012  db       [postgres]  Unexpected ingress network communication from: 10.42.1.16:5432 using TCP to: postgres
```

`10.42.1.16` is the frontend pod, `10.42.0.16` is the database pod — one TCP connection, reported
independently from both ends, on two different nodes. `R0011` and `R0012` must both be enabled for
this; on `main` they are, at severity 8, guarded on loopback only. An `is_private_ip` guard would
exclude all pod-to-pod traffic and this alert pair could never fire.

## Layout

```
sbobs/              the five tier profiles
kyverno/            00 RBAC · 01 clone profiles into every namespace · 02 classify pods into tiers
adr/                the decisions the profiles encode, each with how it is verified
app.yaml            sample three-tier app (nginx / python / postgres / redis / busybox)
demo.sh             setup | deploy | attack | scan | review | show | alerts | reset
scan.sh             install the kubescape CLI, scan the cluster, write JSON
scan-failures.py    explore a raw scan: --summary, --sev, --control, --resource
review.py           the verdict: runtime evidence + scan, as agent-applicable actions
verdict.sample.json a real verdict from the run described above
```

## Bind

```yaml
metadata:
  labels:
    app.kubernetes.io/tier: frontend        # | backend | middleware | database   (drives the selectors)
    kubescape.io/user-defined-profile: tier-frontend
```

Each profile ships with `metadata.namespace: CHANGEME`. `demo.sh setup` rewrites it to
`sbob-library`; if you apply them by hand, set it yourself.

ContainerProfiles are **namespaced**, and node-agent resolves that label in the pod's *own*
namespace. If the profile is absent there the container gets no profile at all and goes unwatched,
silently. `kyverno/01-clone-profiles.yaml` is what makes this work across namespaces; without it the
demo produces nothing and looks broken.

## The feedback table

| Alert you get | What it actually means | Fix |
|---|---|---|
| **R0011** egress, frontend → 5432/3306/27017/6379 | frontend talks straight to the DB; the middle tier was skipped and the browser-facing process holds DB credentials | route through the backend |
| **R0011** egress, database → anywhere but DNS/replicas | a DB initiating outbound is the shape of exfiltration | nothing legitimate needs this; investigate |
| **R0011** egress, backend → unlisted external host | an undeclared third-party dependency, or a library phoning home | add it explicitly, or drop the dependency |
| **R0005** DNS for a name outside the learned set | an undeclared dependency being resolved; usually pairs with the R0011 that follows it | declare it, or remove the call |
| **R0001** exec of `apt`/`apk`/`pip`/`npm` | installing packages at container start | bake into the image; runtime installs are unpinned supply chain |
| **R0001** exec of `curl`/`wget`/`nc` in the DB tier | classic ingress-tool-transfer / exfil step | remove the tool from the image |
| **R0001** exec of `psql`/`mysql` in the backend | debug workflow left in production | apps talk over the wire, not via vendor CLIs |
| **R0006** serviceaccount token read by frontend | frontend has cluster credentials it cannot need | drop `automountServiceAccountToken` |
| **R0010** `/etc/shadow` read | credential access in any tier | never legitimate |
| **R0012** ingress, database ← `tier: frontend` | the same tier violation seen from the receiving end; pairs with the frontend's R0011 | route through the backend |

## Why the capability lists look strict

Measured from **real recordings**, not assumption:

| image | capabilities actually requested |
|---|---|
| `nginx` (stock) | `CHOWN, DAC_OVERRIDE, SETGID, SETPCAP, SETUID, SYS_ADMIN` |
| `redis`, `valkey` (bitnami) | `CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, NET_ADMIN, SETGID, SETPCAP, SETUID, SYS_ADMIN` |
| `keydb` | `NET_ADMIN, SETGID, SETPCAP, SETUID, SYS_ADMIN` |

The database tier keeps only the privilege-drop set (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`,
`SETUID`) plus `IPC_LOCK` for Redis-family memory locking — without those, mainstream images cannot
start at all. Frontend and backend are `capabilities: []`.

### The capability alert is real — but you will not see it in `kubectl logs`

Stock `nginx` does trip `R0004` against `capabilities: []`. Measured on the frontend pod:

```
Unexpected capability used: CAP_SETPCAP in syscall read with PID 135767
Unexpected capability used: CAP_SYS_ADMIN in syscall read with PID 135767
Unexpected capability used: CAP_SETUID in syscall read with PID 135767
```

Exactly the privilege-drop set the table above predicts, because the image starts as root and
drops. The fix is the non-root variant, not a wider profile.

**But those six events appear only in alertmanager.** In the same window, node-agent's stdout
contained zero R0004 — zero by RuleID, zero by rule name, zero by message text — while R0002
appeared 19 times.

```bash
# this finds nothing, and proves nothing
kubectl logs -n honey -l app.kubernetes.io/component=node-agent -c node-agent | grep R0004

# this is the real view
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
curl -s localhost:9093/api/v2/alerts | jq -r '.[].labels.rule_id' | sort | uniq -c
```

`R0004`, `R0007`, `R1009` and `R1016` carry `isTriggerAlert: false`. That flag is a field on the
exported alert payload, not a switch that stops the alert — the stdout exporter applies no filter
on it, and why stdout omits these rules is not established here. The operational consequence is
what matters: **`kubectl logs` is not a complete view of alerts.** `review.py` reads alertmanager
for exactly this reason, and lists these four under `not_visible_in_node_agent_logs`.

An earlier revision of this file claimed R0004 "never alerts on its own", concluded from grepping
logs. That was wrong, and it was wrong in the most expensive way: a control that works, reported
as absent.

## One design decision worth knowing

**`/etc/⋯` is never wildcarded.** Only named files are allowed (`passwd`, `group`, `hosts`,
`resolv.conf`, `nsswitch.conf`, `localtime`, plus `ssl/⋯`, `pki/⋯`, `ca-certificates/⋯`).

This is load-bearing. A ContainerProfile is an allowlist consulted by `ap.was_path_opened`, and the
path matcher treats `⋯` and `*` as wildcards. An `/etc/⋯` entry therefore **matches `/etc/shadow`**
and silently suppresses R0010 — verified directly against `dynamicpathdetector.CompareDynamic`:

```
CompareDynamic("/etc/⋯",  "/etc/shadow") = true
CompareDynamic("/*",      "/etc/shadow") = true
CompareDynamic("/etc/hostname", "/etc/shadow") = false
```

Any generous wildcard placed above a sensitive path disables the rule protecting it. Same reason
`/var/run/⋯` is allowed but `/var/run/secrets/kubernetes.io/serviceaccount/⋯` is listed explicitly
only in the backend tier.

## Scope and honesty about coverage

The engine/port/binary lists cover the mainstream of each tier — the databases and runtimes people
actually reach for — but they are drawn from ecosystem knowledge and the profiles recorded in this
repo, **not** from a scraped ranking of CNCF projects. Treat them as a starting baseline to extend,
not an exhaustive survey.

Deliberately out of scope: service mesh sidecars (Envoy/Istio need `NET_ADMIN` and would need a
fourth profile), batch/ETL workloads, and anything requiring host networking.

## Tuning

These profiles are **learned**, not authored: each was captured from the real image with
`bobctl get | generalize --sbob` and validated. Idle false positives measured on k3s with the
released chart: `web 0, postgres 0, worker 0, api 0, redis 1`.

Those counts are **R0002 counts, and R0002's default changed mid-chart**. Charts up to
`1.41.0-duckling35` ship it enabled; `duckling36` and later ship it **disabled** — ruling D2,
because R0002 judged against partial profiles (node-agent#43), not because of profile noise. The
route back to enabled-by-default is the completion gate, which is a follow-up.

This matters when reading any R0002 number here. On a chart from duckling36 on, leaving it off
would make every count above read `0` — identical to a perfectly tuned profile, and for an
entirely different reason. `demo.sh setup` therefore arms R0002 itself before deploying anything,
the way the component tests do, and the setup check fails loudly if it is not armed.

**There are two switches, not one.** Ruling X-28 also stops node-agent alerting on file opens
while a container is under **deny-all**, since a `find /` in a rogue container floods. Opens
judged against a *governing* profile are untouched, so this example's bound-profile measurements
are unaffected — but anything measured before a profile is in force is not. The full
measurement precondition is therefore both of:

| switch | where | default | needed here |
|---|---|---|---|
| `R0002` `enabled` | `default-rules` Rules CR | off from duckling36 | **on** |
| `denyAllAlertsOnOpens` | node-agent ConfigMap | `false` | **true**, for pre-profile windows |

**Read the second switch off the node-agent build, not off whether the key is set.** Up to
`rogue61` an absent key means deny-all opens alert, so the precondition holds by default. From
`rogue62` the exclusion is in the agent, its default is off, and the chart writes no key at all —
so on `rogue62`+ an absent key means opens are *silent*. The same absence means opposite things
either side of that build:

```
kubectl -n honey get ds node-agent \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="node-agent")].image}'
kubectl -n honey get cm node-agent -o jsonpath='{.data.config\.json}' | grep -o 'denyAllAlertsOnOpens[^,]*'
```

Explicit `true` is measurable on any build and explicit `false` is suppressed on any build. Absent
is only safe below `rogue62`.

Human users should keep both defaults — they exist because the flood is real. These are the
settings a *measurement* needs, not the settings a cluster wants.

If you measure this example by hand, arm R0002 the same way or your zeros mean nothing:

```
kubectl -n honey get rules.kubescape.io default-rules -o json \
  | python3 -c "import sys,json;d=json.load(sys.stdin);[r.update(enabled=True) for r in d['spec']['rules'] if r['id']=='R0002'];json.dump(d,sys.stdout)" \
  | kubectl apply --server-side --force-conflicts -f -
```

1. apply, run the app's real traffic, collect alerts;
2. for each alert decide **"is this my architecture being wrong, or my stack being different?"**;
3. stack difference → add the entry; architecture wrong → fix the architecture.

Step 2 is the whole point. `bobctl tune` automates the mechanical half by folding false positives
into `AllowedProcesses` per rule, but it cannot make that judgement for you.

### `demo.sh attack` generates R0002 by itself — do not tune it away

`attack` drives the violations with `kubectl exec`, and every exec spawns `runc:[2:INIT]` *inside*
the target container. That process reads `/sys/fs/cgroup/cpu.max`, `/proc/sys/kernel/cap_last_cap`,
`/dev/null` and friends, and node-agent attributes all of it to the application container. Measured
on one run: **81 of ~120 R0002 events came from `runc`**, the rest from the `bash`, `cat` and `wget`
the drive itself ran. Idle, the same pods produce ~0.

So a burst of R0002 alongside the network findings is the *harness*, not the app. The tempting fix —
adding `/proc/⋯` or `/sys/⋯` to a profile's `opens` — is exactly the self-disabling wildcard
[ADR-0007](adr/0007-detection-must-not-be-self-disabling.md) forbids: it would switch `R0010` off for
that container. Read the alert's triggering process before treating it as a false positive.

### Learning a profile from a workload that is violating an ADR silently disables that ADR

The API container runs `pip install flask` at startup, which is the ADR-0004 violation. A profile
learned from *that* container contains pip's whole footprint — 107 of 189 `opens` on the first
attempt — so ADR-0004 can never fire against it again. `tier-backend` here is therefore learned from
a compliant python container that only serves HTTP, and the violating one is left as the subject.

It is not limited to file opens, and it is not hypothetical. On a second cluster the profiles were
left to learn while the violations were being driven — the drive ran at 20:58:01–20:58:15, inside the
20:57:49–20:58:19 window that wrote them — and **all three network ADRs landed in the baseline as
permitted egress**:

```
frontend: {"podSelector":{"matchLabels":{"app":"db"}},"ports":[{"port":5432}],"type":"internal"}
db:       {"ipAddress":"1.1.1.1","ports":[{"port":443}],"type":"external"}
worker:   {"dns":"one.one.one.one.","ipAddress":"1.1.1.1","ports":[{"port":443},{"port":80}]}
```

That is ADR-0001, ADR-0002 and ADR-0005 each written in as normal behaviour. `R0011`/`R0012` then
cannot fire on them — not because the agent cannot see the traffic, but because it has been taught to
expect it. The run produced zero alerts on the whole namespace and looked like a detection failure.

So: **never drive a violation during a learning window**, and before trusting any profile, read what
it permits. The profiles shipped here were learned from an idle app and carry no `egress`, `ingress`
or `endpoints` at all, which is why ADR-0001 still fires against them.

Two checks that tell you a profile is bound rather than learned, because a learned one silently
replaces the authored allowlist: every pod must carry `kubescape.io/user-defined-profile`, and
node-agent must log `adopted user-authored ContainerProfile as authoritative base` once per
container. Timestamped per-replicaset profile names mean it is learning.

One trap when checking any of this: `kubectl get containerprofile <name>` — singular — is **not a
resource type**. It errors, and grepping the error text finds nothing, which reads exactly like "the
profile is clean". Use `containerprofiles.spdx.softwarecomposition.kubescape.io`, and fetch by name,
because a `List` returns the objects with `.spec` nulled.

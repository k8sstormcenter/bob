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
./demo.sh alerts           # the review
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
sbobs/            the five tier profiles
kyverno/          00 RBAC · 01 clone profiles into every namespace · 02 classify pods into tiers
app.yaml          sample three-tier app (nginx / python / postgres / redis / busybox)
demo.sh           setup | deploy | attack | show | alerts | reset
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
| **R0004** capability on frontend/backend | container runs as root and drops privileges | use the `-unprivileged` / rootless / distroless variant, bind a port >1024 |
| **R0004** `CAP_SYS_ADMIN`/`NET_ADMIN` on database | stock DB image running root-entrypoint | switch to the non-root image variant |
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

So stock images **will** trip `R0004` against these profiles. That is intended: the alert says
*"this image needs root to start"*, and the fix is the non-root variant. The database tier keeps
only the privilege-drop set (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`) plus `IPC_LOCK`
for Redis-family memory locking — without those, mainstream images cannot start at all.

Frontend and backend are `capabilities: []`. A web server or app server that needs a capability is
telling you something.

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

These are a starting point, and they will over-alert on a first run. Correct workflow:

1. apply, run the app's real traffic, collect alerts;
2. for each alert decide **"is this my architecture being wrong, or my stack being different?"**;
3. stack difference → add the entry; architecture wrong → fix the architecture.

Step 2 is the whole point. `bobctl tune` automates the mechanical half by folding false positives
into `AllowedProcesses` per rule, but it cannot make that judgement for you.

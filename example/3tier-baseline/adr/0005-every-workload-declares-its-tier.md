# ADR-0005 — Every workload declares its tier; an undeclared one is quarantined

**Status:** accepted
**Applies to:** every pod in an application namespace

## Context

The tier decisions in [ADR-0001](0001-strict-tier-layering.md) and
[ADR-0002](0002-data-tier-does-not-initiate-egress.md) are expressed as label selectors. A workload
with no tier label is therefore not merely unlabelled — it is **outside the entire scheme**. It
appears in no other tier's allowlist and no other tier's expectations apply to it.

Worse, the failure is silent. node-agent resolves `kubescape.io/user-defined-profile` against a
ContainerProfile in the pod's **own namespace**. If the label is missing or points at a profile
that is not there, the container ends up with **no profile at all**. It does not fall back to
learning; it is simply not watched. Nothing logs an error at a level anyone reads.

An unclassified workload is also, empirically, the interesting one. Everything recognisable gets
labelled by image name. What falls through is the custom image on a nonstandard port — which is
exactly the thing nobody has reviewed.

## Decision

Kyverno assigns a tier at admission using image name first and container port second. Anything
matching neither is labelled `tier=unclassified` and bound to a deliberately narrow profile:
DNS egress only, **no ingress at all**.

Quarantine, not exemption. An unclassified workload that does anything on the network produces a
finding, and the finding's fix is *"tell the platform what this is"*.

## Verified by

**Admission** — the Kyverno `ClusterPolicy` is a webhook; it cannot be bypassed by the author.
Classification is visible immediately:

```bash
kubectl -n <ns> get pods -o custom-columns=\
'POD:.metadata.name,TIER:.metadata.labels.app\.kubernetes\.io/tier'
```

**Runtime** — `R0011`/`R0012` against the narrow unclassified profile.

## Evidence emitted

```
ADR-0005 VIOLATED
  observed  R0011  worker/main  egress TCP 10.42.0.9:6379
  context   worker matched no known image and no known port → tier=unclassified
  fix       label the workload with app.kubernetes.io/tier so it gets a real profile
```

## Operational note — profile warm-up, measured

Profiles attach when a container **starts**, and network enforcement is not instantaneous. A
container exercised in the first ~90 seconds of its life produces file-access findings while
producing no network findings at all — which looks exactly like a clean result and is not one.

Measured on k3s by driving one identical frontend→database connection every 55 seconds and
correlating alert `startsAt` against pod start time:

| pod age | observed |
|---|---|
| 30–90 s | nothing |
| 151 s | `R0012` only — first network alert |
| 206 s → 537 s | full `R0011` + `R0012` pair, **every round, 1:1** |

So the loop is usable from roughly **2.5 minutes** and reliable from **3.5 minutes**. That is the
floor on feedback latency for anything network-related; budget for it rather than treating an early
clean run as a pass.

Two incidental findings from the same experiment:

* **No de-duplication of network alerts.** Eight identical connections produced eight alert pairs.
  Repeated evidence is available, so the review tool must dedupe on its own side — which is why
  `review.py` collapses on `(decision, container, peer)`.
* File rules (`R0002`) fire well before network rules, so "some findings but no network findings"
  is the specific signature of an under-warm container, not of a clean network posture.

The review tooling therefore never reports "no findings" as a pass. It reports *"nothing observed
in this window"* and says why that is different.

## Consequences

* Classification is heuristic and will be wrong sometimes — `redis` lands in `database` even when
  it is being used as a cache. Wrong-but-visible beats unclassified-and-silent.
* Multi-container pods need per-container profile names (`tier-backend-<containerName>`);
  node-agent only falls back to the bare label for single-container pods.

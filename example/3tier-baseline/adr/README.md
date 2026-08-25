# Architecture Decision Records — and how each one is actually checked

These are the decisions a platform team makes once and then has to enforce forever. They are
written here in the ordinary ADR form, but with one extra section every ADR must carry:

> **Verified by** — the specific check that proves the decision held, and the evidence it emits.

An ADR with no verification is a wish. The point of this directory is that every decision below
resolves to either an admission check, a static control, or an observed runtime event — and the
detector reports the violation **with the evidence attached**, never as generic advice.

## Why evidence and not guidelines

A coding agent handed "follow the principle of least privilege" cannot act. A coding agent handed

```
ADR-0001 VIOLATED
  observed: frontend/web opened TCP 10.42.0.16:5432 at 15:41:07  (node-agent R0011)
  corroborated: db/postgres saw ingress from 10.42.1.16          (node-agent R0012)
  decision: the presentation tier may not reach the data tier
  fix: route the query through the service labelled app.kubernetes.io/tier=backend on 8080
```

can act, and can verify its own fix by re-running the check. Every finding this demo emits carries
the observed event that produced it. **No observation, no finding.** That rule is what keeps the
report honest and is why the report is short.

## Producing a verdict

```bash
# 1. conformance — the whole cluster, every control kubescape ships
kubescape scan framework AllControls --include-namespaces flashy-product \
  --format json --output /tmp/all.json

# 2. runtime evidence + the verdict
kubectl -n honey port-forward svc/alertmanager 9093:9093 &
./review.py flashy-product --scan /tmp/all.json --json verdict.json
```

`AllControls` on this one namespace returns **139 failed control instances** across five
workloads. That is unreadable, and worse, it is *repetitive*: five separate controls
(`C-0004`, `C-0009`, `C-0050`, `C-0268`, `C-0269`) all resolve to the same edit — put
`resources` on the container.

So `review.py` groups by **the fix**, not by the control. 139 instances become 26 actions,
each classified by whether an agent can act on it unaided:

| bucket | count | meaning |
|---|---|---|
| `apply_directly` | 10 | kubescape supplied a concrete value — `runAsNonRoot = true` — patchable as-is |
| `needs_a_decision` | 13 | kubescape supplied `YOUR_VALUE` — how much memory is a judgement only someone who knows the workload can make |
| `remove` | 3 | a field that must go away, e.g. a password sitting in `env` |

The control IDs ride along as provenance, so nothing is lost — but the agent reads 26 rows
instead of 139, and knows immediately which ten it can just do.

### The strongest finding is where the two halves agree

When a manifest defect and a runtime observation describe the same thing, the finding is
promoted to `declared+observed` and sorted to the top:

```json
"path": "spec.template.spec.automountServiceAccountToken",
"value": "false",
"evidence_class": "declared+observed",
"control": "C-0034, C-0190, C-0261",
"confirmed_at_runtime": {
  "rule": "R0006",
  "containers": ["postgres", "web"],
  "evidence": "Unexpected access to service account token: /run/secrets/..."
}
```

The scan says *the manifest permits this*. The detector says *and it happened, twice*. That
pairing is far more actionable than either half alone, and it is the first thing the report
shows.

### One operational constraint

Alertmanager expires alerts. Runtime evidence older than its resolve timeout disappears, and
the reviewer will silently report fewer observations — during development of this tooling,
`R0006` and `R0012` vanished from a verdict for exactly that reason. Run the review shortly
after exercising the app, or persist the alerts elsewhere first.

## The three enforcement points

| Point | When | Mechanism | Can it be evaded by the app author? |
|---|---|---|---|
| **Admission** | before the pod exists | Kyverno mutate/validate | no — it is a webhook |
| **Static** | any time, no runtime needed | `kubescape scan` controls | no, but it only sees the manifest |
| **Runtime** | while the container runs | node-agent + the tier profile | no — it is eBPF below the app |

The three see different things and that difference is the whole design. A manifest can declare
`runAsNonRoot: true` and still have the app open a database connection it should not — static
catches the first, only runtime catches the second.

## The decision set

| ADR | Decision | Verified by | Evidence emitted |
|---|---|---|---|
| [0001](0001-strict-tier-layering.md) | tiers are strictly layered; no tier skipping | **runtime** R0011 + R0012 | both endpoints of the offending connection |
| [0002](0002-data-tier-does-not-initiate-egress.md) | the data tier never initiates outbound traffic | **runtime** R0011 | destination address and port |
| [0003](0003-no-cluster-credentials-in-presentation-tier.md) | the presentation tier holds no cluster credentials | **runtime** R0006 + **static** C-0034 | the token path that was read |
| [0004](0004-images-are-immutable-at-runtime.md) | no package installation after build | **runtime** R0001 | the binary that was executed |
| [0005](0005-every-workload-declares-its-tier.md) | an unlabelled workload is quarantined, not trusted | **admission** Kyverno | the tier assigned and on what evidence |
| [0006](0006-workloads-run-as-non-root.md) | containers do not run as root | **static only** — see the ADR | the manifest field, not a runtime event |
| [0007](0007-detection-must-not-be-self-disabling.md) | profiles may not wildcard above sensitive paths | **review** of the profile itself | the offending allowlist entry |

## One honest limitation, stated up front

ADR-0006 is **static-only**, and not by choice. The runtime rule that would confirm it,
`R0004 Linux Capabilities Anomalies`, ships with `isTriggerAlert: false` — it is evaluated and
enriches other findings, but it never raises an alert by itself. Verified empirically: across 60
minutes on a cluster full of root-entrypoint stock images, R0004 fired **zero** times.

So capability usage cannot be part of the runtime feedback loop as configured. Do not write an ADR
that depends on it and assume runtime will catch the violation — it will not. ADR-0006 is checked
against the manifest instead, and the report says so rather than implying runtime coverage it does
not have.

The same applies to `R0007 Workload uses Kubernetes API unexpectedly`, which is also
`isTriggerAlert: false`. Both are listed in the report's `not_checked_at_runtime` section so the
consuming agent knows exactly what was and was not observed.

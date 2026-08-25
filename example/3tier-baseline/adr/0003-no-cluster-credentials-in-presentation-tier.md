# ADR-0003 — The presentation tier holds no cluster credentials

**Status:** accepted
**Applies to:** `tier=frontend`, `tier=database`, `tier=middleware`

## Context

Kubernetes mounts a ServiceAccount token into every pod by default. Most workloads never use it,
and most authors never notice it is there. The presentation tier is the tier most likely to be
reached from outside the cluster and the least likely to need the Kubernetes API — which is the
worst possible combination for a credential that is mounted by default.

The token is not inert. Depending on the role bound to the ServiceAccount it may permit reading
secrets in the namespace, listing pods across the cluster, or creating workloads. An attacker who
achieves file read in the frontend gets the token for free.

## Decision

Only `tier=backend` may read the ServiceAccount token, and only because some backends legitimately
talk to the API (leader election, config watch). Frontend, middleware and database workloads set
`automountServiceAccountToken: false`.

Correspondingly, only the backend profile allows the token path in its `opens` list. The other
tiers do not list it at all.

## Verified by

**Runtime** — `R0006 Unexpected service account token access`, severity 5, `isTriggerAlert: true`.

**Static** — kubescape control `C-0034 Automatic mapping of service account`, which reads the
manifest and reports pods that leave `automountServiceAccountToken` at its default.

These two do different jobs and both are worth having. The static control finds every pod that
*could* read the token, including ones that never do — useful for cleanup. The runtime rule finds
the pods that actually *did* read it, which is the shorter and more urgent list.

## Evidence emitted

```
ADR-0003 VIOLATED
  observed  R0006  frontend/web  read /var/run/secrets/kubernetes.io/serviceaccount/token
  static    C-0034 flags Deployment/frontend: automountServiceAccountToken not set
  fix       set automountServiceAccountToken: false on the frontend pod spec
```

## Consequences

* A frontend that turns out to need the API is a design question, not a config question — it
  probably wants a backend endpoint instead.
* Removing the mount can break libraries that probe for in-cluster config at startup. That probe
  failing is the intended outcome; the library should fall back.

## Note on scope

This ADR is verifiable at runtime **because** the tier profiles avoid a wildcard above the token
path. See [ADR-0007](0007-detection-must-not-be-self-disabling.md) — an `opens` entry of
`/var/run/⋯` in the frontend profile would silently make this ADR uncheckable while appearing to
change nothing.

# ADR-0001 — Tiers are strictly layered; the presentation tier never reaches the data tier

**Status:** accepted
**Applies to:** every workload carrying `app.kubernetes.io/tier`

## Context

A three-tier split (presentation → application → data) is only worth anything if the middle tier
is actually on the path. The failure mode is not malice, it is convenience: the quickest way to get
data onto a page is to query the database from the thing rendering the page. It works immediately,
so it survives review unless something mechanical objects.

The consequences are concrete, not stylistic:

* the browser-facing process must hold database credentials, so compromising the least-hardened
  tier yields the credentials to the most valuable one;
* the query has no authorisation layer in front of it — whatever the connection can do, the
  frontend can do;
* the database's connection budget is now driven by frontend replica count;
* schema changes acquire a second, undocumented consumer.

## Decision

A workload labelled `tier=frontend` may open connections to `tier=backend` and to DNS. Nothing
else. A workload labelled `tier=database` accepts connections from `tier=backend` and from its own
tier's replication ports. Nothing else.

The tiers reference each other by **label selector**, never by service or pod name, so the decision
survives renames, rewrites and language changes.

## Verified by

**Runtime — and from both ends of the same connection.**

| | rule | fires on | severity |
|---|---|---|---|
| sender | `R0011` unexpected egress | the frontend container | 8 |
| receiver | `R0012` unexpected ingress | the database container | 8 |

Both are `isTriggerAlert: true`, so both actually alert. The pairing matters: a single log line
can be argued away as a scanner or a stray probe, but two independent observations of the same
flow — recorded by different node-agent instances when the pods are on different nodes — cannot.

The guard on both rules is **loopback-only** (`!dstAddr.startsWith('127.') && dstAddr != '::1'`).
This is load-bearing. Pod IPs are RFC1918, so a plausible-looking `is_private_ip` guard would
exclude every pod-to-pod connection in the cluster and this ADR would become unverifiable.

## Evidence emitted

```
ADR-0001 VIOLATED
  observed     R0011  frontend/web       egress  TCP 10.42.0.16:5432
  corroborated R0012  db/postgres        ingress TCP from 10.42.1.16
  mapping      10.42.1.16 = pod frontend-5d5d669787-6fqm7 (tier=frontend, node A)
               10.42.0.16 = pod db-fbff4859-lgdct        (tier=database, node B)
  fix          route the query through the service labelled tier=backend on 8080/8000/3000
```

## Consequences

* A frontend that legitimately needs data must gain a backend endpoint. That is the intended cost.
* Direct database access for migrations and admin tooling must run as its own workload, labelled
  `tier=backend`, not smuggled into the frontend.
* Rendering-time data fetching (SSR) is still fine — it just goes through the API like everything
  else.

## Related

[ADR-0002](0002-data-tier-does-not-initiate-egress.md) covers the same tier boundary in the
outbound direction.

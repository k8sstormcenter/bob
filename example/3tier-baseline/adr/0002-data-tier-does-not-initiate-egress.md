# ADR-0002 — The data tier never initiates outbound connections

**Status:** accepted
**Applies to:** `tier=database`, `tier=middleware`

## Context

A database is a destination. It accepts connections, it answers queries, and — if it is
replicated — it talks to its own peers. It has no reason to open a socket to an address outside the
cluster.

That property is unusually valuable because it is *simple*. Most anomaly detection has to reason
about whether an outbound connection is normal. For the data tier the answer is always no, so the
rule needs no learning period, no baseline, and no tuning. It is the cleanest signal in the whole
system, and it happens to be the exact shape of data exfiltration: the process holding the data
opening a connection to somewhere it can be sent.

Legitimate-looking causes exist and all of them are still worth knowing about — an image that
phones home for telemetry, an init script that fetches an extension at startup, a backup sidecar
writing to object storage that nobody documented.

## Decision

`tier=database` egress is limited to DNS and its own tier's replication ports (5432, 6379, 16379,
27017, 7000, 9300, 2380). `tier=middleware` may additionally reach the database tier and its own
cluster ports. Neither may reach anything outside the cluster.

Backups, telemetry and extension downloads run as separate workloads labelled `tier=backend`.

## Verified by

**Runtime** — `R0011 Unexpected Egress Network Traffic`, severity 8, `isTriggerAlert: true`.

Unlike [ADR-0001](0001-strict-tier-layering.md) this one usually cannot be corroborated from the
receiving end, because the receiver is outside the cluster and has no node-agent on it. A single
observation is all you get — which is fine, because for this tier a single observation is already
conclusive.

## Evidence emitted

```
ADR-0002 VIOLATED
  observed  R0011  db/postgres  egress TCP 1.1.1.1:443
  fix       remove the outbound call; if a database genuinely needs egress,
            it belongs in a sidecar or job labelled tier=backend
```

## Consequences

* Database images that fetch extensions at startup will alert on first boot. Bake the extension in.
* A managed database outside the cluster inverts this ADR — the backend's egress list carries the
  endpoint instead, and the data tier does not exist in-cluster at all.

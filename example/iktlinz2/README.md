# ran-chain-2: the IKT-Linz chain over different protocols

Chain 2 runs the same 20-step lesion as `example/iktlinz`, varying the
**protocol** and nothing else, so a measurement taken on chain 1 can be repeated
without changing what is being measured.

| | chain 1 | chain 2 |
| --- | --- | --- |
| scanner | `nmap` SYN sweep | `dig` reverse lookups |
| datastore | redis | postgres |
| RCE | CVE-2022-0543, Lua sandbox escape via `EVAL` | CVE-2019-9193, `COPY … FROM PROGRAM` |
| leak | CVE-2026-47701 → redis key | CVE-2026-47702 → postgres row |

## What is here now

`specimens/cve-2026-47702/` — the postgres specimen and the leak arm. See its
README for what is changed and what is deliberately reused from
`cve-2026-47701/`.

The chain-2 driver (`demo_chain2.py`) and deploy script are **not written yet**:
they need chain 1's `demo_chain.py` and `run-iktlinz-e2e.sh` as their base, and
the running deploy script carries a local modification that is not yet in this
repository.

## Where chain 1's pieces actually live

Worth stating because it is not obvious and it cost a wrong assumption to find:

- the **driver and deploy script** are in this repo, `example/iktlinz/` (PR #223)
- the **specimens** are not: `run-iktlinz-e2e.sh` fetches them at apply time from
  `Magier/Oopserability` `manifests/` and `Magier/ikt26` `k8s/`
- the **harness** that runs a measurement cell — setup, policy, fire, settle,
  read KPI — is local to the rig and in neither repository

Chain 2's specimens are kept **in this repo** rather than fetched, so the lesion
and the manifests that produce it version together.

## The four literals chain 2 shares with the scoring side

The obligation spec lives in the dx repository
(`e2e/volume/obligations-iktlinz-chain2.json`) and matches on these. They must
agree with what actually deploys, or the obligations silently ground nothing:

| literal | value |
| --- | --- |
| worker pod | `agent-system/agent-worker%` |
| privileged pod | `agent-system/ran-privileged` |
| specimen pod | `oopservability/oopservability-postgres%` |
| cache key | `oopservability:receiver:last-authorization` (identical to chain 1) |

## Verified

The receiver's hand-rolled Postgres wire protocol, the CVE-2019-9193 RCE and the
extraction were run against a real `postgres:16-alpine`:

```
COPY rce FROM PROGRAM 'id'   ->  uid=70(postgres) gid=70(postgres) groups=70(postgres)
SELECT value FROM oopservability.receiver
  WHERE key = 'oopservability:receiver:last-authorization'   ->  the cached header
```

and both obligations match that SQL. What is **not** verified is the cluster
path: the ServiceMonitor trigger, the allocator, and the collector sidecar are
reused from chain 1 unchanged but have not been run against a postgres receiver.

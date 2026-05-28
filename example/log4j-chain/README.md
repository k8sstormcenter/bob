# Log4Shell three-scenario chain demo

Reproducible CVE-2021-44228 testbed for bobctl. ONE payload, THREE
backend variants — the negative-control test for any active-diagnosis
framework that claims to discriminate "vulnerable", "contained", and
"patched" from the same kernel-observable trace.

## Scenarios

| | backend image | log4j version | securityContext | expected verdict |
|---|---|---|---|---|
| **A** | `eclipse-temurin:11-jdk` (Ubuntu base) | 2.14.1 | default | full chain — LDAP egress, class fetch, `/bin/sh` exec, pg-wire data read, DNS exfil |
| **B** | `gcr.io/distroless/java11-debian11` | 2.14.1 | `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true` | contained at exec layer — JNDI resolves, class loads, `Runtime.exec("/bin/sh")` returns `ENOENT` (no `/bin/sh` in distroless) |
| **C** | `eclipse-temurin:11-jdk` | **2.17.1** | default | inert — log4j 2.17.1 never performs JNDI substitution; payload sits in headers, nothing fires |

The frontend, postgres, attacker, observer, and the JNDI payload string
are identical across scenarios. The discriminator is the backend image
alone.

## Topology

```
   external curl                attacker.attacker-ns
        │                            │  marshalsec LDAP :1389
        ▼                            │  python3 HTTP :8888
   chain-frontend ──────┐            ▲
   (nginx :8080)        │            │  (only A & B reach here)
                        ▼            │
                   chain-backend ────┘
                   (java + log4j)
                        │
                        ▼
                   chain-postgres
                   (trust-auth :5432)

   chain-observer  ─── benign /api/products poll every 30s
   (never attacked; the negative-control workload)
```

## What's in this directory

```
example/log4j-chain/
├── README.md                          this file
├── RUNBOOK-FOR-AGENTS.md              step-by-step deploy + attack guide
├── log4j-chain.yaml                   all manifests (ns + postgres + frontend
│                                       + observer + attacker + scenario-A backend)
├── log4j-functional-tests.yaml        FunctionalTestSuite — benign baseline
│                                       (drives sbob learning)
├── log4j-attacks.yaml                 AttackSuite — same payload, 3 scenarios
├── backend-b.yaml                     scenario-B backend (replaces scenario A)
├── backend-c.yaml                     scenario-C backend (replaces scenario A)
├── attack-pod.yaml                    in-cluster curl pod that fires the JNDI
│                                       probe (used by RUNBOOK step 6)
├── backend/                           Dockerfile.{vulnerable,contained,patched}
│                                       + pom.xml + src/  (the Java app)
├── attacker/                          Dockerfile + Payload.java + run.sh
│                                       (marshalsec + python3 HTTP server)
├── frontend/                          nginx ConfigMap + Deployment
├── postgres/                          standalone postgres manifest (used by
│                                       log4j-chain.yaml indirectly)
└── kubescape/                         pre-baked ApplicationProfiles +
                                       RuntimeRuleAlertBinding (R1100 etc.)
```

## Building the images

The default `log4j-chain.yaml` references pre-published GHCR images:

- `ghcr.io/k8sstormcenter/log4j-chain-attacker:latest`
- `ghcr.io/k8sstormcenter/log4j-chain-backend-vulnerable:latest`
- `ghcr.io/k8sstormcenter/log4j-chain-backend-contained:latest`
- `ghcr.io/k8sstormcenter/log4j-chain-backend-patched:latest`

To rebuild locally:

```bash
docker build -t YOURREG/log4j-chain-attacker:dev            -f attacker/Dockerfile attacker/
docker build -t YOURREG/log4j-chain-backend-vulnerable:dev  -f backend/Dockerfile.vulnerable backend/
docker build -t YOURREG/log4j-chain-backend-contained:dev   -f backend/Dockerfile.contained  backend/
docker build -t YOURREG/log4j-chain-backend-patched:dev     -f backend/Dockerfile.patched    backend/
# then sed -i s|ghcr.io/k8sstormcenter|YOURREG|g log4j-chain.yaml backend-{b,c}.yaml
```

## Running

See `RUNBOOK-FOR-AGENTS.md` for the step-by-step.

## bobctl-tune

This directory is structured so `bobctl-tune` can consume it:

1. Apply `log4j-chain.yaml` (scenario A baseline)
2. Run `log4j-functional-tests.yaml` (learns the four sbobs in log4j-poc ns)
3. Switch backend to B → re-run functional tests → sbobs converge on
   "distroless variant" shape
4. Switch backend to C → re-run functional tests → sbobs converge on
   "patched library" shape
5. For each scenario, run `log4j-attacks.yaml` and confirm the expected
   detections per scenario

The three sbobs produced per scenario become the discriminator catalog
for active-diagnosis decision trees.

## Detection narrative (with kubescape ApplicationProfile baseline)

Each scenario produces a distinct kubescape rule-fire signature:

| Signal | A | B | C |
|---|---|---|---|
| JNDI substring in HTTP header (Pixie http_events) | ✓ | ✓ | ✓ |
| Outbound TCP to attacker:1389 (R0011) | ✓ | ✓ | ✗ |
| LDAP referral → HTTP class fetch on :8888 (Pixie conn_stats) | ✓ | ✓ | ✗ |
| New comm `/bin/sh` under java (R0001) | ✓ | ✗ | ✗ |
| Failed execve ENOENT under java (R1100) | ✗ | ✓ | ✗ |
| pg-wire DataRow from chain-backend (Pixie pgsql_events) | ✓ | ✗ | ✗ |
| DNS query with base32 payload in label (Pixie dns_events / R0011) | ✓ | ✗ | ✗ |
| **verdict** | A | B | clean |

Scenario C is the negative-control: same payload string in the User-Agent,
but log4j 2.17.1 (released 2021-12-18 in response to CVE-2021-44228 +
CVE-2021-45046) does not perform JNDI substitution on logged data.

# Redis Attack Tests — Parallel Execution

Each attack is split into its own YAML file so that multiple agents (Claude
Code instances) can work on different attacks in parallel without conflicts.

## Directory Layout

```
redis-tests/
├── attack-01-fileless-memfd.yaml       # R1005 — memfd_create + execve
├── attack-02-sa-token-exfil.yaml       # R0006 — SA token read
├── attack-03-read-etc-shadow.yaml      # R0010 — /etc/shadow read
├── attack-04-unexpected-whoami.yaml    # R0001 — unexpected process
├── attack-05-dns-anomaly.yaml          # R0005 — evil domain lookup
├── attack-06-drifted-binary.yaml       # R1001 — binary not in image
├── attack-07-exec-devshm.yaml          # R1000 — exec from /dev/shm
├── attack-08-read-proc-environ.yaml    # R0008 — procfs environ read
├── attack-09-symlink-shadow.yaml       # R1010 — symlink over shadow
├── attack-10-crypto-mining-dns.yaml    # R1008 — mining pool DNS
├── attack-11-reverse-shell-curl.yaml   # R0001 — curl to C2
├── attack-12-hardlink-shadow.yaml      # R1012 — hardlink over shadow
├── run-all.sh                          # Sequential runner
└── run-parallel.sh                     # Parallel runner (GNU parallel)
```

## Running

```bash
# All attacks sequentially
./run-all.sh

# All attacks in parallel (each agent picks one file)
./run-parallel.sh

# Single attack (for one agent)
bobctl attack run redis-tests/attack-01-fileless-memfd.yaml
```

## Agent Assignment

Each agent should:
1. Pick an unclaimed `attack-NN-*.yaml` file
2. Deploy the redis-vulnerable manifest if not already running
3. Run the attack via `bobctl attack run <file>`
4. Verify the expected detection fired in AlertManager
5. Record results in `results/attack-NN-result.json`

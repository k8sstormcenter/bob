# Redis Attack → Detection Rule Mapping

All attacks exploit CVE-2022-0543 (Lua sandbox escape via `package.loadlib` /
direct `io` access) on the `redis-vulnerable:7.2.10` image to execute OS
commands from within Redis EVAL. Each command triggers a specific Kubescape
node-agent detection rule.

## Verified Detection Results (Kind cluster, 2026-03-16)

| # | Attack File | OS Command | Rule ID | Rule Name | Sev | Verified |
|---|------------|------------|---------|-----------|-----|----------|
| 01 | `attack-01-fileless-memfd.yaml` | `perl` memfd_create+execve | **R1005** | Fileless execution detected | 8 | **YES** |
| 02 | `attack-02-sa-token-exfil.yaml` | `cat /var/run/secrets/.../token` | **R0006** | Unexpected SA token access | 5 | **YES** |
| 03 | `attack-03-read-etc-shadow.yaml` | `cat /etc/shadow` | **R0010** | Unexpected Sensitive File Access | 5 | tracer-dep |
| 04 | `attack-04-unexpected-whoami.yaml` | `whoami` | **R0001** | Unexpected process launched | 1 | **YES** |
| 05 | `attack-05-dns-anomaly.yaml` | `getent hosts evil.attacker.example.com` | **R0005** | DNS Anomalies in container | 1 | **YES** |
| 06 | `attack-06-drifted-binary.yaml` | `cp /bin/ls /tmp/drifted_redis && exec` | **R1001** | Drifted process executed | 8 | **YES** |
| 07 | `attack-07-exec-devshm.yaml` | `cp /bin/echo /dev/shm/malicious && exec` | **R1000** | Process from malicious source | 8 | **YES** |
| 08 | `attack-08-read-proc-environ.yaml` | `cat /proc/1/environ` | **R0008** | Read Environment Variables from procfs | 5 | **YES** |
| 09 | `attack-09-symlink-shadow.yaml` | `ln -sf /etc/shadow /tmp/shadow_link` | **R1010** | Soft link over sensitive file | 5 | tracer-dep |
| 10 | `attack-10-crypto-mining-dns.yaml` | `getent hosts xmr.pool.minergate.com` | **R1008** | Crypto Mining Domain Communication | 10 | **YES** |
| 11 | `attack-11-reverse-shell-perl.yaml` | `perl IO::Socket::INET c2.evil.example.com` | **R0001** | Unexpected process launched | 1 | **YES** |
| 12 | `attack-12-credential-harvest.yaml` | `awk /etc/passwd && id` | **R0001** | Unexpected process launched | 1 | **YES** |

**Verified: 10/12 primary rules fire.** Attacks 03 and 09 still execute correctly but their
specific rule IDs (R0010, R1010) depend on the open/symlink eBPF tracers. In practice they
ALSO fire R0001 (unexpected process: `cat`, `ln`) which is verified.

## AlertManager Summary (42 total alerts)

```
R0001  Unexpected process launched          16 alerts (sh,cat,cp,ls,rm,ln,whoami,perl,awk,id,getent,head,tr,drifted_redis,malicious)
R0003  Syscalls Anomalies in container       1 alert  (redis-server itself during exploit)
R0005  DNS Anomalies in container            2 alerts (evil.attacker.example.com, c2.evil.example.com)
R0006  Unexpected SA token access            1 alert  (cat reading SA token)
R0008  Read Environment Variables            1 alert  (cat /proc/1/environ)
R1000  Process from malicious source         1 alert  (/dev/shm/malicious)
R1001  Drifted process executed              1 alert  (/tmp/drifted_redis)
R1005  Fileless execution detected           1 alert  (memfd_create + execve)
R1008  Crypto Mining Domain Communication    1 alert  (xmr.pool.minergate.com)
```

## Rules Covered

12 attacks targeting **9 confirmed + 2 tracer-dependent** detection rules:
- **Confirmed**: R0001, R0005, R0006, R0008, R1000, R1001, R1005, R1008 (+ bonus R0003)
- **Tracer-dependent**: R0010 (open tracer), R1010 (symlink tracer)

## Rules NOT Covered (and why)

| Rule | Reason |
|------|--------|
| R0002 | File access anomalies — fires as R0001 instead (process-level) |
| R0004 | Capability anomalies — not alert-triggering by default |
| R0007 | K8s API access — would need kubectl in container |
| R0009 | eBPF load — requires root + BPF capabilities |
| R0011 | Egress traffic — disabled by default |
| R1002 | Kernel module load — requires CAP_SYS_MODULE |
| R1006 | Container escape (unshare) — may not work without permissions |
| R1007 | RandomX crypto miner — requires actual xmrig binary |
| R1009 | Crypto mining port — requires outbound TCP to 3333/45700 |
| R1012 | Hardlink over shadow — overlayfs blocks cross-layer hardlinks |
| R1015 | Malicious ptrace — requires ptrace syscall |

# redis-client — a database SBoB with exactly ONE allowed client

A minimal, substitutable Bill-of-Behavior for redis (the `database` app type),
built to make the **egress/ingress contrast** concrete: a datastore's network
normal is *"declared clients talk IN on the service port; the server talks OUT
to nobody."* Encode that and every rule below becomes maximally separable.

## What's here

| file | role |
|---|---|
| `redis.yaml` | the redis server (namespace `redis-demo`, label `app: redis`) |
| `client.yaml` | the **one allowed client** — a benign SET/GET/PING loop (`app: redis-client`) |
| `sbobs/nn-redis.yaml` | NetworkNeighborhood: **one** ingress peer, `egress: null` |
| `sbobs/ap-redis.yaml` | ApplicationProfile: exact execs, wildcard only volatile paths |

## Deploy

```bash
kubectl apply -f example/redis-client/sbobs/     # SBoBs first (User-managed)
kubectl apply -f example/redis-client/redis.yaml
kubectl apply -f example/redis-client/client.yaml
```

## Substitute your own client (the point)

The redis NN whitelists **one** ingress peer by label selector. To authorize
*your* real client instead of the demo one, edit the `>>> SUBSTITUTE <<<` block
in `sbobs/nn-redis.yaml`:

```yaml
podSelector:
  matchLabels:
    app: redis-client                        # ← your client's pod label
namespaceSelector:
  matchLabels:
    kubernetes.io/metadata.name: redis-demo  # ← your client's namespace
```

Then delete `client.yaml`. Two selectors, one peer — an explicit, auditable
allow-list. More than one legitimate client? Add another `- identifier:` block
per client; each is a named exception a reviewer can see. Anything **not** on
this list that connects to redis is, by construction, an anomaly.

## Why so tight (the generalization principle)

A database's contrast strength comes from a *narrow* envelope:

- **execs exact** — only `redis-server` / `redis-cli`. Wildcarding execs is what
  destroys a DB's detection; a shell or fetched binary must stand out.
- **opens: literal stable paths, wildcard only the volatile** — the ConfigMap
  `..data` generation dir (`/etc/redis/*/redis.conf`, changes every restart) and
  per-PID `/proc/⋯`, per-device `/sys/*`. Nothing else.
- **egress empty** — the server dials nobody, so R0011/R0005 fire on the first
  unexpected packet.

## What a detection MEANS — TTP mapping (database lens)

When one of these kubescape rules fires against this baseline, here is what it
tells the end-user. For the `database` type every rule is **Separable** (the
symptom stands out) — with the one caveat in the last section.

| Rule | ATT&CK | Fires when redis… | What it means for you |
|---|---|---|---|
| R0001 Unexpected process | T1059 | spawns a non-redis process | **RCE** — Lua `io.popen`, module exec, injected command |
| R0040 Unexpected args | T1059 | a known binary runs with new args | living-off-the-land variant of the above |
| R1001 Drifted process | T1554 | runs a binary not in the image | a **dropped/implanted** tool executed |
| R1004 Process from mount | T1059 | execs from a mounted volume | payload delivered via a writable mount |
| R1000 Process from /dev/shm | T1620 | execs from shared memory | staged fileless-style payload |
| R1005 Fileless execution | T1620 | runs code from an anon memfd | **in-memory malware**, nothing on disk |
| R0002 File access anomaly | T1005 | reads/writes outside baseline | data staging / config tamper / reading `/etc/shadow` |
| R0010 Sensitive file access | T1552.001 | reads keys/tokens/secrets | **credential access** |
| R0006 SA-token access | T1552.001 | reads the k8s serviceaccount token | theft to **pivot to the API server** |
| R0008 Env from procfs | T1552 | reads another process' `environ` | secret/cred harvesting |
| R0007 Uses k8s API | T1613 | talks to kube-apiserver | a DB has no reason to — **recon/lateral** |
| R0005 DNS anomaly | T1071 | resolves a new domain | **C2 beacon** or exfil target lookup |
| R0011 Unexpected egress | T1041 | opens ANY outbound connection | **exfiltration / reverse shell** (server egress = 0) |
| R1003 SSH unexpected dest | T1021.004 | initiates SSH | **lateral movement** |
| R1007/8/9 crypto-mine | T1496 | spawns miner / hits pool domain / port | **resource hijack** |
| R0004 Capabilities anomaly | T1611 | uses a new Linux capability | **privilege escalation / escape prep** |
| R1006 unshare | T1611 | creates a new namespace | **container-escape** primitive |
| R0009 eBPF load | T1611 | loads an eBPF program | kernel-level **rootkit/tamper** |
| R1002 Kernel module load | T1547.006 | loads a kmod | **rootkit** |
| R1015 ptrace | T1055.008 | ptraces another process | **code injection / credential dumping** |
| R1030 io_uring | T1620 | uses io_uring | stealthy I/O — **detection evasion** |
| R0003 Syscall anomaly | T1106 | new syscall vs baseline | exploit primitive (broad signal) |
| R1010/R1012 sym/hardlink | T1222 | links over a sensitive file | **persistence / priv-esc** |
| R1011 ld_preload | T1574.006 | sets `LD_PRELOAD` | library-injection **persistence** |
| R2000 Exec to pod | T1609 | someone `kubectl exec`s in | interactive intrusion (or admin — verify) |
| R2001 Port-forward to pod | T1609/T1090 | someone port-forwards in | access **tunnel** to the datastore |

### The honest caveat (why the model isn't finished)

Two known gaps, both provable on this very SBoB:

**(a) `reads-host-files` is over-broad.** Run
`bobctl contrast --profile sbobs/ap-redis.yaml --type database` and it reports a
`reads-host-files` deviation — triggered by the benign `/sys/devices/*` read
(device topology / hugepage settings) that essentially every container performs.
`isHostPath` currently counts `/sys` and `/proc/sys` as host-escape surface,
which makes *every* database falsely deviate. The fix is to narrow it to genuine
breakout paths (`/host*`, `/proc/1/*`, `/proc/sysrq-trigger`) so `/sys/devices`
and `/proc/sys/net` tuning reads stop counting.

**(b) capabilities aren't read yet.** The "all Separable" row assumes the
envelope is truly empty. The **real** redis profile from CI carries `SYS_ADMIN`
+ `NET_ADMIN` in its granted capabilities.
If contrast read capabilities (it does not yet), redis would gain the
`uses-kernel-features` property, and the kernel-family rules — **R0003, R0004,
R0009, R1002, R1006, R1015, R1030** — flip from Separable to **Blind**: a redis
allowed to hold `SYS_ADMIN` cannot be told apart from one abusing it. That is
why `ap-redis.yaml` declares `capabilities: []` **explicitly (NONE)** — the
authored baseline says "this redis needs no added caps," turning R0004 back into
a hard signal. Match that by dropping the caps in your redis Deployment
(`securityContext.capabilities.drop: ["ALL"]`).

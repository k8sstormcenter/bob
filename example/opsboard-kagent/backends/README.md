# shop backend SBoBs (signed)

Signed base-class ContainerProfiles for opsboard's five backends, so the whole
`shop` namespace runs FP-clean (not just opsboard). Learned on duckling2, signed
with `vendor.pem`, verified + adopted, then soaked: **zero alerts across all six
workloads over an 8-minute steady-state window** (opsboard driving its 6-protocol
loop, a redis BGSAVE forced mid-soak).

Two backends needed volatile-path wildcards (the learn window can't capture a
path whose name embeds a changing PID/random id):

- **redis** — BGSAVE forks write `/data/temp-<childPID>.rdb` and read
  `/proc/<childPID>/smaps`. Wildcarded to `/data/⋯` + `/proc/⋯/smaps`.
- **postgres** — dynamic shared memory `/dev/shm/PostgreSQL.<random>`.
  Wildcarded to `/dev/shm/⋯`.

`hack/fragfix.py` applies the per-workload name + these wildcards to a
`cp-to-fragment.py` output before signing. `frag-<w>.yaml` is the unsigned
source; `frag-<w>-signed.yaml` is applied.

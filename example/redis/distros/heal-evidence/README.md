# Redis client-overlay heal — before/after evidence

Cluster: k3s, chart 1.41.0-duckling23, node-agent v0.1.0-rogue35, storage rc-rogue23.
redis-master bound to signed `redis` profile throughout; the variable is the client.

## Verdict

| | redis R0012 | client R1017 | client R0040 | redis-ns total |
|---|---|---|---|---|
| BEFORE (client unbound, redis ingress empty) | 1 | 1 | 53 | 55 |
| AFTER  (overlay applied + client bound, signed) | 0 | 0 | 0 | 0 |

BEFORE R0012: `Unexpected ingress network communication from 10.42.0.54:6379 to redis`.
AFTER: node-agent verified both signatures and adopted both user-authored profiles;
80s of steady healed traffic produced zero redis-ns alerts.

## Files
- 01-raw-client-CP.yaml       raw ContainerProfile as node-agent LEARNED it (137 execs, 12 opens, 2 egress, 35 syscalls)
- 02-before-alerts.txt        alertmanager, client unbound
- 03-before-nodeagent.log     R0012 on redis + R1017 on client
- 04-overlay-SBOB.yaml        ingress overlay DERIVED from the raw CP by `bobctl overlay` (podSelector app=redis-client:6379)
- 05-redis-healed-profile.yaml redis SBoB + overlay, composed
- 06-redis-healed-SIGNED.yaml  signed (sign-object, embed-content, vendor key)
- 07-client-SBOB.yaml          client SBoB from raw CP (generalize --sbob + portable)
- 08-client-SBOB-SIGNED.yaml   signed
- 09-after-nodeagent.log       signature verified + adopted, both profiles
- 10-after-alerts.txt          alertmanager, healed = 0

## How the overlay was produced (not hand-authored)
    bobctl overlay --peer <client-CP> --target redis-master
podSelector from the client's learned labels, namespace from where it ran, port
from what it connected to — all read from 01-raw-client-CP.yaml.

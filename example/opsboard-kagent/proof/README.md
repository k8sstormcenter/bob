# opsboard SBoB — rogue→learned proof

Captured on a kubescape-operator **1.41.0-duckling2** cluster (node-agent
`duckling:v0.1.0-rogue2`, storage `rc-rogue5`), trust-policy = this repo's
`example/redis/distros/signed-bundles/trust-policy.signed.json`.

Snapshot is the state **before** binding `opsboard-base`: workload learned but
still unsigned/unbound.

- `rogueartifacts.yaml` — R1017 on all six shop containers (unbound).
- `cp-opsboard-learned-complete.yaml` — learned ContainerProfile, completion=complete: exec `/opsboard` only + egress to redis 6379 / postgres 5432 / inventory-gRPC 9090 / rabbitmq 5672 / fx 80 / DNS 53.
- `cp-opsboard-learned-partial.yaml` — earlier partial learn.
- `all-shop-containerprofiles.yaml` — every shop ContainerProfile.
- `node-agent-evidence.log` — R1017 rogue + `verified object signature: trust-policy` + `signed rule fragments admitted`.
- `shop-pods.txt` — pod/node placement.

# Redis-protocol distros — detect + allowlist a client by identity (ingress)

Same flow as `DEMO.md` §5, for the other distros. Bring up the stack first:

```
make kubescape
make alertmanager
```

`CP=containerprofiles.spdx.softwarecomposition.kubescape.io`

Each section: deploy + bind the SBoB, deploy an unlisted client (R0012 fires),
then allowlist it by identity (R0012 stops within ~30s).

| distro    | ns         | server pod       | service         | client manifest        |
|-----------|------------|------------------|-----------------|------------------------|
| valkey    | valkey     | valkey-primary-0 | valkey-primary  | valkey-client.yaml     |
| keydb     | keydb      | keydb-0          | keydb           | keydb-client.yaml      |
| dragonfly | dragonfly  | dragonfly-0      | dragonfly       | dragonfly-client.yaml  |

## valkey

```
./deploy-distros.sh valkey sbob
```
Watch R0012 on valkey-primary's node-agent:
```
MNODE=$(kubectl -n valkey get pod valkey-primary-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected ingress network"
```
Deploy the client (unlisted) — R0012 fires:
```
kubectl apply -f valkey-client.yaml
```
Allowlist that identity — R0012 stops:
```
kubectl -n valkey patch $CP valkey --type merge -p '{"spec":{"ingress":[{"type":"internal","podSelector":{"matchLabels":{"app":"valkey-client"}},"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"valkey"}},"ports":[{"name":"TCP-6379","port":6379,"protocol":"TCP"}]}]}}'
```

## keydb

```
./deploy-distros.sh keydb sbob
```
Watch R0012 on keydb's node-agent:
```
MNODE=$(kubectl -n keydb get pod keydb-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected ingress network"
```
Deploy the client (unlisted) — R0012 fires:
```
kubectl apply -f keydb-client.yaml
```
Allowlist that identity — R0012 stops:
```
kubectl -n keydb patch $CP keydb --type merge -p '{"spec":{"ingress":[{"type":"internal","podSelector":{"matchLabels":{"app":"keydb-client"}},"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"keydb"}},"ports":[{"name":"TCP-6379","port":6379,"protocol":"TCP"}]}]}}'
```

## dragonfly

```
./deploy-distros.sh dragonfly sbob
```
Watch R0012 on dragonfly's node-agent:
```
MNODE=$(kubectl -n dragonfly get pod dragonfly-0 -o jsonpath='{.spec.nodeName}')
NA=$(kubectl -n honey get pod -o wide --field-selector spec.nodeName=$MNODE --no-headers | awk '/node-agent/{print $1;exit}')
kubectl -n honey logs -f $NA | grep "Unexpected ingress network"
```
Deploy the client (unlisted) — R0012 fires:
```
kubectl apply -f dragonfly-client.yaml
```
Allowlist that identity — R0012 stops:
```
kubectl -n dragonfly patch $CP dragonfly --type merge -p '{"spec":{"ingress":[{"type":"internal","podSelector":{"matchLabels":{"app":"dragonfly-client"}},"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"dragonfly"}},"ports":[{"name":"TCP-6379","port":6379,"protocol":"TCP"}]}]}}'
```

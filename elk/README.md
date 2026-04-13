# ECK Operator

This folder uses a pinned local Helm chart tarball:
- chart archive: `elk/eck-operator-3.3.0.tgz`
- version: `3.3.0`
- namespace: `elastic-system`

No custom Helm values file is required for this setup.

Files:
- `elk/eck-operator-3.3.0.tgz`
- `elk/elastic-components.yaml`

## Install Operator From TGZ

```bash
helm upgrade --install elastic-operator elk/eck-operator-3.3.0.tgz \
  -n elastic-system \
  --create-namespace \
  --wait \
  --timeout 10m
```

## Apply Elastic Components

```bash
kubectl apply -f elk/elastic-components.yaml
```

## Verify

```bash
kubectl -n elastic-system get pods,svc,deploy,sts
kubectl -n elk get elasticsearch,kibana,agent
```

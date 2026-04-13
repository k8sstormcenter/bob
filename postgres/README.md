# Simple Postgres (CloudPirates Helm)

This folder contains a minimal values file for `cloudpirates/postgres` pinned to chart version `0.19.0`.

Pinned chart version:
- `0.19.0`

Pinned image:
- `docker.io/postgres:18.3-alpine3.23`

## Values used

```yaml
image:
  registry: docker.io
  repository: postgres
  tag: "18.3-alpine3.23"

auth:
  username: app
  password: app-password
  database: app

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

persistence:
  enabled: true
  size: 8Gi

service:
  type: ClusterIP
  port: 5432
  targetPort: 5432
```

## Template

```bash
helm template postgres oci://registry-1.docker.io/cloudpirates/postgres \
  --version 0.19.0 \
  -n postgres \
  -f postgres/values.yaml \
  > postgres/postgres-rendered.yaml
```

## Apply

```bash
kubectl apply -f postgres/postgres-rendered.yaml
```

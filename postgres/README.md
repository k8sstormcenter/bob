# PostgreSQL (CloudNativePG)

Uses [CloudNativePG](https://cloudnative-pg.io/) (CNCF Sandbox) operator for
a production-grade PostgreSQL deployment with rich upstream e2e tests.

## Install

```bash
make deploy-postgres
```

This installs the CNPG operator and creates a single-instance PG 17 cluster
in the `postgres` namespace with:
- `pg_stat_statements` extension
- Pre-created `bobtest` table for functional tests
- Superuser access enabled (for attack surface testing)

## Services

| Service | Port | Protocol |
|---------|------|----------|
| `pg-rw` | 5432 | TCP (PostgreSQL wire protocol) |
| `pg-r` | 5432 | TCP (read replicas) |
| `pg-ro` | 5432 | TCP (read-only) |

## Verify

```bash
kubectl -n postgres get cluster,pods,svc
```

## Uninstall

```bash
make postgres-uninstall
```

# java-poc — golden source for the SOC e2e test apps

This directory is the **single source of truth** for the sample workloads the SOC
end-to-end / calibration suite drives (pixie fork `src/e2e_test/adaptive_export_loadtest`,
`TestJavaPocCalibration`). Previously these manifests lived only ephemerally on a
rig (applied inline, medical-named) while the on-disk copies under
`../log4j-chain/` used the older `log4j-poc` / `chain-*` / `attacker-ns` naming.
This dir captures the exact working, medically-named, digest-pinned deployment.

## What it deploys

| Namespace | Workload | Image | Role |
|---|---|---|---|
| `java-poc` | `backend` | `log4j-chain-backend-vulnerable@sha256:72655e…` | the vulnerable Java app (scenario A) |
| `java-poc` | `frontend` | `nginx:1.27-alpine` | edge |
| `java-poc` | `postgres` | `postgres:16` | app DB (PII the disease hemorrhages) |
| `java-poc` | `observer` | `curlimages/curl:8.6.0` | benign traffic generator |
| `pathogen-ns` | `pathogen` | `log4j-chain-attacker@sha256:c4dd5f…` | serves the LDAP Specimen (disease origin) |

Plus the **user-defined SBoBs** (`sbobs/*-ap.yaml`, `*-nn.yaml`) — the
ApplicationProfile + NetworkNeighborhood for each java-poc workload, carrying
`kubescape.io/managed-by: User` + `completion: complete`. These are what make the
detection bind to a User profile (the calibration relies on `backend` being
SBoB-bound).

## Naming convention (medical vocabulary)

- app namespace `java-poc`, pathogen namespace `pathogen-ns`
- workloads `backend` / `frontend` / `observer` / `postgres` / `pathogen`
- **image names stay literal** (`log4j-chain-*`) — they are external wire, digest-pinned.

The `TestJavaPocCalibration` config defaults (`appNS=java-poc`, `backend`,
`pathogenNS=pathogen-ns`, `pathogen`) match these names exactly, so the e2e suite
needs no overrides.

## Deploy

```bash
skaffold deploy -m java-poc-apps -p k3s      # from this dir
# or plain kubectl, in the same order:
kubectl apply -f 00-namespaces.yaml -f sbobs/ -f 10-postgres.yaml \
  -f 20-frontend.yaml -f 30-backend.yaml -f 40-observer.yaml -f 50-pathogen.yaml
```

**Order is load-bearing:** namespaces → SBoBs → workloads. A User SBoB must exist
*before* the pod starts, or the node-agent binds a learnt sibling profile instead.
If a pod started before its SBoB (e.g. CRDs not yet ready), `kubectl delete pod`
it to rebind — do **not** `rollout restart` (that clobbers the managed-by
annotation).

## Layering

This is **only the apps**. It assumes the detection/forensics stack (kubescape +
CRDs, vector, ClickHouse, dx) is already deployed — that is the **soc** repo's
Skaffold. Compose them: soc stack first, then these apps, then Pixie's native
Skaffold. k3s only for now.

## Pinning status

Custom images are digest-pinned. Stock images (`nginx`, `postgres`, `curl`) are
tag-pinned here; digest-pin them as part of the fully-pinned Skaffold work
(soc #230).

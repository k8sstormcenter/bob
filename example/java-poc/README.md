# java-poc — golden source for the SOC e2e test apps

This directory is the **single source of truth** for the sample workloads the SOC
end-to-end / calibration suite drives (pixie fork `src/e2e_test/adaptive_export_loadtest`,
`TestJavaPocCalibration`). Previously these manifests lived only ephemerally on a
rig (applied inline, medical-named) while the retired on-disk copies used older
`chain-*` / `attacker-ns` naming. This dir captures the exact working,
medically-named, digest-pinned deployment.

## What it deploys

| Namespace | Workload | Image | Role |
|---|---|---|---|
| `java-poc` | `backend` | `<backend-vulnerable>@sha256:72655e…` | the vulnerable Java app (scenario A) |
| `java-poc` | `frontend` | `nginx:1.27-alpine` | edge |
| `java-poc` | `postgres` | `postgres:16` | app DB (PII the disease hemorrhages) |
| `java-poc` | `observer` | `curlimages/curl:8.6.0` | benign traffic generator |
| `java-poc` | `cleannoise` | `busybox:1.36` | benign noise (x3) → frontend `/api/products?q=noise`; a true-negative in the confusion matrix |
| `pathogen-ns` | `pathogen` | `<attacker>@sha256:c4dd5f…` | serves the LDAP Specimen (disease origin) |

Plus the **user-defined SBoBs** (`sbobs/*-cp.yaml`) — one unified
ContainerProfile per java-poc workload (process view + inline network shape),
carrying `kubescape.io/managed-by: User` + `completion: complete`. These are what
make the detection bind to a User profile (the calibration relies on `backend`
being SBoB-bound).

## Naming convention (medical vocabulary)

- app namespace `java-poc`, pathogen namespace `pathogen-ns`
- workloads `backend` / `frontend` / `observer` / `postgres` / `pathogen`
- **image names stay literal** — they are external wire, digest-pinned.

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

## Sources, suites and scenario variants

The retired chain tree folded into this directory, so everything the demo needs
now lives here:

| Path | What |
|---|---|
| `backend/` | the vulnerable Java app — `Dockerfile.{vulnerable,contained,patched}`, `pom.xml`, `App.java` |
| `pathogen/` | the LDAP Specimen server — `Dockerfile`, `Payload.java`, `run.sh` |
| `backend-b.yaml` / `backend-c.yaml` | scenario B (distroless + hardened SC) and C (patched library) overlays for `backend` |
| `java-attacks.yaml` | bobctl `AttackSuite` — one payload, three scenarios |
| `java-functional-tests.yaml` | bobctl `FunctionalTestSuite` — the benign baseline to learn against |
| `attack-pod.yaml`, `exfil-dns.yaml` | in-cluster probe and the DNS egress surface |
| `kubescape/rules/R1100_rulespec.yaml` | the failed-execve binding scenario B turns on |
| `RUNBOOK-FOR-AGENTS.md` | step-by-step operation |

Images are built by `.github/workflows/ci-java-poc-images.yaml` and published as
`ghcr.io/k8sstormcenter/java-poc-<component>`. The digests pinned in
`30-backend.yaml` and `50-pathogen.yaml` still carry the old repository name:
they are immutable and resolve, and re-pinning waits on either a registry retag
or the first publish under the new name.

## Layering

This is **only the apps**. It assumes the detection/forensics stack (kubescape +
CRDs, vector, ClickHouse, dx) is already deployed — that is the **soc** repo's
Skaffold. Compose them: soc stack first, then these apps, then Pixie's native
Skaffold. k3s only for now.

## Pinning status

Custom images are digest-pinned. Stock images (`nginx`, `postgres`, `curl`) are
tag-pinned here; digest-pin them as part of the fully-pinned Skaffold work
(soc #230).

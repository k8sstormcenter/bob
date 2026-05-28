# Log4j-chain SBOBs — hand-crafted for the active-diagnosis test

**From**: BoB-agent
**For**: PoC-agent (PR #131)
**Date**: 2026-05-28

These are hand-crafted minimal SBOBs (4 ApplicationProfiles + 4 NetworkNeighborhoods) for the four pods in the `log4j-poc` namespace, designed so the A/B/C scenarios produce distinct kubescape signatures:

| Scenario | Backend image | Expected kubescape detections |
|---|---|---|
| A | eclipse-temurin:11-jdk + log4j 2.14.1 | R0001 (new `/bin/sh` comm under java) + R0011 (egress to attacker:1389) + R0010 (if payload reads sensitive file) |
| B | gcr.io/distroless/java11-debian11 + log4j 2.14.1 | R1100 (failed execve `/bin/sh` ENOENT) + R0011 |
| C | eclipse-temurin:11-jdk + log4j 2.17.1 | nothing — payload literal stays inert |

## Schema sources

- `apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1` (matches the storage repo's CRD)
- AP template + NN template at `github.com/k8sstormcenter/node-agent/tests/resources/known-{application-profile,network-neighborhood}.yaml`
- Cross-checked against `example/chain/sbobs/` shape that ships today in main

## Design notes

- **Execs are the attack discriminator** for A vs B. AP intentionally does NOT include `/bin/sh`, `sh`, `bash`, `dash` — so when JNDI triggers an exec on /bin/sh, it's either R0001 (A: succeeds) or R1100 (B: ENOENT).
- **Java path covers both base images**: `/opt/java/openjdk/bin/java` (eclipse-temurin) and `/usr/bin/java` (distroless). Same AP works for A, B, and C without scenario-specific swaps.
- **Opens are conservatively minimal**. If a benign baseline run triggers spurious R0010 on a legitimate read, add the path to that pod's `opens[]` and re-apply. The AP shipped here covers the JVM startup ladder + Spring Boot's typical reads but is not exhaustive.
- **NetworkNeighborhood egress** is RFC-1918-friendly: kube-dns matched by selectors (not IP), chain-postgres matched by service-pod selector. Will work on any cluster with the standard `log4j-poc` namespace + the deployments named `chain-postgres`, etc.

## Applying

Pods need to reference the user-supplied AP+NN via labels. Patch the deployments in `log4j-chain.yaml`:

```yaml
spec:
  template:
    metadata:
      labels:
        kubescape.io/user-defined-profile: chain-backend     # ←
        kubescape.io/user-defined-network: chain-backend     # ←
```

(Same for chain-frontend, chain-postgres, chain-observer.)

Then:

```bash
kubectl apply -f _artifacts/log4j-sbobs/ap-chain-backend.yaml
kubectl apply -f _artifacts/log4j-sbobs/nn-chain-backend.yaml
kubectl apply -f _artifacts/log4j-sbobs/ap-chain-frontend.yaml
kubectl apply -f _artifacts/log4j-sbobs/nn-chain-frontend.yaml
kubectl apply -f _artifacts/log4j-sbobs/ap-chain-postgres.yaml
kubectl apply -f _artifacts/log4j-sbobs/nn-chain-postgres.yaml
kubectl apply -f _artifacts/log4j-sbobs/ap-chain-observer.yaml
kubectl apply -f _artifacts/log4j-sbobs/nn-chain-observer.yaml

kubectl rollout restart -n log4j-poc deploy/chain-backend deploy/chain-frontend deploy/chain-postgres deploy/chain-observer
```

node-agent picks up user-supplied profiles at pod START only — restart required.

## Verification ladder

After applying + restarting, BEFORE running attacks, sanity-check that the SBOBs got picked up:

```bash
# Should report "managed-by: User" (not "Learning") for all four
kubectl -n log4j-poc get applicationprofile -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.kubescape\.io/managed-by}{"\n"}{end}'
```

Then run scenario A and check rule fires. Expected on chain-backend:

```bash
kubectl get --raw "/api/v1/namespaces/honey/services/alertmanager:9093/proxy/api/v2/alerts?active=true" \
  | jq '.[] | select(.labels.container_name == "backend" and (.labels.pod_name // "" | startswith("chain-backend"))) |
        {rule: .labels.rule_id, comm: .labels.comm, exepath: .labels.exepath}'
```

Should see at least:
- A: `R0001` with `comm=sh` or `comm=java` exec'ing /bin/sh
- B: `R1100` with `exepath=/bin/sh`, status=ENOENT
- C: empty list

## Open issues / known limitations

1. **Opens list is minimal**. The auto-tuner would have hundreds; this is a starting point. Expect R0010 flakes on legitimate file reads — those are bug reports for me to add to the list, not test failures.
2. **The backend AP includes both java paths** (temurin + distroless). If you observe R0001 firing on benign baseline because java is at a different path than expected, ping me with the actual `exepath` from the alert.
3. **R0011 expects networkEventsStreaming enabled**. If your kubescape cluster has it disabled, R0011 won't fire even on the LDAP egress — that's a knob, not a missing SBOB entry.
4. **R0010 sensitive-file rule** depends on which file the JNDI payload reads. The reference is `/etc/shadow` in the existing chain demo; log4j's payload may target a different one. If you see R0010 fire, capture the path and we'll align expectations.

Iterate via PR #132 (the design + delivery channel) or directly on #131 — whichever is easier.

— BoB-agent

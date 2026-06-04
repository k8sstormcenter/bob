# react — GitOps-managed front-end (blind detection exercise)

A Next.js / React 19 front-end (React2Shell class, CVE-2025-55182) running on
k3s, **deployed and managed by Argo CD** (the `argocd` ns demo in
`../argocd/`). The `argocd ↔ react` management edge is part of normal
operation.

## What's here

```
sbobs/ap-react.yaml   ApplicationProfile — the workload's runtime baseline (User-managed)
sbobs/nn-react.yaml   NetworkNeighborhood — the workload's network baseline (User-managed)
```

Bind them the usual way (delete-first, then apply; pod carries
`kubescape.io/user-defined-{profile,network}: react`, set from the GitOps
manifest so node-agent enforces from pod start).

## This is a blind test

These are the **only** artifacts shared for this scenario: the `react` AP/NN
baseline plus the existing `argocd` AP/NN. The attack, its stages, and the
expected signals are intentionally **withheld**. Run the workload live, watch
node-agent, and report what — if anything — you can detect and how you'd
classify it. The point is to see whether the detection can find what's fishy
without being told where to look.

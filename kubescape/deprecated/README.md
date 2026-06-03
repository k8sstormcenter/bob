# Deprecated kubescape values files

These value files are kept only so existing `make` targets keep working.
**Do not use them as a starting point for a new install** — they caused
confusion because they ship `capabilities.networkEventsStreaming: disable`,
which silently blinds the network rules **R0005** (unexpected DNS/domain) and
**R0011** (unexpected egress). The supported file is `../values.yaml`, which
sets `networkEventsStreaming: enable`.

| File | Still referenced by | Why deprecated |
|------|---------------------|----------------|
| `values_orig.yaml` | `make kubescape-orig` | `networkEventsStreaming: disable` |
| `values_vendor.yaml` | Makefile vendor target | `networkEventsStreaming: disable` |
| `valuesk0s.yaml` | (nothing) | `networkEventsStreaming: disable`; unreferenced |

The single source of truth for the install is **`kubescape/values.yaml`**.
For when network streaming is needed (and the consumer-URL crashloop pitfall),
see `docs/portability-spec.md` § D7a.

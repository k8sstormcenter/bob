# Noise-model variation layer

A swappable **shape** for the benign background traffic the demo loadgens
generate, on top of each chain's realistic *functional* baseline. The point is
to study how much the baseline noise model helps or hurts detection/tuning:
the same attack against a flat baseline vs. a bursty one looks very different to
a runtime detector.

`profiles.js` is the canonical reference implementation (source of truth). To
keep each k6 loadgen self-contained (single ConfigMap key, no cross-namespace
module mount), a compact copy of `scenarios()`/`think()` is **inlined** into
each loadgen's `script.js`. `profiles.js` is what those copies are flattened
from — edit it first, then update the inlined copies.

## Profiles

| PROFILE | VU shape | think-time | use |
|---|---|---|---|
| `realistic` (default) | organic peaks/valleys (ramping-vus) | exponential | lifelike baseline |
| `flat` | constant VUs | constant | deterministic, low-variance **control** — anomalies stand out trivially |
| `bursty` | low base + sharp short spikes | heavy-tailed (clusters) | high-variance baseline |
| `diurnal` | slow day/night cycle | exponential | slowly drifting baseline |

## Coverage

- **k6 chains** (`react2shell`, `dapr-shop`, `log4j-chain`): profile drives the
  k6 `scenarios` (executor + VU stages) and the think-time distribution.
- **argo** (`example/argocd/loadgen.yaml`): not k6 — the profile drives the
  `argocd.argoproj.io/refresh` cadence instead (flat = fixed interval,
  bursty = clustered refreshes, diurnal = slow sine, realistic = jittered).

## Switching the profile

Each loadgen Deployment has a `PROFILE` env var (default `realistic`). Flip it:

```bash
# k6 chains
kubectl set env deploy/react-loadgen  -n react-loadgen  PROFILE=bursty
kubectl set env deploy/shop-loadgen   -n shop-loadgen   PROFILE=flat
kubectl set env deploy/log4j-loadgen  -n log4j-loadgen  PROFILE=diurnal
# argo
kubectl set env deploy/argocd-loadgen -n argocd-loadgen PROFILE=bursty
```

The pod restarts and the new shape takes effect. Re-learn the SBoBs under the
chosen profile (restart node-agent after the loadgen settles — the usual
learning-race fix) to capture that baseline.

## Keeping the inlined copies in sync

`profiles.js` here is the reference. The compact inlined selector lives in the
`script.js` ConfigMap of `example/react2shell/loadgen.yaml`,
`example/dapr-shop/loadgen.yaml`, and `example/log4j-chain/loadgen.yaml` (each
with its own `PEAK`). After editing `profiles.js`, update those inlined copies.

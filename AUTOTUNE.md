# Autotune CI Success Criteria

## Matrix Job Isolation (MANDATORY)

Each matrix job (webapp, redis, etc.) runs on its own GH runner and MUST produce
artifacts that contain ONLY results from that job. Cross-contamination between
matrix jobs is a CI failure.

### What can go wrong

- The `results/` directory is NOT cleaned before a job writes to it.
  Files checked into git (or left from a prior step) leak into the artifact ZIP.
- `bobctl tune --output-dir results` writes `<profile>-iteration<N>.yaml` files.
  If a webapp iteration file appears in a redis artifact (or vice versa), the
  artifact is tainted and cannot be trusted.

### How we prevent it

1. **`rm -rf results && mkdir results`** runs as the first step before any tool
   writes to `results/`. This is the "Clean results directory" step.
2. **`results/` is in `.gitignore`** so stale run artifacts are never committed
   to the repository.
3. **"Validate artifact isolation"** step runs before artifact upload. It checks
   that every `*-iteration*.yaml` file in `results/` belongs to the current
   matrix app. If a foreign file is found, the step exits non-zero.

### Invariant

```
For each matrix job with app=X:
  ALL files matching results/*-iteration*.yaml MUST contain "X" in the filename.
  NO file from app=Y (where Y != X) may be present.
```

### How to verify locally

```bash
# After running local-ci.sh --app webapp:
ls results/*-iteration*.yaml | grep -v webapp && echo "FAIL: foreign files" || echo "PASS"

# After running local-ci.sh --app redis:
ls results/*-iteration*.yaml | grep -v redis && echo "FAIL: foreign files" || echo "PASS"
```

## Metrics Integrity

Each tune run writes `results/metrics.json`. The metrics MUST reflect only the
current app's tuning process:

- `metrics.json` iteration 0 phase MUST be `raw-baseline`
- All iteration profile names in YAML snapshots MUST match the profile name in
  `summary.json`
- Score at iteration 0 MUST be 0 (raw baseline, no tests run yet)

## Alertmanager Isolation

Alertmanager is shared across all apps in the cluster. To prevent stale alerts
from a previous run affecting the current run:

- `bobctl tune` uses timestamp-based `NewAlerts()` filtering — only alerts fired
  AFTER the tune started are counted
- If running multiple apps sequentially on the same cluster (local-ci), be aware
  that alerts from app A may still be in alertmanager when app B runs. The
  timestamp filter handles this, but it is worth noting.

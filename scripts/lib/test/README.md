# chain-pipeline helper test harness

Hermetic tests for `scripts/lib/chain-*.sh` and `scripts/sbob-pipeline.sh`.

## Run

```bash
bash scripts/lib/test/run.sh
```

Exit 0 if all green, 1 if any file failed. CI runs this in
`.github/workflows/ci-sbob-request.yaml`.

## Design

Two seams make the orchestration logic testable without a cluster:

- **kubectl is mocked.** `install_mocks` writes a `kubectl` shim onto
  `PATH` that records every invocation to `$KUBECTL_LOG` and returns
  canned, env-tunable output. Tests assert on the recorded calls
  (`assert_log_contains`, `assert_log_order`, ...). `sleep` is mocked
  too so the cache-flush wait doesn't block.
- **manifest accessors are stubbed.** `stub_manifest` redefines
  `manifest_pods` / `manifest_deploy` / `manifest_scenarios` /
  `manifest_field` to return fixture data, so the orchestration tests
  need no `yq`.

## Tiers

- **Tier 1** (apply_sbobs, deploy, scenario-switch's no-scenarios path):
  fully hermetic — no `yq`, `jq`, or cluster. Run everywhere.
- **Tier 2** (manifest_parse, scenario-switch apply/restart): exercise
  the real `yq`-backed parse layer against fixture manifests. Self-skip
  when `yq` is absent (`require_yq` / `have_yq`). CI installs `yq` so
  these always run there.

## Files

| File | Covers |
|---|---|
| `test_helper.bash` | mocks, assertions, stubs, tally |
| `apply_sbobs_test.sh` | delete-before-apply (D4), managed-by check, missing-file abort, cache-flush wait |
| `deploy_test.sh` | apply order, optional-skip, rollout waits, non-Deployment pods |
| `scenario_switch_test.sh` | no-scenarios rc, apply+restart, unknown scenario |
| `manifest_parse_test.sh` | real yq accessors: validate, pods/deploy/scenarios/field |
| `fixtures/` | dummy + scenarios manifests, sbob yamls, backend-b |

## Adding a test

Create `<thing>_test.sh`:

```bash
source "$(dirname "${BASH_SOURCE[0]}")/test_helper.bash"
source "$LIB_DIR/chain-<thing>.sh"
set +e   # the lib enables `set -e`; tests exercise nonzero returns

test_something() {
  install_mocks
  stub_manifest "ns" "$PODS_TSV"
  chain_<thing> "$FIXTURES/dummy.manifest.yaml" >/dev/null 2>&1
  assert_rc 0 $? "does the thing"
  assert_log_contains "expected kubectl call" "calls kubectl right"
}

test_something
finish
```

`run.sh` auto-discovers it.

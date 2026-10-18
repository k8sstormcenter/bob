#!/usr/bin/env bash
# Detection demo on one runner set: one clean build and one held build that the mock suite is
# replayed against, both on bound runners, then both scored into a confusion matrix.
#
#   REPO=k8sstormcenter/nnf-community-infra RUNNER=nnf-c-ubuntu-24.04-2-8-x86 \
#   CH_USER=… CH_PASSWORD=… harness/demo.sh [dataset-dir]
#
# Needs: gh (workflow dispatch on REPO), kubectl on the runner cluster (KUBECONFIG), bobctl,
# python3. The workflow takes LANG, PROJECT, STEPS, RUNNER and TAG and holds the job for 600 s
# when STEPS contains "hold", which is the window the suite runs in.
set -euo pipefail
G=$(cd "$(dirname "$0")/.." && pwd)
REPO=${REPO:?set REPO to the repo holding the workflow}
WF=${WF:-sbob-portability.yaml}
RUNNER=${RUNNER:?set RUNNER to the runner set label}
DLANG=${DLANG:-go}
PROJECT=${PROJECT:-A}
STEPS=${STEPS:-test,coverage,lint,package,cache,upload,sarif,hold}
NS=${NS:-arc-systems}
SETTLE=${SETTLE:-360}
B=${BOBCTL:-bobctl}
SUITE=${SUITE:-$G/../github-runner-attacks.yaml}
STAMP=$(date -u +%Y%m%d-%H%M%S)
DS=${1:-$PWD/demo-$RUNNER-$STAMP}
mkdir -p "$DS/builds/clean" "$DS/builds/attack"
: "${CH_USER:?}" "${CH_PASSWORD:?}"

dispatch() {
  gh workflow run "$WF" -R "$REPO" -f LANG="$DLANG" -f PROJECT="$PROJECT" -f STEPS="$STEPS" \
    -f RUNNER="$RUNNER" -f TAG="$1" >/dev/null
}

# run id of the dispatch tagged $1 (the workflow puts TAG in its run name)
run_id() {
  for _ in $(seq 1 60); do
    id=$(gh run list -R "$REPO" -w "$WF" -L 30 --json databaseId,displayTitle \
      --jq ".[] | select(.displayTitle | contains(\"$1\")) | .databaseId" | head -1)
    [ -n "$id" ] && { echo "$id"; return; }
    sleep 5
  done
  echo "no run for $1" >&2; exit 1
}

# the runner pod a run landed on: the job's runner_name is the pod name
pod_of() {
  for _ in $(seq 1 120); do
    p=$(gh api "repos/$REPO/actions/runs/$1/jobs" --jq '.jobs[0].runner_name // empty')
    [ -n "$p" ] && kubectl -n "$NS" get pod "$p" >/dev/null 2>&1 && { echo "$p"; return; }
    sleep 10
  done
  echo "run $1 got no runner pod" >&2; exit 1
}

wait_done() { gh run watch "$1" -R "$REPO" --exit-status >/dev/null 2>&1 || true; }

echo "dataset $DS"
dispatch "demo-clean-$STAMP"
dispatch "demo-attack-$STAMP"
rc=$(run_id "demo-clean-$STAMP"); ra=$(run_id "demo-attack-$STAMP")
pc=$(pod_of "$rc"); pa=$(pod_of "$ra")
echo "clean  run $rc pod $pc"
echo "attack run $ra pod $pa"

echo "replaying the suite against $pa"
"$B" simulate --suite "$SUITE" --pod "$pa" -n "$NS" --exec-timeout 25s --record "$DS/builds/attack/fire.json" --format table

wait_done "$rc"; wait_done "$ra"
echo "both runs done; waiting ${SETTLE}s for evidence-only scoring at pod departure"
sleep "$SETTLE"

printf '{"role":"clean","run":%s,"pod":"%s","runner":"%s","stamp":"%s"}\n' "$rc" "$pc" "$RUNNER" "$STAMP" > "$DS/builds/clean/meta.json"
printf '{"role":"attack","run":%s,"pod":"%s","runner":"%s","stamp":"%s"}\n' "$ra" "$pa" "$RUNNER" "$STAMP" > "$DS/builds/attack/meta.json"
python3 "$G/harness/collect.py" alerts --pod "$pc" --out "$DS/builds/clean"
python3 "$G/harness/collect.py" alerts --pod "$pa" --fire "$DS/builds/attack/fire.json" --out "$DS/builds/attack"
python3 "$G/harness/collect.py" kpi --pod "$pc" --out "$DS/builds/clean"
python3 "$G/harness/collect.py" kpi --pod "$pa" --out "$DS/builds/attack"

python3 "$G/harness/matrix.py" "$DS" --suite "$SUITE" ${KNOWN:+--known "$KNOWN"} --json "$DS/matrix.json" | tee "$DS/matrix.md"
echo
python3 "$G/harness/matrix.py" "$DS" --suite "$SUITE" --subset "$G/harness/teampcp-steps.txt" ${KNOWN:+--known "$KNOWN"} | tee "$DS/matrix-teampcp.md"
echo
echo "KPI panel: dx/kpi_proof, pod filter $pa (and $pc for the clean build), window covering $STAMP"

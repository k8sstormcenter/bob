#!/usr/bin/env bash
# local-ci-chain.sh — multi-pod chain demo orchestration.
#
# Reuses bobctl's existing attack runner against the four-component
# chain in example/chain/. Adds a cross-pod alert verifier (this script)
# that doesn't fit the single-target tuner shape (filterByContainers in
# pkg/autotune/tuner.go restricts alerts to the baseline profile's
# containers; the chain demo intentionally crosses pods).
#
# Usage:
#   ./scripts/local-ci-chain.sh                       # full pipeline (build + push to ttl.sh)
#   ./scripts/local-ci-chain.sh --use-published       # skip build, pull GHCR images
#   ./scripts/local-ci-chain.sh --setup-only          # deploy + learn, stop
#   ./scripts/local-ci-chain.sh --attack-only         # skip setup, re-run chain
#   ./scripts/local-ci-chain.sh --extended            # also run s5 (pg-wire) + s6 (DNS exfil)
#   ./scripts/local-ci-chain.sh --teardown            # delete the chain ns
#
#   Flags compose: --use-published --extended, --attack-only --extended, etc.
#
#   CHAIN_PUBLISHED_TAG=<sha>   override default `latest` for --use-published
#
# Layout assumed:
#   example/chain/chain.yaml                  4 deployments + 4 services
#   example/chain/{frontend,backend}/         Go services with Dockerfiles
#   example/chain/chain-attacks.yaml          AttackSuite (4 stages)
#   example/chain/chain-functional-tests.yaml benign baseline (5 reqs)
#   example/chain/sbobs/                      exported AP+NN per pod
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

NS=chain
KS_NS=honey
LEARN_WAIT=180s
PROPAGATION_WAIT=20

SETUP_ONLY=false
ATTACK_ONLY=false
TEARDOWN=false
USE_PUBLISHED=false
EXTENDED=false
LEARN_SBOBS=false
PUBLISHED_TAG="${CHAIN_PUBLISHED_TAG:-latest}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    # CUSTOMER FLOW (default + --setup-only): apply the pre-shipped
    # ApplicationProfile / NetworkNeighborhood YAMLs from
    # example/chain/sbobs/ BEFORE the chain pods start. Pods carry
    # `kubescape.io/user-defined-profile` + `user-defined-network`
    # labels referencing those resources by name — node-agent picks
    # them up directly and skips the learning phase entirely. This is
    # the "vendor ships sealed sbobs, customer applies and runs" flow.
    --setup-only)    SETUP_ONLY=true ;;
    --attack-only)   ATTACK_ONLY=true ;;
    --teardown)      TEARDOWN=true ;;
    # --use-published: skip the local build+push, pull the published
    # GHCR images instead. Lets devs without docker access (or under
    # docker credstore breakage) run the demo. Tag defaults to
    # `latest` or whatever CHAIN_PUBLISHED_TAG env var is set to —
    # CI matrix jobs pin to a short-sha for reproducibility.
    --use-published) USE_PUBLISHED=true ;;
    # --extended: also run example/chain/chain-attacks-extended.yaml
    # after the basic chain. Adds two stages:
    #   s5 — full pg-wire conversation (StartupMessage + Query + parse
    #        DataRow) from inside redis pod, extracts ONE postgres row
    #        via the lateral pivot.
    #   s6 — DNS exfiltration of the extracted row: base32-encoded
    #        label per chunk, one DNS query per chunk so the leaked
    #        bytes show up in alert.labels.address.
    # Requires chain.yaml's POSTGRES_HOST_AUTH_METHOD=trust (already
    # set). The basic chain still runs first regardless of this flag.
    --extended)      EXTENDED=true ;;
    # VENDOR FLOW: skip applying the pre-shipped sbobs, strip the
    # user-defined-profile labels from chain.yaml at deploy time so
    # node-agent doesn't try to use the supplied AP/NN (which we
    # don't want for a fresh learn anyway), then run benign traffic
    # while kubescape learns. The vendor regenerates the sbobs by
    # exporting whatever kubescape sealed and hand-cleaning it
    # (annotation strip + version-segment wildcarding) into
    # example/chain/sbobs/ — the tuner will eventually do this
    # auto-cleanup, but today it's a one-off manual edit.
    --learn-sbobs)   LEARN_SBOBS=true ;;
    -h|--help)       sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }

need kubectl
need jq
# docker + go are only needed when building locally (not for --teardown
# or --use-published). Gated below at the build site so flag-only paths
# work on dev boxes without docker (rabbit-flagged 2026-05-17).

if $TEARDOWN; then
  log "=== Teardown $NS namespace ==="
  # --wait=true so re-running setup-after-teardown in a script chain
  # doesn't race against the still-terminating namespace and fail with
  # "namespace is being terminated" on every apply.
  kubectl delete ns "$NS" --ignore-not-found --wait=true
  exit 0
fi

# ── Setup phase ──────────────────────────────────────────────────────
if ! $ATTACK_ONLY; then
  log "=== Cluster sanity ==="
  kubectl get nodes >/dev/null || die "no cluster"
  kubectl get ns "$KS_NS" >/dev/null 2>&1 || die "kubescape ns ($KS_NS) missing — run scripts/local-ci.sh --setup-only first"

  if $USE_PUBLISHED; then
    # ── Published-image path ───────────────────────────────────────
    # Skip docker build + push. Pull stable GHCR images that the
    # CI workflow (.github/workflows/ci-chain-images.yaml) published
    # on the last main/feat/postgres-endpoint-attacks push. Useful
    # when the dev box has no docker daemon, or when the host's
    # docker credstore is broken (pass/gpg pinentry not available).
    # TDD gate is skipped here too — CI ran it before publishing,
    # so the published image already passed.
    CHAIN_BACKEND_IMG="ghcr.io/k8sstormcenter/chain-backend:${PUBLISHED_TAG}"
    CHAIN_FRONTEND_IMG="ghcr.io/k8sstormcenter/chain-frontend:${PUBLISHED_TAG}"
    log "=== Using published images (no local build) ==="
    log "  backend:  $CHAIN_BACKEND_IMG"
    log "  frontend: $CHAIN_FRONTEND_IMG"
  else
    # Local-build path needs docker + go on PATH; --use-published
    # skipped both. Gate here instead of upfront so --teardown +
    # --use-published work on dev boxes without either.
    need docker
    need go
    log "=== TDD gate: chain-backend + chain-frontend tests must pass ==="
    for component in backend frontend; do
      (cd "example/chain/$component" && \
        GOWORK=off GOPATH=/mnt/dev-data/go GOMODCACHE=/mnt/dev-data/go/pkg/mod GOCACHE=/mnt/dev-data/go-cache \
          go test ./... >/dev/null) \
        || die "chain-$component tests failed — fix before deploying"
    done

    # docker / buildkit walks $HOME/.docker/config.json regardless of
    # DOCKER_CONFIG env. If the host config references a credstore that
    # needs interactive GPG (e.g. "pass"), every metadata fetch on a
    # public image fails non-interactively. Workaround: build inside a
    # scoped HOME pointing at an empty docker config. Doesn't touch the
    # host ~/.docker; doesn't break kubectl elsewhere in this script.
    CHAIN_DOCKER_HOME=$(mktemp -d /tmp/chain-dckr-home.XXX)
    mkdir -p "$CHAIN_DOCKER_HOME/.docker"
    echo '{}' > "$CHAIN_DOCKER_HOME/.docker/config.json"
    trap 'rm -rf "$CHAIN_DOCKER_HOME"' EXIT
    # Wrapper: docker_anon for any registry call that should bypass creds.
    docker_anon() { HOME="$CHAIN_DOCKER_HOME" docker "$@"; }

    # ── ttl.sh ephemeral registry ─────────────────────────────────────
    # ttl.sh: anonymous, public-pull, per-tag TTL (24h). Each component
    # gets its own UUID-tagged image so concurrent iterations don't
    # trample each other. Kubelet pulls publicly via containerd —
    # no daemon edits, no in-cluster registry, no sudo.
    TTL_UUID="${CHAIN_IMAGE_UUID:-$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)}"
    CHAIN_BACKEND_IMG="ttl.sh/chain-backend-${TTL_UUID}:24h"
    CHAIN_FRONTEND_IMG="ttl.sh/chain-frontend-${TTL_UUID}:24h"

    log "=== Build chain-backend (ttl.sh, 24h TTL) ==="
    log "  image ref: $CHAIN_BACKEND_IMG"
    DOCKER_HOST=${DOCKER_HOST:-unix:///var/run/docker.sock} \
      docker_anon build -t "$CHAIN_BACKEND_IMG" example/chain/backend/ >/dev/null \
      || die "chain-backend image build failed"
    DOCKER_HOST=${DOCKER_HOST:-unix:///var/run/docker.sock} \
      docker_anon push "$CHAIN_BACKEND_IMG" 2>&1 | tail -2 \
      || die "push chain-backend to ttl.sh failed"

    log "=== Build chain-frontend (ttl.sh, 24h TTL) ==="
    log "  image ref: $CHAIN_FRONTEND_IMG"
    DOCKER_HOST=${DOCKER_HOST:-unix:///var/run/docker.sock} \
      docker_anon build -t "$CHAIN_FRONTEND_IMG" example/chain/frontend/ >/dev/null \
      || die "chain-frontend image build failed"
    DOCKER_HOST=${DOCKER_HOST:-unix:///var/run/docker.sock} \
      docker_anon push "$CHAIN_FRONTEND_IMG" 2>&1 | tail -2 \
      || die "push chain-frontend to ttl.sh failed"
  fi  # end USE_PUBLISHED

  # Inject the image refs into the manifest. Keep the YAML clean —
  # ttl.sh / ghcr.io paths only land in the rendered copy.
  CHAIN_MANIFEST=$(mktemp /tmp/chain-XXX.yaml)
  sed -e "s|image: chain-backend:latest|image: ${CHAIN_BACKEND_IMG}|" \
      -e "s|image: chain-frontend:latest|image: ${CHAIN_FRONTEND_IMG}|" \
    example/chain/chain.yaml > "$CHAIN_MANIFEST"

  log "=== Deploy 4 components into $NS ==="
  kubectl apply -f "$CHAIN_MANIFEST"
  for d in chain-postgres chain-redis chain-backend chain-frontend; do
    kubectl rollout status deployment/"$d" -n "$NS" --timeout=180s \
      || log "  WARN: $d not ready (continuing — readiness loop will catch it)"
  done

  log "=== Wait for frontend /healthz ==="
  kubectl wait --for=condition=ready pod -l app=chain-frontend -n "$NS" --timeout=120s \
    || die "frontend never became ready"

  log "=== Generate benign baseline traffic for sbob learning ==="
  # Two benign patterns, both via frontend (which is the user-facing
  # entrypoint of the chain):
  #   1. /api/products  — frontend → backend → postgres  (HTTP, pg-wire)
  #   2. /api/cache/eval — frontend → redis EVAL (RESP, atomic counter)
  # Both populate the relevant NetworkNeighborhood edges; without (2)
  # the chain attack's first redis call would be a NN violation, which
  # would defeat the demo's premise (the eval endpoint is a FEATURE,
  # not a backdoor — the SCRIPT being untrusted is the vuln).
  for _ in $(seq 1 15); do
    kubectl run curl-tmp-$RANDOM --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
      --namespace="$NS" --quiet -- \
      curl -sf "http://chain-frontend.$NS.svc:8080/api/products" >/dev/null 2>&1 || true
  done
  for _ in $(seq 1 15); do
    kubectl run curl-tmp-$RANDOM --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
      --namespace="$NS" --quiet -- \
      sh -c 'curl -sf -X POST -H "Content-Type: application/json" \
        --data "{\"script\":\"return redis.call(\\\"INCR\\\", KEYS[1])\",\"keys\":[\"chain:bench\"]}" \
        "http://chain-frontend.'$NS'.svc:8080/api/cache/eval"' >/dev/null 2>&1 || true
  done

  log "=== Wait for sbob learning to mark profile completed AND non-empty ($LEARN_WAIT) ==="
  # kubescape creates the AP CR after the pod starts AND sometimes
  # seals it with execs=0 if no process activity was observed inside
  # the learning window (race between pod start and node-agent BPF
  # attach). An empty AP is fail-open — no R0001 will ever fire on
  # such a pod. To keep the demo reliable, we wait for BOTH
  # `kubescape.io/status: completed` AND at least one exec entry.
  # If the window expires with execs=0 we delete the AP and force a
  # fresh learn (which restarts the kubescape clock for that pod);
  # the deletion is cheap because the AP is empty anyway.
  for app in chain-backend chain-postgres chain-redis chain-frontend; do
    log "  waiting for $app profile (completed + execs>0)"
    deadline=$(( $(date +%s) + ${LEARN_WAIT%s} ))
    while [[ $(date +%s) -lt $deadline ]]; do
      info=$(kubectl get applicationprofile -n "$NS" -o json 2>/dev/null \
        | jq -r --arg app "$app" '
          [.items[] | select(.metadata.name | startswith("replicaset-" + $app))][0]
          | (.metadata.annotations["kubescape.io/status"] // "missing") + "|" + ((.spec.containers[0].execs // []) | length | tostring)')
      status="${info%%|*}"
      execs="${info##*|}"
      if [[ "$status" == "completed" && "$execs" -gt 0 ]]; then
        log "    $app: completed (execs=$execs)"
        break
      fi
      # If sealed empty, delete + retry. Topping up benign traffic
      # is what gives kubescape something to learn.
      if [[ "$status" == "completed" && "$execs" -eq 0 ]]; then
        log "    $app: completed-but-empty, deleting AP+NN to force re-learn"
        ap_name=$(kubectl get applicationprofile -n "$NS" -o json | jq -r --arg app "$app" '[.items[] | select(.metadata.name | startswith("replicaset-" + $app))][0].metadata.name')
        nn_name=$(kubectl get networkneighborhood -n "$NS" -o json | jq -r --arg app "$app" '[.items[] | select(.metadata.name | startswith("replicaset-" + $app))][0].metadata.name')
        [[ -n "$ap_name" && "$ap_name" != "null" ]] && kubectl delete applicationprofile -n "$NS" "$ap_name" --ignore-not-found >/dev/null 2>&1
        [[ -n "$nn_name" && "$nn_name" != "null" ]] && kubectl delete networkneighborhood -n "$NS" "$nn_name" --ignore-not-found >/dev/null 2>&1
        # Force fresh learning by restarting the deployment and
        # generating a burst of benign traffic so the new pod has
        # observable activity during its learning window.
        kubectl rollout restart deployment/"$app" -n "$NS" >/dev/null 2>&1
        kubectl rollout status deployment/"$app" -n "$NS" --timeout=60s >/dev/null 2>&1 || true
        # Hit BOTH benign endpoints — /api/products only reaches backend
        # +postgres, /api/cache/eval is what reaches redis. Without
        # the eval calls, chain-redis would re-seal empty again because
        # no redis-server activity was observed during its second
        # learning window. (rabbit-flagged 2026-05-17.)
        for _ in 1 2 3 4 5; do
          kubectl run curl-t-$RANDOM --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
            --namespace="$NS" --quiet -- \
            curl -sf "http://chain-frontend.$NS.svc:8080/api/products" >/dev/null 2>&1 || true
        done
        for _ in 1 2 3 4 5; do
          kubectl run curl-t-$RANDOM --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
            --namespace="$NS" --quiet -- \
            sh -c 'curl -sf -X POST -H "Content-Type: application/json" --data "{\"script\":\"return redis.call(\\\"INCR\\\", KEYS[1])\",\"keys\":[\"chain:bench\"]}" "http://chain-frontend.'$NS'.svc:8080/api/cache/eval"' >/dev/null 2>&1 || true
        done
      fi
      sleep 4
    done
    [[ "$status" == "completed" && "$execs" -gt 0 ]] \
      || log "    WARN: $app profile status=$status execs=$execs (continuing — detections may be unreliable)"
  done
fi  # end setup

if $SETUP_ONLY; then
  log "=== --setup-only: stopping after deploy + learn ==="
  exit 0
fi

# ── Attack phase ─────────────────────────────────────────────────────
log "=== Snapshot alertmanager BEFORE chain attacks ==="
PRE=$(mktemp /tmp/chain-pre.XXX.json)
kubectl get --raw "/api/v1/namespaces/$KS_NS/services/alertmanager:9093/proxy/api/v2/alerts?active=true" \
  > "$PRE" 2>/dev/null || echo "[]" > "$PRE"
PRE_FP=$(jq -r '[.[] | (.labels // {}) | "\(.rule_id // "x")|\(.container_name // "x")|\(.pod_name // "x")|\(.comm // "x")"] | sort | unique | .[]' "$PRE" 2>/dev/null || true)
log "  pre-attack alerts: $(echo "$PRE_FP" | grep -c . || true) unique fingerprints"

log "=== Build bobctl (cached) ==="
GOPATH=/mnt/dev-data/go GOMODCACHE=/mnt/dev-data/go/pkg/mod GOCACHE=/mnt/dev-data/go-cache \
  go build -o bin/bobctl ./pkg/main.go

log "=== Run chain-attacks suite ==="
# Don't pass --service: the AttackSuite YAML's target.service is the
# source of truth (chain-frontend, port 8080). Passing --service
# chain-backend made bobctl route the POSTs to a pod that doesn't
# even serve /api/cache/eval — every request 404'd but the coverage
# table still showed DETECTED because alertmanager still held alerts
# from earlier ad-hoc /api/cache/eval calls (rabbit-flagged
# 2026-05-17).
bin/bobctl attack \
  --attack-suite example/chain/chain-attacks.yaml \
  --namespace "$NS" \
  --format markdown \
  | tee /tmp/chain-attack-results.md

if $EXTENDED; then
  log "=== Run chain-attacks-extended (s5 pg-wire + s6 DNS exfil) ==="
  # The extended suite shares the redis sandbox-escape primitive with
  # the basic chain — it just chains additional outbound traffic onto
  # the same io.popen. Runs AFTER the basic suite so all expectations
  # from both YAMLs land in alertmanager before the coverage step.
  bin/bobctl attack \
    --attack-suite example/chain/chain-attacks-extended.yaml \
    --namespace "$NS" \
    --format markdown \
    | tee /tmp/chain-attack-results-extended.md
fi

log "=== Wait $PROPAGATION_WAIT s for alert propagation ==="
sleep "$PROPAGATION_WAIT"

log "=== Snapshot alertmanager AFTER ==="
POST=$(mktemp /tmp/chain-post.XXX.json)
kubectl get --raw "/api/v1/namespaces/$KS_NS/services/alertmanager:9093/proxy/api/v2/alerts?active=true" \
  > "$POST" 2>/dev/null || echo "[]" > "$POST"
POST_COUNT=$(jq 'length' "$POST")
log "  post-attack alerts: $POST_COUNT total"

# ── Active alerts: match against EVERY chain-namespace alert ────────
# Why "all post" rather than "post − pre": alertmanager dedupes by
# fingerprint, so a rule that fired in an earlier iteration still has
# its alert in the active set. A pre/post diff against fingerprint
# would mark those as "not new" and the chain would falsely report
# BLIND on real detections. The right question for the demo is "does
# this rule fire on this container?" — recency matters less than
# coverage. Pre-snapshot is kept above only for the operator log so
# they can spot environment noise.
ACTIVE=$(mktemp /tmp/chain-active.XXX.json)
jq '[.[] | select((.labels.namespace // "") == "chain" or ((.labels.pod_name // "") | startswith("chain-")))]' "$POST" > "$ACTIVE"

ACTIVE_COUNT=$(jq 'length' "$ACTIVE")
log "=== Active chain-namespace alerts: $ACTIVE_COUNT ==="
jq -r '.[] | "  \(.labels.rule_id // "?") | container=\(.labels.container_name // "?") pod=\(.labels.pod_name // "?") comm=\(.labels.comm // "-") | starts=\(.startsAt)"' "$ACTIVE" \
  | sort -u | awk 'NR<=30 { print } NR==31 { print "  ... (truncated)" }'

# ALIAS for downstream coverage step (kept name for diff readability)
NEW="$ACTIVE"

# ── Coverage: match NEW alerts against expectedDetections in YAML ───
#
# Parser is deliberately minimal: chain-attacks.yaml uses a stable
# two-space indent and the only `expectedDetections:` blocks live
# directly under each top-level attack entry. We don't need a full
# YAML parser — just the four keys we care about. If the YAML schema
# changes, this script's first failed run will spot the regression
# faster than a silent partial parse would.
log "=== Coverage report ==="
COVERAGE=$(mktemp /tmp/chain-coverage.XXX.json)
EXPECTATIONS=$(mktemp /tmp/chain-expect.XXX.json)

# 1. Build [{scenario, ruleID, containerName, command}, ...] from YAML.
# Parses BOTH chain-attacks.yaml AND (when --extended was passed)
# chain-attacks-extended.yaml so the coverage table covers every
# expectation that bobctl attack actually ran.
SUITE_FILES=( "$REPO_ROOT/example/chain/chain-attacks.yaml" )
if $EXTENDED; then
  SUITE_FILES+=( "$REPO_ROOT/example/chain/chain-attacks-extended.yaml" )
fi
awk '
  BEGIN { OFS=""; printing=0; scn=""; rule=""; rname=""; cnt=""; cmd="" }
  function flush() {
    if (rule != "") {
      printf "%s{\"scenario\":\"%s\",\"ruleID\":\"%s\",\"ruleName\":\"%s\",\"containerName\":\"%s\",\"command\":\"%s\"}",
        (first ? "" : ","), scn, rule, rname, cnt, cmd
      first=0
    }
    rule=""; rname=""; cnt=""; cmd=""
  }
  BEGIN { print "["; first=1 }
  /^  - name:/                   { flush(); scn=$3; in_exp=0 }
  /^    expectedDetections:/     { in_exp=1; next }
  in_exp && /^      - ruleID:/   { flush(); rule=$3 }
  in_exp && /^        ruleName:/ { sub(/^ +ruleName: */, ""); rname=$0; gsub(/"/, "\\\"", rname) }
  in_exp && /^        containerName:/ { cnt=$2 }
  in_exp && /^        command:/  { cmd=$2 }
  /^  - name:/ && in_exp         { in_exp=0 }
  END { flush(); print "]" }
' "${SUITE_FILES[@]}" > "$EXPECTATIONS"

EXP_COUNT=$(jq 'length' "$EXPECTATIONS")
log "  expectations parsed: $EXP_COUNT"

# 2. Match each expectation against NEW alerts.
# Note: jq's `as` only binds at the top of a pipeline, so we lift the
# slurpfile + the `any` predicate into a separate function.
jq --slurpfile alerts "$NEW" '
  def matches($e):
    any($alerts[0][]?;
      (.labels // {}) as $l
      | $l.rule_id == $e.ruleID
      and ($e.containerName == "" or $l.container_name == $e.containerName)
      # Parens around the contains chain — without them jq applies
      # `|` across the `or`, fighting precedence (saw: boolean has no
      # containment).
      and ($e.command == "" or (($l.comm // "") | contains($e.command)))
    );
  map(. + {status: (if matches(.) then "DETECTED" else "BLIND" end)})
' "$EXPECTATIONS" > "$COVERAGE"

# 3. Render table
printf "  %-40s %-7s %-15s %-12s %s\n" "SCENARIO" "RULE" "CONTAINER" "COMM" "STATUS"
jq -r '.[] | [.scenario, .ruleID, .containerName, .command, .status] | @tsv' "$COVERAGE" \
  | awk -F'\t' '{ printf "  %-40s %-7s %-15s %-12s %s\n", $1, $2, $3, $4, $5 }'

DETECTED=$(jq '[.[] | select(.status == "DETECTED")] | length' "$COVERAGE")
TOTAL=$(jq 'length' "$COVERAGE")
log "  Coverage: $DETECTED / $TOTAL expected detections matched"

# Sentinel block — preserves the rest of the original heredoc usage
# pattern (no-op since we no longer call go run):
true << 'GOEOF'
//go:build chainreport
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type detection struct {
	RuleID, RuleName, ContainerName, Command string
}
type attackDef struct {
	Name               string
	ExpectedDetections []detection
}
type suite struct {
	Attacks []attackDef
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: chainreport <new-alerts.json> <out-coverage.json> <suite.yaml>")
		os.Exit(2)
	}
	newPath, outPath, suitePath := os.Args[1], os.Args[2], os.Args[3]

	suiteBytes, err := os.ReadFile(suitePath)
	if err != nil { fmt.Fprintln(os.Stderr, "read suite:", err); os.Exit(1) }
	var s suite
	// yaml.v3 honours yaml tags; our struct field names happen to align with attack.AttackSuite.
	type rawDet struct {
		RuleID        string `yaml:"ruleID"`
		RuleName      string `yaml:"ruleName"`
		ContainerName string `yaml:"containerName"`
		Command       string `yaml:"command"`
	}
	type rawAtk struct {
		Name               string   `yaml:"name"`
		ExpectedDetections []rawDet `yaml:"expectedDetections"`
	}
	type rawSuite struct {
		Attacks []rawAtk `yaml:"attacks"`
	}
	var rs rawSuite
	if err := yaml.Unmarshal(suiteBytes, &rs); err != nil { fmt.Fprintln(os.Stderr, "yaml:", err); os.Exit(1) }
	for _, a := range rs.Attacks {
		ad := attackDef{Name: a.Name}
		for _, d := range a.ExpectedDetections {
			ad.ExpectedDetections = append(ad.ExpectedDetections, detection(d))
		}
		s.Attacks = append(s.Attacks, ad)
	}

	newBytes, err := os.ReadFile(newPath)
	if err != nil { fmt.Fprintln(os.Stderr, "read new:", err); os.Exit(1) }
	var alerts []struct {
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(newBytes, &alerts); err != nil { fmt.Fprintln(os.Stderr, "json:", err); os.Exit(1) }

	type row struct {
		Scenario, Rule, Container, Comm, Status string
	}
	var report []row
	totalExp, totalDet := 0, 0
	for _, a := range s.Attacks {
		for _, e := range a.ExpectedDetections {
			totalExp++
			matched := false
			for _, al := range alerts {
				if al.Labels["rule_id"] != e.RuleID { continue }
				if e.ContainerName != "" && al.Labels["container_name"] != e.ContainerName { continue }
				if e.Command != "" && !strings.Contains(al.Labels["comm"], e.Command) { continue }
				matched = true; break
			}
			status := "BLIND"
			if matched { status = "DETECTED"; totalDet++ }
			report = append(report, row{
				Scenario: a.Name, Rule: e.RuleID, Container: e.ContainerName,
				Comm: e.Command, Status: status,
			})
		}
		if len(a.ExpectedDetections) == 0 {
			report = append(report, row{Scenario: a.Name, Status: "(no expectations)"})
		}
	}

	for _, r := range report {
		fmt.Printf("  %-40s %-8s container=%-15s comm=%-12s %s\n",
			r.Scenario, r.Rule, r.Container, r.Comm, r.Status)
	}
	fmt.Printf("\nCoverage: %d/%d expected detections matched\n", totalDet, totalExp)

	out, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(outPath, out, 0644)
}
GOEOF

log "=== Coverage written to $COVERAGE ==="
log "=== local-ci-chain done ==="

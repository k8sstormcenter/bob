#!/usr/bin/env bash
# Flux SBoB demo — deploy Flux and optionally bind the hand-built SBoBs.
# Symmetrical to example/redis/distros/deploy-distros.sh.
#
#   ./distro.sh          # deploy only  (make deploy-flux)
#   ./distro.sh sbob     # deploy AND bind the six controller SBoBs from sbobs/
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-}"
NS=flux-system
CONTROLLERS="source-controller kustomize-controller helm-controller notification-controller image-reflector-controller image-automation-controller"

deploy() { make -C ../.. deploy-flux; }

# Bind: apply the CP, then label the Deployment's pod template so node-agent
# enforces it. The operator only stamps the label onto NEWLY created pods, so
# the patch rolls the controller — a live pod is not relabelled in place.
bind() {
  for c in $CONTROLLERS; do
    kubectl apply -f "sbobs/cp-flux-$c.yaml"
    kubectl -n "$NS" patch deployment "$c" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"kubescape.io/user-defined-profile\":\"flux-$c\"}}}}}"
  done
  for c in $CONTROLLERS; do kubectl -n "$NS" rollout status deploy/"$c" --timeout=180s; done
  echo "bound 6 flux SBoBs (kubescape.io/user-defined-profile=flux-<controller>)"
}

deploy
[ "$MODE" = sbob ] && bind

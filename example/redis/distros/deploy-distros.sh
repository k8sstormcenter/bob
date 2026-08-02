#!/usr/bin/env bash
# Deploy an upstream redis-protocol distro with its SBoB bound at deploy time.
# Each manifest uses the UPSTREAM distro image (the image the SBoB in sbobs/ was
# learned against) and carries the kubescape.io/user-defined-profile pod label;
# the matching ContainerProfile is applied in the same step, so node-agent
# enforces the SBoB from the moment the pod starts — no post-deploy patch.
#
#   distro     upstream image                  ns          bound profile
#   redis-oss  redis:8.10.0                    redis-oss   sbobs/cp-redis.yaml
#   valkey     valkey/valkey:9.1.1             valkey      sbobs/cp-valkey.yaml
#   keydb      eqalpha/keydb:x86_64_v6.3.4     keydb       sbobs/cp-keydb.yaml
#   dragonfly  dragonflydb/dragonfly:v1.39.0   dragonfly   sbobs/cp-dragonfly.yaml
#
# Usage: ./deploy-distros.sh [redis|valkey|keydb|dragonfly|all]   (no arg = all)
set -euo pipefail
cd "$(dirname "$0")"

bind() {  # manifest ns sbob
  kubectl apply -f "$1.yaml"
  kubectl apply -f "sbobs/$3"
  kubectl -n "$2" rollout status deploy/redis --timeout=120s
}

deploy_redis()     { bind redis-oss redis-oss cp-redis.yaml ; }
deploy_valkey()    { bind valkey    valkey    cp-valkey.yaml ; }
deploy_keydb()     { bind keydb     keydb     cp-keydb.yaml ; }
deploy_dragonfly() { bind dragonfly dragonfly cp-dragonfly.yaml ; }

distro="${1:-all}"
case "$distro" in
  redis|redis-oss) deploy_redis ;;
  valkey)          deploy_valkey ;;
  keydb)           deploy_keydb ;;
  dragonfly)       deploy_dragonfly ;;
  all)             deploy_redis; deploy_valkey; deploy_keydb; deploy_dragonfly ;;
  *)
    echo "unknown distro: $distro" >&2
    echo "usage: $0 [redis|valkey|keydb|dragonfly|all]" >&2
    exit 2
    ;;
esac

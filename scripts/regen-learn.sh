#!/usr/bin/env bash
# Fresh learning run for one example: deploy without profile labels, drive load, export learned profiles, generalize in both exec forms.
set -uo pipefail
EX="$1"; OUT="${2:-regen-out}"; BOBCTL="${BOBCTL:-bin/bobctl}"; WINDOW="${WINDOW:-420}"
mkdir -p "$OUT/learned" "$OUT/regex" "$OUT/legacy" "$OUT/capped" "$OUT/logs"
nolabel() { sed -e '/kubescape\.io\/user-defined-profile/d' "$@"; }
img() { sed -e "s#$1#$2#g"; }
NS=""
case "$EX" in
  php2shell)
    NS="php2shell"
    nolabel example/php2shell/php2shell.yaml | img 'ghcr.io/k8sstormcenter/php2shell-vulnerable:latest' "${APP_IMAGE:-ghcr.io/k8sstormcenter/php2shell-vulnerable:latest}" | kubectl apply -f -
    kubectl -n php2shell rollout status deploy --timeout=300s
    kubectl apply -f example/php2shell/loadgen.yaml ;;
  php2shell-wordpress)
    NS="wordpress wordpress-db wordpress-loadgen"
    kubectl apply -f example/php2shell-wordpress/mariadb.yaml
    kubectl -n wordpress-db rollout status deployment/mariadb --timeout=300s
    nolabel example/php2shell-wordpress/wordpress.yaml | img 'ghcr.io/k8sstormcenter/php2shell-wordpress:latest' "${APP_IMAGE:-php2shell-wordpress:demo}" | kubectl apply -f -
    kubectl -n wordpress rollout status deployment/wordpress --timeout=300s
    nolabel example/php2shell-wordpress/loadgen.yaml | img 'ghcr.io/k8sstormcenter/php2shell-wordpress:latest' "${APP_IMAGE:-php2shell-wordpress:demo}" | kubectl apply -f -
    kubectl -n wordpress-loadgen rollout status deployment/loadgen --timeout=420s ;;
  chain)
    NS="chain"
    nolabel example/chain/chain.yaml | kubectl apply -f -
    kubectl -n chain rollout status deploy --timeout=420s
    kubectl apply -f example/chain/loadgen.yaml
    ( for i in 1 2 3 4 5 6; do sleep 60; kubectl -n chain-loadgen delete job chain-loadgen --ignore-not-found; kubectl apply -f example/chain/loadgen.yaml; done ) >/dev/null 2>&1 & ;;
  java-poc)
    NS="java-poc"
    kubectl apply -f example/java-poc/00-namespaces.yaml
    for f in 10-postgres 20-frontend 30-backend 40-observer 60-cleannoise; do nolabel example/java-poc/$f.yaml | kubectl apply -f -; done
    kubectl -n java-poc rollout status deploy --timeout=600s ;;
  redis-demo)
    NS="redis-demo"
    nolabel example/redis/redis.yaml | kubectl apply -f -
    kubectl -n redis-demo rollout status deploy --timeout=300s ;;
  redis-distro-*)
    D="${EX#redis-distro-}"
    ( cd example/redis/distros && ./deploy-distros.sh "$D" )
    NS="$(kubectl get ns -o name | sed 's#namespace/##' | grep -E "^(redis|valkey|keydb|dragonfly)" | tr '\n' ' ')" ;;
  *) echo "unknown example $EX"; exit 2 ;;
esac
echo "namespaces: $NS"
sleep 120
for n in $NS; do
  for w in $(kubectl -n "$n" get deploy,statefulset -o name 2>/dev/null); do kubectl -n "$n" rollout restart "$w"; done
  for w in $(kubectl -n "$n" get deploy,statefulset -o name 2>/dev/null); do kubectl -n "$n" rollout status "$w" --timeout=600s || true; done
done
date -u +%FT%TZ > "$OUT/t_deployed"
if [[ "$EX" == redis-distro-* ]]; then
  F="example/redis/distros/functional/${D/redis/redis-oss}.yaml"
  for n in $NS; do "$BOBCTL" learn -n "$n" --functional-tests "$F" --timeout 180s --interval 15s > "$OUT/logs/learn-$n.log" 2>&1 || true; done
fi
if [[ "$EX" == java-poc ]]; then "$BOBCTL" test apply example/java-poc/java-functional-tests.yaml > "$OUT/logs/functional.log" 2>&1 || true; fi
sleep "$WINDOW"
for i in $(seq 1 60); do
  pending=0
  for n in $NS; do
    while read -r name st; do [ -z "$name" ] && continue; [ "$st" = "completed" ] || pending=$((pending+1)); done < <(kubectl get containerprofiles -n "$n" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.kubescape\.io/status}{"\n"}{end}' 2>/dev/null)
  done
  have=$(for n in $NS; do kubectl get containerprofiles -n "$n" --no-headers 2>/dev/null; done | wc -l)
  [ "$have" -gt 0 ] && [ "$pending" -eq 0 ] && break
  sleep 15
done
for n in $NS; do
  kubectl get pods -n "$n" -o wide > "$OUT/logs/pods-$n.txt" 2>&1
  kubectl get containerprofiles -n "$n" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.kubescape\.io/status}{"\t"}{.metadata.annotations.kubescape\.io/completion}{"\n"}{end}' >> "$OUT/profiles.tsv" 2>/dev/null
  for p in $(kubectl get containerprofiles -n "$n" -o name 2>/dev/null); do
    b="$n--${p##*/}"
    comp=$(kubectl get "$p" -n "$n" -o jsonpath='{.metadata.annotations.kubescape\.io/completion}')
    if [ "$comp" != "complete" ]; then mkdir -p "$OUT/partial"; kubectl get "$p" -n "$n" -o yaml > "$OUT/partial/$b.yaml"; continue; fi
    mkdir -p "$OUT/learned/$b"
    kubectl get "$p" -n "$n" -o yaml > "$OUT/learned/$b/$b.yaml"
    for form in regex legacy; do
      "$BOBCTL" generalize -d "$OUT/learned/$b" --sbob "$b" --exec-form "$form" --generator-ref "${BOBCTL_REF:-unknown}" \
        --capped-report "$OUT/capped/$b.$form.json" -o "$OUT/$form/$b.yaml" > "$OUT/logs/generalize-$b.$form.log" 2>&1 || echo "generalize $form failed: $b" >> "$OUT/failures.txt"
    done
  done
done
kubectl -n honey get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[0].image}{"\n"}{end}' > "$OUT/logs/stack.txt" 2>&1
helm list -n honey > "$OUT/logs/helm.txt" 2>&1
cat "$OUT/profiles.tsv"; [ -f "$OUT/failures.txt" ] && cat "$OUT/failures.txt"
[ -s "$OUT/profiles.tsv" ]

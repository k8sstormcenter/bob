#!/bin/bash
# usage : path to dir [namespace]

if [ ! -z "$2" ]; then
  NAMESPACE="$2"
fi
for f in $1/*_bob.yaml; do
  shortname=$(basename "$f" | sed 's/_bob.yaml$//')
  kind=$(echo "$shortname" | cut -d'-' -f1)
  name=$(echo "$shortname" | cut -d'-' -f2-)
  # Label deployment if kind is replicaset
  if [ "$kind" = "replicaset" ]; then
    kubectl label --overwrite -n "$NAMESPACE" "deployment/$name" kubescape.io/user-defined-profile="$shortname"
    # Also label all pods belonging to the replicaset
    pods=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$name" -o jsonpath='{.items[*].metadata.name}')
    for pod in $pods; do
      kubectl label --overwrite -n "$NAMESPACE" pod/$pod kubescape.io/user-defined-profile="$shortname"
    done
  fi
  # Label pods for jobs or other resources that change templatehash
  if [ "$kind" = "job" ] || [ "$kind" = "replicaset" ]; then
    pods=$(kubectl get pods -n "$NAMESPACE" -l "job-name=$name" -o jsonpath='{.items[*].metadata.name}')
    for pod in $pods; do
      kubectl label --overwrite -n "$NAMESPACE" pod/$pod kubescape.io/user-defined-profile="$shortname"
    done
  fi
  echo $shortname $kind $name
  kubectl apply -f $f 
  kubectl label --overwrite -n "$NAMESPACE" "$kind/$name" kubescape.io/user-defined-profile="$shortname"
done
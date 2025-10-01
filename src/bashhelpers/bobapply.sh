#!/bin/bash
echo "usage : path to dir "
for f in $1/*_bob.yaml; do
  shortname=$(basename "$f" | sed 's/_bob.yaml$//')
  kind=$(echo "$shortname" | cut -d'-' -f1)
  name=$(echo "$shortname" | cut -d'-' -f2-)
  kubectl apply -f $f 
  # Label deployment if kind is replicaset
  if [ "$kind" = "replicaset" ]; then
    kubectl label --overwrite -n harbor "deployment/$name" kubescape.io/user-defined-profile="$shortname"
    # Also label all pods belonging to the replicaset
    pods=$(kubectl get pods -n harbor -l "app.kubernetes.io/name=$name" -o jsonpath='{.items[*].metadata.name}')
    for pod in $pods; do
      kubectl label --overwrite -n harbor pod/$pod kubescape.io/user-defined-profile="$shortname"
    done
  fi

  # Label pods for jobs or other resources that change templatehash
  if [ "$kind" = "job" ] || [ "$kind" = "replicaset" ]; then
    pods=$(kubectl get pods -n harbor -l "job-name=$name" -o jsonpath='{.items[*].metadata.name}')
    for pod in $pods; do
      kubectl label --overwrite -n harbor pod/$pod kubescape.io/user-defined-profile="$shortname"
    done
  fi

  echo $shortname $kind $name
  kubectl label --overwrite -n harbor "$kind/$name" kubescape.io/user-defined-profile="$shortname"
done
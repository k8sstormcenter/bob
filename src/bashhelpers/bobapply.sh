#!/bin/bash
echo "usage : path to dir "
for f in $1/*_bob.yaml; do
  shortname=$(basename "$f" | sed 's/_bob.yaml$//')
  kind=$(echo "$shortname" | cut -d'-' -f1)
  name=$(echo "$shortname" | cut -d'-' -f2-)
  if [ "$kind" = "replicaset" ]; then
    2kind="deployment"
    kubectl label --overwrite -n harbor "$2kind/$name" kubescape.io/user-defined-profile="$shortname"
  fi
  echo $shortname $kind $name
  kubectl apply -f $f 
  kubectl label --overwrite -n harbor "$kind/$name" kubescape.io/user-defined-profile="$shortname"
done
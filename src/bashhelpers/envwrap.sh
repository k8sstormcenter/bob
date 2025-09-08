#!/usr/bin/env bash
set -euo pipefail

INPUT_DIR="${1:-all-bobs}"

image="ghcr.io/k8sstormcenter/bobctl-env:latest"
if [[ $(uname) == "Darwin" ]]; then
  image="docker.io/entlein/bobctl-env:0.0.1"
  echo " using ARM we are"
fi

 docker run --rm \
   -v "$PWD/$INPUT_DIR":/workspace/all-bobs \
   -v "$PWD/testdata/superset.sh":/workspace/superset.sh \
   --workdir /workspace \
   $image /usr/local/bin/bash /workspace/superset.sh /workspace/all-bobs

  docker run --rm \
  -v "$PWD/$INPUT_DIR":/workspace/all-bobs \
  -v "$PWD/testdata/attacksurface.sh":/workspace/attacksurface.sh \
  --workdir /workspace \
  $image /usr/local/bin/bash -c "/workspace/attacksurface.sh /workspace/all-bobs > /workspace/all-bobs/attacksurface.md"
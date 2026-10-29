<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->
# Flux controllers

ContainerProfiles for the four Flux controllers (helm, kustomize, notification, source), learned on the NNF gha-runners cluster and generalized with `bobctl generalize --type controller`. Flux is a long-running reconciler, not a CI runner, so it has its own preset: no CI registry allowlist, each controller's own service-account token read allowed on R0006, `/tmp` and source-controller's `/data` artifact store collapsed.

| path | what |
|---|---|
| `deploy/flux-<controller>-manager.yaml` | the bound profile for container `manager` of `<controller>-controller` |
| `deploy/kustomization.yaml` | all four, for Flux |

Bind by labelling each controller's pod template `kubescape.io/user-defined-profile: flux-<controller>`.

The profiles name the cluster's API server endpoint and the Git and Helm sources it reconciles, so they are specific to the cluster they were learned on.

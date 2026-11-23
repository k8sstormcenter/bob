<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->
# The Contrast loop

One workflow, `Contrast`, produces every SBoB under `example/`. Nobody writes or tunes an SBoB by hand.

```
new simulation method (internal)  ─┐
new application in the workflow   ─┼─▶  Contrast run  ─▶  gate per application  ─▶  pass: file placed, pull request for example/
change to bobctl or the chart     ─┘                                              └▶  held back: reason on the run page, example left as it is
```

## What a run does for each application

1. Deploys the application with its usual traffic and learns its behaviour.
2. `bobctl conditions` reads the pod's configuration and the rights of its service account; `bobctl generalize` finds the language ecosystem. Together they select the signatures.
3. `bobctl generalize` writes the SBoB: a broad allow list plus the subtract entries of those signatures.
4. The SBoB is bound, usual traffic runs again, then `bobctl simulate` runs the inert steps.
5. The cluster is rebuilt with other pod and service addresses, the same SBoB is bound and usual traffic runs once more.
6. The run page gets the summary, the SBoB, a GIF and the gate verdict.

The three KPIs of the GIF come from these steps: **Detectability** is the number of simulated steps that ran and were missed, **Noisiness** the number of alert causes under usual traffic, **Portability** the number of additional alert causes on the second cluster.

## The gate

An SBoB is good enough when all of these hold in the run that produced it:

| Check | Limit |
|---|---|
| `bobctl validate` accepts the profile | must pass |
| usual traffic ran while learning | at least one successful cycle |
| the sensor did not restart | no restart after binding |
| alert causes from the allow list under usual traffic | 0 (`GATE_MAX_BENIGN_CAUSES`) |
| alert causes from a subtract entry under usual traffic | 0 |
| simulated steps that ran and were not detected | 0 (`GATE_MAX_MISSED`) |
| if no step can run in the image: probes the offline check admits | 0 |
| alert causes on a second cluster with other pod and service addresses, beyond the first cluster's (Portability) | 0 (`GATE_MAX_PORTABILITY`) |

The job `Example SBoBs` downloads the SBoBs of the run, places those that passed and opens or updates one pull request from the branch `ci/example-sbobs`. The pull request lists every application with its verdict. An SBoB that is held back never overwrites an example.

## Known and unknown applications

- **Known**: the simulation is written with the application's own history in mind (its advisories of the last ten years, its paths, its tools). Most applications here are known.
- **Unknown**: nothing is written for the application. bobctl is told its type and has to find the language ecosystem and the deployment conditions itself. Their results are the measure of how bobctl does on an application nobody prepared it for; the run page shows them in their own table. An application is marked unknown in the last column of its row in the workloads table.

## Checks on a pull request

- **SBoB lint** (required): every profile under `example/` and `kubescape/` must pass `bobctl validate` of the current release. It takes under a minute.
- The Contrast workflow does not run on pull requests. On main it runs only when `.github/contrast/pins.env` changes, that is when the package revision, the bobctl build, the chart or the list of applications changes. A change to the workflow or its actions alone does not start it; start it by hand for that. Its gate decides what reaches `example/`.

The earlier tune matrix (`CI - bobctl tune`) is retired. Its suites and manifests are under `example/deprecated/`, its local runner under `scripts/deprecated/`.

## Adding an application

1. Add its row, its deployment and its usual traffic to the workloads directory of the `pkg` submodule.
2. Add its name to `ALL_APPS` in `.github/workflows/contrast.yaml`. Containers that must run in one cluster are joined with `+`.
3. If it needs preparation, add `.github/contrast/<application>.pre.sh`.
4. If its SBoB replaces an existing example file, add a line to `examples.txt`. Otherwise it goes to `example/contrast/<application>/`.

## Adding a simulation method

Simulation steps live in the internal build of bobctl and are not published. A new method changes the pinned build (in `.github/contrast/pins.env`: `BOBCTL_TAG`, `BOBCTL_SHA256`, `PKG_REF`) in the workflow file; that change starts a run, and the gate decides which examples move.

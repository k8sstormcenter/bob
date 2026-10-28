<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->
# IoC subtract fragments

An IoC fragment is an advisory's footprint, lifted from the runner's **shadow-profile** of a run that was actually hit. Its entries sit under `spec.subtract`, not under the allow sections; an allow-section copy would *allow* the IoC. `bobctl compose` unions every fragment's `spec.subtract` into the composed profile and removes nothing. The agent evaluates every profile helper as `match(allow) && !match(subtract)`, with the same matcher for both. Allow `/home/runner/*` with subtract `/home/runner/.config/systemd/user/sysmon.py` alerts on `sysmon.py` only; everything else under `/home/runner` stays admitted.

## How it is built

1. If a runner was hit, export its shadow-profile.
2. Grep it for the advisory's IoCs and copy those exact `execs`/`opens`/`egress` entries into a subtract fragment.
3. `harness/compose.sh` passes every `ioc-overlays/*.yaml` to `bobctl compose`.

Allow and subtract can cancel each other: a subtract entry equal to an allow entry makes that behaviour alert. Requires storage with the `spec.subtract` section (k8sstormcenter/storage #73/#74) and a node-agent that evaluates it.

## Files

- `ioc-overlay-teampcp-trivy.yaml`: the TeamPCP compromised-Trivy footprint from the `…runner-lzbzx` shadow-profile:
  - the `sysmon.py --c2 45.148.10.212` backdoor exec, under each exepath it was seen with (`/usr/bin/dash` in the shadow-profile; `/usr/bin/env` on noble and `/usr/lib/cargo/bin/coreutils/env` on resolute, via its shebang);
  - the four `getent` C2-domain lookups;
  - the `tpcp.tar.gz` exfil tar;
  - the persistence open (`~/.config/systemd/user/sysmon.py`) and the stage open (`~/dac-collected.txt`).

The C2 IP and domains appear as exec arguments (`getent hosts …`, `--c2 …`), not as egress: `sysmon.py` makes no real connection and `getent` only resolves.

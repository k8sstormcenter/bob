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

Allow and subtract can cancel each other: a subtract entry equal to an allow entry makes that behaviour alert. 

## Other options to make your profile detect such an attack
You can include adversary test cases during the calibration of the profiles:


1. Use previous, historically known attacks of the type of your setup (here type=`runners`) and leave those unallowed
2. You can choose between the `fragment: subtract` and not generalizing the allow entries

The better option must be decided case-by-case. In this case, for runners, we need to allowlist half of the universe (roughly :P) so the subtract verb is the better choice.


## Files

- `ioc-overlay-teampcp-trivy.yaml`: the TeamPCP compromised-Trivy footprint from the `…runner-lzbzx` shadow-profile:
  - the `sysmon.py --c2 45.148.10.212` backdoor exec, under each exepath it was seen with (`/usr/bin/dash` in the shadow-profile; `/usr/bin/env` on noble and `/usr/lib/cargo/bin/coreutils/env` on resolute, via its shebang);
  - the four `getent` C2-domain lookups;
  - the `tpcp.tar.gz` exfil tar;
  - the persistence open (`~/.config/systemd/user/sysmon.py`) and the stage open (`~/dac-collected.txt`).

The C2 IP and domains appear as exec arguments (`getent hosts …`, `--c2 …`), not as egress: `sysmon.py` makes no real connection and `getent` only resolves.

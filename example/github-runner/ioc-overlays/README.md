# IoC subtract fragments

An IoC fragment is an advisory's footprint, lifted from the runner's **shadow-profile** of a run that was actually hit. A ContainerProfile only allows; it has no deny entries. Composing the footprint as an overlay would therefore *allow* the IoC. These fragments are labelled `kubescape.io/profile-fragment: subtract`. `bobctl compose` removes from the union of base and overlays every exec, open and egress entry that admits one of their entries: the equal literal, or any wildcard that covers it (`⋯`/`*` paths and argv, or a path-only exec). The deployed profile is everything the family allows except the IoC, so the agent alerts on it.

## How it is built

1. If a runner was hit, export its shadow-profile.
2. Grep it for the advisory's IoCs and copy those exact `execs`/`opens`/`egress` entries into a subtract fragment.
3. `harness/compose.sh` passes every `ioc-overlays/*.yaml` to `bobctl compose`.

There is no "everything except X" form inside one entry. A wildcard that covered an IoC is removed whole, not narrowed. Clean behaviour it also covered fires again until the family re-learns it literally.

## Files

- `ioc-overlay-teampcp-trivy.yaml`: the TeamPCP compromised-Trivy footprint from the `…runner-lzbzx` shadow-profile:
  - the `sysmon.py --c2 45.148.10.212` backdoor exec, under each exepath it was seen with (`/usr/bin/dash` in the shadow-profile; `/usr/bin/env` on noble and `/usr/lib/cargo/bin/coreutils/env` on resolute, via its shebang);
  - the four `getent` C2-domain lookups;
  - the `tpcp.tar.gz` exfil tar;
  - the persistence open (`~/.config/systemd/user/sysmon.py`) and the stage open (`~/dac-collected.txt`).

The C2 IP and domains appear as exec arguments (`getent hosts …`, `--c2 …`), not as egress: `sysmon.py` makes no real connection and `getent` only resolves.

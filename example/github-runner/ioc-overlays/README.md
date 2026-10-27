# IoC overlays

An IoC overlay is an advisory's real footprint, lifted from the runner's **shadow-profile** captured when the actual attack action ran. It is not an invented tripwire: the exec and open entries here are grepped out of the learned shadow-profile for the advisory's indicators and copied verbatim.

## How it is built

1. Run the advisory's action through a runner (here: Ben's compromised-Trivy action, `slashben/kubecon26us-detection-as-a-service-talk`).
2. Export the runner's shadow/learned ContainerProfile from that run.
3. Grep it for the advisory's IoCs and lift those exact `execs`/`opens` entries into the overlay.

## What it is for

The supergeneric base admits benign CI behaviour. The overlay is the ground-truth set of entries the advisory produces — what a clean runner must never exhibit. It is the detection-as-code signature for profiles: derived from a real run, versioned, reviewable, and diffable against the base.

## Files

- `ioc-overlay-teampcp-trivy.yaml` — the TeamPCP compromised-Trivy footprint from the `…runner-lzbzx` shadow-profile: the `sysmon.py --c2 45.148.10.212` backdoor exec (dash shebang), the four `getent` C2-domain beacons, the `tpcp.tar.gz` exfil tar, and the persistence (`~/.config/systemd/user/sysmon.py`) and stage (`~/dac-collected.txt`) opens.

## Two observations from the real capture

- The C2 IP and domains appear as **exec arguments** (the `getent` args and the `--c2` arg), not as network/egress entries. The advisory's `sysmon.py` makes no real connection and `getent` only resolves, so there is nothing to learn as egress; the network IoCs live in the exec footprint.
- On the agent build that ran this (rogue105), the dash-shebang backdoor exec trips no exec rule; it is caught only by the R0002 read of `sysmon.py`. Making an exec rule flag it is node-agent #132 (`was_executed_with_args` must evaluate the `/bin/sh` arg-vector), not a profile change, and must not tighten the empty-argv[0] `/bin/sh` grant, which is exactly what the collapse removed to kill the 227 legit script-invocation false positives.

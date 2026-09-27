# ADR-0004 — Images are immutable at runtime; nothing is installed after build

**Status:** accepted
**Applies to:** every tier

## Context

`apt-get install` in an entrypoint, `pip install -r requirements.txt` at container start, a
`curl | sh` in an init step — each works, and each moves the definition of what is running out of
the image and into whatever the network returned at boot time.

The consequences are the ones supply-chain guidance keeps describing, but stated concretely: the
running container's contents are not reproducible; the same tag deploys different code on different
days; there is nothing to scan, because the SBOM describes the image and the image is not what is
running; and the container needs outbound network access at startup for reasons unrelated to its
function.

The same rule covers fetch tools generally. `curl`, `wget` and `nc` inside a running application
container are the standard first move after a foothold — pull the next stage in, push the data out.

## Decision

No package manager, and no general-purpose fetch tool, executes inside a running container. Every
dependency is resolved at build time and baked into the image.

None of the tier profiles list `apt`, `apt-get`, `apk`, `yum`, `dnf`, `pip`, `npm`, `gem`, `curl`,
`wget`, `nc` or `ssh` in their `execs`. The absence is deliberate, not an oversight.

## Verified by

**Runtime** — `R0001 Unexpected process launched`, `isTriggerAlert: true`.

Note the severity is **1**. This rule is the noisiest of the alerting set, because "a process ran
that the profile does not list" covers both a package manager and a shell utility the image
happens to invoke on a code path nobody exercised during profiling. Treat R0001 as a queue to
triage, not a page — and read the actual binary name before reacting.

**Supporting** — `R0005 DNS Anomalies` (severity 5) usually fires alongside, because installing
something requires resolving a repository first. Two rules agreeing raises confidence.

## Evidence emitted

```
ADR-0004 VIOLATED
  observed  R0001  frontend/web  Unexpected process launched: apt-get with PID 14882
  supporting R0005 frontend/web  DNS lookup: deb.debian.org
  fix       move the installation into the image build; the running container
            should not need a package repository
```

## Consequences

* Debug sessions (`kubectl exec … bash`) produce findings. That is intended — an interactive shell
  in a production container is worth a line in a log. `R2000 Exec to pod` records it separately at
  severity 8.
* Images that genuinely need a fetch at startup (config from a bucket, secrets from a vault) should
  do it in an **init container**, which is profiled separately from the application container.

## Known sharp edge

The `execs` lists in the tier profiles mix `/bin/...` and `/usr/bin/...` paths inconsistently —
for example the frontend profile lists `/bin/bash` but `/usr/bin/dash`. On Debian-family images
`/bin` is a symlink to `usr/bin` (verified in `nginx:1.27`), so the kernel reports the resolved
`/usr/bin/...` form. Whether this produces spurious R0001 findings was **not** established: two
attempts to test it were confounded, once by alert de-duplication on a long-lived container and
once by profile warm-up on a fresh one. Treat unexplained R0001 findings on shell binaries with
suspicion until this is resolved.

# IoC overlays

Per-advisory detection tripwires layered on the most-generic CI/CD base, the profile analog of a detection-as-code rule.

## Why

The generic runner base folds every attack-free toolchain and package zone to a `DIR/*` subtree wildcard (see `../../harness/compose.sh` `--collapse-cicd`). That is what makes it portable, and the collapse is measured safe: no attack step in the suite hides in a folded zone. The cost is latent: if a future advisory says attackers now stage payloads inside a folded zone, the base's `DIR/*` would allow the drop and no R0002 fires.

An IoC overlay re-specifies one zone. It carries the enumerated known-good opens for that zone, so applying it replaces the zone's `DIR/*` fold with those literals and any off-list access there raises R0002 again. It adds detection by re-narrowing, not by a deny rule, because a ContainerProfile is an allow-list and `compose` only unions. One overlay per advisory, reviewable and versioned, the same shape as a per-advisory rule but profile-native.

## Apply

The base is composed, then collapsed with the overlay's zone exempted:

```
bobctl harden --file <composed-runner>.yaml --collapse-cicd --exempt-zone /home/runner/.dotnet --in-place
```

`applied/` holds a generated example (the collapsed noble runner with `/home/runner/.dotnet` kept specific) so the tripwire is visible without the toolchain.

## Files

- `ioc-overlay-dotnet-cache.yaml` — the `.dotnet` SDK-cache tripwire: the known-good `/home/runner/.dotnet` opens. The generic base folds this zone to `/home/runner/.dotnet/*`; a planted file in the SDK cache would be masked. With the overlay the zone is enumerated, so the drop fires R0002.
- `applied/nnf-runner-noble-dotnet-tripwire.yaml` — the demo: generic collapsed base, `.dotnet` un-folded.

## Scope

An overlay only restores detection for an IoC that hides in a folded zone. The four IoCs in Ben's Detection-as-Code action all land outside folded zones, which is why the collapse is safe for them: three fire by anomaly already, and the exfil tar (DAC-0003) is inherent to `$HOME` being a write-zone. Catching that one needs a `$HOME` narrowing that trades a clean-build false positive, a different and FP-costly case, not an un-fold.

# Kubescape integration for the log4j PoC

The evaluator consumes signals from two sources:

| source | what it gives us | signals used in this PoC |
|---|---|---|
| **Pixie** | protocol-level (HTTP / pg-wire / DNS / payload bytes) | jndi-in-header (01), outbound-LDAP-payload-bytes (03), pgwire-DataRow (05), dns-high-label-entropy (06) |
| **Kubescape node-agent** | process / file / capability / egress deviations from ApplicationProfile | R0001 unexpected process (04), R0010 unexpected sensitive file (08), R0011 unexpected egress (02), **R1100 failed-execve-ENOENT (new — see `rules/`)** |

Kubescape's R-rules fire when the runtime behaviour deviates from the
locked ApplicationProfile. That makes them naturally usable as **diagnostic
queries** in the evaluator: the planner picks which R-rule output channel to
read next, given the current belief state.

## Pre-baked ApplicationProfiles

`application-profiles/` contains a *minimal* profile per pod that allows
only the legitimate application behaviour:

- `chain-backend-profile.yaml`: `java` + outbound TCP to `chain-postgres:5432` + log writes
- `chain-postgres-profile.yaml`: `postgres` + standard DB internals

Anything else fires R-rules. The profiles are pre-baked (not learning-mode)
so the diagnostic signals are deterministic from the first attack run.

## R1100 — the new rule

Kubescape's default rules do not surface **syscall return codes**. R1100
fills that gap: it listens to Inspektor Gadget's `exec` trace and fires when
`execve()` returns `-ENOENT` (errno 2) under a process whose `comm` is `java`
inside a container whose name contains `backend`.

R1100 is the sole diagnostic signal that distinguishes scenario B (RCE
contained — distroless image has no `/bin/sh`) from "scenario A in progress".
Without it the framework would need to wait K seconds for a positive signal
(new process under java), then commit on the absence. R1100 makes the
distinction one-shot.

Implementation: `rules/R1100_failed_execve_enoent.go` — drop into
`node-agent/pkg/ruleengine/v1/` and register in `rule_creator.go`. Enable
via the RuleSpec in `rules/R1100_rulespec.yaml`.

## Gadgets

`gadgets/` is a placeholder for v2 signals that need new Inspektor Gadget
tracers:

- **page-cache-hotness probe** — was `/bin/sh` already in page cache when the
  failed `execve` happened? Diagnostic for "RCE attempted novel code path".
  Not part of v1.
- **vfs-flags inspector** — query a pod's mount table to confirm
  `readOnlyRootFilesystem`. Currently inferred from PodSpec, but a runtime
  probe would catch tampering / privilege-escalation that mutates mounts.
  Not part of v1.

Both could be implemented as `IG_GADGET_TYPE=tracer` Go programs running on
each node and exposed to node-agent via the same gRPC channel R0001 uses.

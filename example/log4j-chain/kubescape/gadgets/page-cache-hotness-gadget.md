# Page-cache hotness gadget (v2 — not in PoC v1)

## Why this gadget would exist

The evaluator's decision tree has a layer for "cache" signals, but no
existing Kubescape rule or default Inspektor Gadget surfaces them. This is
the rough spec for the gadget that would.

## What it measures

For a given file path + container, returns whether the file's pages are
currently resident in the kernel page cache. Two probes:

1. **mincore(2) sweep** on a sample of binaries in the container's mount
   namespace: `/bin/sh`, `/usr/bin/psql`, `/usr/bin/curl`, `/usr/bin/getent`.
   Returns vector of `(path, present_in_cache_bool, last_access_estimate)`.

2. **eBPF kprobe on filemap_fault** scoped to inode IDs we care about.
   Fires when the kernel page-faults the target file for the first time
   (cold-cache load). Diagnostic for "novel exec attempt".

## How the evaluator would use it

After R1100 fires (failed execve ENOENT under JVM), the evaluator queries:
"was `/bin/sh` cold or hot at execve time?". Answer differentiates:

- **cold + ENOENT** → attacker's payload class is generic — assumed
  `/bin/sh` would exist; no specific reconnaissance happened first.
- **hot + ENOENT** → attacker had prior intelligence that something would
  shell out from this pod, and tried anyway. Possibly an automated
  payloadation framework that targets specific images.

The distinction matters for IR triage: cold = drive-by, hot = targeted.

## Implementation sketch (Go, IG framework)

```
package main

import (
    "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
    "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace"
    "golang.org/x/sys/unix"
)

type Event struct {
    eventtypes.CommonData `ebpf:"common"`
    Path          string `ebpf:"path"`
    InCache       bool   `ebpf:"in_cache"`
    LastFaultTime uint64 `ebpf:"last_fault_ns"`
}

func (g *Gadget) Run(ctx context.Context, host containers.K8sContainer) {
    // mincore probe on a path list passed in via params
    for _, path := range g.params.PathList {
        cached := mincoreProbe(host.MountNS, path)
        g.emit(Event{Path: path, InCache: cached, ...})
    }
    // optional: subscribe to filemap_fault kprobe for live observation
    g.attachKprobe("filemap_fault", g.onFault)
    <-ctx.Done()
}
```

Then wire into Kubescape node-agent as an event source (same channel pattern
as the existing exec / dns / open tracers).

## Why it isn't in v1

- Cross-mount-namespace mincore() from the node-agent process requires
  either CAP_SYS_ADMIN or a per-pod helper. Both work but neither is a
  half-day's effort.
- The diagnostic value is *qualitative* (cold-vs-hot), not the kind of
  signal a decision tree commits a verdict on. It enriches forensic
  reports more than it changes verdicts.
- Defer to v2 once R1100 + Pixie signal coverage is validated.

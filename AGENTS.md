# Instructions for agents

## Install every application the way its users install it

An application in this repository is always installed the way an end user most likely installs it.

- For a CNCF project, use the installer the upstream project itself publishes: its official Helm chart, its operator or its install manifest.
- Where a project publishes none, use the distribution or version that is most commonly used.
- Do not hand-write a Deployment around the image when an upstream installer exists.
- Pin the installer and its version, and record both next to the workload.

The reason: an operator or a chart changes what a container does (init containers, wrapper scripts, probes, sidecars, paths). An SBoB learned from an install nobody uses does not fit the installs people have.

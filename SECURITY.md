# Security Policy

## Scope

This repository is a research and demonstration project for the Software Bill
of Behavior (SBOB) and the `bobctl` tuner. It is not distributed as a
production dependency or a signed release artifact. The container images built
here (redis, postgres, log4j and other kill-chain targets) are deliberately
vulnerable and are intended **only** for use in isolated lab clusters.

## Reporting a Vulnerability

Please report suspected security issues **privately**. Do not open a public
issue or pull request for a vulnerability.

- Preferred: open a private advisory via GitHub's
  [**Report a vulnerability**](https://github.com/k8sstormcenter/bob/security/advisories/new)
  button under the **Security** tab.
- Alternatively, email the maintainers at `croedig@sba-research.org`.

Please include:

- the affected component (e.g. `bobctl`, a workflow, a chain image),
- a description of the issue and its impact,
- reproduction steps or a proof of concept where possible.

## Response

We aim to acknowledge a report within **5 working days** and to agree on a
disclosure timeline with the reporter. Fixes are coordinated privately and
disclosed once a patch or mitigation is available.

## A Note on the Attack Content

Exploits, vulnerable images, and attack suites in this repository are part of
the SBOB methodology — they exist to prove detection coverage. Their presence
is intentional and is **not** in itself a vulnerability in this project. Report
issues that affect the tooling, CI, or unintended exposure of secrets, rather
than the deliberately-vulnerable demonstration targets.

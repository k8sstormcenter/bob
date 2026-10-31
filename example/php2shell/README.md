<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE.
All trademarks are expressly reserved.
-->
# php2shell — vulnerable PHP runner workload (PHP2Shell)

A stock, **unpatched PHP 8.4.26 behind Apache `mod_php`** serving an innocent
CI build-artifact uploader. This is the real **PHP2Shell** surface —
CVE-2026-109618 / CVE-2026-109619 (CISA KEV 2026-10-26, CVSS 9.2,
unauthenticated RCE through `session.upload_progress`), fixed upstream on
2026-10-21 in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Run separately from the
team's other tradecraft; also demoable on the NNF gha-runner cluster.

## Why it's believable (and not declawed)

- **Nothing is planted.** The vulnerable surface — `session.upload_progress` —
  is PHP's shipping default. A runner that built or pulled any PHP image from
  **before 2026-10-21** is vulnerable out of the box. No web shell, no backdoor,
  no eval sink in the app: the bug is in PHP core (`ext/session/session.c`,
  `php_session_rfc1867_callback`), reached while parsing a multipart POST.
- **The app is innocent.** `app/index.php` + `app/upload.php` are an ordinary
  artifact uploader with a progress bar — the legitimate reason
  `session.upload_progress` is active and exercised by normal traffic.
- **The only non-stock bit** is `conf/php.ini` + `conf/apache-prefork.conf`: a
  single prefork worker and a small heap so the use-after-free grooms
  deterministically for a repeatable classroom demo. These are reliability
  knobs, not the vulnerability — a stock multi-worker server is exploitable too,
  just less deterministically.

## What's here

```
Dockerfile                 php:8.4.26-apache (digest-pinned) + vulnerable calibration + the app
app/index.php              innocent artifact-upload form (starts a session, renders the progress field)
app/upload.php             innocent upload handler (no eval/shell/deserialize)
app/healthz.php            readiness/liveness probe
conf/php.ini               PHP2Shell calibration profile (upload_progress On by default)
conf/apache-prefork.conf   single-worker prefork for deterministic heap grooming
php2shell.yaml             Namespace + Deployment + Service, user-defined profile/network labels
```

Image: `ghcr.io/k8sstormcenter/php2shell-vulnerable:8.4.26` (+ `:latest`).

## Deploy

```
kubectl apply -f php2shell.yaml
```

The pod carries `kubescape.io/user-defined-profile: php2shell` so node-agent
enforces from pod start. Learn/bind the baseline the usual way (benign app =
Apache serving web requests, no child processes), then run the attack live.

## Detection payoff

The benign baseline never spawns a child process from the web worker. A
successful PHP2Shell exploit makes the Apache/`php` worker spawn `/bin/sh`,
`curl`, or `wget` — the published PHP2Shell IoC — which deviates from the
baseline and fires the runtime rules. The exploit (sealed, mirrors the other
chains under `pkg/attack/`) and the expected rule set are withheld here: run it
blind, watch node-agent, and classify what you see.

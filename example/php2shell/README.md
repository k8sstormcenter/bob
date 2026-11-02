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

## Run it (verified on the `honey` k3s, 2026-10-31)

```
kubectl apply -f php2shell.yaml           # Namespace + Deployment + Service
kubectl apply -f loadgen.yaml             # benign upload baseline (optional)
kubectl apply -f sbobs/cp-php2shell.yaml  # bind the learned SBoB (enforce mode; skips the 10m learn)
# exploit the pod directly (port-forward jitter breaks stage-3 grooming — use the pod IP or an in-cluster client):
POD_IP=$(kubectl -n php2shell get pod -l app=php2shell -o jsonpath='{.items[0].status.podIP}')
bash ../../pkg/attack/php2shell/private/run-php2shell.sh "http://$POD_IP/index.php" 'id>/tmp/p2s'
# watch node-agent: R0001 "Unexpected process launched"  apache2 -> sh -> id
```

Verified end to end: unpatched 8.4.26 target → learned `execs=0` baseline →
genuine RCE (`uid=33(www-data)`) → node-agent R0001 on the `apache2→sh→id`
lineage. Pause the loadgen during the exploit (it contends for the single
Apache worker and perturbs the heap grooming).

## As a CI/CD integration test — and a detection blind spot

The same image also runs as a self-contained CI job: a build on a self-hosted
runner stands up an ephemeral Kind cluster in its own dind, deploys this image
as an integration-test fixture, and runs PHP2Shell against it — so the workload
is owned *during* the build (`uid=33(www-data)`, verified on NNF 2026-11-01).

This deliberately exposes a runtime blind spot. When the victim runs on a
node-agent-covered node (above), the `apache2→sh→id` spawn fires R0001. But
buried two levels down in Kind-in-dind (runner → dind → containerd → kind node →
victim pod), it is **invisible** to the host sensor: node-agent's nested-container
visibility reaches the kind node (one level) but not pods inside it, so the RCE
goes undetected and only the CI driver (`kubectl`/`kind`/`containerd`) shows up.
A CI runner that uses Kind-in-dind can be compromised beneath the sensor's
horizon. See `pkg/attack/php2shell-groundtruth.md` for the full evidence.

## Detection payoff

The benign baseline never spawns a child process from the web worker. A
successful PHP2Shell exploit makes the Apache/`php` worker spawn `/bin/sh`,
`curl`, or `wget` — the published PHP2Shell IoC — which deviates from the
baseline and fires the runtime rules. The exploit (sealed, mirrors the other
chains under `pkg/attack/`) and the expected rule set are withheld here: run it
blind, watch node-agent, and classify what you see.

<!--
Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->
# php2shell detection: SBoB vs rule — side by side

Same target (php:8.4.26-apache, unpatched; CVE-2026-109618 / CVE-2026-109619), same
sealed PoC, same in-runner k3s, same node-agent image. The only variable is the
detection mechanism.

| | SBoB arm | Rule arm |
| --- | --- | --- |
| Workflow | `ci-php2shell-k3s-demo.yaml` | `ci-php2shell-k3s-rules.yaml` |
| What is applied | ContainerProfile `cp-php2shell.yaml` (bobctl-generalized, enforce) | `rules/php2shell-rules.yaml` (custom rule + binding, no profile) |
| Rule | R0001 Unexpected process launched (`profileDependency: Required`) | R1505 web server spawned a shell (`profileDependency: NotRequired`) |
| How it decides | `apache2→sh→id` is not in the learned Apache baseline | `event.comm in [sh,bash,…] && event.pcomm in [apache2,httpd,php,…]` |
| Advisory basis | learned-behaviour baseline deviation | Falco `spawn_shell_under_httpd` / "Suspicious Command Executed by Web Server"; MITRE T1505.003 / T1059 |
| Needs a learned profile | yes | no |

## Shared preconditions (both arms)
- Exploit lands and RCE is confirmed (proof file written by `sh`/`id`, uid 33).
- node-agent must actually monitor the pod. On GH-hosted k3s (kernel 7.0.0-azure) the
  container-add fanotify hook is silently blind, so post-start pods are adopted by the
  node-agent fallback pod-informer (startup-enumeration path, a bounded delay instead of a
  blind spot). It ships in the node-agent bundled with chart `1.41.0-duckling124`, the
  default `chart_ver` for both workflows, so both arms bind out of the box — no override.

## Evidence
- **SBoB arm — CONFIRMED.** Run 42144465569 (chart duckling124): exploit lands, the pod
  binds profile `php2shell-php2shell`, and **R0001 "Unexpected process launched"** fires on
  `apache2(uid33)→sh→id`.
- **Rule arm — CONFIRMED.** Run 42144475334 (chart duckling124): the custom rule loads and
  binds (`RuntimeRuleAlertBinding /php2shell-webshell-binding`), the exploit lands, and
  **R1505 "web server spawned a shell"** fires on `apache2→sh`. The earlier Azure-kernel
  hook flake is resolved by the fallback pod-informer (RCA'd with the node-agent owner).
- **Twin (both arms, one node-agent) — CONFIRMED.** Run 42144484971: `php2shell` (SBoB) and
  `php2shellb` (rule) both RCE-land; detections **R0001 × 3** (SBoB) + **R1505 × 2** (rule).
  The two observed shadow profiles share identical execs and differ only in incidental
  opens — expected per-instance learned-profile variance.

## Reproduce
Both workflows default to chart `1.41.0-duckling124` (carries the fallback pod-informer),
so both arms are reliable on GH-hosted k3s out of the box. `na_tag`/`na_digest` override the
node-agent image only to pin a different build; `chart_ver` overrides the chart.

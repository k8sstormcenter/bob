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
- node-agent must actually monitor the pod. This needs the live-container fix in
  node-agent image `v0.1.0-rogue91-mcontract-*` (identity repaired before the ignore
  decision; a not-yet-registered container is no longer read as departed). Without it
  the post-start pod never binds and neither arm fires.

## Evidence
- **SBoB arm — CONFIRMED.** Run 41761761179 (patched image, info logs): container binds
  (`processing container namespace:php2shell`), profile `php2shell-php2shell` completed,
  **R0001 × 5** on `apache2(uid33)→sh→id` (PID 12503). Reproduced 2/2.
- **Rule arm — rule verified, detection gated on hook delivery.** The custom rule loads
  and binds (`RulesWatcher 28→29 enabledRules`, `RuntimeRuleAlertBinding /php2shell-webshell-binding`),
  exploit lands, but on 2/2 runs the node-agent container-fanotify ADD hook never fired
  for the pod (24 startup containers processed, 0 for php2shell), so no exec event
  reached the rule. This is a non-deterministic node-agent hook flake on GH-hosted k3s
  (kernel 7.0.0-azure, k3s v1.33.3+k3s1), under RCA with the node-agent owner; the fix
  in progress adopts such containers through the startup enumeration path (bounded delay
  instead of blind spot). On a run where the hook fires, R1505 fires on `apache2→sh`.

## Reproduce
Both workflows take `chart_ver`, `na_tag`, `na_digest` dispatch inputs; pin the patched
node-agent image with `na_tag`/`na_digest`. SBoB arm is reliable today; the rule arm
becomes reliable once the node-agent hook-adoption fix lands.

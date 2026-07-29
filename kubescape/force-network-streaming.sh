#!/usr/bin/env bash
# Helm post-renderer: force node-agent networkStreamingEnabled=true.
#
# The chart ANDs capabilities.networkEventsStreaming with cloud-submit
# (templates/_common.tpl, "capabilities.gates"): submit is true only when
# .Values.server is non-empty. On an on-prem stack with no backend the flag
# therefore renders FALSE no matter what capabilities.networkEventsStreaming
# says, which leaves the profile's inline network shape inert and makes R0005
# (DNS) and R0011 (egress) silently never fire.
#
# We rewrite the *rendered manifest* rather than patching the live ConfigMap
# after install. That matters: a post-install patch only reaches node-agent if
# the DaemonSet is restarted, and node-agent must not be restarted on the
# laptop k3s. Rewriting here means the very first node-agent boot already has
# the correct config.json.
#
# See docs/portability-spec.md D7a.
set -euo pipefail

sed 's/"networkStreamingEnabled": false/"networkStreamingEnabled": true/'

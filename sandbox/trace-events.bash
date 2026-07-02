# shellcheck shell=bash
# shellcheck disable=SC2034  # consumed by as_trace (trace.bash) via the maps below, not here.
# In-container bash mirror of config/trace-events.json (the SSOT). Edit BOTH together:
# tests/test_trace_events_ssot.py pins this file's constants + layer/level maps equal to
# the JSON in the same commit, and asserts every event has ≥1 emitter under sandbox/.
#
# Sourced by sandbox/trace.bash (co-located, copied into the container beside it).
# as_trace looks an event's layer and level up in the maps below to label and gate its
# line. as_trace runs in-container with no JSON manifest to read, so the map lives here
# as plain bash. Only LIBRARY-emitted events belong here; a consumer's own events
# (monitor, redactor, managed settings, host-side worktree seed/extract) live in the
# consumer's overlay, not the library.

# Idempotent: a re-source returns early rather than redefining.
[[ -n "${TRACE_EVENTS_LOADED:-}" ]] && return 0
TRACE_EVENTS_LOADED=1

TRACE_FIREWALL_RULES_APPLIED="firewall_rules_applied"
TRACE_FIREWALL_ALLOW_ALL_APPLIED="firewall_allow_all_applied"
TRACE_FIREWALL_REFRESH_SUPERVISED="firewall_refresh_supervised"
TRACE_FIREWALL_ALLOWLIST_EXPANDED="firewall_allowlist_expanded"
TRACE_FIREWALL_REFRESH_DIED="firewall_refresh_died"
TRACE_FIREWALL_IPSET_BATCH_FAILED="firewall_ipset_batch_failed"
TRACE_HARDENER_LOCKDOWN_APPLIED="hardener_lockdown_applied"
TRACE_AUDIT_SINK_STARTED="audit_sink_started"

declare -A TRACE_EVENT_LAYER=(
  ["firewall_rules_applied"]="firewall"
  ["firewall_allow_all_applied"]="firewall"
  ["firewall_refresh_supervised"]="firewall"
  ["firewall_allowlist_expanded"]="firewall"
  ["firewall_refresh_died"]="firewall"
  ["firewall_ipset_batch_failed"]="firewall"
  ["hardener_lockdown_applied"]="hardener"
  ["audit_sink_started"]="audit"
)
declare -A TRACE_EVENT_LEVEL=(
  ["firewall_rules_applied"]="info"
  ["firewall_allow_all_applied"]="info"
  ["firewall_refresh_supervised"]="info"
  ["firewall_allowlist_expanded"]="info"
  ["firewall_refresh_died"]="info"
  ["firewall_ipset_batch_failed"]="info"
  ["hardener_lockdown_applied"]="info"
  ["audit_sink_started"]="info"
)

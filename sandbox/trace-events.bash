# shellcheck shell=bash
# shellcheck disable=SC2034  # consumed by as_trace (trace.bash) via the maps below, not here.
# GENERATED FROM config/trace-events.json BY scripts/gen-trace-events.py — DO NOT EDIT.
# Change an event in config/trace-events.json, then regenerate:
#   python3 scripts/gen-trace-events.py
# The pre-commit `gen-trace-events` hook regenerates this on commit, and
# tests/test_trace_events_ssot.py fails CI if it is ever out of sync with the JSON.
#
# Sourced by sandbox/trace.bash (co-located, copied into the container beside it).
# as_trace runs in-container with no JSON parser available, so the events must exist
# here as plain bash — this file is that generated in-container mirror. Only
# LIBRARY-emitted events live in the JSON (a consumer's own events belong in the
# consumer's overlay), so only those are generated here.

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

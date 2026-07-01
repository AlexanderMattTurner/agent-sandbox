#!/usr/bin/env bash
# The library's END-TO-END ACCEPTANCE, run on a CI Docker daemon:
# `agent-sandbox run workloads/demo-bash.json` must boot a non-claude workload
# behind the firewall and prove, from the outside:
#   1. the allowed host was reached (workload output) AND spliced through squid
#      (a CONNECT entry in the exported egress log),
#   2. the blocked host was denied at the proxy (workload output) AND the denial
#      was recorded in the egress log (the tamper-evident floor),
#   3. the workload's write landed on the review branch, never the working tree,
#   4. the ephemeral teardown left no session volumes behind.
set -Eeuo pipefail

docker build -f sandbox/Dockerfile -t agent-sandbox-firewall:ci sandbox/
export FIREWALL_IMAGE=agent-sandbox-firewall:ci
export CONTAINER_RUNTIME=runc
export AGENT_SANDBOX_STATE_DIR="$PWD/.acceptance-state"

# The host-side replay (git worktree + am) needs a committer identity the bare
# runner checkout lacks.
git config user.email "ci@agent-sandbox.local"
git config user.name "agent-sandbox CI"

rc=0
bin/agent-sandbox run workloads/demo-bash.json >run.log 2>&1 || rc=$?
cat run.log
if [[ "$rc" -ne 0 ]]; then
  echo "FAIL: agent-sandbox run exited $rc" >&2
  exit "$rc"
fi

fail=0
check() { # <description> <grep-args...>
  local desc="$1"
  shift
  if grep -Eq "$@"; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc" >&2
    fail=1
  fi
}

# 1+2. The workload observed the boundary from the inside.
check "allowed host reached from the workload" 'ALLOWED host reached \(pypi\.org\)' run.log
check "blocked host denied at the proxy" 'BLOCKED host denied at proxy \(example\.com\)' run.log

# The egress log the launcher exported before teardown.
egress_log="$(find "$AGENT_SANDBOX_STATE_DIR/sessions" -name egress.log | head -n1)"
if [[ -z "$egress_log" || ! -s "$egress_log" ]]; then
  echo "FAIL: no exported egress log under $AGENT_SANDBOX_STATE_DIR/sessions" >&2
  exit 1
fi
echo "--- egress log ($egress_log) ---"
cat "$egress_log"
check "allowed host spliced through squid (logged CONNECT tunnel)" 'CONNECT pypi\.org:443' "$egress_log"
check "blocked host's denial recorded in the egress log" 'example\.com' "$egress_log"
if grep -E 'example\.com' "$egress_log" | grep -q 'TCP_TUNNEL/200'; then
  echo "FAIL: the blocked host shows a successful tunnel in the egress log" >&2
  fail=1
fi

# 3. The write landed on the review branch, not the working tree.
git rev-parse --verify -q sandbox/demo-review >/dev/null || {
  echo "FAIL: review branch sandbox/demo-review does not exist" >&2
  exit 1
}
git show sandbox/demo-review:demo-output.txt | grep -q 'written by the sandboxed workload' || {
  echo "FAIL: demo-output.txt is not on the review branch" >&2
  exit 1
}
if [[ -e demo-output.txt ]]; then
  echo "FAIL: the workload's write leaked into the host working tree" >&2
  fail=1
fi
echo "PASS: workload write landed on the review branch only"

# 4. Ephemeral teardown is verified fail-loud by the launcher; assert independently.
leftovers="$(docker volume ls -q | grep '^agent-sandbox-' || true)"
if [[ -n "$leftovers" ]]; then
  echo "FAIL: session volumes survived teardown: $leftovers" >&2
  fail=1
else
  echo "PASS: no session volumes survived teardown"
fi

exit "$fail"

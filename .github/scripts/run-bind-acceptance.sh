#!/usr/bin/env bash
# BIND-MODE guardrail acceptance, run on a CI Docker daemon (this repo's dev sandbox has
# no Docker): `agent-sandbox run workloads/demo-bind.json` must boot a bind-mode workload
# whose declared overmount_paths (default `.git/hooks node_modules`) are provably NOT
# writable from inside the sandbox, while the rest of /workspace stays writable and lands
# on the host bind. It proves, from the outside:
#   1. the workload observed each guardrail as read-only (RO-BLOCKED lines) and could still
#      write elsewhere in /workspace (WRITE-OK),
#   2. the launcher's own fail-closed probe ran and passed ("overmounts verified read-only"),
#   3. the writable file landed on the host bind with the expected content, and NO probe or
#      planted-hook artifact appeared under the read-only paths,
#   4. the ephemeral teardown left no session volumes behind.
set -Eeuo pipefail

docker build -f sandbox/Dockerfile -t agent-sandbox-firewall:ci sandbox/
export FIREWALL_IMAGE=agent-sandbox-firewall:ci
export CONTAINER_RUNTIME=runc
export AGENT_SANDBOX_STATE_DIR="$PWD/.acceptance-state-bind"

# The host workspace the workload binds. Fresh each run; world-writable so the workload's
# unprivileged uid can write the non-guardrail parts of /workspace.
ws=/tmp/agent-sandbox-bind-demo
rm -rf "$ws"
install -d -m 0777 "$ws" "$ws/.git/hooks" "$ws/node_modules"
# Marker files so overmount_applies sees the guardrail paths as present on the host (it
# gates on existence and never fabricates empty dirs).
echo "host hook marker" >"$ws/.git/hooks/marker"
echo "host module marker" >"$ws/node_modules/marker"

rc=0
bin/agent-sandbox run workloads/demo-bind.json >run.log 2>&1 || rc=$?
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

# 1. The workload saw the guardrails as read-only and could still write elsewhere.
check "workload found .git/hooks read-only" 'RO-BLOCKED \.git/hooks' run.log
check "workload found node_modules read-only" 'RO-BLOCKED node_modules' run.log
check "workload wrote the non-guardrail file" 'WRITE-OK bind-output\.txt' run.log

# 2. The launcher's fail-closed probe actually ran (2 default paths apply). This line is
#    the non-vacuous anchor: it only prints when verify_guardrails_readonly returned 0.
check "launcher verified the overmounts read-only" 'overmounts verified read-only \(2 paths\)' run.log

# 3. The writable file landed on the host bind; the guardrails were not written.
if [[ ! -s "$ws/bind-output.txt" ]] || ! grep -q 'bind demo wrote at' "$ws/bind-output.txt"; then
  echo "FAIL: bind-output.txt did not land on the host bind with the expected content" >&2
  fail=1
else
  echo "PASS: workload write landed on the host bind"
fi
# The read-only guardrails carry ONLY their host markers — no planted hook, no leftover
# write-probe artifact.
planted="$(find "$ws/.git/hooks" "$ws/node_modules" -mindepth 1 ! -name marker)"
if [[ -n "$planted" ]]; then
  echo "FAIL: artifacts appeared under a read-only guardrail: $planted" >&2
  fail=1
else
  echo "PASS: no artifacts under the read-only guardrails"
fi

# 4. Ephemeral teardown left nothing.
leftovers="$(docker volume ls -q | grep '^agent-sandbox-' || true)"
if [[ -n "$leftovers" ]]; then
  echo "FAIL: session volumes survived teardown: $leftovers" >&2
  fail=1
else
  echo "PASS: no session volumes survived teardown"
fi

exit "$fail"

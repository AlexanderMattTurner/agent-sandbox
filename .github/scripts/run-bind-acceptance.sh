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
# Then the parity legs: a bind path carrying a literal `$` still writes through (the
# launcher compose-escapes it), and hostile records refuse loudly — both modes at once,
# a dangling-symlink source (refused BEFORE compose up), and an explicitly declared
# overmount path missing from the host workspace.
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

# 5. A literal `$` in the bind path: the launcher escapes it to `$$` for compose's
#    interpolation pass, so the bind still resolves and writes still land on the host.
ws_dollar='/tmp/agent-sandbox-bind-$lit'
rm -rf "$ws_dollar"
install -d -m 0777 "$ws_dollar" "$ws_dollar/.git/hooks" "$ws_dollar/node_modules"
jq --arg ws "$ws_dollar" '.workspace_mount = $ws
  | .entrypoint = ["bash", "-lc", "set -uo pipefail; cd /workspace; echo dollar-path write-through > dollar-output.txt && echo WRITE-OK dollar-output.txt"]' \
  workloads/demo-bind.json >dollar-workload.json
rc=0
bin/agent-sandbox run dollar-workload.json >dollar.log 2>&1 || rc=$?
cat dollar.log
if [[ "$rc" -ne 0 ]]; then
  echo "FAIL: dollar-path bind run exited $rc" >&2
  fail=1
fi
check "dollar-path workload wrote inside the sandbox" 'WRITE-OK dollar-output\.txt' dollar.log
if grep -q 'dollar-path write-through' "$ws_dollar/dollar-output.txt" 2>/dev/null; then
  echo "PASS: dollar-path write landed on the host bind"
else
  echo "FAIL: dollar-path write did not land on the host bind" >&2
  fail=1
fi

# 6. Hostile records refuse loudly. neg runs a workload that MUST fail, asserting the
#    refusal message — and, when a forbidden pattern is given, that the refusal came
#    BEFORE that stage of the launch (e.g. before compose ever brought anything up).
neg() { # <description> <workload-file> <expected-regex> [<forbidden-regex>]
  local desc="$1" wl="$2" want="$3" forbid="${4:-}" nrc=0
  bin/agent-sandbox run "$wl" >neg.log 2>&1 || nrc=$?
  if [[ "$nrc" -eq 0 ]]; then
    echo "FAIL: $desc — run unexpectedly succeeded" >&2
    cat neg.log
    fail=1
    return
  fi
  if ! grep -Eq "$want" neg.log; then
    echo "FAIL: $desc — refusal output lacks '$want'" >&2
    cat neg.log
    fail=1
    return
  fi
  if [[ -n "$forbid" ]] && grep -Eq "$forbid" neg.log; then
    echo "FAIL: $desc — refused too late ('$forbid' appeared)" >&2
    cat neg.log
    fail=1
    return
  fi
  echo "PASS: $desc"
}

jq '.seed_from_git = {ref: "HEAD", review_branch: "sandbox/never"}' \
  workloads/demo-bind.json >both-modes.json
neg "workspace_mount + seed_from_git together are refused" both-modes.json \
  'mutually exclusive' 'compose: bringing up'

rm -f /tmp/agent-sandbox-bind-dangling
ln -s /tmp/agent-sandbox-bind-nonexistent /tmp/agent-sandbox-bind-dangling
jq '.workspace_mount = "/tmp/agent-sandbox-bind-dangling"' \
  workloads/demo-bind.json >dangling.json
neg "dangling-symlink workspace_mount is refused before compose up" dangling.json \
  'is a symlink' 'compose: bringing up'

jq '.overmount_paths = ["missing/dir"]' workloads/demo-bind.json >missing-overmount.json
neg "explicitly declared missing overmount path is refused" missing-overmount.json \
  'do not exist under the host workspace'

# The negative legs (the missing-overmount one boots a stack, then is torn down at the
# gate) must also leave no volumes behind.
leftovers="$(docker volume ls -q | grep '^agent-sandbox-' || true)"
if [[ -n "$leftovers" ]]; then
  echo "FAIL: session volumes survived the negative legs: $leftovers" >&2
  fail=1
else
  echo "PASS: no session volumes survived the negative legs"
fi

exit "$fail"

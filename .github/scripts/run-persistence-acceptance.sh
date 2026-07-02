#!/usr/bin/env bash
# Persistent-session END-TO-END ACCEPTANCE (issue #33), on a CI Docker daemon:
# three legs of one story prove ephemeral:false is a real lifecycle.
#   leg 1 (cold):      a persistent workload (session_id) seeds, commits, exits;
#                      its volumes and session manifest survive teardown.
#   leg 2 (re-attach): the same session_id re-attaches to the stopped stack —
#                      seeding is SKIPPED (leg 1's file is still in /workspace)
#                      and the new commit lands on the SAME review branch.
#   leg 3 (resume):    a FRESH session resumes from legs 1+2's outputs — the prior
#                      commits are replayed onto a new seed, new work lands on a
#                      NEW review branch, and the prior session's exported audit
#                      log is mounted read-only at audit.prior.jsonl inside the
#                      new session's audit container.
set -Eeuo pipefail

docker build -f sandbox/Dockerfile -t agent-sandbox-firewall:ci sandbox/
export FIREWALL_IMAGE=agent-sandbox-firewall:ci
export CONTAINER_RUNTIME=runc
export AGENT_SANDBOX_STATE_DIR="$PWD/.acceptance-state"

# The host-side replay (git worktree + am) needs a committer identity the bare
# runner checkout lacks.
git config user.email "ci@agent-sandbox.local"
git config user.name "agent-sandbox CI"

state1="$AGENT_SANDBOX_STATE_DIR/sessions/agent-sandbox-persist-demo"
state3="$AGENT_SANDBOX_STATE_DIR/sessions/agent-sandbox-persist-demo-2"

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

mk_workload() { # <out-file> <extra-json> <entrypoint-script>
  local out="$1" extra="$2" script="$3"
  jq -n --arg script "$script" --argjson extra "$extra" '{
    image: "buildpack-deps:stable-scm",
    entrypoint: ["bash", "-lc", $script],
    user: "1000",
    egress_allowlist: [],
    backend: "local"
  } + $extra' >"$out"
}

run_leg() { # <leg-name> <workload-file> <log-file>
  local leg="$1" wl="$2" log="$3" rc=0
  bin/agent-sandbox run "$wl" >"$log" 2>&1 || rc=$?
  echo "--- $leg log ($log) ---"
  cat "$log"
  if [[ "$rc" -ne 0 ]]; then
    echo "FAIL: $leg exited $rc" >&2
    exit "$rc"
  fi
}

# ---- leg 1: cold persistent session ----
mk_workload wl1.json '{
  "ephemeral": false,
  "session_id": "persist-demo",
  "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/persist-review"}
}' 'set -euo pipefail; cd /workspace; echo leg1 >leg1.txt; git add leg1.txt; git commit -qm "feat: leg one"; echo "LEG1 committed"'
run_leg "leg 1 (cold)" wl1.json run1.log
check "leg 1 ran its entrypoint" 'LEG1 committed' run1.log
git show sandbox/persist-review:leg1.txt >/dev/null || {
  echo "FAIL: leg 1's commit is not on the review branch" >&2
  exit 1
}
check "leg 1 wrote a session manifest (mode seed)" '"mode": "seed"' "$state1/session.json"
leftover="$(docker volume ls -q --filter label=com.docker.compose.project=agent-sandbox-persist-demo)"
if [[ -z "$leftover" ]]; then
  echo "FAIL: ephemeral:false left no volumes to re-attach to" >&2
  exit 1
fi
echo "PASS: persistent volumes survived teardown"

# ---- leg 2: re-attach the stopped session ----
mk_workload wl2.json '{
  "ephemeral": false,
  "session_id": "persist-demo",
  "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/persist-review"}
}' 'set -euo pipefail; cd /workspace; test -f leg1.txt || { echo "MISSING leg1.txt: the workspace was re-seeded" >&2; exit 1; }; echo leg2 >leg2.txt; git add leg2.txt; git commit -qm "feat: leg two"; echo "LEG2 saw leg1"'
run_leg "leg 2 (re-attach)" wl2.json run2.log
check "leg 2 re-attached instead of seeding" 're-attaching to the stopped session agent-sandbox-persist-demo' run2.log
check "leg 2 found leg 1's file in the kept workspace" 'LEG2 saw leg1' run2.log
git show sandbox/persist-review:leg2.txt >/dev/null || {
  echo "FAIL: leg 2's commit did not land on the SAME review branch" >&2
  exit 1
}
echo "PASS: both legs' commits are on sandbox/persist-review"

# ---- leg 3: resume into a fresh session, audit continuity ----
if [[ ! -s "$state1/audit.jsonl" || ! -s "$state1/audit.secret" ]]; then
  echo "FAIL: leg 2 did not export the prior session's audit log + secret" >&2
  exit 1
fi
echo "PASS: prior session's audit log + HMAC secret exported to the host"

mk_workload wl3.json '{
  "ephemeral": true,
  "session_id": "persist-demo-2",
  "resume_from": "persist-demo",
  "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/persist-review-resumed"}
}' 'set -euo pipefail; cd /workspace; test -f leg1.txt && test -f leg2.txt || { echo "MISSING replayed files" >&2; exit 1; }; echo leg3 >leg3.txt; git add leg3.txt; git commit -qm "feat: leg three"; echo "LEG3 saw prior work"; sleep 15'

# Run leg 3 in the background: the audit.prior.jsonl assertion must observe the
# audit container while the session is LIVE (the entrypoint's trailing sleep is the
# observation window; ephemeral teardown removes the container afterwards).
rc3=0
bin/agent-sandbox run wl3.json >run3.log 2>&1 &
leg3_pid=$!
audit_cid=""
for ((i = 0; i < 180; i++)); do
  audit_cid="$(docker ps -q --filter label=com.docker.compose.project=agent-sandbox-persist-demo-2 --filter label=com.docker.compose.service=audit)"
  [[ -n "$audit_cid" ]] && break
  sleep 1
done
if [[ -z "$audit_cid" ]]; then
  echo "FAIL: leg 3's audit container never appeared" >&2
  fail=1
else
  if docker exec "$audit_cid" test -f /var/log/agent-sandbox/audit.prior.jsonl; then
    echo "PASS: prior session's audit log is mounted at audit.prior.jsonl"
  else
    echo "FAIL: audit.prior.jsonl is not visible in the resumed session's audit container" >&2
    fail=1
  fi
  if docker exec "$audit_cid" sh -c 'echo tamper >>/var/log/agent-sandbox/audit.prior.jsonl' 2>/dev/null; then
    echo "FAIL: audit.prior.jsonl is writable — the prior record must be read-only" >&2
    fail=1
  else
    echo "PASS: audit.prior.jsonl is read-only in the resumed session"
  fi
fi
wait "$leg3_pid" || rc3=$?
echo "--- leg 3 log (run3.log) ---"
cat run3.log
if [[ "$rc3" -ne 0 ]]; then
  echo "FAIL: leg 3 (resume) exited $rc3" >&2
  exit "$rc3"
fi
check "leg 3 ignored the workload ref in favor of the prior base" "seed_from_git.ref 'HEAD' is ignored on resume" run3.log
check "leg 3 saw legs 1+2's replayed work" 'LEG3 saw prior work' run3.log
for f in leg1.txt leg2.txt leg3.txt; do
  git show "sandbox/persist-review-resumed:$f" >/dev/null || {
    echo "FAIL: $f is missing from the resumed review branch" >&2
    fail=1
  }
done
echo "PASS: the resumed review branch carries the replayed AND the new work"
check "leg 3 wrote its own session manifest" '"review_branch": "sandbox/persist-review-resumed"' "$state3/session.json"

# ---- cleanup: `down` must reap the persistent session, verified fail-loud ----
bin/agent-sandbox down agent-sandbox-persist-demo
leftovers="$(docker volume ls -q | grep '^agent-sandbox-' || true)"
if [[ -n "$leftovers" ]]; then
  echo "FAIL: session volumes survived the final teardown: $leftovers" >&2
  fail=1
else
  echo "PASS: no session volumes survived the final teardown"
fi

exit "$fail"

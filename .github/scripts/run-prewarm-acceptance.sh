#!/usr/bin/env bash
# Prewarm-pool END-TO-END ACCEPTANCE (issue #34), on a CI Docker daemon:
# three legs prove the warm-start path is a real lifecycle.
#   leg 1 (prewarm): `agent-sandbox prewarm` leaves a running, labeled spare —
#                    firewall healthy, workspace empty, no entrypoint run.
#   leg 2 (adopt):   a matching `run` ADOPTS the spare (the adoption marker names
#                    it), the workload's commit lands on the review branch, and
#                    the ephemeral teardown destroys the spare's stack —
#                    containers AND volumes — as the session's own.
#   leg 3 (reap):    a fresh spare over the (zeroed) age limit is reaped by
#                    `gc`, leaving no containers or volumes behind.
set -Eeuo pipefail

docker build -f sandbox/Dockerfile -t agent-sandbox-firewall:ci sandbox/
export FIREWALL_IMAGE=agent-sandbox-firewall:ci
export CONTAINER_RUNTIME=runc
export AGENT_SANDBOX_STATE_DIR="$PWD/.acceptance-state"

# The spec hash digests the workload image's Id, so the image must be present
# BEFORE prewarm computes the spare's label (and before run recomputes it).
docker pull buildpack-deps:stable-scm

# The host-side extract (git worktree + am) needs a committer identity the bare
# runner checkout lacks.
git config user.email "ci@agent-sandbox.local"
git config user.name "agent-sandbox CI"

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

mk_workload() { # <out-file> <entrypoint-script>
  local out="$1" script="$2"
  jq -n --arg script "$script" '{
    image: "buildpack-deps:stable-scm",
    entrypoint: ["bash", "-lc", $script],
    user: "1000",
    egress_allowlist: [],
    ephemeral: true,
    backend: "local",
    seed_from_git: {ref: "HEAD", review_branch: "sandbox/prewarm-review"}
  }' >"$out"
}

# The two records deliberately differ in entrypoint (an exec-time field the spec
# hash excludes): adoption keys on the boot shape, not the workload's argv.
mk_workload wl-prewarm.json 'echo prewarm-entrypoint-must-never-run; exit 97'
mk_workload wl-run.json 'set -euo pipefail; cd /workspace; echo adopted >adopted.txt; git add adopted.txt; git commit -qm "feat: adopted work"; echo "ADOPTED RAN"'

# ---- leg 1: prewarm a spare ----
spare="$(bin/agent-sandbox prewarm wl-prewarm.json 2>prewarm.log)" || {
  cat prewarm.log >&2
  echo "FAIL: prewarm exited non-zero" >&2
  exit 1
}
cat prewarm.log
echo "prewarm spare: $spare"
[[ "$spare" =~ ^agent-sandbox-prewarm-[0-9a-f]{8}$ ]] || {
  echo "FAIL: prewarm printed an unexpected project name: '$spare'" >&2
  exit 1
}
spare_cid="$(docker ps -q --filter "label=com.docker.compose.project=$spare" --filter label=agent-sandbox.prewarm=ready)"
if [[ -z "$spare_cid" ]]; then
  echo "FAIL: no running container carries the spare's ready label" >&2
  exit 1
fi
echo "PASS: the spare is up and labeled ready"
if grep -q 'prewarm-entrypoint-must-never-run' prewarm.log; then
  echo "FAIL: the prewarm entrypoint ran — a spare must stop before serving" >&2
  fail=1
else
  echo "PASS: the prewarm entrypoint never ran"
fi

# ---- leg 2: a matching run adopts the spare ----
rc=0
bin/agent-sandbox run wl-run.json >run.log 2>&1 || rc=$?
echo "--- adoption run log (run.log) ---"
cat run.log
if [[ "$rc" -ne 0 ]]; then
  echo "FAIL: the adopting run exited $rc" >&2
  exit "$rc"
fi
check "the run adopted the prewarmed spare" "adopted prewarmed spare $spare" run.log
check "the adopted session ran the workload entrypoint" 'ADOPTED RAN' run.log
git show sandbox/prewarm-review:adopted.txt >/dev/null || {
  echo "FAIL: the adopted session's commit is not on the review branch" >&2
  fail=1
}
echo "PASS: the adopted session's work was extracted to sandbox/prewarm-review"
leftover_containers="$(docker ps -aq --filter "label=com.docker.compose.project=$spare")"
leftover_volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$spare")"
if [[ -n "$leftover_containers" || -n "$leftover_volumes" ]]; then
  echo "FAIL: the adopted spare's stack survived teardown (containers: $leftover_containers volumes: $leftover_volumes)" >&2
  fail=1
else
  echo "PASS: the adopted spare's stack was torn down as the session's own"
fi

# ---- leg 3: gc reaps an over-age spare ----
spare2="$(bin/agent-sandbox prewarm wl-prewarm.json 2>prewarm2.log)" || {
  cat prewarm2.log >&2
  echo "FAIL: second prewarm exited non-zero" >&2
  exit 1
}
echo "second prewarm spare: $spare2"
sleep 2 # age the spare past the zeroed limit (reap fires on age > max)
AGENT_SANDBOX_PREWARM_MAX_AGE=0 bin/agent-sandbox gc
leftover_containers="$(docker ps -aq --filter "label=com.docker.compose.project=$spare2")"
leftover_volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$spare2")"
if [[ -n "$leftover_containers" || -n "$leftover_volumes" ]]; then
  echo "FAIL: gc left the over-age spare behind (containers: $leftover_containers volumes: $leftover_volumes)" >&2
  fail=1
else
  echo "PASS: gc reaped the over-age spare, volumes verified gone"
fi

exit "$fail"

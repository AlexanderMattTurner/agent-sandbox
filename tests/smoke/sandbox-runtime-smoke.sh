#!/usr/bin/env bash
# Runtime-ladder install/smoke: prove the extracted runtime-detect ladder + backend
# seam actually SELECT a runtime and that Docker can RUN a throwaway container under
# it — the gap `docker info`-listing alone can't close (a listed-but-broken runtime
# passes registration yet dies deep in a launch). Two assertions:
#   1. backend_select_runtime local picks a runtime that really runs a container
#      (docker run --runtime=<selected> alpine echo runtime-ok -> exact match);
#   2. the fail-closed gate refuses a bogus CONTAINER_RUNTIME=doesnotexist
#      (backend_select_runtime returns non-zero AND names "not registered").
# Emits PASS:/FAIL: lines and exits non-zero on any failure. Needs a working Docker
# daemon (the CI runner has one; this repo's dev sandbox does not), so it runs from
# the runtime-smoke workflow, not the local test sweep.
set -euo pipefail

SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SMOKE_DIR/../.." && pwd)"

# backend.bash pulls in runtime-detect.bash itself; source both explicitly so this
# script reads self-contained and a future backend.bash reorg can't silently drop
# either dependency out from under the assertions.
# shellcheck source=../../bin/lib/runtime-detect.bash disable=SC1091
source "$REPO_ROOT/bin/lib/runtime-detect.bash"
# shellcheck source=../../bin/lib/backend.bash disable=SC1091
source "$REPO_ROOT/bin/lib/backend.bash"

ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.21}"
RUNTIME_MARKER="runtime-ok"

fails=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  fails=$((fails + 1))
}

# The selected runtime must not just appear in `docker info` — it must launch a
# container. Pull the tiny image (cached after the first pull) so a slow/rate-limited
# registry doesn't masquerade as a runtime fault, then match the container's echo
# EXACTLY (a partial/substring match would pass on daemon noise interleaved on stdout).
assert_runtime_runs_container() {
  local runtime="$1" out
  docker pull "$ALPINE_IMAGE" >/dev/null 2>&1 || {
    fail "could not pull $ALPINE_IMAGE to smoke-test runtime '$runtime'"
    return 1
  }
  out="$(docker run --rm --runtime="$runtime" "$ALPINE_IMAGE" echo "$RUNTIME_MARKER" 2>/dev/null || true)"
  if [[ "$out" == "$RUNTIME_MARKER" ]]; then
    pass "runtime '$runtime' ran a container (echo '$RUNTIME_MARKER' matched exactly)"
  else
    fail "runtime '$runtime' did not run a container cleanly: expected '$RUNTIME_MARKER', got '$out'"
  fi
}

# Assertion 1 — backend_select_runtime local picks a runtime that actually runs.
selected="$(backend_select_runtime local)" || {
  fail "backend_select_runtime local returned non-zero (no usable runtime selected)"
  selected=""
}
if [[ -n "$selected" ]]; then
  pass "backend_select_runtime local selected runtime '$selected'"
  assert_runtime_runs_container "$selected"
fi

# Assertion 2 — the fail-closed gate refuses a runtime Docker never registered.
# Run in a subshell so the CONTAINER_RUNTIME override never leaks into later checks,
# and capture stderr (as_error writes there) to prove the message NAMES the fault.
bogus_out="$(CONTAINER_RUNTIME=doesnotexist backend_select_runtime local 2>&1)" && bogus_rc=0 || bogus_rc=$?
if [[ "$bogus_rc" -ne 0 ]]; then
  pass "backend_select_runtime refused bogus CONTAINER_RUNTIME=doesnotexist (rc=$bogus_rc)"
else
  fail "backend_select_runtime accepted a bogus runtime (expected non-zero, got 0)"
fi
if grep -qi 'not registered' <<<"$bogus_out"; then
  pass "fail-closed error names the fault ('not registered')"
else
  fail "fail-closed error did not name 'not registered': $bogus_out"
fi

if [[ "$fails" -ne 0 ]]; then
  printf '\nSMOKE FAIL: %d assertion(s) failed\n' "$fails" >&2
  exit 1
fi
printf '\nSMOKE OK: runtime ladder selected a runtime that ran a container; fail-closed gate refused a bogus runtime\n'

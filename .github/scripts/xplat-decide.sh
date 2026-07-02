#!/usr/bin/env bash
# Emit run=true to GITHUB_OUTPUT when the cross-platform host tests should run:
# always when there is no PR to diff (push/dispatch), or when a host-facing path
# changed in the PR. Keeps the (10x-cost) macOS runner off PRs that can't affect
# host behaviour, while the workflow still always fires so the required reporter
# reports. Env: BASE_SHA, HEAD_SHA (empty outside pull_request).
set -euo pipefail

if [[ -z "${BASE_SHA:-}" || -z "${HEAD_SHA:-}" ]]; then
  echo "run=true" >>"$GITHUB_OUTPUT"
  exit 0
fi

# Host launcher surface + the test/harness files that select and drive it.
re='^(setup\.sh|bin/|tests/.*\.py|pyproject\.toml|uv\.lock|\.python-version|\.github/scripts/xplat-decide\.sh|\.github/workflows/cross-platform-tests\.yaml)'
# Assign separately so a failing `git diff` (bad SHA) aborts under set -e rather
# than silently reading empty and failing open to run=false.
changed="$(git diff --name-only "$BASE_SHA...$HEAD_SHA")"
if grep -qE "$re" <<<"$changed"; then
  echo "run=true" >>"$GITHUB_OUTPUT"
else
  echo "run=false" >>"$GITHUB_OUTPUT"
fi

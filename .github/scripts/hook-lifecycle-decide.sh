#!/usr/bin/env bash
# Emit run=true to GITHUB_OUTPUT when the hook lifecycle should run: always when
# there is no PR to diff (push/dispatch), or when a hook-relevant path changed in
# the PR. Keeps the expensive lifecycle job off PRs that can't affect the hooks,
# while the workflow still always fires so the required reporter reports.
# Env: BASE_SHA, HEAD_SHA (empty outside pull_request).
set -euo pipefail

if [[ -z "${BASE_SHA:-}" || -z "${HEAD_SHA:-}" ]]; then
  echo "run=true" >>"$GITHUB_OUTPUT"
  exit 0
fi

# Hook-relevant paths — kept in sync with the push: trigger's paths filter above.
re='^(\.claude/hooks/|\.hooks/|setup\.sh|package\.json|pnpm-lock\.yaml|pyproject\.toml|uv\.lock|\.pre-commit-config\.yaml|\.github/scripts/(run-hook-lifecycle|hook-lifecycle-decide)\.sh|\.github/workflows/hook-lifecycle\.yaml)'
# Assign separately so a failing `git diff` (bad SHA) aborts under set -e rather
# than silently reading empty and failing open to run=false.
changed="$(git diff --name-only "$BASE_SHA...$HEAD_SHA")"
if grep -qE "$re" <<<"$changed"; then
  echo "run=true" >>"$GITHUB_OUTPUT"
else
  echo "run=false" >>"$GITHUB_OUTPUT"
fi

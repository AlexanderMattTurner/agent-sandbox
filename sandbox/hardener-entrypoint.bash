#!/usr/bin/env bash
# hardener-entrypoint.bash — the transient root init service's generic hook
# runner: execute every executable in the read-only hooks dir (empty/absent =
# no-op success), each writing hardened config into the shared volume the
# workload mounts read-only. Fail closed: any hook exiting non-zero exits this
# script non-zero, so the workload's `service_completed_successfully` gate never
# opens on a partially-hardened session.
set -Eeuo pipefail

_HARDENER_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
# shellcheck source=trace.bash disable=SC1091
source "$_HARDENER_DIR/trace.bash"

HOOKS_DIR="${HARDENER_HOOKS_DIR:-/run/hardener-hooks.d}"
HARDENED_CONFIG_DIR="${HARDENED_CONFIG_DIR:-/run/hardened-config}"
export HARDENED_CONFIG_DIR

# The shared volume is the hooks' output contract; verify the post-condition
# (mkdir -p exits 0 even over a dangling symlink on some platforms).
mkdir -p "$HARDENED_CONFIG_DIR"
if [[ ! -d "$HARDENED_CONFIG_DIR" ]]; then
  echo "hardener: hardened-config dir is not a directory: $HARDENED_CONFIG_DIR" >&2
  exit 1
fi

# A missing/non-directory hooks mount (the /dev/null compose default) means no
# hooks were provided — the documented no-op success.
hook_count=0
if [[ -d "$HOOKS_DIR" ]]; then
  while IFS= read -r hook; do
    rc=0
    "$hook" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
      echo "hardener: hook failed (exit $rc): $hook" >&2
      exit "$rc"
    fi
    hook_count=$((hook_count + 1))
  done < <(find "$HOOKS_DIR" -maxdepth 1 -type f -perm -u+x | sort)
fi

as_trace "$TRACE_HARDENER_LOCKDOWN_APPLIED" "hooks=$hook_count"
echo "hardener: applied $hook_count hook(s)"

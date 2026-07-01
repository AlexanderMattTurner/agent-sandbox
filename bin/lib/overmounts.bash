# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
# overmounts.bash — workload-declared read-only guardrail overmounts.
#
# A Workload can declare `overmount_paths`: workspace-relative paths mounted READ-ONLY
# on top of the base /workspace bind, so the workload can read them but never write them.
# A read-only bind is kernel-enforced (even in-container root can't write it), strictly
# stronger than a permission-bit `a-w` and without touching host ownership.
#
# This is a BIND-MODE feature. In seed mode /workspace is a named volume (not a host
# bind), so a host read-only bind has nothing to overlay, AND the workload's writes are
# already gated by the review-branch extract (bin/lib/worktree-seed.bash) before they can
# reach the host — so nothing here applies and write_overmount_compose emits a no-op.
#
# The default set is `.git/hooks node_modules`:
#   - `.git/hooks` is a container->host code-execution guard: in bind mode the host
#     checkout is mounted read-write at /workspace, so without this a compromised workload
#     could plant /workspace/.git/hooks/pre-commit (or post-checkout, ...) that then runs
#     ON THE HOST the next time the user invokes git in that checkout — a breakout that
#     outlives the session and, living in .git, never shows in `git diff`.
#   - `node_modules` locks the tooling the workload imports so it can't tamper with it.

_OVERMOUNTS_LIB_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
# shellcheck source=msg.bash disable=SC1091
source "$_OVERMOUNTS_LIB_DIR/msg.bash"

# Default guardrail paths, mounted read-only when a Workload declares no `overmount_paths`.
# SSOT for the default; the schema's `overmount_paths.default` must equal this
# (tests/test_workload_schema.py cross-checks it by invoking overmount_paths_for).
_OVERMOUNT_DEFAULT_PATHS=(.git/hooks node_modules)

# overmount_paths_for WORKLOAD_JSON — emit the record's `overmount_paths`, one per line,
# or the default set when the field is ABSENT. An explicit `[]` means "no overmounts" and
# prints nothing. Fails loud on an absolute entry or one containing `..`: a traversal there
# would bind host paths outside the workspace.
overmount_paths_for() {
  local workload="$1" p
  local -a paths=()
  if jq -e 'has("overmount_paths")' "$workload" >/dev/null 2>&1; then
    while IFS= read -r p; do paths+=("$p"); done < <(jq -r '.overmount_paths[]' "$workload")
  else
    paths=("${_OVERMOUNT_DEFAULT_PATHS[@]}")
  fi
  for p in ${paths[@]+"${paths[@]}"}; do
    if [[ "$p" == /* || "$p" == *".."* ]]; then
      as_error "overmount_paths entry '$p' is absolute or contains '..' — refusing (a traversal would bind host paths outside the workspace)"
      return 1
    fi
    printf '%s\n' "$p"
  done
}

# overmount_applies WORKSPACE_HOST REL — 0 iff "$WORKSPACE_HOST/$REL" EXISTS on the host
# (a dir or a regular file). Existence is what keeps us from fabricating empty dirs for a
# workload that ships none of these paths. `[[ -e ]]` follows symlinks, so a DANGLING
# symlink does not apply (its target is missing). Checked on the RAW host path.
overmount_applies() {
  local workspace="$1" rel="$2"
  [[ -e "$workspace/$rel" ]]
}

# overmount_applicable_paths WORKLOAD_JSON — emit the declared paths that actually apply
# (exist under the workload's host workspace_mount), one per line. Empty in seed mode
# (no workspace_mount). Single source of applicability shared by the compose generator and
# the fail-closed verify. Fails loud (non-zero) when overmount_paths_for rejects an entry.
overmount_applicable_paths() {
  local workload="$1" workspace rel paths_out
  workspace="$(jq -r '.workspace_mount // empty' "$workload")"
  [[ -n "$workspace" ]] || return 0
  paths_out="$(overmount_paths_for "$workload")" || return 1
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    overmount_applies "$workspace" "$rel" && printf '%s\n' "$rel"
  done <<<"$paths_out"
  # An explicit success: the loop's status is the last overmount_applies result, which is
  # 1 whenever the final declared path simply doesn't apply — that is not a failure to
  # resolve, and the caller must not read it as one.
  return 0
}

# Write stdin to <out> atomically (temp file in the same dir, then rename), REFUSING to
# install an empty result. A failed generator pipeline or an empty file must NOT replace an
# existing read-only-guardrail override: a truncated override silently drops the :ro binds,
# demoting a kernel-enforced protection to nothing. On either failure the original (if any)
# is left untouched and no temp sibling leaks.
_overmount_write_atomic() {
  local out="$1" tmp
  tmp="$(mktemp "$out.XXXXXX")"
  # shellcheck disable=SC2064  # expand $tmp now, not at trap time.
  trap "rm -f -- '$tmp'" RETURN
  if ! cat >"$tmp"; then
    as_error "failed to write the compose override $out (write to temp $tmp failed); keeping any existing file"
    return 1
  fi
  if [[ ! -s "$tmp" ]]; then
    as_error "refusing to install an empty compose override $out (temp $tmp produced no output); keeping any existing file"
    return 1
  fi
  mv -f "$tmp" "$out"
}

# write_overmount_compose WORKLOAD_JSON OUT — generate a compose override adding one
# read-only bind per applicable overmount path, stacked on the base /workspace bind.
# Compose merges a service's `volumes` by container target, so these DISTINCT targets union
# across files. When nothing applies — including seed mode, where /workspace is a named
# volume — emit the no-op `{"services":{}}` rather than an empty volumes list (which would
# clear the base mount). A literal `$` in the host source is escaped to `$$` so compose's
# interpolation pass leaves it verbatim (same reason as _stack_write_override).
write_overmount_compose() {
  local workload="$1" out="$2" workspace rel applic
  workspace="$(jq -r '.workspace_mount // empty' "$workload")"
  if ! applic="$(overmount_applicable_paths "$workload")"; then
    as_error "could not resolve the workload's overmount paths"
    return 1
  fi
  local -a rels=()
  while IFS= read -r rel; do [[ -n "$rel" ]] && rels+=("$rel"); done <<<"$applic"
  if ((${#rels[@]} == 0)); then
    printf '%s\n' '{"services":{}}' | _overmount_write_atomic "$out"
    return
  fi
  jq -n --arg ws "$workspace" '
    {services: {workload: {volumes: [
      $ARGS.positional[] | {
        type: "bind",
        source: (($ws + "/" + .) | gsub("\\$"; "$$")),
        target: ("/workspace/" + .),
        read_only: true
      }
    ]}}}
  ' --args "${rels[@]}" | _overmount_write_atomic "$out"
}

# The in-container write-probe body (dash-safe; run under the container's /bin/sh). For each
# positional path: a dir is probed by creating+removing a marker child, a regular file by
# opening it for append (no content change), a missing path is UNVERIFIABLE. Emits one
# "<path>\t<verdict>" line per path, then exits 1 if ANY path was writable, else 2 if any
# was unverifiable, else 0 — WRITABLE (a real breach) outranks unverifiable. `true >>` (not
# `: >>`): `:` is a POSIX special built-in, so under dash a failed redirection on it EXITS
# the shell — which on a correctly read-only file (the success case) would abort the loop
# and drop later verdicts. `true` is a regular built-in: a failed redirection just leaves it
# non-zero and the loop continues.
_overmount_probe_body() {
  cat <<'PROBE'
w=0
u=0
for p in "$@"; do
  if [ -d "$p" ]; then
    if touch "$p/.as-write-probe.$$" 2>/dev/null; then
      rm -f "$p/.as-write-probe.$$"
      printf '%s\tWRITABLE\n' "$p"
      w=1
    else
      printf '%s\tPROTECTED\n' "$p"
    fi
  elif [ -e "$p" ]; then
    if true >>"$p" 2>/dev/null; then
      printf '%s\tWRITABLE\n' "$p"
      w=1
    else
      printf '%s\tPROTECTED\n' "$p"
    fi
  else
    printf '%s\tUNVERIFIABLE\n' "$p"
    u=1
  fi
done
[ "$w" = 1 ] && exit 1
[ "$u" = 1 ] && exit 2
exit 0
PROBE
}

# verify_guardrails_readonly CID USER CONTAINER_PATH... — fail-closed proof that USER cannot
# write any of the given container paths, via ONE batched `docker exec` of the write-probe.
# The probe's exit code carries the verdict; the host maps it:
#   0  -> every path read-only            (return 0)
#   1  -> a path was WRITABLE (breach)     (return 1)
#   2  -> a path was UNVERIFIABLE          (return 2)
#   *  -> the exec itself could not run (rc >= 125), or any other code — a fail-closed
#         control must never assume protection it did not observe, so this is unverifiable
#         too (return 2).
# The per-path verdict lines ride to stderr so CI/logs show what was checked.
verify_guardrails_readonly() {
  local cid="$1" user="$2"
  shift 2
  (($#)) || return 0
  local probe out rc=0
  probe="$(_overmount_probe_body)"
  out="$(docker exec -u "$user" "$cid" sh -c "$probe" sh "$@" 2>/dev/null)" || rc=$?
  [[ -n "$out" ]] && printf '%s\n' "$out" >&2
  case "$rc" in
  0) return 0 ;;
  1) return 1 ;;
  *) return 2 ;; # 2 = probe found an unverifiable path; anything else (rc >= 125: the exec could not run) also fails closed as unverifiable
  esac
}

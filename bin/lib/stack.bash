# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
# stack.bash — one sandbox session's compose orchestration: bring up the
# firewall+workload stack (sandbox/docker-compose.yml), seed the workspace from
# git, exec the Workload's entrypoint, extract its commits onto a reviewable host
# branch, export the egress log, then tear down. Every step fails closed: a stack
# that can't come up is torn down, a failed extract KEEPS the session's volumes
# (the work must never die with them), and an ephemeral teardown fails loud on
# any volume it could not remove.

_STACK_LIB_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
# shellcheck source=msg.bash disable=SC1091
source "$_STACK_LIB_DIR/msg.bash"
# shellcheck source=worktree-seed.bash disable=SC1091
source "$_STACK_LIB_DIR/worktree-seed.bash"
# shellcheck source=overmounts.bash disable=SC1091
source "$_STACK_LIB_DIR/overmounts.bash"

# _stack_compose PROJECT COMPOSE OVERRIDE OVERMOUNTS CMD... — every compose call goes
# through here so the project name and file set can never drift between up/exec/down. The
# overmount override is ALWAYS in the set (a no-op `{"services":{}}` in seed mode), so no
# call site can accidentally boot the stack without the read-only guardrails. Consumer
# overlays (stack_run's extra compose files) ride in via _STACK_EXTRA_COMPOSE, LAST in
# the -f order so a consumer's service extensions merge on top of the library's stack —
# through the same choke point, so no call site can see a different file set than `up` did.
_STACK_EXTRA_COMPOSE=()
_stack_compose() {
  local project="$1" compose="$2" override="$3" overmounts="$4"
  shift 4
  local -a files=(-f "$compose" -f "$override" -f "$overmounts")
  local extra
  for extra in ${_STACK_EXTRA_COMPOSE[@]+"${_STACK_EXTRA_COMPOSE[@]}"}; do
    files+=(-f "$extra")
  done
  docker compose -p "$project" "${files[@]}" "$@"
}

# stack_partition_allowlist WORKLOAD_JSON — export the Workload's egress_allowlist
# as the two newline-separated tier lists the firewall consumes. A bare string is
# rw ("allow this host" means it works); the object form opts a host down to ro.
stack_partition_allowlist() {
  local workload="$1"
  WORKLOAD_ALLOWED_DOMAINS_RO="$(jq -r '.egress_allowlist[]? | select(type == "object" and .access == "ro") | .host' "$workload")"
  WORKLOAD_ALLOWED_DOMAINS_RW="$(jq -r '.egress_allowlist[]? | if type == "string" then . elif (.access // "rw") == "rw" then .host else empty end' "$workload")"
  export WORKLOAD_ALLOWED_DOMAINS_RO WORKLOAD_ALLOWED_DOMAINS_RW
}

# _stack_state_dir PROJECT — this session's owner-only host dir for the artifacts
# that outlive the containers: the WIP patch, the agent's mbox, the egress log.
_stack_state_dir() {
  printf '%s/sessions/%s' \
    "${AGENT_SANDBOX_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agent-sandbox}" "$1"
}

# stack_ensure_firewall_image SANDBOX_DIR — make sure $FIREWALL_IMAGE exists,
# building it from the shipped Dockerfile on first run. A build failure refuses
# the launch (no firewall image ⇒ no egress boundary ⇒ no launch).
stack_ensure_firewall_image() {
  local sandbox_dir="$1"
  FIREWALL_IMAGE="${FIREWALL_IMAGE:-agent-sandbox-firewall:local}"
  export FIREWALL_IMAGE
  docker image inspect "$FIREWALL_IMAGE" >/dev/null 2>&1 && return 0
  as_info "building the firewall image $FIREWALL_IMAGE (first run)"
  docker build -f "$sandbox_dir/Dockerfile" -t "$FIREWALL_IMAGE" "$sandbox_dir" || {
    as_error "could not build the firewall image — refusing to launch without the egress boundary"
    return 1
  }
}

# _stack_write_override WORKLOAD_JSON OUT — generate the per-session compose
# override carrying the parts of the Workload record a static file can't: its env
# map and (host-mode) its workspace bind, which replaces the named volume by
# target-path merge. JSON is valid YAML, so compose consumes it directly.
_stack_write_override() {
  local workload="$1" out="$2"
  # `$` → `$$`: compose runs variable interpolation over every file it loads,
  # so a literal dollar in a Workload env value (or mount path) must be escaped
  # or it would be expanded against the LAUNCHER's environment.
  jq '{
    services: {
      workload: ({environment: ((.env // {}) | with_entries(.value |= gsub("\\$"; "$$")))}
        + (if .workspace_mount
           then {volumes: [{type: "bind", source: (.workspace_mount | gsub("\\$"; "$$")), target: "/workspace"}]}
           else {} end))
    }
  }' "$workload" >"$out"
}

# _stack_export_egress_log PROJECT COMPOSE OVERRIDE OVERMOUNTS STATE_DIR — copy squid's
# access.log (the tamper-evident egress log) out of the firewall container before
# teardown destroys its volume. Warn-loud on failure (the session's audit record
# is lost) but don't block teardown on it.
_stack_export_egress_log() {
  local project="$1" compose="$2" override="$3" overmounts="$4" state="$5" fw_cid
  fw_cid="$(_stack_compose "$project" "$compose" "$override" "$overmounts" ps -q firewall)"
  if [[ -z "$fw_cid" ]] || ! docker cp "$fw_cid:/var/log/squid/access.log" "$state/egress.log" >/dev/null 2>&1; then
    as_warn "could not export the egress log from the firewall container — this session has no audit record on the host"
    return 1
  fi
  as_info "egress log: $state/egress.log"
}

# stack_verify_no_volumes PROJECT — verify no compose-labeled volume survived a
# teardown. The guarantee is verified, not assumed: any survivor fails loud so
# "ephemeral" can never silently mean "persistent".
stack_verify_no_volumes() {
  local project="$1" leftovers
  leftovers="$(docker volume ls -q --filter "label=com.docker.compose.project=$project")"
  [[ -z "$leftovers" ]] || {
    as_error "ephemeral teardown left volumes behind (fail-loud): $leftovers"
    return 1
  }
}

# _stack_down_ephemeral PROJECT COMPOSE OVERRIDE OVERMOUNTS — remove containers, networks AND
# volumes, then verify no volume survived (stack_verify_no_volumes fails loud on any).
_stack_down_ephemeral() {
  local project="$1" compose="$2" override="$3" overmounts="$4"
  _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || {
    as_error "ephemeral teardown failed (compose project $project) — session containers/volumes may survive"
    return 1
  }
  stack_verify_no_volumes "$project"
}

# stack_run WORKLOAD_JSON COMPOSE RUNTIME [EXTRA_COMPOSE...] — the whole session:
# up → seed → exec → extract → export egress log → down. Returns the workload's exit
# status when the session machinery succeeded; machinery failures return non-zero
# themselves. Reads SANDBOX_IP/SANDBOX_SUBNET from the caller (export_sandbox_subnet).
# EXTRA_COMPOSE files are consumer overlays merged after the library's file set on
# EVERY compose invocation of this session (see _stack_compose). The compose project
# name is randomized per session unless the consumer pins its own identity via
# AGENT_SANDBOX_PROJECT_NAME (its lifecycle tooling finds the stack by that label).
stack_run() {
  local workload="$1" compose="$2" runtime="$3"
  shift 3
  _STACK_EXTRA_COMPOSE=("$@")
  local sandbox_dir project state
  sandbox_dir="$(cd "$(dirname "$compose")" && pwd)"
  project="${AGENT_SANDBOX_PROJECT_NAME:-agent-sandbox-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')}"
  state="$(_stack_state_dir "$project")"
  worktree_secure_mkdir "$state" || return 1

  WORKLOAD_IMAGE="$(jq -r '.image' "$workload")"
  WORKLOAD_USER="$(jq -r '.user // "1000"' "$workload")"
  WORKLOAD_RUNTIME="$runtime"
  WORKLOAD_IP="${SANDBOX_IP%.*}.3"
  export WORKLOAD_IMAGE WORKLOAD_USER WORKLOAD_RUNTIME WORKLOAD_IP
  # The seed/extract execs must run as the same user the workload writes as.
  export AGENT_SANDBOX_WORKLOAD_USER="$WORKLOAD_USER"
  stack_partition_allowlist "$workload"
  # The default library services (hardener, audit) are profile-gated in the
  # compose: compose cannot REMOVE a service via an override, so a workload
  # opt-out (hardener:false / audit:false) is expressed by not activating the
  # profile. The workload's depends_on entries carry required:false, so a
  # deactivated profile drops the gate instead of failing `up`.
  local _profiles=()
  jq -e '.hardener == false' "$workload" >/dev/null || _profiles+=("hardener")
  jq -e '.audit == false' "$workload" >/dev/null || _profiles+=("audit")
  COMPOSE_PROFILES="$(
    IFS=,
    printf '%s' "${_profiles[*]-}"
  )"
  export COMPOSE_PROFILES
  stack_ensure_firewall_image "$sandbox_dir" || return 1

  local override="$state/workload-override.json"
  _stack_write_override "$workload" "$override" || {
    as_error "could not generate the per-session compose override"
    return 1
  }
  # The read-only guardrail overmounts ride in on their own always-present override
  # (a no-op in seed mode). Generating it is fail-closed: a workload that declares
  # traversal-shaped overmount paths is refused before anything comes up.
  local overmounts="$state/overmount-override.json"
  write_overmount_compose "$workload" "$overmounts" || {
    as_error "could not generate the read-only guardrail overmount override"
    return 1
  }

  local ephemeral
  ephemeral="$(jq -r '.ephemeral' "$workload")"

  as_info "compose: bringing up firewall + workload (project $project)"
  if ! _stack_compose "$project" "$compose" "$override" "$overmounts" up -d --wait --wait-timeout 240; then
    as_error "the firewall+workload compose stack did not come up healthy — firewall logs follow"
    _stack_compose "$project" "$compose" "$override" "$overmounts" logs firewall >&2 || true           # allow-exit-suppress: best-effort diagnostics on an already-failed launch
    _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup of a stack that never came up healthy; the launch already failed loudly
    return 1
  fi
  local cid
  cid="$(_stack_compose "$project" "$compose" "$override" "$overmounts" ps -q workload)"
  if [[ -z "$cid" ]]; then
    as_error "the workload container did not start (compose project $project)"
    _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
    return 1
  fi

  # Fail-closed guardrail verify (BIND MODE only): the read-only overmounts are a security
  # control, so prove the workload user truly cannot write them before handing over. Seed
  # mode has no host ro-binds (workspace is a named volume) and its writes are gated by the
  # review-branch extract, so it is not probed. Run before seeding/exec so a guardrail that
  # isn't actually read-only never gets a chance to be bypassed.
  if jq -e '.workspace_mount' "$workload" >/dev/null 2>&1; then
    local -a _cpaths=()
    local _rel
    while IFS= read -r _rel; do
      [[ -n "$_rel" ]] && _cpaths+=("/workspace/$_rel")
    done < <(overmount_applicable_paths "$workload")
    if ((${#_cpaths[@]})); then
      if ! verify_guardrails_readonly "$cid" "$WORKLOAD_USER" "${_cpaths[@]}"; then
        as_error "a read-only guardrail is writable or unverifiable — refusing to hand over the sandbox"
        _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup of a stack refused at the guardrail gate; the launch already failed loudly
        return 1
      fi
      as_info "overmounts verified read-only (${#_cpaths[@]} paths)"
    fi
  fi

  # Seed the workspace from git BEFORE the entrypoint runs, so the workload never
  # sees a half-seeded tree. A seed failure keeps nothing: no work exists yet, so
  # tear the stack down and refuse.
  local seeded=0 base_ref="" base_commit="" review_branch="" repo_root="" wip_patch=""
  if jq -e '.seed_from_git' "$workload" >/dev/null; then
    local ref
    ref="$(jq -r '.seed_from_git.ref' "$workload")"
    review_branch="$(jq -r '.seed_from_git.review_branch' "$workload")"
    if [[ "$ref" != "HEAD" ]]; then
      as_error "seed_from_git.ref: only HEAD (the current checkout's tracked tree + uncommitted delta) is supported by this build"
      _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
      return 1
    fi
    if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
      as_error "seed_from_git needs to run from inside a git checkout (no repo at $PWD)"
      _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
      return 1
    fi
    base_commit="$(git -C "$repo_root" rev-parse HEAD)"
    wip_patch="$state/wip.patch"
    if ! (umask 077 && worktree_capture_wip_patch "$repo_root" >"$wip_patch") ||
      ! worktree_seed_tar "$repo_root" | worktree_seed_into_container "$cid" ||
      ! base_ref="$(worktree_container_init_repo "$cid" "$review_branch")"; then
      as_error "could not seed the workspace into the sandbox"
      _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
      return 1
    fi
    seeded=1
    as_info "workspace seeded from $repo_root (HEAD + uncommitted delta); review branch: $review_branch"
  fi

  # Run the Workload's entrypoint. Its env rode in on the override, so a plain
  # docker exec sees it; -w /workspace so relative paths land in the seeded tree.
  # Read the argv by index, not by splitting jq's newline-joined output: an
  # entrypoint element may itself contain newlines (a multi-line `bash -c`
  # script is the common case), which a line-delimited read would split into
  # several argv words, silently truncating a `-c` body to its first line.
  local -a argv=()
  local _n _i
  _n="$(jq '.entrypoint | length' "$workload")"
  for ((_i = 0; _i < _n; _i++)); do
    argv+=("$(jq -r ".entrypoint[$_i]" "$workload")")
  done
  local workload_rc=0
  docker exec -u "$WORKLOAD_USER" -w /workspace "$cid" "${argv[@]}" || workload_rc=$?
  if [[ "$workload_rc" -ne 0 ]]; then
    as_warn "workload exited with status $workload_rc"
  fi

  # Extract BEFORE teardown — mandatory. A failed extract keeps the containers
  # and volumes so the workload's commits are never destroyed with them.
  if [[ "$seeded" == 1 ]]; then
    local wt_dir="$state/review-worktree" agent_mbox="$state/agent.mbox"
    if ! worktree_extract_to_host "$cid" "$base_ref" "$repo_root" "$base_commit" \
      "$review_branch" "$wt_dir" "$wip_patch" "$agent_mbox"; then
      as_error "extract failed — keeping the session's containers and volumes (compose project $project) so the workload's work is not lost"
      return 1
    fi
    # The branch is the deliverable; the worktree directory was only the replay
    # surface. A failed remove is loud but non-fatal (the branch already exists).
    git -C "$repo_root" worktree remove "$wt_dir" 2>/dev/null ||
      as_warn "could not remove the scratch worktree $wt_dir (branch $review_branch is intact)"
    worktree_print_merge_hint "$review_branch"
  fi

  _stack_export_egress_log "$project" "$compose" "$override" "$overmounts" "$state" || true # allow-exit-suppress: the export already warned loudly; a lost audit copy must not block teardown of an otherwise-complete session

  if [[ "$ephemeral" == "true" ]]; then
    _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || return 1
  else
    _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || {
      as_error "teardown failed (compose project $project)"
      return 1
    }
    as_info "volumes kept (ephemeral=false): docker volume ls --filter label=com.docker.compose.project=$project"
  fi
  return "$workload_rc"
}

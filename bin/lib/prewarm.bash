# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
# prewarm.bash — the warm-start pool's primitives (issue #34): the spec hash that
# decides whether a running spare's bring-up matches a launch, and the claim locks
# that make adopting (or reaping) a spare a single-winner operation. Sourced by
# stack.bash; prewarm_gc calls back into stack.bash helpers (_stack_state_dir,
# stack_verify_no_volumes), which bash resolves at call time, so the source order
# inside stack.bash is not a constraint.
#
# Discovery is by docker labels (agent-sandbox.prewarm=ready + the spec hash), but
# labels are immutable after container create, so they can NEVER be the lock — the
# lock is an atomic mkdir under PREWARM_CLAIM_DIR, in the RUNTIME dir (not the state
# dir): claims are ephemeral cross-process mutexes, not session artifacts, and a
# reboot clearing them is correct (the containers they guarded are gone too).

PREWARM_CLAIM_DIR="${AGENT_SANDBOX_PREWARM_CLAIM_DIR:-${XDG_RUNTIME_DIR:-/tmp/agent-sandbox-$(id -u)}/agent-sandbox/prewarm-claims}"

# _prewarm_claim PROJECT — take the exclusive claim on a spare's compose project.
# `mkdir` (no -p) of the claim dir is the atomic test-and-set: exactly one caller
# wins; losing the race (or finding an existing claim, stale included — gc owns
# stale-claim removal) returns non-zero. The winner records its pid so gc can tell
# a live claimer from a crashed one.
_prewarm_claim() {
  local project="$1"
  (umask 077 && mkdir -p "$PREWARM_CLAIM_DIR") || return 1
  mkdir "$PREWARM_CLAIM_DIR/$project" 2>/dev/null || return 1
  printf '%s\n' "$$" >"$PREWARM_CLAIM_DIR/$project/pid"
}

# _prewarm_release PROJECT — release a claim taken by _prewarm_claim.
_prewarm_release() {
  local project="$1"
  rm -rf "${PREWARM_CLAIM_DIR:?}/$project"
}

# _prewarm_claim_is_stale PROJECT — 0 iff a claim exists whose recorded claimer is
# dead (kill -0 fails), i.e. the claiming process crashed without releasing. A
# claim with no readable pid is stale too (the winner writes it immediately after
# mkdir, so a missing pid means the claimer died in that window).
_prewarm_claim_is_stale() {
  local project="$1" pid
  [[ -d "$PREWARM_CLAIM_DIR/$project" ]] || return 1
  pid="$(cat "$PREWARM_CLAIM_DIR/$project/pid" 2>/dev/null)" || return 0
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  ! kill -0 "$pid" 2>/dev/null
}

# prewarm_write_override SPEC_HASH CREATED_EPOCH OUT — generate the compose
# override that marks a bring-up as an adoptable spare: the discovery labels
# (ready + spec hash + creation epoch; labels are immutable post-create, so
# they can never be the claim) and the /run/secrets tmpfs, declared VALUE-FREE
# and unconditionally — an adopter's secret_env is delivered at exec time, and
# a tmpfs can only be mounted at create, so every spare must carry the mount
# (a harmless empty dir for adopters without secrets).
prewarm_write_override() {
  local spec_hash="$1" created="$2" out="$3"
  jq -n --arg spec "$spec_hash" --arg created "$created" '{
    services: {
      workload: {
        labels: {
          "agent-sandbox.prewarm": "ready",
          "agent-sandbox.prewarm-spec": $spec,
          "agent-sandbox.prewarm-created": $created
        },
        tmpfs: ["/run/secrets:mode=0755,size=1m"]
      }
    }
  }' >"$out"
}

# _prewarm_sha256 — sha256-hex of stdin (GNU sha256sum, or BSD/macOS shasum).
_prewarm_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# prewarm_spec_hash WORKLOAD_JSON COMPOSE RUNTIME [EXTRA_COMPOSE...] — print the
# 16-hex spec hash of everything that shapes a stack's BRING-UP, so a launch
# adopts a spare only when the spare's boot is indistinguishable from the cold
# boot the launch would have done. A matching gate, not a security control: a
# hash failure or mismatch falls back to a cold boot, never to a wrong adoption.
#
# Hashed (create-time-baked inputs):
#   - the workload image's Id and the firewall image's Id (content digests via
#     `docker image inspect`, never the mutable tag the record names)
#   - the resolved runtime
#   - the egress allowlist, canonically normalized ({host, access} objects,
#     defaults applied, sorted) so entry order and string-vs-object spelling
#     don't split equal specs
#   - user/hardener/audit/backend with the schema defaults applied (they select
#     the exec uid and the compose profiles at up)
#   - control_plane.egress_grants (compose passes them into the firewall
#     container's environment at create)
#   - the compose file's content, and each extra-compose overlay's content in
#     argument order (they shape every service compose renders)
#   - each seccomp profile the compose file references (security_opt applies
#     the profile's CONTENT at container-create, but compose only stores the
#     path — an edited profile would neither move the compose hash nor force
#     a recreate at the adoption re-up)
#
# Deliberately NOT hashed (nothing here is baked into the spare's bring-up):
#   - entrypoint, tty: exec-time — the spare's container idles until serve
#   - env, secret_env: delivered at adoption exec time, never baked into a spare
#   - ephemeral: teardown-time
#   - seed_from_git: adoption-time (every spare is an empty seed-shaped workspace)
#   - workspace_mount/overmount_paths: bind-only; a bind workload never adopts
#   - session_id/resume_from: deterministic-identity sessions never adopt
#   - control_plane.require: an exec-time readiness barrier, re-run at serve
#   - launcher env knobs (EGRESS_QUOTA_MB, AGENT_SANDBOX_TRACE, ...): adoption
#     re-enters `up` under the LIVE environment, so a divergent knob is
#     reconciled by compose (a recreate — colder, still correct), not a hazard
prewarm_spec_hash() {
  local workload="$1" compose="$2" runtime="$3"
  shift 3
  local wl_image wl_id fw_id allow fields grants compose_sha extra
  wl_image="$(jq -r '.image' "$workload")" || return 1
  wl_id="$(docker image inspect -f '{{.Id}}' "$wl_image" 2>/dev/null)" || return 1
  fw_id="$(docker image inspect -f '{{.Id}}' "${FIREWALL_IMAGE:-agent-sandbox-firewall:local}" 2>/dev/null)" || return 1
  allow="$(jq -cS '[.egress_allowlist[]? | if type == "string" then {host: ., access: "rw"} else {host: .host, access: (.access // "rw")} end] | sort' "$workload")" || return 1
  # `if has(...)` rather than `//`: jq's alternative operator treats an explicit
  # `false` as absent, which would hash hardener:false as hardener:true.
  fields="$(jq -cS '{user: (.user // "1000"), hardener: (if has("hardener") then .hardener else true end), audit: (if has("audit") then .audit else true end), backend: (.backend // "local")}' "$workload")" || return 1
  grants="$(jq -cS '.control_plane.egress_grants // []' "$workload")" || return 1
  compose_sha="$(_prewarm_sha256 <"$compose")" || return 1
  local -a lines=("$wl_id" "$fw_id" "$runtime" "$allow" "$fields" "$grants" "$compose_sha")
  # seccomp:./<file> paths resolve relative to the compose file's directory.
  local seccomp_rel seccomp_path
  while IFS= read -r seccomp_rel; do
    [[ -n "$seccomp_rel" ]] || continue
    seccomp_path="$(dirname "$compose")/$seccomp_rel"
    lines+=("$(_prewarm_sha256 <"$seccomp_path")") || return 1
  done < <(sed -n 's/^[[:space:]]*-[[:space:]]*seccomp:\.\///p' "$compose" | sort -u)
  for extra in "$@"; do
    lines+=("$(_prewarm_sha256 <"$extra")") || return 1
  done
  printf '%s\n' "${lines[@]}" | _prewarm_sha256 | cut -c1-16
}

# prewarm_gc — spare hygiene for `agent-sandbox gc`: reap running spares whose
# age (agent-sandbox.prewarm-created label) exceeds AGENT_SANDBOX_PREWARM_MAX_AGE
# seconds (default 86400) via a full compose down --volumes (verified fail-loud),
# and remove claim dirs whose recorded claimer is dead. Spec-STALE spares are not
# detected here — gc has no workload to hash against — they age out on this
# timer, and hash equality already fail-closes adoption away from them. Honors
# GC_DRY_RUN=1 (report counts, touch nothing).
prewarm_gc() {
  local max="${AGENT_SANDBOX_PREWARM_MAX_AGE:-86400}"
  if [[ ! "$max" =~ ^[0-9]+$ ]]; then
    as_error "AGENT_SANDBOX_PREWARM_MAX_AGE must be a whole number of seconds, got '$max'"
    return 1
  fi
  local now rc=0
  now="$(date +%s)"
  local -a cids=()
  local cid
  while IFS= read -r cid; do
    [[ -n "$cid" ]] && cids+=("$cid")
  done < <(docker ps -q --filter label=agent-sandbox.prewarm=ready 2>/dev/null)
  local project created would_reap=0
  for cid in ${cids[@]+"${cids[@]}"}; do
    project="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null)" || continue
    [[ "$project" =~ ^agent-sandbox-prewarm-[0-9a-f]{8}$ ]] || continue
    created="$(docker inspect -f '{{index .Config.Labels "agent-sandbox.prewarm-created"}}' "$cid" 2>/dev/null)" || continue
    if [[ ! "$created" =~ ^[0-9]+$ ]]; then
      as_warn "prewarm spare $project has an unparseable creation label ('$created') — leaving it alone"
      continue
    fi
    ((now - created > max)) || continue
    # An ADOPTED stack keeps its immutable ready label; its lifecycle belongs to
    # the session that adopted it (or to `down`), never to spare hygiene — even
    # when the adopter crashed and its claim went stale (kept-for-rescue volumes).
    [[ -e "$(_stack_state_dir "$project")/prewarm-adopted" ]] && continue
    if [[ "${GC_DRY_RUN:-}" == "1" ]]; then
      would_reap=$((would_reap + 1))
      continue
    fi
    # Claim before down: an adoption in flight owns the spare — skip, next gc
    # pass sees either an adopted marker or a stale claim.
    _prewarm_claim "$project" || continue
    if ! docker compose -p "$project" down --volumes --timeout 30; then
      as_error "could not reap the over-age prewarm spare $project — its containers/volumes may survive"
      _prewarm_release "$project"
      rc=1
      continue
    fi
    stack_verify_no_volumes "$project" || rc=1
    _prewarm_release "$project"
  done
  [[ "${GC_DRY_RUN:-}" == "1" ]] && printf 'Would remove: %s over-age prewarm spare(s)\n' "$would_reap"

  # Dead claims: a crashed claimer's mkdir would otherwise pin its spare forever.
  local claim would_release=0
  for claim in "$PREWARM_CLAIM_DIR"/*/; do
    [[ -d "$claim" ]] || continue
    claim="${claim%/}"
    _prewarm_claim_is_stale "${claim##*/}" || continue
    if [[ "${GC_DRY_RUN:-}" == "1" ]]; then
      would_release=$((would_release + 1))
      continue
    fi
    rm -rf "$claim"
  done
  [[ "${GC_DRY_RUN:-}" == "1" ]] && printf 'Would remove: %s stale prewarm claim(s)\n' "$would_release"
  return "$rc"
}

# prewarm_spawn_next SELF WORKLOAD [EXTRA_COMPOSE...] — replenish the pool after a
# `run --prewarm-next`: launch `SELF prewarm WORKLOAD [--extra-compose EXTRA]...`
# fully detached so a fresh spare is ready for the next launch. The pool does NOT
# self-replenish otherwise (an opt-in flag, unlike a per-launch auto-replenish), so
# each --prewarm-next spawns exactly one spare; extras age out via prewarm_gc. The
# spawn is best-effort: a failure to detach must never fail the completed run.
# AGENT_SANDBOX_PREWARM_CMD overrides the launched command (tests point it at a
# recorder); AGENT_SANDBOX_NO_PREWARM=1 disables the spawn entirely.
prewarm_spawn_next() {
  local self="$1" workload="$2"
  shift 2
  [[ -z "${AGENT_SANDBOX_NO_PREWARM:-}" ]] || return 0
  local -a cmd=()
  if [[ -n "${AGENT_SANDBOX_PREWARM_CMD:-}" ]]; then
    # A test-provided recorder command, word-split deliberately, then the workload.
    # shellcheck disable=SC2206
    cmd=(${AGENT_SANDBOX_PREWARM_CMD} "$workload")
  else
    cmd=("$self" prewarm)
    local extra
    for extra in "$@"; do
      cmd+=(--extra-compose "$extra")
    done
    cmd+=("$workload")
  fi
  # Detach so the spare outlives this launcher and a Ctrl-C at the terminal can't
  # cancel a multi-second boot: a new session via setsid where available (Linux),
  # else a nohup background job (macOS has no setsid). stdio to /dev/null so the
  # spawn neither blocks on nor spams the terminal.
  if command -v setsid >/dev/null 2>&1; then
    setsid "${cmd[@]}" </dev/null >/dev/null 2>&1 &
  else
    nohup "${cmd[@]}" </dev/null >/dev/null 2>&1 &
  fi
  disown 2>/dev/null || true # allow-exit-suppress: disown is a shell builtin absent in some subshell contexts; the job is already detached by setsid/nohup
  as_info "prewarm-next: spawned a background spare for the next run"
}

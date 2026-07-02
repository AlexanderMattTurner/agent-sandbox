# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
# prewarm.bash — the warm-start pool's primitives (issue #34): the spec hash that
# decides whether a running spare's bring-up matches a launch, and the claim locks
# that make adopting (or reaping) a spare a single-winner operation. Sourced after
# stack.bash (the gc reaper uses _stack_state_dir/stack_verify_no_volumes).
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
  for extra in "$@"; do
    lines+=("$(_prewarm_sha256 <"$extra")") || return 1
  done
  printf '%s\n' "${lines[@]}" | _prewarm_sha256 | cut -c1-16
}

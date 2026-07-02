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

# stack_export_control_plane_grants WORKLOAD_JSON — validate the Workload's
# control_plane.egress_grants and export CONTROL_PLANE_EGRESS_GRANTS as the compact
# JSON array the firewall renders (compose env passthrough). Every uid must be an
# integer >= 1 (uid 0 would carve out the firewall's own root-owned daemons) and
# every host must be a hostname, never an IP literal — the same doctrine as the
# egress_allowlist IP rejection in bin/agent-sandbox. No grants exports the EMPTY
# STRING (not "[]") so the firewall's render path is a clean no-op.
stack_export_control_plane_grants() {
  local workload="$1" grants
  grants="$(jq -c '.control_plane.egress_grants // []' "$workload")"
  if [[ "$grants" == "[]" ]]; then
    CONTROL_PLANE_EGRESS_GRANTS=""
    export CONTROL_PLANE_EGRESS_GRANTS
    return 0
  fi
  jq -e '[.[] | (.uid | type == "number" and . == floor and . >= 1)] | all' <<<"$grants" >/dev/null || {
    as_error "control_plane.egress_grants: every uid must be an integer >= 1 (a uid-0 grant would carve out the firewall's own root-owned traffic)"
    return 1
  }
  jq -e '[.[] | .hosts | type == "array" and length > 0 and ([.[] | type == "string" and test("^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")] | all)] | all' <<<"$grants" >/dev/null || {
    as_error "control_plane.egress_grants: every entry needs a non-empty hosts list of hostname-shaped strings"
    return 1
  }
  if jq -e '[.[].hosts[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))] | length > 0' <<<"$grants" >/dev/null; then
    as_error "control_plane.egress_grants must name HOSTNAMES, not IPs — grants are resolved by name at the firewall, like the egress allowlist"
    return 1
  fi
  # One entry per uid: the firewall builds each grant's ipset fresh, so a second
  # entry for the same uid would silently wipe the first one's resolved IPs.
  jq -e 'map(.uid) | length == (unique | length)' <<<"$grants" >/dev/null || {
    as_error "control_plane.egress_grants: duplicate uid — merge each uid's hosts into one entry"
    return 1
  }
  CONTROL_PLANE_EGRESS_GRANTS="$grants"
  export CONTROL_PLANE_EGRESS_GRANTS
}

# _stack_wait_control_plane_ready CID WORKLOAD_JSON — block until every consumer
# service named in control_plane.require has published its readiness marker
# (/run/control-plane/<name>.ready on the shared control-plane volume, probed via
# the workload container's read-only mount). Returns 0 immediately when nothing is
# required; polls at 1s up to AGENT_SANDBOX_READY_TIMEOUT seconds (default 60),
# then fails closed naming the missing marker(s) — a workload must never start
# against a control plane the Workload record says it depends on but that isn't up.
_stack_wait_control_plane_ready() {
  local cid="$1" workload="$2" name
  local -a required=()
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    # The name lands in the probed path; a traversal-shaped value from an
    # untrusted workload record must not walk out of /run/control-plane.
    if [[ ! "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
      as_error "control_plane.require name '$name' is not a valid marker name (want [a-z0-9][a-z0-9-]*, the schema's pattern)"
      return 1
    fi
    required+=("$name")
  done < <(jq -r '.control_plane.require // [] | .[]' "$workload")
  ((${#required[@]})) || return 0
  local timeout="${AGENT_SANDBOX_READY_TIMEOUT:-60}"
  # A non-numeric timeout would break the deadline arithmetic and turn the
  # barrier into an unbounded poll — fail loud instead (same doctrine as
  # init-firewall's DNS_BATCH_SIZE guard).
  if [[ ! "$timeout" =~ ^[0-9]+$ ]]; then
    as_error "AGENT_SANDBOX_READY_TIMEOUT must be a whole number of seconds, got '$timeout'"
    return 1
  fi
  local deadline=$((SECONDS + timeout))
  local -a missing=()
  while true; do
    missing=()
    for name in "${required[@]}"; do
      if ! docker exec "$cid" test -f "/run/control-plane/$name.ready"; then
        missing+=("$name")
      fi
    done
    ((${#missing[@]} == 0)) && return 0
    ((SECONDS >= deadline)) && break
    sleep 1
  done
  as_error "control-plane readiness timed out after ${timeout}s — missing marker(s): ${missing[*]} (each required service must create /run/control-plane/<name>.ready on the shared volume)"
  return 1
}

# _stack_state_root — the library's own host state base dir (per-session dirs live
# under it). The one place the AGENT_SANDBOX_STATE_DIR/XDG default chain is spelled.
_stack_state_root() {
  printf '%s' "${AGENT_SANDBOX_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agent-sandbox}"
}

# _stack_state_dir PROJECT — this session's owner-only host dir for the artifacts
# that outlive the containers: the WIP patch, the agent's mbox, the egress log.
_stack_state_dir() {
  printf '%s/sessions/%s' "$(_stack_state_root)" "$1"
}

# stack_validate_workspace_mount WORKLOAD_JSON — fail-closed pre-launch validation of
# the bind-mode workspace source (called by the launcher before anything comes up).
# Refuses: a non-absolute path (compose resolves a relative bind against the compose
# FILE's directory, not the caller's $PWD — a silent foot-gun); a symlinked source,
# dangling included (the bind would mount the TARGET, so the record's path and the
# mounted path diverge — and a dangling one would surface as a confusing failure at
# `up`); a missing or non-directory source (Docker would fabricate a root-owned dir at
# that host path); and a source resolving to or under the library's own state root
# (the workload could then rewrite session artifacts: the egress log copy, WIP patches).
stack_validate_workspace_mount() {
  local workload="$1" src resolved state_root
  src="$(jq -r '.workspace_mount // empty' "$workload")"
  # Strip trailing slashes first: `[[ -L "/path/link/" ]]` is FALSE for a symlink
  # written with a trailing slash, which would slip it past the refusal below.
  while [[ "$src" == */ && "$src" != "/" ]]; do src="${src%/}"; done
  [[ "$src" == /* ]] || {
    as_error "workspace_mount must be an absolute host path (got '$src') — compose resolves a relative bind against the compose file's directory, not your working directory"
    return 1
  }
  # Deliberately final-component-only: a symlinked PARENT (/alias/project) is
  # tolerated because the containment check below runs on the fully-resolved
  # pwd -P path, so it cannot be used to sneak inside the state root.
  [[ ! -L "$src" ]] || {
    as_error "workspace_mount '$src' is a symlink — the bind would mount its target, so the record's path and the mounted path diverge; bind the resolved directory itself"
    return 1
  }
  [[ -d "$src" ]] || {
    as_error "workspace_mount '$src' does not exist or is not a directory — Docker would fabricate a root-owned directory at that host path; create the directory first"
    return 1
  }
  resolved="$(cd "$src" && pwd -P)" || {
    as_error "could not resolve workspace_mount '$src' (cd/pwd failed — check its permissions)"
    return 1
  }
  state_root="$(_stack_state_root)"
  # Compare resolved-to-resolved: the state root may not exist yet (first run), in
  # which case nothing can resolve under it and the literal path is the right compare.
  if [[ -d "$state_root" ]]; then
    state_root="$(cd "$state_root" && pwd -P)" || {
      as_error "could not resolve the state dir '$state_root'"
      return 1
    }
  fi
  if [[ "$resolved" == "$state_root" || "$resolved" == "$state_root"/* ]]; then
    as_error "workspace_mount '$src' resolves inside the library's own state dir ($state_root) — the workload could rewrite session artifacts (egress log, WIP patches); bind a directory outside it"
    return 1
  fi
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
# override carrying the part of the Workload record a static file can't: (host-mode)
# its workspace bind, which replaces the named volume by target-path merge, and (when
# secret_env is declared) the /run/secrets tmpfs the secret files are streamed into
# post-create (_stack_deliver_secrets). The env map does NOT ride here — it is
# delivered via a 0600 up-only env-file (_stack_write_env_delivery) — and neither do
# the secret_env VALUES (only the value-free tmpfs declaration does), so secrets never
# persist in this on-disk override. JSON is valid YAML, so compose consumes it
# directly. With neither field the workload object is `{}`, a valid no-op override.
_stack_write_override() {
  local workload="$1" out="$2"
  # `$` → `$$`: compose runs variable interpolation over every file it loads, so a
  # literal dollar in a mount path must be escaped or it would be expanded against
  # the LAUNCHER's environment.
  jq '{
    services: {
      workload: ((if .workspace_mount
                  then {volumes: [{type: "bind", source: (.workspace_mount | gsub("\\$"; "$$")), target: "/workspace"}]}
                  else {} end)
                 + (if ((.secret_env // {}) | length) > 0
                    then {tmpfs: ["/run/secrets:mode=0755,size=1m"]}
                    else {} end))
    }
  }' "$workload" >"$out"
}

# _stack_deliver_secrets WORKLOAD_JSON CID USER — stream each secret_env value into
# /run/secrets/<name> on the workload container's tmpfs (mode 0400, chowned to the
# workload user) over the exec's STDIN — never argv, never container env, never the
# host state dir — so no secret byte is visible to `docker inspect` or ever touches
# host disk. jq -j delivers the value byte-exact (newlines allowed). The tmpfs dies
# with the container, so teardown removes the material by construction. Fail-closed:
# any failed delivery refuses the session. Keys are read by INDEX (like stack_run's
# entrypoint argv), never by iterating a newline-joined key list — a line-based read
# would silently deliver zero secrets when the producing jq fails, and would split a
# newline-carrying key into bogus names.
_stack_deliver_secrets() {
  local workload="$1" cid="$2" user="$3" name n i
  # POSIX sh, not bash: the workload image is arbitrary and may not carry bash.
  # $1 (name) and $2 (user) ride argv; the secret VALUE rides stdin only.
  # shellcheck disable=SC2016 # single quotes are the point: $1/$2 expand in the container's sh, never here
  local deliver='umask 377 && cat >"/run/secrets/$1" && chown -- "$2" "/run/secrets/$1"'
  # Defense in depth below the launcher gate: stack_run is the documented library
  # entry point, and an unshaped record must never become a zero-delivery success
  # (a non-object dies in `keys`, leaving n="" and a 0-iteration loop) or a
  # root-privileged write at a path of the record's choosing (an unshaped name —
  # checked in jq, not bash, because command substitution strips the trailing
  # newline a "NAME\n" key smuggles past a post-substitution [[ =~ ]] test).
  jq -e '.secret_env | type == "object" and ([.[] | type == "string"] | all) and (keys | all(test("\\A[A-Za-z_][A-Za-z0-9_]*\\z")))' "$workload" >/dev/null || {
    as_error "secret_env must be a name -> value object of string values with env-var-shaped names — refusing delivery"
    return 1
  }
  n="$(jq '.secret_env | keys | length' "$workload")"
  for ((i = 0; i < n; i++)); do
    name="$(jq -r "(.secret_env | keys)[$i]" "$workload")"
    jq -je --arg k "$name" '.secret_env[$k]' "$workload" | docker exec -i -u root "$cid" sh -c "$deliver" _ "$name" "$user" || {
      as_error "could not deliver secret '$name' into the sandbox"
      return 1
    }
  done
}

# _stack_write_env_delivery WORKLOAD_JSON ENVFILE OVERRIDE — stage the workload's env
# map for delivery to the container WITHOUT persisting it in the session override:
# write a 0600 KEY=VALUE env-file and an up-only compose override that references it
# via `env_file`. The caller passes the override to `up` only, then unlinks the
# env-file, so the secrets live on disk just long enough for compose to bake them into
# the container. env-file is line-based, so a value containing a newline (which would
# corrupt the file / split into bogus KEY lines) is refused loudly.
_stack_write_env_delivery() {
  local workload="$1" envfile="$2" override="$3"
  if jq -e '[(.env // {})[] | select(contains("\n"))] | length > 0' "$workload" >/dev/null; then
    as_error "workload.env values must be single-line (a value contains a newline); env is delivered via a line-based env-file"
    return 1
  fi
  # env-file values are literal (compose does no interpolation over env_file), so —
  # unlike the compose override above — no `$` escaping is applied.
  (umask 077 && jq -r '(.env // {}) | to_entries[] | "\(.key)=\(.value)"' "$workload" >"$envfile") || return 1
  jq -n --arg ef "$envfile" '{services: {workload: {env_file: [$ef]}}}' >"$override"
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

# _stack_write_manifest STATE PROJECT SESSION_ID MODE SEED_REF BASE_COMMIT BASE_REF
# REVIEW_BRANCH REPO_ROOT — record the session's identity and seed provenance in
# $STATE/session.json (owner-only). This is what a later `run` re-attaches or resumes
# FROM: the extract base (base_ref/base_commit), the review branch, and the repo the
# branch lives in all outlive the launcher process here. An empty SESSION_ID is stored
# as null (the session is only pinned by AGENT_SANDBOX_PROJECT_NAME).
_stack_write_manifest() {
  local state="$1" project="$2" session_id="$3" mode="$4" seed_ref="$5"
  local base_commit="$6" base_ref="$7" review_branch="$8" repo_root="$9"
  if ! (umask 077 && jq -n --arg project "$project" --arg session_id "$session_id" --arg mode "$mode" --arg seed_ref "$seed_ref" --arg base_commit "$base_commit" --arg base_ref "$base_ref" --arg review_branch "$review_branch" --arg repo_root "$repo_root" --arg created "$(date -u +%FT%TZ)" '{project: $project, session_id: (if $session_id == "" then null else $session_id end), mode: $mode, seed_ref: $seed_ref, base_commit: $base_commit, base_ref: $base_ref, review_branch: $review_branch, repo_root: $repo_root, created: $created}' >"$state/session.json"); then
    as_error "could not write the session manifest $state/session.json"
    return 1
  fi
}

# _stack_read_manifest_field STATE FIELD — print one manifest field; non-zero when the
# manifest or the field is absent, so callers fail loud instead of trusting "".
_stack_read_manifest_field() {
  local state="$1" field="$2"
  jq -er --arg f "$field" '.[$f] // empty' "$state/session.json" 2>/dev/null
}

# _stack_update_manifest STATE LAST_EXIT EXTRACTED — record the session's outcome in the
# manifest at teardown. Warn-loud, non-blocking bookkeeping: a failed update must never
# mask the session's real status. No-op when no manifest exists (unseeded session).
_stack_update_manifest() {
  local state="$1" last_exit="$2" extracted="$3"
  local tmp="$state/session.json.tmp"
  [[ -f "$state/session.json" ]] || return 0
  if ! (umask 077 && jq --argjson last_exit "$last_exit" --argjson extracted "$extracted" '. + {last_exit: $last_exit, extracted: $extracted}' "$state/session.json" >"$tmp") || ! mv "$tmp" "$state/session.json"; then
    as_warn "could not update the session manifest $state/session.json"
    return 1
  fi
}

# _stack_export_audit_log PROJECT COMPOSE OVERRIDE OVERMOUNTS STATE_DIR — copy the audit
# sink's chained log AND its per-session HMAC secret out of the audit container before
# teardown (the _stack_export_egress_log twin): a later resume mounts the exported log
# read-only beside the new sink's, and the exported secret keeps the prior chain
# verifiable. Owner-only on the host (docker cp preserves the source mode, so chmod is
# explicit). Warn-loud on failure but never block teardown.
_stack_export_audit_log() {
  local project="$1" compose="$2" override="$3" overmounts="$4" state="$5" audit_cid
  audit_cid="$(_stack_compose "$project" "$compose" "$override" "$overmounts" ps -q audit)"
  if [[ -z "$audit_cid" ]] ||
    ! docker cp "$audit_cid:/var/log/agent-sandbox/audit.jsonl" "$state/audit.jsonl" >/dev/null 2>&1 ||
    ! docker cp "$audit_cid:/run/audit-secret/secret" "$state/audit.secret" >/dev/null 2>&1 ||
    ! chmod 600 "$state/audit.jsonl" "$state/audit.secret" 2>/dev/null; then
    as_warn "could not export the audit log + HMAC secret from the audit container — this session's audit chain has no host copy (a later resume cannot mount it)"
    return 1
  fi
  as_info "audit log: $state/audit.jsonl"
}

# _stack_write_audit_prior_override PRIOR_LOG OUT — generate the compose override that
# binds a prior session's exported audit log read-only at audit.prior.jsonl inside the
# NEW session's audit container, beside the fresh sink's own log. `$` → `$$` because
# compose interpolates every file it loads (same escaping as _stack_write_override).
_stack_write_audit_prior_override() {
  local prior_log="$1" out="$2"
  jq -n --arg src "$prior_log" '{services: {audit: {volumes: [{type: "bind", source: ($src | gsub("\\$"; "$$")), target: "/var/log/agent-sandbox/audit.prior.jsonl", read_only: true}]}}}' >"$out"
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
  local sandbox_dir project state session_id resume_from
  sandbox_dir="$(cd "$(dirname "$compose")" && pwd)"
  session_id="$(jq -r '.session_id // empty' "$workload")"
  resume_from="$(jq -r '.resume_from // empty' "$workload")"
  # One identity per session: the workload's session_id and the consumer env override
  # both name the compose project, and a silent precedence rule would let lifecycle
  # tooling target a different stack than the one that booted.
  if [[ -n "$session_id" && -n "${AGENT_SANDBOX_PROJECT_NAME:-}" ]]; then
    as_error "workload.session_id ('$session_id') and AGENT_SANDBOX_PROJECT_NAME ('$AGENT_SANDBOX_PROJECT_NAME') are both set — a session has exactly one identity; drop one"
    return 1
  fi
  if [[ -n "$session_id" ]]; then
    project="agent-sandbox-$session_id"
  else
    project="${AGENT_SANDBOX_PROJECT_NAME:-agent-sandbox-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')}"
  fi
  state="$(_stack_state_dir "$project")"
  worktree_secure_mkdir "$state" || return 1

  WORKLOAD_IMAGE="$(jq -r '.image' "$workload")"
  WORKLOAD_USER="$(jq -r '.user // "1000"' "$workload")"
  WORKLOAD_RUNTIME="$runtime"
  WORKLOAD_IP="${SANDBOX_IP%.*}.3"
  export WORKLOAD_IMAGE WORKLOAD_USER WORKLOAD_RUNTIME WORKLOAD_IP
  # The seed/extract execs must run as the same user the workload writes as.
  export AGENT_SANDBOX_WORKLOAD_USER="$WORKLOAD_USER"

  # tty is a runtime precondition, not a file field: an interactive entrypoint needs a
  # real terminal on the launcher's stdin. Check it BEFORE bringing anything up so we
  # fail fast instead of tearing down a healthy stack we could never attach to.
  local want_tty=false
  if [[ "$(jq -r '.tty // false' "$workload")" == "true" ]]; then
    [[ -t 0 ]] || {
      as_error "workload.tty is true but the launcher's stdin is not a TTY — run agent-sandbox from an interactive terminal, or set tty:false"
      return 1
    }
    want_tty=true
  fi

  stack_partition_allowlist "$workload"
  # Grants must be validated and exported BEFORE `up`: compose passes
  # CONTROL_PLANE_EGRESS_GRANTS through to the firewall service's environment,
  # and a malformed grant refuses the launch before anything comes up.
  stack_export_control_plane_grants "$workload" || return 1
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

  # A deterministic identity (session_id, or a pinned AGENT_SANDBOX_PROJECT_NAME) can
  # name an EXISTING stack, so probe before `up`: a running session is refused (never
  # disturb it), a stopped persistent one is re-attached (compose `up` under the same
  # project recreates the containers onto the kept volumes) with seeding skipped. The
  # probe covers containers AND volumes — a persistent teardown removes the containers
  # but keeps the volumes, so volumes alone mean "stopped session".
  local reattach=0
  if [[ -n "$session_id" || -n "${AGENT_SANDBOX_PROJECT_NAME:-}" ]]; then
    if [[ -n "$(docker ps -q --filter "label=com.docker.compose.project=$project")" ]]; then
      as_error "session $project is already running — use expand/down (or wait for it to exit) instead of launching it again"
      return 1
    fi
    if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" || -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ]]; then
      if [[ -n "$resume_from" ]]; then
        as_error "resume_from needs a FRESH session, but project $project already has containers or volumes — pick a new session_id, or take the old stack down (agent-sandbox down $project)"
        return 1
      fi
      if [[ "$ephemeral" == "true" ]]; then
        as_error "project $project has a stopped persistent stack but this workload is ephemeral:true — re-attach needs ephemeral:false (or take the stack down first: agent-sandbox down $project)"
        return 1
      fi
      reattach=1
      as_info "re-attaching to the stopped session $project (kept volumes; seeding skipped)"
    fi
  fi

  # Resume: resolve the prior session's manifest and exported artifacts BEFORE `up`,
  # so its audit log can ride into the compose file set as a read-only bind.
  local prior_state="" prior_base_commit="" prior_review_branch=""
  if [[ -n "$resume_from" ]]; then
    prior_state="$(_stack_state_dir "agent-sandbox-$resume_from")"
    if [[ ! -f "$prior_state/session.json" ]]; then
      as_error "nothing to resume: no session manifest at $prior_state/session.json (did session '$resume_from' run with session_id set and reach its seed?)"
      return 1
    fi
    if ! prior_base_commit="$(_stack_read_manifest_field "$prior_state" base_commit)" ||
      ! prior_review_branch="$(_stack_read_manifest_field "$prior_state" review_branch)"; then
      as_error "the prior session's manifest $prior_state/session.json is missing base_commit/review_branch — cannot resume from it"
      return 1
    fi
    if [[ "$(jq -r '.seed_from_git.review_branch' "$workload")" == "$prior_review_branch" ]]; then
      as_error "seed_from_git.review_branch must differ from the prior session's ('$prior_review_branch') — a resumed session extracts onto its own review branch"
      return 1
    fi
    if [[ ",${COMPOSE_PROFILES}," == *,audit,* ]]; then
      # -f, not -s: a quiet prior session legitimately exported an EMPTY chain,
      # and continuity means mounting whatever record exists.
      if [[ -f "$prior_state/audit.jsonl" ]]; then
        local audit_prior_override="$state/audit-prior-override.json"
        _stack_write_audit_prior_override "$prior_state/audit.jsonl" "$audit_prior_override" || {
          as_error "could not generate the prior-audit-log compose override"
          return 1
        }
        _STACK_EXTRA_COMPOSE+=("$audit_prior_override")
        as_info "audit continuity: the prior session's log rides read-only at /var/log/agent-sandbox/audit.prior.jsonl"
      else
        as_warn "the prior session exported no audit log ($prior_state/audit.jsonl) — audit.prior.jsonl will not be mounted"
      fi
    fi
  fi

  # env delivery: a 0600 env-file consumed ONLY by `up` (staged as an up-only
  # override appended last to the compose file set), then unlinked once the container
  # is created — so the workload's env never persists in the on-disk override.
  # Empty env → no file, no override. env values remain visible on the live container
  # via `docker inspect`; credentials belong in secret_env (file-delivered, invisible
  # to inspect — _stack_deliver_secrets below).
  local env_file="" env_override="" env_idx=-1
  if [[ "$(jq '(.env // {}) | length' "$workload")" -gt 0 ]]; then
    env_file="$state/workload.env"
    env_override="$state/workload-env-override.json"
    _stack_write_env_delivery "$workload" "$env_file" "$env_override" || {
      as_error "could not prepare the workload env-file"
      return 1
    }
    env_idx=${#_STACK_EXTRA_COMPOSE[@]}
    _STACK_EXTRA_COMPOSE+=("$env_override")
  fi

  as_info "compose: bringing up firewall + workload (project $project)"
  if ! _stack_compose "$project" "$compose" "$override" "$overmounts" up -d --wait --wait-timeout 240; then
    as_error "the firewall+workload compose stack did not come up healthy — firewall logs follow"
    _stack_compose "$project" "$compose" "$override" "$overmounts" logs firewall >&2 || true           # allow-exit-suppress: best-effort diagnostics on an already-failed launch
    _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup of a stack that never came up healthy; the launch already failed loudly
    [[ -n "$env_file" ]] && rm -f "$env_file"                                                          # never leave the secret env-file on disk, even on a failed launch
    return 1
  fi
  local cid
  cid="$(_stack_compose "$project" "$compose" "$override" "$overmounts" ps -q workload)"
  if [[ -z "$cid" ]]; then
    as_error "the workload container did not start (compose project $project)"
    _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
    [[ -n "$env_file" ]] && rm -f "$env_file"                                                          # never leave the secret env-file on disk
    return 1
  fi

  # Container created — its env is baked in. Drop the up-only env override so no later
  # compose call (ps/logs/down) references it, and unlink the secret env-file now.
  if [[ -n "$env_file" ]]; then
    [[ "$env_idx" -ge 0 ]] && unset "_STACK_EXTRA_COMPOSE[$env_idx]"
    rm -f "$env_file" "$env_override"
  fi

  # Stream secret_env files into the container's /run/secrets tmpfs BEFORE anything
  # else runs in it (the entrypoint idles), so the workload always sees its secrets.
  if [[ "$(jq '(.secret_env // {}) | length' "$workload")" -gt 0 ]]; then
    if ! _stack_deliver_secrets "$workload" "$cid" "$WORKLOAD_USER"; then
      as_error "secret delivery failed — refusing to hand over the sandbox"
      _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup of a stack refused at secret delivery; the launch already failed loudly
      return 1
    fi
  fi

  # Fail-closed guardrail gate (BIND MODE only): bind mode has no review-branch
  # quarantine — the read-only overmounts are the ONLY kernel-enforced guard between the
  # workload and the host checkout — so this block ALWAYS runs when workspace_mount is
  # set. Seed mode has no host ro-binds (workspace is a named volume) and its writes are
  # gated by the review-branch extract, so it is not probed. Runs before seeding/exec so
  # a guardrail that isn't actually read-only never gets a chance to be bypassed.
  if jq -e '.workspace_mount' "$workload" >/dev/null 2>&1; then
    # A declared path missing under the host workspace gets NO bind at all. An EXPLICIT
    # overmount_paths declaration is the consumer stating a security requirement, so a
    # missing explicit path refuses the launch; a missing DEFAULT path only warns (most
    # checkouts ship without e.g. node_modules, and the default must stay launchable).
    local _rel _missing_out
    local -a _missing=()
    if ! _missing_out="$(overmount_missing_declared_paths "$workload")"; then
      as_error "could not resolve the workload's overmount paths — refusing to hand over the sandbox"
      _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup of a stack refused at the guardrail gate; the launch already failed loudly
      return 1
    fi
    while IFS= read -r _rel; do
      [[ -n "$_rel" ]] && _missing+=("$_rel")
    done <<<"$_missing_out"
    if ((${#_missing[@]})); then
      if jq -e 'has("overmount_paths")' "$workload" >/dev/null; then
        as_error "explicitly declared overmount_paths do not exist under the host workspace, so NO read-only bind would protect them: ${_missing[*]} — create them on the host or drop them from overmount_paths"
        _stack_compose "$project" "$compose" "$override" "$overmounts" down --volumes --timeout 30 || true # allow-exit-suppress: best-effort cleanup of a stack refused at the guardrail gate; the launch already failed loudly
        return 1
      fi
      for _rel in "${_missing[@]}"; do
        as_warn "default guardrail path '$_rel' does not exist under the host workspace — it is NOT mounted read-only this session"
      done
    fi
    local -a _cpaths=()
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
    else
      # Non-vacuous marker: bind mode ran the gate and found NOTHING to hold read-only —
      # the workload can write anywhere under /workspace, directly onto the host.
      as_info "bind mode: no overmount guardrails apply — nothing under /workspace is mounted read-only this session"
    fi
  fi

  # Control-plane readiness barrier, BEFORE seeding: a consumer gate that never
  # comes up must fail the launch while there is still nothing to lose — no
  # seeded work, no running entrypoint the consumer believed was supervised.
  if ! _stack_wait_control_plane_ready "$cid" "$workload"; then
    _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
    return 1
  fi

  # Seed the workspace from git BEFORE the entrypoint runs, so the workload never
  # sees a half-seeded tree. A cold-seed failure keeps nothing (no work exists yet,
  # so tear the stack down and refuse); a RE-ATTACH failure instead stops the
  # containers but KEEPS the volumes — they hold a prior leg's work.
  local seeded=0 base_ref="" base_commit="" review_branch="" repo_root="" wip_patch="" seed_ref=""
  if jq -e '.seed_from_git' "$workload" >/dev/null; then
    seed_ref="$(jq -r '.seed_from_git.ref' "$workload")"
    review_branch="$(jq -r '.seed_from_git.review_branch' "$workload")"
    wip_patch="$state/wip.patch"
    if [[ "$reattach" == 1 ]]; then
      # Trust the manifest + an in-container probe; the only destructive path is the
      # explicit --reseed flag.
      local manifest_mode
      manifest_mode="$(_stack_read_manifest_field "$state" mode)" || manifest_mode=""
      if [[ "$manifest_mode" != "seed" ]] ||
        ! docker exec -u "$WORKLOAD_USER" "$cid" test -d /workspace/.git; then
        as_error "re-attach: $project's manifest/workspace is not a seeded session (manifest mode '${manifest_mode:-absent}') — take the stack down (agent-sandbox down $project) and start fresh"
        _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || true # allow-exit-suppress: best-effort stop of a stack refused at re-attach; volumes are deliberately kept
        return 1
      fi
      if ! base_commit="$(_stack_read_manifest_field "$state" base_commit)" ||
        ! review_branch="$(_stack_read_manifest_field "$state" review_branch)" ||
        ! repo_root="$(_stack_read_manifest_field "$state" repo_root)"; then
        as_error "re-attach: the session manifest $state/session.json is missing base_commit/review_branch/repo_root — cannot extract this leg's work; take the stack down and start fresh"
        _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || true # allow-exit-suppress: best-effort stop of a stack refused at re-attach; volumes are deliberately kept
        return 1
      fi
      if [[ "${AGENT_SANDBOX_RESEED:-0}" == 1 ]]; then
        as_warn "--reseed: discarding $project's seeded workspace and re-seeding from the current checkout"
        if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
          as_error "--reseed needs to run from inside a git checkout (no repo at $PWD)"
          _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || true # allow-exit-suppress: best-effort stop of a stack refused at re-seed; volumes are deliberately kept
          return 1
        fi
        base_commit="$(git -C "$repo_root" rev-parse HEAD)"
        if ! (umask 077 && worktree_capture_wip_patch "$repo_root" >"$wip_patch") ||
          ! worktree_seed_tar "$repo_root" | worktree_reseed_container "$cid" ||
          ! base_ref="$(worktree_container_init_repo "$cid" "$review_branch")" ||
          ! worktree_stamp_seed_fingerprint "$cid" "$repo_root" ||
          ! _stack_write_manifest "$state" "$project" "$session_id" "seed" "HEAD" "$base_commit" "$base_ref" "$review_branch" "$repo_root"; then
          as_error "could not re-seed the workspace"
          _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || true # allow-exit-suppress: best-effort stop of a stack refused mid-re-seed; volumes are deliberately kept
          return 1
        fi
        as_info "workspace re-seeded from $repo_root (HEAD + uncommitted delta); review branch: $review_branch"
      else
        if [[ "$(_stack_read_manifest_field "$state" seed_ref)" == "HEAD" ]] &&
          ! worktree_seed_fingerprint_matches "$cid" "$repo_root"; then
          as_warn "the re-attached workspace was seeded from an older state of $repo_root — continuing with the session's tree as-is; pass --reseed to discard it and re-seed from your current checkout"
        fi
        # The extract below assumes the prior legs' work is already on the host
        # review branch; if the user deleted it (e.g. after merging), a rebuilt
        # branch would start from leg 1's launch state and this leg's patches
        # would misapply — refuse with the remedy instead.
        if ! git -C "$repo_root" show-ref --verify --quiet "refs/heads/$review_branch"; then
          as_error "re-attach: review branch '$review_branch' no longer exists in $repo_root (deleted after a merge?) — the session's prior work cannot extract onto it; pass --reseed to discard the in-container tree and start this session fresh"
          _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || true # allow-exit-suppress: best-effort stop of a stack refused at re-attach; volumes are deliberately kept
          return 1
        fi
        # This leg extracts only ITS OWN commits: the extract base is the container's
        # current HEAD — the prior legs' work is already on the review branch.
        if ! base_ref="$(worktree_container_seed_head "$cid")"; then
          as_error "re-attach: could not read the workspace repo HEAD"
          _stack_compose "$project" "$compose" "$override" "$overmounts" down --timeout 30 || true # allow-exit-suppress: best-effort stop of a stack refused at re-attach; volumes are deliberately kept
          return 1
        fi
      fi
    else
      if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
        as_error "seed_from_git needs to run from inside a git checkout (no repo at $PWD)"
        _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
        return 1
      fi
      if [[ -n "$resume_from" ]]; then
        # Resume: seed the prior session's recorded base commit, then replay its
        # review branch on top — the workload's seed_from_git.ref is deliberately
        # ignored (the prior manifest is the provenance).
        as_info "resume: seeding from session '$resume_from' (base $prior_base_commit); seed_from_git.ref '$seed_ref' is ignored on resume"
        if ! git -C "$repo_root" rev-parse --verify --quiet "$prior_base_commit^{commit}" >/dev/null; then
          as_error "the prior session's base commit $prior_base_commit is not in $repo_root — cannot resume"
          _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
          return 1
        fi
        local resume_mbox="$state/resume.mbox"
        if ! (umask 077 && : >"$wip_patch") ||
          ! (umask 077 && git -C "$repo_root" format-patch --stdout --binary "$prior_base_commit..$prior_review_branch" >"$resume_mbox") ||
          ! worktree_seed_tar_ref "$repo_root" "$prior_base_commit" | worktree_seed_into_container "$cid" ||
          ! base_ref="$(worktree_container_init_repo "$cid" "$review_branch")"; then
          as_error "could not seed the resumed workspace into the sandbox"
          _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
          return 1
        fi
        base_commit="$prior_base_commit"
        if [[ -s "$resume_mbox" ]]; then
          # The new session's extract must branch the host review branch from the
          # prior work's tip — patches formatted against the post-replay tree only
          # apply there. A tip that is the extract's uncommitted-changes fold is
          # soft-reset back into an UNCOMMITTED overlay (and the host base steps to
          # its parent), so the agent resumes with it uncommitted, as it was left.
          if ! worktree_container_apply_mbox "$cid" <"$resume_mbox"; then
            _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
            return 1
          fi
          base_commit="$(git -C "$repo_root" rev-parse "$prior_review_branch")"
          if worktree_tip_is_wip_fold "$repo_root" "$prior_review_branch"; then
            if ! worktree_container_soft_reset_tip "$cid"; then
              _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
              return 1
            fi
            base_commit="$(git -C "$repo_root" rev-parse "$prior_review_branch~1")"
          fi
          if ! base_ref="$(worktree_container_seed_head "$cid")"; then
            as_error "resume: could not read the post-replay workspace HEAD"
            _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
            return 1
          fi
        fi
        # The manifest records the ACTUAL seed provenance (the prior base commit),
        # not the ignored workload ref — so a later re-attach of this session never
        # runs the HEAD-only staleness check against a seed that wasn't HEAD.
        seed_ref="$prior_base_commit"
        as_info "workspace resumed from session '$resume_from' ($prior_review_branch replayed); review branch: $review_branch"
      elif [[ "$seed_ref" == "HEAD" ]]; then
        base_commit="$(git -C "$repo_root" rev-parse HEAD)"
        if ! (umask 077 && worktree_capture_wip_patch "$repo_root" >"$wip_patch") ||
          ! worktree_seed_tar "$repo_root" | worktree_seed_into_container "$cid" ||
          ! base_ref="$(worktree_container_init_repo "$cid" "$review_branch")" ||
          ! worktree_stamp_seed_fingerprint "$cid" "$repo_root"; then
          as_error "could not seed the workspace into the sandbox"
          _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
          return 1
        fi
        as_info "workspace seeded from $repo_root (HEAD + uncommitted delta); review branch: $review_branch"
      else
        # An arbitrary committed ref: seed its committed tree only; the wip patch is
        # written EMPTY (its emptiness means "nothing uncommitted" downstream).
        if ! base_commit="$(git -C "$repo_root" rev-parse --verify --quiet "$seed_ref^{commit}")"; then
          as_error "seed_from_git.ref '$seed_ref' does not resolve to a commit in $repo_root"
          _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
          return 1
        fi
        if ! (umask 077 && : >"$wip_patch") ||
          ! worktree_seed_tar_ref "$repo_root" "$base_commit" | worktree_seed_into_container "$cid" ||
          ! base_ref="$(worktree_container_init_repo "$cid" "$review_branch")"; then
          as_error "could not seed the workspace into the sandbox"
          _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
          return 1
        fi
        as_info "workspace seeded from $seed_ref ($base_commit, committed tree only); review branch: $review_branch"
      fi
      _stack_write_manifest "$state" "$project" "$session_id" "seed" "$seed_ref" "$base_commit" "$base_ref" "$review_branch" "$repo_root" || {
        _stack_down_ephemeral "$project" "$compose" "$override" "$overmounts" || true # allow-exit-suppress: best-effort cleanup; the launch already failed loudly
        return 1
      }
    fi
    seeded=1
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
  local -a exec_flags=(-u "$WORKLOAD_USER" -w /workspace)
  # tty:true attaches an interactive terminal (validated against a real stdin at the
  # top of stack_run); the default is a plain non-interactive exec.
  [[ "$want_tty" == true ]] && exec_flags+=(-it)
  local workload_rc=0
  docker exec "${exec_flags[@]}" "$cid" "${argv[@]}" || workload_rc=$?
  if [[ "$workload_rc" -ne 0 ]]; then
    as_warn "workload exited with status $workload_rc"
  fi

  # Extract BEFORE teardown — mandatory. A failed extract keeps the containers
  # and volumes so the workload's commits are never destroyed with them.
  if [[ "$seeded" == 1 ]]; then
    local wt_dir="$state/review-worktree" agent_mbox="$state/agent.mbox"
    if ! worktree_extract_to_host "$cid" "$base_ref" "$repo_root" "$base_commit" \
      "$review_branch" "$wt_dir" "$wip_patch" "$agent_mbox"; then
      _stack_update_manifest "$state" "$workload_rc" false || true # allow-exit-suppress: manifest bookkeeping already warns; it must not mask the extract failure
      as_error "extract failed — keeping the session's containers and volumes (compose project $project) so the workload's work is not lost"
      return 1
    fi
    # The branch is the deliverable; the worktree directory was only the replay
    # surface. A failed remove is loud but non-fatal (the branch already exists).
    git -C "$repo_root" worktree remove "$wt_dir" 2>/dev/null ||
      as_warn "could not remove the scratch worktree $wt_dir (branch $review_branch is intact)"
    worktree_print_merge_hint "$review_branch" "$([[ "$ephemeral" == "true" ]] && echo 0 || echo 1)"
  fi

  _stack_export_egress_log "$project" "$compose" "$override" "$overmounts" "$state" || true # allow-exit-suppress: the export already warned loudly; a lost audit copy must not block teardown of an otherwise-complete session
  if [[ ",${COMPOSE_PROFILES}," == *,audit,* ]]; then
    _stack_export_audit_log "$project" "$compose" "$override" "$overmounts" "$state" || true # allow-exit-suppress: the export already warned loudly; a lost audit copy must not block teardown of an otherwise-complete session
  fi
  local extracted=false
  [[ "$seeded" == 1 ]] && extracted=true
  _stack_update_manifest "$state" "$workload_rc" "$extracted" || true # allow-exit-suppress: manifest bookkeeping already warns; it must not block teardown

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

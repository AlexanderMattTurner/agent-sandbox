# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
# backend.bash — the runtime backend seam. A backend turns a Workload into a running,
# isolated container. 'local' runs the Kata->gVisor->runc auto-downgrade ladder on the
# local Docker engine; 'hosted' (a managed remote sandbox) is a documented interface
# stub. The name-level egress allowlist is enforced at the forward proxy and the proxy
# log IS the egress log — that invariant is backend-independent and lives in the
# firewall stack, NOT here; no backend may weaken it (e.g. an IP allowlist).
_AS_BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=runtime-detect.bash disable=SC1091
source "$_AS_BACKEND_DIR/runtime-detect.bash"
# shellcheck source=msg.bash disable=SC1091
source "$_AS_BACKEND_DIR/msg.bash"
unset _AS_BACKEND_DIR

# backend_select_runtime BACKEND — print the runtime the workload will launch under,
# failing closed if the backend cannot honor it. Dispatches on the Workload's backend.
backend_select_runtime() {
  local backend="${1:-local}"
  case "$backend" in
  local) _local_backend_select_runtime ;;
  hosted)
    as_error "backend 'hosted' is not implemented — the managed remote-sandbox backend is a documented interface stub. Every backend must still enforce the allowlist at a forward proxy and keep the proxy log as the egress log. Use backend=local."
    return 1
    ;;
  *)
    as_error "unknown backend '$backend' (expected: local or hosted)"
    return 1
    ;;
  esac
}

# _local_backend_select_runtime — run the auto-downgrade ladder and refuse a runtime
# that isn't usable BEFORE anything is launched, so a broken backend fails loudly
# instead of hanging on a healthcheck that can never pass. Three fail-closed gates,
# skipped only for runc (Docker's built-in default, always present):
#   1. registration — the runtime appears in `docker info` (else compose can't use it);
#   2. provider     — refuse a hardened runtime on Docker Desktop, which hangs it;
#   3. execution    — a throwaway container actually starts under it (a listed runtime
#                     whose binary is missing/broken surfaces here, not deep in `up`).
# Prints the verified runtime on success.
_local_backend_select_runtime() {
  local rt
  rt="$(detect_container_runtime)"
  if [[ "$rt" != runc ]]; then
    wait_for_docker_runtime "$rt" 5 ||
      { as_error "container runtime '$rt' is not registered with Docker — refusing to launch (fail closed) rather than hang on healthchecks"; return 1; }
    docker_runtime_works "$rt" ||
      { as_error "Docker Desktop + '$rt' is known to hang workloads — refusing to launch"; return 1; }
    docker_runtime_executes "$rt" ||
      { as_error "container runtime '$rt' is registered with Docker but its binary won't execute a container — refusing to launch"; return 1; }
  fi
  printf '%s\n' "$rt"
}

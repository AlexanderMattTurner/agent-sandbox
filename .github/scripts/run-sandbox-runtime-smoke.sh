#!/usr/bin/env bash
# Drive the runtime-ladder smoke on the CI runner. The runner always has runc; it
# has no /dev/kvm, so Kata is N/A and never required here. This script OPTIONALLY
# installs gVisor/runsc and registers it as a Docker runtime so the ladder has a
# hardened runtime to select — but degrades gracefully to runc-only if gVisor can't
# be installed (a download blip, a checksum sidecar 404, an arch with no release):
# an unavailable gVisor is LOGGED, not a job failure. The smoke itself
# (tests/smoke/sandbox-runtime-smoke.sh) is the pass/fail gate.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Pin the gVisor release point-in-time and the amd64 binary's sha512. The runner is
# amd64; a different arch skips the install and the smoke runs runc-only. gVisor
# publishes a runsc.sha512 sidecar next to each binary, so the download is verified
# against a checksum either way — the pin below is the belt to that sidecar's braces,
# tying THIS job to one known binary rather than "whatever release/latest serves".
# pin-exempt: verified below
GVISOR_RELEASE="20250811.0"
GVISOR_BASE="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}"
GVISOR_AMD64_SHA512="95cc8973a8ba6fdea608c36288afe83e17a890398d387de89dfd1457e902ab1d73fd3bd52a4fc2b923accd36ad5d1e76b5ea373e9c68d9821efb1785f830892d"

log() { printf '[runtime-smoke] %s\n' "$1"; }

# install_gvisor_runsc — download runsc + its .sha512 sidecar, verify BOTH (the
# published sidecar and, on amd64, the pinned digest), install the binary, and
# register it as the "runsc" Docker runtime with a daemon restart. Returns non-zero
# on any failure so the caller can degrade to runc-only; never aborts the job.
install_gvisor_runsc() {
  local arch bin_arch tmp
  arch="$(uname -m)"
  case "$arch" in
  x86_64) bin_arch="x86_64" ;;
  aarch64) bin_arch="aarch64" ;;
  *)
    log "unsupported arch '$arch' for the gVisor install — skipping (runc-only smoke)"
    return 1
    ;;
  esac

  tmp="$(mktemp -d)"
  local url="${GVISOR_BASE}/${bin_arch}"
  log "downloading runsc + runsc.sha512 from ${url}"
  if ! curl -fsSL --connect-timeout 15 --max-time 180 "${url}/runsc" -o "$tmp/runsc" ||
    ! curl -fsSL --connect-timeout 15 --max-time 60 "${url}/runsc.sha512" -o "$tmp/runsc.sha512"; then
    log "could not download runsc from gVisor storage — skipping (runc-only smoke)"
    rm -rf "$tmp"
    return 1
  fi

  # The published sidecar is "<sha512>  runsc"; verify it in the download dir where
  # that basename resolves. Fail closed: a mismatch means a tampered/corrupt binary.
  if ! (cd "$tmp" && sha512sum -c runsc.sha512 >/dev/null 2>&1); then
    log "runsc.sha512 sidecar verification FAILED — refusing to install a corrupt/tampered binary"
    rm -rf "$tmp"
    return 1
  fi
  log "runsc verified against its published sha512 sidecar"

  # On amd64 also pin to a known digest, so a maintainer-swapped release can't slip
  # a fresh (validly-sidecar'd) binary past this job unnoticed. Off-amd64 rides the
  # sidecar alone (no pin published here).
  if [[ "$bin_arch" == "x86_64" ]]; then
    if ! printf '%s  %s\n' "$GVISOR_AMD64_SHA512" "$tmp/runsc" | sha512sum -c - >/dev/null 2>&1; then
      log "runsc does not match the pinned amd64 sha512 — skipping install (runc-only smoke)"
      rm -rf "$tmp"
      return 1
    fi
    log "runsc matches the pinned amd64 sha512"
  fi

  sudo install -m 0755 "$tmp/runsc" /usr/local/bin/runsc
  rm -rf "$tmp"

  # Register runsc with the daemon via `runsc install` (writes /etc/docker/daemon.json),
  # then restart so the runtime appears in `docker info`.
  log "registering runsc as a Docker runtime"
  sudo /usr/local/bin/runsc install
  sudo systemctl restart docker

  # runtime-detect.bash's poll waits out the restart's registration lag.
  # shellcheck source=../../bin/lib/runtime-detect.bash disable=SC1091
  source "$REPO_ROOT/bin/lib/runtime-detect.bash"
  if ! wait_for_docker_runtime runsc 30; then
    log "runsc did not register with Docker after the restart — continuing runc-only"
    return 1
  fi
  log "runsc registered with Docker"
}

if install_gvisor_runsc; then
  log "gVisor/runsc available — the ladder may select it"
else
  log "gVisor/runsc unavailable — the ladder falls back to runc (this is not a failure)"
fi

log "running the runtime-ladder smoke"
bash "$REPO_ROOT/tests/smoke/sandbox-runtime-smoke.sh"

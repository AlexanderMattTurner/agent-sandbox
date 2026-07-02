#!/usr/bin/env bash
# Install a pinned, checksum-verified runsc (gVisor), register it with Docker, then
# run the isolation smoke assertions in tests/smoke/runsc-smoke.sh.
#
# The runsc binary + its containerd shim are downloaded from gVisor's GCS release
# bucket at a PINNED release point and verified against the published .sha512 sums
# before they are ever installed — never register an unverified binary as a runtime.
#
# Requires root + a working Docker daemon (the GitHub runner has both; this repo's
# dev sandbox lacks a Docker daemon, so the suite runs on CI only).
set -euo pipefail

# Pin gVisor to a specific dated release, not "latest": a moving target means the
# smoke suite silently starts testing a different runtime build on every run. Bump
# this deliberately. The .sha512 fetched alongside each binary is the integrity gate.
RUNSC_RELEASE="20250811.0"
ARCH="$(uname -m)"
BASE_URL="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${ARCH}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SMOKE="$REPO_ROOT/tests/smoke/runsc-smoke.sh"

status() { printf ':: %s\n' "$1"; }
die() {
  printf '!! %s\n' "$1" >&2
  exit 1
}

[[ "$(uname)" == "Linux" ]] || die "runsc install requires Linux"
[[ "$(id -u)" -eq 0 ]] || die "run as root (needs to install the runtime + reload docker)"
command -v docker >/dev/null 2>&1 || die "docker not found"

# ── Debounce a live-reloading daemon's transient runtime sighting ───
# `runsc install` rewrites daemon.json; a live-reloading daemon exposes the runtime
# mid-reload, momentarily present then gone. Require three consecutive positive polls
# so a stable registration is not confused with a reload flicker; give up after <max>s.
runsc_registered() {
  local max="$1" streak=0 i
  for ((i = 0; i < max; i++)); do
    if docker info 2>/dev/null | grep -q runsc; then
      ((++streak >= 3)) && return 0
    else
      streak=0
    fi
    sleep 1
  done
  return 1
}

if docker info 2>/dev/null | grep -q runsc; then
  status "runsc already registered — skipping install"
else
  status "Downloading runsc ${RUNSC_RELEASE} for ${ARCH}..."
  tmpd="$(mktemp -d)"
  trap 'rm -rf "$tmpd"' EXIT
  (
    cd "$tmpd"
    # pin-exempt: sha512-verified below
    curl -fsSL -O "${BASE_URL}/runsc" -O "${BASE_URL}/runsc.sha512" \
      -O "${BASE_URL}/containerd-shim-runsc-v1" -O "${BASE_URL}/containerd-shim-runsc-v1.sha512"
    sha512sum -c runsc.sha512 containerd-shim-runsc-v1.sha512
  ) || die "runsc download or checksum verification failed"

  install -m 0755 "$tmpd/runsc" "$tmpd/containerd-shim-runsc-v1" /usr/local/bin/
  /usr/local/bin/runsc --version >/dev/null 2>&1 || die "runsc binary unusable after download (partial fetch?)"

  status "Registering runsc with Docker..."
  # Retry the whole install+reload sequence once: if the daemon does not live-reload
  # the runtime, restart it and poll until docker responds and the runtime settles.
  registered=false
  for attempt in 1 2; do
    /usr/local/bin/runsc install
    if runsc_registered 6; then
      registered=true
      break
    fi
    systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || true
    for ((i = 0; i < 60; i++)); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
    if runsc_registered 30; then
      registered=true
      break
    fi
    status "runsc not registered after restart (attempt $attempt/2); retrying install..."
  done
  "$registered" || die "runsc not registered after install + restart"
fi

# Warm the local image cache once before the assertions. The smoke suite launches
# ~10 short-lived containers from the same image; without a pre-pull each `docker run`
# can trigger its own unauthenticated Docker Hub pull, and the runner's shared IP
# routinely trips the anonymous pull rate limit ("toomanyrequests") mid-suite. One
# cached pull turns every subsequent run into a local hit; the backoff absorbs a
# transient 429 rather than failing the whole security smoke on a throttle.
SMOKE_IMAGE="${SMOKE_IMAGE:-alpine}"
export SMOKE_IMAGE
status "Pre-pulling smoke image ${SMOKE_IMAGE}..."
pulled=false
for delay in 0 5 15 30; do
  ((delay > 0)) && {
    status "pull failed (rate limit?); retrying in ${delay}s..."
    sleep "$delay"
  }
  if docker pull "$SMOKE_IMAGE" >/dev/null 2>&1; then
    pulled=true
    break
  fi
done
"$pulled" || die "could not pull $SMOKE_IMAGE after retries (Docker Hub rate limit?)"

status "Running gVisor isolation smoke assertions..."
bash "$SMOKE"

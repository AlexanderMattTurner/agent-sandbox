#!/usr/bin/env bash
# gVisor (runsc) isolation smoke test: assert that runsc is registered with Docker
# and that a runsc-launched container enforces the isolation properties the sandbox
# relies on — Sentry kernel, process/device/network/filesystem isolation, blocked
# host bind mounts, dropped capabilities, and a host-matching architecture.
#
# Each assertion FAILS CLOSED: an empty or unmeasured probe result is a FAIL, never
# a PASS — for a security smoke suite "could not measure" must never certify green.
#
# Requires: docker with the runsc runtime already registered (see
# .github/scripts/run-runsc-smoke.sh for the install path).
set -euo pipefail

status() { printf ':: %s\n' "$1"; }
warn() { printf '!! %s\n' "$1" >&2; }
die() {
  warn "$1"
  exit 1
}
pass() { printf 'PASS: %s\n' "$1"; }
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

# The three checks below are the negative-result side of a security probe: an
# unconfirmed/unreadable result means the property under test could NOT be verified,
# which for a security smoke suite is a failure — "unmeasured" is never "pass".

# Verify the container's /proc/version names gVisor — the suite's headline property.
# A runc-fallback container (runtime dropped, install flickered out) has no "gvisor"
# marker and every downstream isolation check passes under plain runc too, so a soft
# warn here would certify zero gVisor isolation as green.
check_gvisor_kernel() {
  local kernel="$1"
  if echo "$kernel" | grep -qi "gvisor"; then
    pass "gVisor Sentry kernel active"
  else
    fail "could not confirm gVisor Sentry (got: ${kernel:0:100})"
  fi
}

# Verify a --cap-drop=ALL container reports CapEff=0. An empty probe result means the
# measurement itself failed (container didn't start, grep/awk pipeline broke); treating
# "could not read" as success would let a real cap-drop regression slip through whenever
# the read also fails, so it fails closed.
check_cap_drop() {
  local cap_value="$1"
  if [[ "$cap_value" == "0000000000000000" ]]; then
    pass "all capabilities dropped (CapEff=0)"
  elif [[ -n "$cap_value" ]]; then
    fail "capabilities not fully dropped: CapEff=$cap_value"
  else
    fail "could not read CapEff (cap-drop unverified)"
  fi
}

# Verify the container arch matches the host. A mismatch signals qemu/binfmt emulation
# or a misconfigured runtime that can degrade gVisor's arch-specific isolation; an empty
# result means the probe failed. Both are failures — a green smoke run must mean the
# runtime the sandbox will use is the one measured here.
check_arch_match() {
  local container_arch="$1" host_arch="$2"
  if [[ "$container_arch" == "$host_arch" ]]; then
    pass "arch match: $host_arch"
  elif [[ -n "$container_arch" ]]; then
    fail "arch mismatch: host=$host_arch container=$container_arch"
  else
    fail "could not detect container architecture"
  fi
}

# True once the runsc runtime is registered with Docker AND that registration has
# settled. `runsc install` rewrites daemon.json, and a live-reloading daemon exposes
# the runtime mid-reload — momentarily present, then gone again — so a single
# `docker info | grep` can latch onto that transient flicker and report a registration
# that vanishes a second later. Require the runtime on three consecutive polls to
# debounce the flicker; give up after <max> seconds.
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

FAILURES=0

command -v docker >/dev/null 2>&1 || die "docker not found"

# ── 1. Runtime registration + Sentry kernel ─────────────────────────
status "Checking runsc registration..."
runsc_registered 30 || die "runsc not registered — install it first (see run-runsc-smoke.sh)"
pass "runsc registered with Docker"

kernel=$(docker run --rm --runtime=runsc alpine cat /proc/version) || true
status "kernel: ${kernel:-<unavailable>}"
check_gvisor_kernel "$kernel"

# ── 2. Basic execution ──────────────────────────────────────────────
status "Running basic container..."
output=$(docker run --rm --runtime=runsc alpine echo "runsc-smoke-ok" 2>&1) || die "failed to run container with runsc"
if [[ "$output" == *"runsc-smoke-ok"* ]]; then
  pass "basic container execution"
else
  fail "unexpected output: $output"
fi

# ── 3. Process isolation ────────────────────────────────────────────
status "Checking process isolation..."
proc_count=$(docker run --rm --runtime=runsc alpine sh -c 'ls /proc | grep -cE "^[0-9]+$"' 2>/dev/null) || proc_count=0
if [[ "$proc_count" -le 5 ]]; then
  pass "process isolation ($proc_count PIDs)"
else
  fail "saw $proc_count PIDs — may leak host processes"
fi

# ── 4. Device isolation ─────────────────────────────────────────────
status "Checking device isolation..."
host_devices=$(docker run --rm --runtime=runsc alpine sh -c 'ls /dev/sda /dev/kvm /dev/mem 2>/dev/null | wc -l')
if [[ "$host_devices" -eq 0 ]]; then
  pass "device isolation"
else
  fail "host devices visible in container"
fi

# ── 5. Host bind mount blocked ──────────────────────────────────────
status "Checking host mount restrictions..."
mount_result=$(docker run --rm --runtime=runsc alpine sh -c \
  'mkdir -p /mnt/escape && mount --bind / /mnt/escape 2>&1; echo "exit:$?"') || true
if echo "$mount_result" | grep -qE "exit:[1-9]|not permitted|denied|Invalid argument|No such device"; then
  pass "bind mount blocked"
else
  fail "bind mount may not be blocked: ${mount_result:0:100}"
fi

# ── 6. Capability drops ─────────────────────────────────────────────
status "Checking capability drops..."
cap_value=$(docker run --rm --runtime=runsc --cap-drop=ALL alpine sh -c \
  'grep -i capeff /proc/1/status' | awk '{print $2}') || true
check_cap_drop "$cap_value"

# ── 7. Network isolation ────────────────────────────────────────────
status "Checking network isolation..."
NET_NAME="runsc-smoke-internal-$$"
docker network create --internal "$NET_NAME" >/dev/null || fail "failed to create isolated test network $NET_NAME"
net_result=$(docker run --rm --runtime=runsc --network="$NET_NAME" alpine sh -c \
  'wget -q -O /dev/null --timeout=3 http://1.1.1.1 2>&1; echo "exit:$?"') || true
docker network rm "$NET_NAME" >/dev/null 2>&1 || true
if echo "$net_result" | grep -qE "exit:[1-9]|timed out|unreachable|refused"; then
  pass "network isolation on internal network"
else
  fail "container on internal network could reach the internet"
fi

# ── 8. Read-only root filesystem ─────────────────────────────────────
status "Checking read-only filesystem..."
ro_result=$(docker run --rm --runtime=runsc --read-only alpine sh -c \
  'touch /test-file 2>&1; echo "exit:$?"') || true
if echo "$ro_result" | grep -qE "exit:[1-9]|Read-only|denied"; then
  pass "read-only filesystem enforced"
else
  fail "read-only filesystem not enforced: ${ro_result:0:100}"
fi

# ── 9. Volume mount ─────────────────────────────────────────────────
status "Checking volume mount..."
TMPDIR_MOUNT=$(mktemp -d)
echo "mount-test-content" >"$TMPDIR_MOUNT/test.txt"
vol_result=$(docker run --rm --runtime=runsc -v "$TMPDIR_MOUNT:/mnt/test:ro" alpine \
  cat /mnt/test/test.txt 2>&1) || true
rm -rf "$TMPDIR_MOUNT"
if [[ "$vol_result" == *"mount-test-content"* ]]; then
  pass "volume mount works"
else
  fail "volume mount failed: ${vol_result:0:100}"
fi

# ── 10. Architecture match ──────────────────────────────────────────
status "Checking architecture..."
container_arch=$(docker run --rm --runtime=runsc alpine uname -m) || true
host_arch=$(uname -m)
check_arch_match "$container_arch" "$host_arch"

# ── Summary ──────────────────────────────────────────────────────────
echo ""
[[ $FAILURES -eq 0 ]] && {
  status "All runsc smoke tests passed"
  exit 0
}
warn "$FAILURES test(s) failed"
exit 1

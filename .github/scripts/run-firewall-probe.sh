#!/usr/bin/env bash
# Run a self-asserting firewall smoke probe (tests/smoke/<name>) inside the built
# firewall image as root. The probe owns its assertions and exits non-zero on any
# failure, which propagates out of `docker run` as this script's status. Root is
# required: the probe creates a dummy interface (NET_ADMIN) and installs ipset
# rules (NET_RAW), so do NOT --cap-drop.
set -euo pipefail

probe="${1:?usage: run-firewall-probe.sh <probe-filename under tests/smoke/>}"
img="${FIREWALL_IMAGE:-agent-sandbox-firewall:ci}"
path="tests/smoke/$probe"
[[ -f "$path" ]] || {
  echo "probe not found: $path" >&2
  exit 1
}

docker run --rm --user root \
  -v "$PWD/$path:/probe.sh:ro" \
  "$img" bash /probe.sh

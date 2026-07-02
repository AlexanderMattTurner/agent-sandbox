#!/usr/bin/env bash
# Run a self-asserting firewall smoke probe (tests/smoke/<name>) inside the built
# firewall image as root. The probe owns its assertions and exits non-zero on any
# failure, which propagates out of `docker run` as this script's status.
#
# The caps are load-bearing and NOT in Docker's default set as root:
#   NET_ADMIN         dummy-interface creation + iptables/ipset rule install
#                     (default caps do NOT include it — `ip link add` fails without it)
#   NET_RAW           the `iptables -m set` match opens a SOCK_RAW netlink socket
#   NET_BIND_SERVICE  the egress-quota probe's origin binds :80
set -euo pipefail

probe="${1:?usage: run-firewall-probe.sh <probe-filename under tests/smoke/>}"
img="${FIREWALL_IMAGE:-agent-sandbox-firewall:ci}"
path="tests/smoke/$probe"
[[ -f "$path" ]] || {
  echo "probe not found: $path" >&2
  exit 1
}

docker run --rm --user root \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
  -v "$PWD/$path:/probe.sh:ro" \
  "$img" bash /probe.sh

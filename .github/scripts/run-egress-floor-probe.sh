#!/usr/bin/env bash
# Run the egress-floor probe in the firewall image, then assert the tamper-evident
# egress log (squid access.log) recorded BOTH an allowed pass-through and a
# proxy-denied write — the floor that underwrites tripwire-audit.
set -euo pipefail

img="agent-sandbox-firewall:ci"
out="$(mktemp)"

# The probe (bind-mounted) drives block/allow traffic through the real squid+dnsmasq
# and exits non-zero on any behavioural failure; we then emit the access log so the
# floor assertion below can read it. Root required (dnsmasq :53); do NOT --cap-drop.
docker run --rm --user root \
  -v "$PWD/tests/smoke/firewall-egress-probe.sh:/probe.sh:ro" \
  "$img" bash -c 'bash /probe.sh; rc=$?; echo "=====ACCESS_LOG====="; cat /var/log/squid/access.log 2>/dev/null || true; exit "$rc"' |
  tee "$out"

alog="$(sed -n '/=====ACCESS_LOG=====/,$p' "$out")"
grep -qE 'rw\.test|ro\.test' <<<"$alog" ||
  {
    echo "FLOOR FAIL: no allowed host recorded in the egress log" >&2
    exit 1
  }
grep -qE 'TCP_DENIED|/403 ' <<<"$alog" ||
  {
    echo "FLOOR FAIL: no proxy-denied write recorded in the egress log" >&2
    exit 1
  }
echo "FLOOR OK: egress log recorded an allowed pass-through AND a proxy-denied write"

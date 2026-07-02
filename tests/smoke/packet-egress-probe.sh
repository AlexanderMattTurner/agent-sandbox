#!/bin/bash
# Runs INSIDE the firewall image, as root, in a PRIVILEGED netns (see
# .github/scripts/run-firewall-probe.sh). End-to-end proof of the PACKET-LAYER
# default-deny egress boundary — the iptables OUTPUT chain that backstops
# squid/dnsmasq. It complements egress-quota-probe.sh (which drives the SAME
# install_egress_output_rules with a byte cap) by driving it WITHOUT a quota and
# asserting the per-destination verdicts on real packet counters:
#   - a bogon/metadata destination is DROPped by the packet-layer backstop, even
#     though nothing about it passed through is_public_ipv4;
#   - a NON-allowlisted public destination hits the final catch-all REJECT;
#   - an allowlisted public destination (in the ipset) is ACCEPTed.
#
# SSOT, not a replay: we source firewall-lib.bash and call the SAME
# install_egress_output_rules that init-firewall.bash calls, so the chain under
# test is the exact chain production installs. No external network: destinations
# are either link-local/on-box or intercepted by the OUTPUT chain before they can
# leave, so counters (not reachability) are the assertion.
#
# Prints PASS:/FAIL: lines; exits non-zero if any assertion failed.
set -uo pipefail

FAILURES=0
status() { printf ':: %s\n' "$1"; }
pass() { printf 'PASS: %s\n' "$1"; }
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}
die() {
  printf '!! %s\n' "$1" >&2
  exit 1
}

for bin in iptables ipset ip curl; do
  command -v "$bin" >/dev/null 2>&1 || die "required binary '$bin' not found in image"
done

FIREWALL_LIB="/usr/local/bin/firewall-lib.bash"
[[ -f "$FIREWALL_LIB" ]] || die "firewall-lib.bash not found at $FIREWALL_LIB"
# shellcheck source=/dev/null
source "$FIREWALL_LIB"

# 93.184.216.34 is public (outside every BOGON_CIDRS range); 169.254.169.254 is the
# cloud-metadata endpoint inside 169.254.0.0/16 (a bogon); 8.8.8.8 is a public
# address deliberately NOT added to the allowlist ipset.
ALLOWED_PUBLIC="93.184.216.34"
METADATA_BOGON="169.254.169.254"
UNLISTED_PUBLIC="8.8.8.8"

# ── Dummy interface bearing EVERY test destination as a local /32 ────────────
# Each destination is assigned to dummy0 so the kernel has a local route for it and
# the packet deterministically traverses the OUTPUT chain (routed out the loopback
# device, but the OUTPUT rules match on DESTINATION, so the tested rule still
# counts it). Without this, the link-local metadata address has no route and curl
# fails with "network unreachable" BEFORE the DROP rule can count it (a vacuous
# pass), and the unlisted public address would try to leave the box. No external
# network: all three are on-box.
ip link add dummy0 type dummy 2>/dev/null || die "ip link add dummy0 failed (need NET_ADMIN + dummy module)"
ip link set dummy0 up || die "ip link set up failed"
for _ip in "$ALLOWED_PUBLIC" "$METADATA_BOGON" "$UNLISTED_PUBLIC"; do
  ip addr add "$_ip/32" dev dummy0 || die "ip addr add $_ip failed"
done

# ── ipset the real ACCEPT rule matches against ───────────────────────────────
ipset destroy allowed-domains 2>/dev/null || true
ipset create allowed-domains hash:net
ipset add allowed-domains "$ALLOWED_PUBLIC"

# ── Install the real OUTPUT chain via the SSOT function (NO quota) ────────────
# shellcheck disable=SC2034  # read by install_egress_output_rules (sourced), not here
SANDBOX_SUBNET="172.30.0.0/24"
# Unset so the non-quota branch installs a single allowed-domains ACCEPT (no cap).
unset EGRESS_QUOTA_MB

iptables -F OUTPUT
install_egress_output_rules

# ── Structural assertions: the chain shape the packet layer depends on ───────
# One DROP per bogon CIDR, plus the loopback + subnet carve-outs and the final
# REJECT. A missing bogon DROP is the exact hole this probe exists to catch, so we
# assert the count equals the live BOGON_CIDRS length (SSOT), not a magic number.
bogon_drops=$(iptables -S OUTPUT | grep -c -- '-j DROP')
[[ "$bogon_drops" -eq "${#BOGON_CIDRS[@]}" ]] ||
  fail "bogon DROP rule count $bogon_drops != ${#BOGON_CIDRS[@]} (BOGON_CIDRS members) — a range is missing from the packet-layer backstop"
iptables -S OUTPUT | grep -q -- '-d 127.0.0.0/8 -j ACCEPT' ||
  fail "loopback carve-out (ACCEPT 127.0.0.0/8) missing"
iptables -S OUTPUT | grep -q -- "-d $SANDBOX_SUBNET -j ACCEPT" ||
  fail "sandbox-subnet carve-out (ACCEPT $SANDBOX_SUBNET) missing"
iptables -S OUTPUT | grep -qE -- '-A OUTPUT -j REJECT' ||
  fail "final catch-all REJECT missing"

# Packet counters, read from verbose iptables. The metadata DROP is the bogon rule
# for 169.254.0.0/16; the catch-all REJECT is the only REJECT with no ipset match.
metadata_drop_pkts() {
  iptables -L OUTPUT -v -n -x | awk '/169.254.0.0\/16/ && /DROP/ {print $1; exit}'
}
final_reject_pkts() {
  iptables -L OUTPUT -v -n -x |
    awk '/reject-with icmp-admin-prohibited/ && !/match-set/ {print $1; exit}'
}
allowed_accept_pkts() {
  iptables -L OUTPUT -v -n -x | awk '/match-set allowed-domains dst/ {print $1; exit}'
}

iptables -Z OUTPUT

# (1) Metadata/bogon destination is DROPped by the packet-layer backstop.
status "(1) cloud-metadata endpoint $METADATA_BOGON is DROPped"
before=$(metadata_drop_pkts)
curl -fsS --max-time 2 -o /dev/null "http://$METADATA_BOGON/" 2>/dev/null || true
after=$(metadata_drop_pkts)
if [[ "${after:-0}" -gt "${before:-0}" ]]; then
  pass "packets to $METADATA_BOGON hit the bogon DROP (counter $before -> $after)"
else
  fail "bogon DROP counter for 169.254.0.0/16 did not advance ($before -> $after) — metadata egress not blocked at the packet layer"
fi

# (2) A public destination NOT in the allowlist hits the final REJECT. The OUTPUT
# chain intercepts the SYN before it can leave, so no packet reaches 8.8.8.8.
status "(2) non-allowlisted public $UNLISTED_PUBLIC hits the catch-all REJECT"
before=$(final_reject_pkts)
curl -fsS --max-time 2 -o /dev/null "http://$UNLISTED_PUBLIC/" 2>/dev/null || true
after=$(final_reject_pkts)
if [[ "${after:-0}" -gt "${before:-0}" ]]; then
  pass "packets to $UNLISTED_PUBLIC hit the final REJECT (counter $before -> $after)"
else
  fail "final REJECT counter did not advance ($before -> $after) — a non-allowlisted destination was not default-denied"
fi

# (3) An allowlisted public destination is ACCEPTed by the allowed-domains rule.
status "(3) allowlisted public $ALLOWED_PUBLIC is ACCEPTed"
before=$(allowed_accept_pkts)
curl -fsS --max-time 2 -o /dev/null "http://$ALLOWED_PUBLIC/" 2>/dev/null || true
after=$(allowed_accept_pkts)
if [[ "${after:-0}" -gt "${before:-0}" ]]; then
  pass "packets to $ALLOWED_PUBLIC hit the allowed-domains ACCEPT (counter $before -> $after)"
else
  fail "allowed-domains ACCEPT counter did not advance ($before -> $after) — an allowlisted destination was not permitted"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
if [[ $FAILURES -gt 0 ]]; then
  {
    echo "==> $FAILURES assertion(s) failed. Diagnostics:"
    echo "--- OUTPUT chain (verbose, exact counters) ---"
    iptables -L OUTPUT -v -n -x
    echo "--- OUTPUT chain (rule spec) ---"
    iptables -S OUTPUT
    echo "--- allowed-domains ipset ---"
    ipset list allowed-domains
  } >&2
  exit 1
fi
echo "All packet-layer egress assertions passed"
exit 0

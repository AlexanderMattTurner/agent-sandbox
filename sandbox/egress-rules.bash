# shellcheck shell=bash
# egress-rules.bash — the OUTPUT-chain egress lockdown in exactly one place.
# Sourced (via firewall-lib.bash) by init-firewall.bash, which calls
# install_egress_output_rules after it has set the chain policies and the INPUT
# rules, and by the egress-quota e2e probe, which drives the SAME function against
# a test ipset. There is no second copy to drift: the test exercises the bytes the
# firewall actually installs.

# install_egress_output_rules — append the egress OUTPUT chain in its
# load-bearing order. Reads from the caller's environment: SANDBOX_SUBNET,
# BOGON_CIDRS (array), EGRESS_QUOTA_MB (optional). The `allowed-domains` ipset
# must already exist.
install_egress_output_rules() {
  # BOGON_CIDRS is the packet-layer metadata/RFC1918 backstop; an empty or unset
  # array would install the OUTPUT chain WITHOUT it (a silent security hole), and a
  # bare "${BOGON_CIDRS[@]}" on an unset array aborts under set -u anyway. Fail loud
  # rather than proceed without the backstop. The +set form is safe when unset.
  if [[ -z "${BOGON_CIDRS[*]+set}" || ${#BOGON_CIDRS[@]} -eq 0 ]]; then
    echo "ERROR: BOGON_CIDRS is empty — refusing to install egress rules without the metadata/RFC1918 packet-layer backstop" >&2
    return 1
  fi
  # Refuse egress to internal/metadata ranges at the packet layer, regardless of
  # what the allowed-domains ipset holds — a backstop for ingestion paths that do
  # NOT pass through is_public_ipv4: the carried-forward GitHub-meta CIDRs and any
  # hand-edited static CIDR. The two legitimate non-public destinations are carved
  # out FIRST — loopback (the firewall's own dnsmasq/squid) and the sandbox subnet
  # (squid<->workload responses) — then every BOGON_CIDRS range is dropped.
  # Placed before the allowed-domains ACCEPT so a bogon can't fall through to it;
  # allowed-domains only ever hold public IPs, so this never shadows the quota rule.
  iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
  iptables -A OUTPUT -d "$SANDBOX_SUBNET" -j ACCEPT
  for _bogon in "${BOGON_CIDRS[@]}"; do
    iptables -A OUTPUT -d "$_bogon" -j DROP
  done

  # Egress byte budget (opt-in): a hard ceiling on outbound bytes to allowed
  # domains, bounding worst-case exfiltration. OFF by default — when the cap is
  # hit it REJECTs *all* further allowed-domain traffic for the rest of the
  # session, which silently bricked long, dependency-heavy sessions (large clones,
  # image pulls, package installs) with an opaque icmp-admin-prohibited. Set
  # EGRESS_QUOTA_MB to a positive value to re-enable it.
  #
  # ORDERING IS LOAD-BEARING — the quota rule (and its over-quota REJECT) MUST
  # precede the ESTABLISHED accept on OUTPUT. -m quota only decrements on packets
  # traversing this rule; a prior generic ESTABLISHED,RELATED ACCEPT would
  # short-circuit every bulk-data packet on an open connection, so the quota would
  # see only NEW SYNs and never decrement — an effectively infinite ceiling.
  EGRESS_QUOTA="${EGRESS_QUOTA_MB:-0}"
  if [[ "$EGRESS_QUOTA" =~ ^[0-9]+$ ]] && ((EGRESS_QUOTA > 0)); then
    iptables -A OUTPUT -m set --match-set allowed-domains dst \
      -m quota --quota $((EGRESS_QUOTA * 1048576)) -j ACCEPT
    # Over-quota: REJECT explicitly so it can't fall through to ESTABLISHED below.
    iptables -A OUTPUT -m set --match-set allowed-domains dst \
      -j REJECT --reject-with icmp-admin-prohibited
  else
    iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT
  fi

  # Return traffic to NON-allowed-domain destinations (intra-sandbox responses).
  # Allowed-domain traffic is already decided above.
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited
}

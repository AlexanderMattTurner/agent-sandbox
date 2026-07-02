#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

# init-firewall.bash — bring up the name-level-allowlist egress boundary inside
# the firewall container: static dnsmasq (NXDOMAIN default), iptables/ipset
# packet backstop, and squid enforcing the ro (GET/HEAD) / rw (all methods)
# tier split. The allowlist is the WORKLOAD's declaration only — the firewall
# boots DENY-ALL and admits exactly what WORKLOAD_ALLOWED_DOMAINS_RO/RW carry.
#
# Fail loudly and locatably. With set -e a denied syscall (e.g. a chmod needing a
# capability the firewall service dropped) aborts with only terse stderr, surfacing
# as an opaque launch hang (the healthcheck never flips). Name script/line/command
# so `docker logs <firewall>` shows the cause. set -E propagates the trap into functions.
trap 'echo "init-firewall.bash: FAILED at line ${LINENO} running: ${BASH_COMMAND}" >&2' ERR

# Where there is no controlled external egress (CI runners, the cap check), the
# reachability self-tests — curl example.com must be BLOCKED, an allowlisted host
# must be REACHABLE, and the "allowed domain resolves" DNS probe — cannot be
# asserted. This flag skips ONLY those network-dependent checks; every privileged
# setup step (ipset, iptables, chown, chmod, dnsmasq, squid) still runs for real,
# so a missing capability is still caught by the healthcheck never going green.
# The purely local "blocked domain → NXDOMAIN" exfil check always runs.
SKIP_VERIFY="${AGENT_SANDBOX_FIREWALL_SKIP_VERIFY:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Opt-in structured trace channel (AGENT_SANDBOX_TRACE): as_trace lets the firewall
# announce it ENGAGED, so a missing announcement is loud (a firewall that silently
# never engaged would otherwise look identical to one that did). A no-op unless
# AGENT_SANDBOX_TRACE is set. Sourced HERE, before the allow-all bypass below, so
# that branch — which exits early — can still announce the firewall is running in
# DISENGAGED (allow-all) mode. Copied beside this script (Dockerfile COPY);
# tolerate its absence with a no-op fallback.
if [[ -f "$SCRIPT_DIR/trace.bash" ]]; then
  # shellcheck source=trace.bash disable=SC1091
  source "$SCRIPT_DIR/trace.bash"
else
  as_trace() { :; }
fi

# === --dangerously-skip-firewall ===
if [[ "${DANGEROUSLY_SKIP_FIREWALL:-}" == "1" ]]; then
  echo "================================================================"
  echo "WARNING: Firewall disabled (DANGEROUSLY_SKIP_FIREWALL=1)"
  echo "The workload has UNRESTRICTED internet access."
  echo "================================================================"
  # The workload container is on the `internal: true` sandbox network with NO L3
  # route off it (see the squid-egress comment near write_squid_conf below), so
  # disabling the allowlist does not by itself grant egress — its only path out is
  # still the proxy at $SANDBOX_IP:3128 and DNS via the firewall. So even here we
  # run two services: a forwarding-only dnsmasq (DNS resolves), and an ALLOW-ALL
  # squid (every host/method/port reachable — the "unrestricted" the flag
  # promises), instead of an allowlisted one. Egress still transits squid, so the
  # access log keeps recording it.
  SANDBOX_IP="${SANDBOX_IP:-172.30.0.2}"
  DOCKER_DNS=$(awk '$1=="nameserver"{print $2; exit}' /etc/resolv.conf)
  if [[ -z "$DOCKER_DNS" ]]; then
    echo "ERROR: no nameserver in /etc/resolv.conf — cannot configure DNS forwarding"
    exit 1
  fi
  cat >/etc/dnsmasq.conf <<DNSMASQ_FWD
server=$DOCKER_DNS
listen-address=127.0.0.1,$SANDBOX_IP
bind-interfaces
port=53
DNSMASQ_FWD
  dnsmasq --test && echo "dnsmasq config valid (forwarding mode)"
  dnsmasq
  echo "dnsmasq started — forwarding to $DOCKER_DNS"

  # shellcheck source=squid-config.bash disable=SC1091
  source "$SCRIPT_DIR/squid-config.bash"
  SQUID_CONF="/etc/squid/squid.conf"
  write_squid_allow_all_conf "$SANDBOX_IP" >"$SQUID_CONF"
  set_mode_then_owner 640 root:proxy "$SQUID_CONF"
  prepare_squid_log_dir /var/log/squid
  if squid_parse_out=$(squid -k parse 2>&1); then
    echo "squid config valid (allow-all mode)"
  else
    echo "ERROR: squid config parse failed — squid will not start. Diagnostics:" >&2
    printf '%s\n' "$squid_parse_out" >&2
    exit 1
  fi
  squid
  echo "squid started — allow-all (firewall disabled)"
  # The POSITIVE "firewall is running in allow-all / DISENGAGED mode" signal: the
  # bypass reaches this point and exits 0 BEFORE the firewall_rules_applied emit far
  # below, so without this line "firewall off" would be only the ABSENCE of an event —
  # a false-green that also matches "the firewall crashed before announcing".
  # Metadata only (the mode, never any traffic). `:-` keeps the no-trace fallback
  # from tripping set -u; the no-op as_trace ignores the empty arg.
  as_trace "${TRACE_FIREWALL_ALLOW_ALL_APPLIED:-}" mode="allow-all"
  exit 0
fi

# === Workload allowlist ===
# The single source is the Workload record: the launcher partitions its
# egress_allowlist by tier and passes the two newline-separated lists in as env
# vars. There is NO baked default list — an empty declaration boots a valid
# deny-all firewall. "rw" = full HTTP; "ro" = GET/HEAD only (squid ssl_bump).
# shellcheck source=firewall-lib.bash disable=SC1091
source "$SCRIPT_DIR/firewall-lib.bash"

# Optional launch-timing marks (AGENT_SANDBOX_LAUNCH_TRACE) split the in-container
# boot legs a host analyzer cannot see; launch_trace_mark is a no-op when the
# env/file is absent. Copied beside this script (Dockerfile COPY); tolerate its
# absence so a stripped image or a direct test invocation still runs.
if [[ -f "$SCRIPT_DIR/launch-trace.bash" ]]; then
  # shellcheck source=launch-trace.bash disable=SC1091
  source "$SCRIPT_DIR/launch-trace.bash"
else
  launch_trace_mark() { :; }
fi

# Runtime overlay for live allowlist expansions: domains added mid-session are
# appended here as `domain<TAB>access`; the refresh loop below merges them every
# cycle so they survive the periodic `ipset swap`. Lives in tmpfs, so it is
# session-scoped and starts empty on every (re)init.
ALLOWLIST_OVERLAY="${ALLOWLIST_OVERLAY:-/run/allowlist/overlay.tsv}"

# Liveness sentinels for the supervised background DNS-refresh loop (see the
# "Background DNS refresh" section below). The refresher stamps the heartbeat every
# cycle and the launch records the supervisor's PID, so a dead/wedged refresher is
# detectable (refresh_dns_alive) instead of silently freezing the allowlist. tmpfs,
# session-scoped, like the overlay.
REFRESH_HEARTBEAT_FILE="${REFRESH_HEARTBEAT_FILE:-/run/allowlist/refresh.heartbeat}"
REFRESH_PID_FILE="${REFRESH_PID_FILE:-/run/allowlist/refresh.pid}"

declare -A DOMAIN_ACCESS
# ro first, then rw, so an explicit rw escalation wins when a host is in both.
add_workload_domains ro <<<"${WORKLOAD_ALLOWED_DOMAINS_RO:-}"
add_workload_domains rw <<<"${WORKLOAD_ALLOWED_DOMAINS_RW:-}"
# `${DOMAIN_ACCESS[*]+set}` (not `${#DOMAIN_ACCESS[@]}`): bash treats an associative
# array that never received an element as UNSET, so `${#DOMAIN_ACCESS[@]}` trips
# `set -u` with "DOMAIN_ACCESS: unbound variable" and kills the firewall on exactly the
# deny-all default (an empty allowlist). The `+set` form is the nounset-safe emptiness
# test: it expands to "set" once any key exists, to nothing while the map is empty.
if [[ -z "${DOMAIN_ACCESS[*]+set}" ]]; then
  echo "Workload declared an empty egress allowlist — booting a deny-all firewall (no egress will resolve or route)."
fi

# === Firewall reset ===
DOCKER_DNS_RULES=$(iptables-save -t nat | grep "127\.0\.0\.11" || true)

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# Drop all IPv6 — an IPv6-enabled Docker network would otherwise bypass the
# entire iptables (v4) firewall. The default-DROP policy is set UNCONDITIONALLY
# (a harmless no-op when the v6 stack is truly absent) rather than trusting a
# /proc/net/if_inet6 probe: that probe early-returned "nothing to lock down"
# whenever the proc file was missing, leaving IPv6 unfiltered if an interface
# appeared after the probe (or the proc file was simply unreadable). Fails loud if
# ip6tables is absent or the DROP policy doesn't take — a silent failure would
# leave IPv6 wide open.
lock_down_ipv6() {
  command -v ip6tables >/dev/null 2>&1 || {
    echo "ERROR: ip6tables not found — cannot lock down IPv6; an IPv6-enabled Docker network would bypass the v4 firewall." >&2
    exit 1
  }
  ip6tables -F
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT DROP
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT
  local chain
  for chain in INPUT FORWARD OUTPUT; do
    ip6tables -S | grep -q "^-P ${chain} DROP" || {
      echo "ERROR: IPv6 lockdown failed — ${chain} policy is not DROP. IPv6 may be unfiltered."
      exit 1
    }
  done
  echo "IPv6 lockdown verified — INPUT/FORWARD/OUTPUT default to DROP"
}
lock_down_ipv6

if [[ "$DOCKER_DNS_RULES" != "" ]]; then
  echo "Restoring Docker DNS rules..."
  iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
  iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
  echo "$DOCKER_DNS_RULES" | xargs -L 1 iptables -t nat
else
  echo "No Docker DNS rules to restore"
fi

# Temporarily allow DNS for initial resolution + the verification curls below
# (resolv.conf is repointed at local dnsmasq only at the DNS lockdown step).
# Scope to the Docker resolver, not any host:53, so the bootstrap window isn't a
# blanket DNS-egress hole. If resolv.conf names no resolver, scope to Docker's
# embedded resolver at 127.0.0.11 specifically (not the whole 127.0.0.0/8 loopback
# block) rather than leaving :53 unscoped — a working container always names a
# resolver here, so this only narrows the abnormal no-nameserver case, it never
# breaks real DNS.
DNS_SERVER=$(awk '$1=="nameserver"{print $2; exit}' /etc/resolv.conf || true)
dns_scope="${DNS_SERVER:-127.0.0.11}"
dns_dst=(-d "$dns_scope")
dns_src=(-s "$dns_scope")
iptables -A OUTPUT -p udp --dport 53 "${dns_dst[@]+"${dns_dst[@]}"}" -j ACCEPT
iptables -A INPUT -p udp --sport 53 "${dns_src[@]+"${dns_src[@]}"}" -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 "${dns_dst[@]+"${dns_dst[@]}"}" -j ACCEPT
iptables -A INPUT -p tcp --sport 53 "${dns_src[@]+"${dns_src[@]}"}" -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

ipset create allowed-domains hash:net

# `ipset create` talks to its own netlink socket and succeeds even when the
# `iptables -m set` match can't, so a firewall that can't filter by ipset only
# blows up at the FIRST `-m set` rule — hundreds of lines later, with the opaque
# "Can't open socket to ipset". Probe in a scratch chain right after the set
# exists so the failure surfaces here with an actionable message. Two known
# causes: a missing CAP_NET_RAW (some kernels gate the match's SOCK_RAW socket
# on it — see docker-compose.yml) or a kernel with no ipset/xt_set support.
verify_ipset_match_support() {
  local probe_chain="AGENT-SANDBOX-IPSET-PROBE" err
  iptables -N "$probe_chain"
  # Tear the scratch chain down on EVERY exit path. A RETURN trap covers the success
  # path; the error path exits the whole script (fail closed) before the trap could
  # fire, so it cleans up explicitly first — either way no probe residue is left in
  # the live ruleset. probe_chain is still in scope when the trap runs.
  # shellcheck disable=SC2064  # expand probe_chain now so the trap is self-contained.
  trap "iptables -F '$probe_chain' 2>/dev/null || true; iptables -X '$probe_chain' 2>/dev/null || true" RETURN
  if ! err=$(iptables -A "$probe_chain" -m set --match-set allowed-domains dst -j RETURN 2>&1); then
    echo "ERROR: the firewall cannot filter outgoing traffic by ipset ($err)." >&2
    echo "The sandbox needs this, so it is refusing to start. Two likely causes:" >&2
    echo "  1. A capability the firewall container is missing. Check that" >&2
    echo "     sandbox/docker-compose.yml grants NET_ADMIN and NET_RAW to 'firewall'." >&2
    echo "  2. The Docker host's kernel lacks ipset support. Fixes by host:" >&2
    echo "       - OrbStack / Docker Desktop: update (or restart) to a current version." >&2
    echo "       - Linux host: sudo modprobe ip_set xt_set" >&2
    echo "       - or switch to a Docker provider whose kernel supports ipset." >&2
    iptables -F "$probe_chain" 2>/dev/null || true
    iptables -X "$probe_chain" 2>/dev/null || true
    exit 1
  fi
}
verify_ipset_match_support

# === Cross-session DNS-resolution cache (on by default) ===
# The resolved `domain<TAB>ip` records are persisted (on a firewall-only volume)
# and a subsequent launch seeds the ipset/dnsmasq from them instantly, moving the
# live resolve off the boot path into an immediate background refresh. ON by
# default; `AGENT_SANDBOX_DNS_CACHE=0` opts out. Default-on cannot widen egress,
# but that rests on a dependency chain, not on the seed-time shape-check alone
# (which only rejects malformed records — a poisoned loopback/private/metadata
# entry is a valid IPv4 and passes it): the cache lives on a firewall-only volume
# the workload cannot write (so it cannot poison it in the first place), and any
# bogon that did reach the ipset is dropped by the packet-layer BOGON_CIDRS rules
# placed before the allowed-domains ACCEPT. The immediate background refresh
# re-resolves live within seconds; DNS_CACHE_TTL bounds staleness, a cache older
# than it is ignored and the domains are resolved live (see dns_cache_fresh).
# Only the workload allowlist is cached — the runtime live-expansion overlay is
# resolved fresh, never persisted.
DNS_CACHE="${DNS_CACHE:-/var/cache/agent-sandbox/dns-resolved.tsv}"
DNS_CACHE_TTL="${DNS_CACHE_TTL:-3600}"
DNS_CACHE_ENABLED="${AGENT_SANDBOX_DNS_CACHE:-1}"
[[ "$DNS_CACHE_ENABLED" == "1" ]] && mkdir -p "$(dirname "$DNS_CACHE")"

# === Resolve all allowed domains and build ipset + static DNS ===
# Static address records (not server= forwarding) so dnsmasq never forwards
# upstream — zero DNS exfil, even via subdomain encoding of allowed domains.
DNSMASQ_CONF="/etc/dnsmasq.d/allowlist.conf"
mkdir -p /etc/dnsmasq.d

# Start the live-expansion overlay empty for this session; root-only as a backstop.
mkdir -p "$(dirname "$ALLOWLIST_OVERLAY")"
: >"$ALLOWLIST_OVERLAY"
chmod 600 "$ALLOWLIST_OVERLAY"

SANDBOX_IP="${SANDBOX_IP:-172.30.0.2}"
SANDBOX_SUBNET="${SANDBOX_SUBNET:-172.30.0.0/24}"

cat >/etc/dnsmasq.conf <<DNSMASQ_BASE
no-resolv
no-hosts
listen-address=127.0.0.1,$SANDBOX_IP
bind-interfaces
port=53
conf-dir=/etc/dnsmasq.d
DNSMASQ_BASE

# Default: NXDOMAIN for everything not explicitly allowed
echo "address=/#/" >"$DNSMASQ_CONF"

# Resolve via the shared batched resolver (firewall-lib.bash) so the build and the
# refresh loop populate the ipset identically. Batch size is env-overridable for
# resolvers with a different concurrency ceiling than Docker's embedded one.
DNS_BATCH_SIZE="${DNS_BATCH_SIZE:-30}"
# A zero or non-numeric size would make batch_resolve_a's `i += batch_size` loop
# never advance — fail loud rather than hang the launch.
if [[ ! "$DNS_BATCH_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: DNS_BATCH_SIZE must be a positive integer, got '$DNS_BATCH_SIZE'"
  exit 1
fi
declare -A _resolved

# Apply a file of `add <set> <ip>` lines with ONE `ipset restore` — a
# fork+netlink round trip per entry is a real launch cost on a long allowlist.
# `-exist` keeps duplicate entries benign. restore ABORTS at the first
# malformed line (unlike a per-entry add, which loses only that entry), so
# every writer must pre-validate what it appends; a failure here means entries
# were dropped — warn with the caller's context and return restore's status so
# a caller that must not act on a partial set (the refresh swap) can gate on
# it. Consumes (removes) the batch file.
apply_ipset_batch() {
  local file="$1" context="$2" status=0
  ipset restore -exist <"$file" || {
    status=$?
    echo "WARNING: ipset restore failed ($context) — some entries may be missing" >&2
    # Surface the swallowed failure on the trace channel too: callers suppress this
    # exit (|| true) because a partial set fails CLOSED (narrows reachability), but a
    # half-populated allowlist — DNS resolves yet the packet layer drops — must be
    # OBSERVABLE, not silent. Metadata only (the caller's context + restore's status).
    as_trace "${TRACE_FIREWALL_IPSET_BATCH_FAILED:-}" context="$context" status="$status"
  }
  rm -f "$file"
  return "$status"
}

# Guarantee <set> exists and is EMPTY for this refresh cycle, returning non-zero only
# when it can be neither (re)created nor flushed. The refresh loop runs under `set +e`,
# so a failed `ipset create` on a set left over from a crashed cycle (the preceding
# `ipset destroy ... || true` swallows a busy/in-use error) would NOT abort — the cycle
# would then `restore` its entries INTO the stale set and the swap install a set still
# carrying the prior cycle's residue, all while _batch_ok stayed 1. Flush as a fallback
# so the set is provably empty; if even that fails, report it so the caller skips the
# swap (leaving the still-valid live set untouched) instead of installing residue.
ensure_fresh_ipset() {
  local set="$1"
  ipset destroy "$set" 2>/dev/null || true
  ipset create "$set" hash:net 2>/dev/null && return 0
  ipset flush "$set" 2>/dev/null && return 0
  echo "WARNING: DNS refresh could not create or flush a fresh '$set' ipset; skipping this cycle's swap so a stale set is not installed (the live allowlist is unchanged)." >&2
  return 1
}

# Build the live ipset + static dnsmasq records from a stream of `domain<TAB>ip`
# pairs on stdin, marking each domain resolved. Shared by the cache-seed and
# live-resolve paths so both populate the set identically. Run as a plain
# redirected command (never the right side of a pipe) so the _resolved updates
# land in THIS shell, where the post-resolve zero-essentials check reads them.
# With a CACHE arg, the pairs are also written through to that file atomically
# (temp + mv) for the next session's warm boot.
_populate_stream() {
  local cache="${1:-}" domain ip tmp="" batch
  # Temp alongside the target (not /tmp) so the write-through is an atomic same-fs
  # rename, never a cross-device copy a concurrent reader could catch mid-write.
  [[ -n "$cache" ]] && tmp="$(mktemp "${cache}.XXXXXX")"
  batch="$(mktemp)"
  while IFS=$'\t' read -r domain ip; do
    # Shape-check every record so a corrupt cache (or any future caller) can't
    # inject a junk ipset/dnsmasq entry — and so no malformed line can reach the
    # batched restore, which would abort it mid-file. The live resolve path
    # already emits only valid IPv4, so this is a no-op there.
    valid_ipv4 "$ip" || continue
    # A record for a domain the CURRENT workload did not declare must not seed
    # the boundary: the cache volume can outlive a session, and a previous
    # workload's wider allowlist would otherwise widen this one's egress. The
    # live resolve path only feeds declared domains, so this too is a no-op there.
    [[ -n "${DOMAIN_ACCESS[$domain]:-}" ]] || continue
    printf 'add allowed-domains %s\n' "$ip" >>"$batch"
    echo "address=/$domain/$ip" >>"$DNSMASQ_CONF"
    _resolved["$domain"]=1
    [[ -n "$tmp" ]] && printf '%s\t%s\n' "$domain" "$ip" >>"$tmp"
  done
  # A restore failure degrades to a smaller set (some domains unreachable), so
  # warn-and-continue: the launch stays usable and the post-resolve count
  # reports what resolved.
  apply_ipset_batch "$batch" "allowlist build" || true # allow-exit-suppress: default-deny firewall: a failed allowlist build only narrows reachability (fails closed), never opens egress; see comment above
  # An `if` (not `[[ ]] &&`) so a no-cache call doesn't return 1 as its last
  # status and trip `set -e` in the caller. The write-through is best-effort: a
  # cache that can't be persisted just means the next boot resolves live, which
  # must never abort this one.
  if [[ -n "$tmp" ]]; then
    mv "$tmp" "$cache" || echo "WARNING: could not write DNS cache to $cache" >&2
  fi
}

_seeded_from_cache=0
_fast_ready=0
declare -a _essential_arr=()
mapfile -t _essential_arr < <(essential_domains)
if [[ ${#_essential_arr[@]} -eq 0 ]]; then
  echo "Deny-all boot: no domains to resolve; dnsmasq will NXDOMAIN everything and the packet layer admits nothing."
elif [[ "$DNS_CACHE_ENABLED" == "1" ]] && dns_cache_fresh "$DNS_CACHE" "$DNS_CACHE_TTL"; then
  # Warm boot: seed instantly from the previous session's resolved IPs and let the
  # background refresh below validate them live (kicked immediately, not in
  # REFRESH_INTERVAL seconds). Don't re-cache here — the seed IS the cache.
  _populate_stream <"$DNS_CACHE"
  _seeded_from_cache=1
  launch_trace_mark fw_cache_seeded
  echo "Seeded ${#_resolved[@]} domains from DNS cache ($DNS_CACHE); live re-resolve runs in background"
else
  # Cold boot: resolve the workload's declared allowlist synchronously — with
  # deny-all as the default, the declared set is small and IS the essential set
  # (essential_domains covers every tier: the tier is a method policy, not an
  # importance ranking). The background refresh below — kicked immediately via
  # _fast_ready — re-validates and keeps rotating CDN IPs fresh. This stays
  # fail-CLOSED throughout: a partially resolved allowed-domains set is strictly
  # MORE restrictive than the full one, and iptables -P OUTPUT DROP + the ipset
  # ACCEPT is the boundary, not squid.
  #
  # A partial result is deliberately NOT written through to DNS_CACHE (empty
  # cache arg): only the background full resolve may persist the cache (refresh
  # loop below), so the next boot's cache-fresh branch can never warm-seed a
  # partial subset.
  launch_trace_mark fw_resolve_start
  _populate_stream "" < <(
    cold_boot_resolve "$DNS_BATCH_SIZE" "${_essential_arr[@]}"
  )
  launch_trace_mark fw_resolve_done
  # Fail loud on a broken egress boundary: the workload DECLARED domains, yet not
  # one resolved — that is broken DNS (or a fully bogus allowlist), and marking
  # the firewall ready would hand the workload a session where every declared
  # host is unreachable with no signal. An EMPTY declaration never reaches this
  # branch: deny-all is a valid boot, handled above.
  if [[ ${#_resolved[@]} -eq 0 ]]; then
    echo "ERROR: the workload declared ${#_essential_arr[@]} egress domain(s) (${_essential_arr[*]}) but ZERO resolved at cold boot. Refusing to mark the firewall ready with a boundary the workload cannot use — failing closed." >&2
    exit 1
  fi
  _fast_ready=1
  echo "Cold boot: resolved ${#_resolved[@]}/${#_essential_arr[@]} declared domain(s) synchronously; the background refresh re-validates and picks up stragglers"
fi
launch_trace_mark fw_ipset_built

# === Host gateway ===
# Take the FIRST default route only: a host with several default routes would
# otherwise make HOST_IP a multi-line value (the "" guard below passes it through),
# yielding a confusing log line and a foot-gun for any future rule consuming it.
HOST_IP=$(ip route show default | awk '{print $3; exit}')
if [[ "$HOST_IP" = "" ]]; then
  echo "ERROR: Failed to detect host IP"
  exit 1
fi
echo "Host gateway detected as: $HOST_IP"

# No blanket host-gateway rules — traffic to the host IP would bypass the domain
# allowlist. Allowed-domain traffic routes through HOST_IP as a gateway, but the
# OUTPUT chain matches the final destination (not the gateway), so the ipset rule
# handles it; ESTABLISHED,RELATED covers return traffic.

# === Conntrack hardening ===
# Cap the conntrack table to prevent exhaustion attacks. 8192 is generous for
# legitimate use but bounds a workload opening thousands of connections. Each set
# is read back and warns loudly if it did not take (ensure_conntrack_sysctl), so a
# kernel/container where the sysctl is unavailable can't silently leave the table
# unbounded.
ensure_conntrack_sysctl net.netfilter.nf_conntrack_max 8192
ensure_conntrack_sysctl net.netfilter.nf_conntrack_tcp_timeout_established 300

# === IP firewall ===
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -s "$SANDBOX_SUBNET" -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -s "$SANDBOX_SUBNET" -p udp --dport 53 -j ACCEPT
iptables -A INPUT -s "$SANDBOX_SUBNET" -p tcp --dport 53 -j ACCEPT

# The OUTPUT-chain egress lockdown (loopback/subnet carve-outs, the packet-layer
# bogon backstop, the optional EGRESS_QUOTA_MB byte cap, ESTABLISHED return
# traffic, and the final REJECT — in that load-bearing order) lives in
# egress-rules.bash so the egress-quota e2e drives the exact same rules. It reads
# SANDBOX_SUBNET, BOGON_CIDRS, and EGRESS_QUOTA_MB from the environment set above.
install_egress_output_rules
launch_trace_mark fw_lockdown_done

echo "Firewall configuration complete"
# Announce the egress lockdown is in place, with the count of OUTPUT-chain rules now
# applied — proof the firewall layer ENGAGED rather than silently leaving egress open.
# Metadata only (a rule count, never the allowlist contents).
# `:-` keeps the no-trace fallback above (TRACE_* unset when trace-events.bash was
# never sourced) from tripping set -u; the no-op as_trace ignores the empty arg.
as_trace "${TRACE_FIREWALL_RULES_APPLIED:-}" rules="$(iptables -S OUTPUT 2>/dev/null | grep -c '^-A' || true)"

# Reachability probe target: a resolved declared domain, deterministic across
# boots (verify_probe_host sorts). Empty when the workload declared nothing —
# then there is nothing to allow-probe and only the deny probe applies.
_resolved_essential=()
while IFS= read -r domain; do
  [[ -n "${_resolved[$domain]:-}" ]] && _resolved_essential+=("$domain")
done < <(essential_domains)
_verify_host="$(verify_probe_host "${_resolved_essential[@]+"${_resolved_essential[@]}"}")"
if [[ "$SKIP_VERIFY" == "1" ]]; then
  echo "Skipping egress reachability verification (AGENT_SANDBOX_FIREWALL_SKIP_VERIFY=1 — no controlled external egress here)"
elif [[ -z "$_verify_host" && ${#_essential_arr[@]} -gt 0 ]]; then
  # Only reachable on a warm boot whose cache somehow held none of the declared
  # domains (the cold path already exits on zero resolved). A boundary the
  # workload cannot use is a broken session — fail closed rather than skip the
  # assertion.
  echo "ERROR: none of the workload's declared domains resolved — cannot verify egress; failing closed." >&2
  exit 1
else
  if [[ -n "$_verify_host" ]]; then
    echo "Verifying firewall rules (deny + allow probes in parallel)..."
  else
    echo "Verifying firewall rules (deny probe only — empty allowlist)..."
  fi
  # Run both probes concurrently so neither's wait serializes behind the other.
  # Both stay BLOCKING: the healthcheck must not flip green (ungating the
  # workload) until "egress is actually blocked" has been asserted — an async
  # deny probe would let the workload start inside an unverified window.
  #
  # The deny probe is SINGLE-SHOT and gets NO --max-time on purpose: a completed
  # handshake to example.com is itself the breach signal, curl exits 0 on the tiny
  # response well inside connect-timeout, and a retry or body cap could turn a real
  # breach (connected, then slow) into a false "blocked" pass. On a correct firewall
  # it fails INSTANTLY — the final OUTPUT rule REJECTs with icmp-admin-prohibited, so
  # curl gets an immediate connect error, not a timeout; the 2s connect-timeout costs
  # no launch time in the normal case and only bounds the abnormal one where the
  # probe's packets vanish without an answer (no SYN-ACK, no reject), which reads as
  # "blocked". The allow probe, by contrast, is a bare L4 TCP connect (_probe_tcp)
  # that RETRIES (verify_allow_reachable): lighter than a full TLS/HTTP exchange, and
  # a single slow connect under boot contention can't false-fail an otherwise-working
  # launch — see verify_allow_reachable's header for the bounded fail-closed semantics.
  curl --connect-timeout 2 https://example.com >/dev/null 2>&1 &
  _deny_pid=$!
  _allow_pid=""
  if [[ -n "$_verify_host" ]]; then
    verify_allow_reachable "$_verify_host" &
    _allow_pid=$!
  fi
  # `if wait` keeps a probe's non-zero exit from tripping `set -e`; each probe exits 0
  # only when it actually connected, so these flags read the reachability off it directly.
  _deny_reachable=0
  if wait "$_deny_pid"; then _deny_reachable=1; fi
  _allow_ok=1
  if [[ -n "$_allow_pid" ]]; then
    _allow_ok=0
    if wait "$_allow_pid"; then _allow_ok=1; fi
  fi
  if [[ "$_deny_reachable" == 1 ]]; then
    echo "ERROR: Firewall verification failed - was able to reach https://example.com"
    exit 1
  fi
  echo "Firewall verification passed - unable to reach https://example.com as expected"
  if [[ "$_allow_ok" != 1 ]]; then
    echo "ERROR: Firewall verification failed - unable to reach https://$_verify_host"
    exit 1
  fi
  if [[ -n "$_verify_host" ]]; then
    echo "Firewall verification passed - able to reach https://$_verify_host as expected"
  fi
fi

# === DNS lockdown ===
# Static records only — dnsmasq never forwards to Docker's resolver; block all
# DNS to it. Lock down DNS configs so the workload user can't read or modify them.
set_mode_then_owner 640 root:root /etc/dnsmasq.conf "$DNSMASQ_CONF"

dnsmasq --test && echo "dnsmasq config valid"
dnsmasq
echo "dnsmasq started — $(wc -l <"$DNSMASQ_CONF") rules (all static)"
launch_trace_mark fw_dnsmasq_up

iptables -D OUTPUT -p udp --dport 53 "${dns_dst[@]+"${dns_dst[@]}"}" -j ACCEPT
iptables -D INPUT -p udp --sport 53 "${dns_src[@]+"${dns_src[@]}"}" -j ACCEPT
iptables -D OUTPUT -p tcp --dport 53 "${dns_dst[@]+"${dns_dst[@]}"}" -j ACCEPT
iptables -D INPUT -p tcp --sport 53 "${dns_src[@]+"${dns_src[@]}"}" -j ACCEPT

# Allow DNS to local dnsmasq (loopback + sandbox interface)
iptables -I OUTPUT 1 -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
iptables -I INPUT 1 -p udp --sport 53 -s 127.0.0.1 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 53 -d "$SANDBOX_IP" -j ACCEPT
iptables -I OUTPUT 1 -p udp --sport 53 -s "$SANDBOX_IP" -j ACCEPT
iptables -I OUTPUT 1 -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT
iptables -I INPUT 1 -p tcp --sport 53 -s 127.0.0.1 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 53 -d "$SANDBOX_IP" -j ACCEPT
iptables -I OUTPUT 1 -p tcp --sport 53 -s "$SANDBOX_IP" -j ACCEPT

cp /etc/resolv.conf /etc/resolv.conf.docker
echo "nameserver 127.0.0.1" >/etc/resolv.conf
chmod 444 /etc/resolv.conf

echo "Verifying DNS allowlist..."
# "allowed domain resolves" depends on a declared domain having resolved during
# setup (live DNS); skipped where external DNS is unreliable and when the
# declaration is empty (nothing SHOULD resolve then). The "blocked domain →
# NXDOMAIN" check below is purely local to dnsmasq — the load-bearing exfil
# assertion — and always runs.
if [[ "$SKIP_VERIFY" != "1" && -n "$_verify_host" ]]; then
  if dig +short +timeout=2 @127.0.0.1 "$_verify_host" A | grep -q '^[0-9]'; then
    echo "DNS allowlist passed — allowed domain resolves"
  else
    echo "ERROR: DNS allowlist failed — allowed domain did not resolve"
    cat /etc/resolv.conf.docker >/etc/resolv.conf
    exit 1
  fi
fi
if dig +short +timeout=2 @127.0.0.1 evil-exfil.example.com A 2>/dev/null | grep -q '^[0-9]'; then
  echo "ERROR: DNS allowlist failed — blocked domain resolved"
  cat /etc/resolv.conf.docker >/etc/resolv.conf
  exit 1
else
  echo "DNS allowlist passed — blocked domain returns NXDOMAIN"
fi

# === Squid proxy for GET/HEAD-only domains ===
# The ro/rw split is NETWORK-enforced, not advisory: the workload container is on
# the `internal: true` sandbox network and this firewall never enables forwarding
# or MASQUERADE (FORWARD stays DROP), so the workload has NO route to any external
# IP — its only egress is squid at ${SANDBOX_IP}:3128. Unsetting http_proxy gains
# nothing (no route at all), so squid's ssl_bump method restriction on read-only
# domains is unbypassable.
# "rw" domains are spliced (no bump => no method restriction) but still transit
# squid.
echo "Configuring squid proxy for read-only domains..."

SQUID_CONF="/etc/squid/squid.conf"
RO_DOMAINS="/etc/squid/readonly-domains.txt"
RW_DOMAINS="/etc/squid/readwrite-domains.txt"

_ro_domains=()
_rw_domains=()
for domain in "${!DOMAIN_ACCESS[@]}"; do
  [[ "${DOMAIN_ACCESS[$domain]}" == "ro" ]] && _ro_domains+=("$domain")
  [[ "${DOMAIN_ACCESS[$domain]}" == "rw" ]] && _rw_domains+=("$domain")
done
write_ro_domains "$RO_DOMAINS" "${_ro_domains[@]+"${_ro_domains[@]}"}"
write_rw_domains "$RW_DOMAINS" "${_rw_domains[@]+"${_rw_domains[@]}"}"

# squid.conf + its read-only-domain denial page are generated by firewall-lib.bash
# so the same text can be rendered and `squid -k parse`-validated in CI (see
# .github/workflows/squid-config.yaml) — no CI job runs this live config otherwise.
write_squid_conf "$SANDBOX_IP" "$RO_DOMAINS" "$RW_DOMAINS" >"$SQUID_CONF"

# Placed in the en/ dir squid ships by default (the deny_info page lookup is
# pinned there via error_default_language en) rather than overriding
# error_directory globally, which would force ALL localized templates under a new
# dir and is fragile. Root-owned like the other squid configs.
SQUID_ERR_DIR="/usr/share/squid/errors/en"
# The dir is shipped by the squid package; write_squid_error_page would mkdir -p
# it regardless, so a squid upgrade that moved or renamed the error tree would
# silently land our deny pages where squid never reads them (the workload then
# sees squid's generic 403). The block still holds — fail closed — so warn loudly
# rather than abort, surfacing the layout drift for a maintainer to fix.
[[ -d "$SQUID_ERR_DIR" ]] || echo "WARNING: squid error directory $SQUID_ERR_DIR is missing — squid's error-template layout may have changed; the custom deny pages may not be served to the workload." >&2
write_squid_error_page "$SQUID_ERR_DIR"
set_mode_then_owner 644 root:proxy \
  "$SQUID_ERR_DIR/ERR_AGENT_SANDBOX_READONLY" "$SQUID_ERR_DIR/ERR_DNS_FAIL"

# Lock down squid configs — the workload user cannot read or modify them.
set_mode_then_owner 640 root:proxy "$SQUID_CONF" "$RO_DOMAINS" "$RW_DOMAINS"

# squid (proxy) writes access.log here. The image bakes /var/log/squid proxy:proxy
# 750, so the volume mount is already proxy-owned. prepare_squid_log_dir verifies
# that and fails loud otherwise; it never chmods/chowns (the firewall lacks
# CAP_FOWNER, and some volume backends ignore an in-container chown).
prepare_squid_log_dir /var/log/squid

# Validate the generated config before starting squid, surfacing squid's own
# diagnostics on failure. This per-launch parse plus the CI render-and-parse job
# are where a squid.conf regression is caught. Abort on parse failure rather than
# starting squid anyway (a non-fatal parse warning would otherwise launch a proxy
# that won't serve); exiting non-zero fails the firewall healthcheck and the
# launch (fail-closed).
if squid_parse_out=$(squid -k parse 2>&1); then
  echo "squid config valid"
else
  echo "ERROR: squid config parse failed — squid will not start. Diagnostics:" >&2
  printf '%s\n' "$squid_parse_out" >&2
  exit 1
fi
squid
echo "squid started — $(wc -l <"$RO_DOMAINS") read-only domains"
launch_trace_mark fw_squid_up

# === Background DNS refresh ===
# CDNs rotate IPs; re-resolve allowed domains every REFRESH_INTERVAL and update
# the ipset + dnsmasq so connections don't break when initial IPs go stale.
# This loop must NEVER re-run the iptables setup: re-adding the -m quota OUTPUT
# rule would reset the egress counter each cycle and silently defeat the cap, so
# the quota rule lives in the one-time setup only.
REFRESH_INTERVAL="${DNS_REFRESH_INTERVAL:-300}"

DOCKER_DNS=$(awk '$1=="nameserver"{print $2; exit}' /etc/resolv.conf.docker)

if [[ -z "$DOCKER_DNS" ]]; then
  echo "WARNING: No nameserver in resolv.conf.docker — DNS refresh disabled"
else

  # The window admits the Docker resolver plus the public fallback resolvers, so a
  # cycle re-resolves the CDN domains the embedded resolver sheds instead of evicting
  # them on the rebuild swap. Compute the list once so open and close pass an
  # identical set (dns_window in firewall-lib.bash deletes exactly what it inserts).
  mapfile -t DNS_WINDOW_SERVERS < <(
    printf '%s\n' "$DOCKER_DNS"
    fallback_resolvers
  )
  open_dns_window() { dns_window open "${DNS_WINDOW_SERVERS[@]}"; }
  close_dns_window() { dns_window close "${DNS_WINDOW_SERVERS[@]}"; }

  refresh_dns() {
    set +e
    trap close_dns_window EXIT
    # Stamp the liveness heartbeat on entry (before the first cycle's slow resolve) so
    # the launch's engagement confirmation below sees the refresher is alive within
    # milliseconds, not after a full allowlist resolve.
    refresh_touch_heartbeat "$REFRESH_HEARTBEAT_FILE"
    # Kick the first cycle IMMEDIATELY (not REFRESH_INTERVAL seconds out) on either
    # fast-ready boot path: a cache-seeded warm boot validates its (possibly stale)
    # seed against live DNS now, so a rotated/poisoned cached IP is corrected within
    # seconds; a cold boot's first cycle re-validates and picks up any straggler the
    # synchronous resolve missed (and writes the cross-session cache, below).
    local _next_delay="$REFRESH_INTERVAL"
    { [[ "${_seeded_from_cache:-0}" == "1" ]] || [[ "${_fast_ready:-0}" == "1" ]]; } &&
      _next_delay=0
    # Persists across cycles: a failed `squid -k reconfigure` leaves the on-disk ACL
    # files already updated, so a later cycle's `cmp` would see no change and never
    # retry. Carry the owed-reconfigure forward until sync_squid_acls succeeds.
    local _squid_reconfig_pending=0
    while true; do
      # Heartbeat at the top of every cycle, so a stale mtime means the loop stopped
      # iterating — the signal refresh_dns_alive checks (engaged iff still alive).
      refresh_touch_heartbeat "$REFRESH_HEARTBEAT_FILE"
      sleep "$_next_delay"
      _next_delay="$REFRESH_INTERVAL"

      local new_conf
      new_conf=$(mktemp /tmp/dnsmasq-refresh.XXXXXX)
      echo "address=/#/" >"$new_conf"

      # Rebuild the set from scratch each cycle so stale/rotated/poisoned IPs are
      # evicted rather than accumulating. Populate a fresh temp ipset, then
      # atomically `ipset swap` — the live set is never empty, so there is no
      # window where legitimate traffic is dropped.
      # Each temp set must be FRESH (created/flushed empty) this cycle; a leftover set
      # from a crashed cycle would otherwise be populated AND swapped in with its
      # residue. ensure_fresh_ipset folds that into _sets_fresh, which gates the swap.
      local _sets_fresh=1
      local new_set="allowed-domains-new"
      ensure_fresh_ipset "$new_set" || _sets_fresh=0

      # Entries for the rebuilt set are collected here and applied as ONE
      # `ipset restore` below — same batching as the initial build.
      local _ipset_batch
      _ipset_batch=$(mktemp /tmp/ipset-batch.XXXXXX)

      # Single DNS window for all domains — per-domain open/close would create
      # repeated brief exfil windows to Docker's resolver.
      open_dns_window
      # Merge the base allowlist with any live expansions (appended to the
      # overlay). Rebuilding from the union each cycle is what keeps an expanded
      # domain alive past the atomic `ipset swap` below; the access column is
      # carried so the squid ro list is reconciled too.
      local -A _cycle_access=()
      local d a
      for d in "${!DOMAIN_ACCESS[@]}"; do _cycle_access["$d"]="${DOMAIN_ACCESS[$d]}"; done
      if [[ -f "$ALLOWLIST_OVERLAY" ]]; then
        while IFS=$'\t' read -r d a; do
          [[ -n "$d" ]] && _cycle_access["$d"]="$a"
        done <"$ALLOWLIST_OVERLAY"
      fi
      # Same resolver path as the initial build (firewall-lib.bash): primary is the
      # Docker resolver, falling back to the public resolvers for the CDN domains it
      # sheds — both opened in the window above — so a domain the embedded resolver
      # drops is recovered this cycle (via retry or fallback) instead of being evicted
      # on the swap below. Capture the answers to a file so build_refreshed_addresses
      # can merge them with the last-known-good records still in $DNSMASQ_CONF.
      local resolved_tsv
      resolved_tsv=$(mktemp /tmp/dns-resolved.XXXXXX)
      resolve_with_fallback "$DOCKER_DNS" "${DNS_BATCH_SIZE:-30}" "${!_cycle_access[@]}" \
        >"$resolved_tsv"
      close_dns_window
      # Records (domain<TAB>ip lines) resolved THIS cycle. Gates the swap below: zero
      # means a total DNS outage, where we must keep the live set untouched rather
      # than swap in a set built purely from carried-forward IPs.
      local _resolved
      _resolved=$(wc -l <"$resolved_tsv")

      # Merge this cycle's answers with the last-known-good records from the current
      # conf: a domain that failed to resolve keeps its prior IPs instead of dropping
      # to dnsmasq's 0.0.0.0 default and being evicted (see build_refreshed_addresses).
      # Populate the fresh ipset from the SAME merged address list so dnsmasq and the
      # ipset never disagree about what a domain resolves to.
      local _line _rest _ip
      while IFS= read -r _line; do
        printf '%s\n' "$_line" >>"$new_conf"
        _rest="${_line#address=/}"
        _ip="${_rest##*/}"
        # Re-validate at the batch writer: a junk value that a per-entry add
        # would have lost alone is a malformed line that aborts the whole
        # restore, silently truncating the set. Skip it from the batch only —
        # the dnsmasq record above keeps the old per-add behavior.
        valid_ipv4 "$_ip" || continue
        printf 'add %s %s\n' "$new_set" "$_ip" >>"$_ipset_batch"
      done < <(build_refreshed_addresses "$DNSMASQ_CONF" "$resolved_tsv" "${!_cycle_access[@]}")
      rm -f "$resolved_tsv"
      # A failed restore means new_set is PARTIAL: gate the swap below on this
      # flag so a complete live set is never replaced by a truncated one.
      local _batch_ok=1
      apply_ipset_batch "$_ipset_batch" "DNS refresh" || _batch_ok=0

      # Atomic swap, then destroy the now-old set. Skip the swap on a total DNS
      # outage (nothing resolved this cycle): the merged set would then be built
      # purely from carried-forward IPs with no fresh confirmation, so leave the
      # already-equivalent live set untouched rather than churn it. Gating on the
      # resolution count — not the set size — is load-bearing: new_set is pre-seeded
      # with last-known-good DNS IPs, so a size check would pass on a total outage
      # and defeat this guard. _batch_ok likewise: a failed restore left new_set
      # partial, and swapping it in would evict working domains. _sets_fresh: a set
      # we could not rebuild empty this cycle may carry a crashed cycle's residue,
      # so it must not be swapped in.
      if [[ "$_resolved" -gt 0 && "$_batch_ok" == 1 && "$_sets_fresh" == 1 ]]; then
        ipset swap "$new_set" allowed-domains
        # Persist the FULL freshly-resolved set so the next boot can warm-seed from
        # it. This is the ONLY writer of DNS_CACHE: the cold boot writes no cache,
        # so the cache is never left a partial subset — it is either absent (no
        # successful full cycle yet) or the complete allowlist.
        # cacheable_dns_records drops the overlay records (dns-resolver.bash);
        # atomic temp+rename so a concurrent next-boot reader never catches a
        # half-written file. Gated on the same swap conditions so a partial/outage
        # cycle can't poison it.
        if [[ "$DNS_CACHE_ENABLED" == "1" ]]; then
          local _cache_tmp
          _cache_tmp=$(mktemp "${DNS_CACHE}.XXXXXX")
          cacheable_dns_records "$new_conf" >"$_cache_tmp"
          mv "$_cache_tmp" "$DNS_CACHE" 2>/dev/null ||
            {
              echo "WARNING: could not write DNS cache to $DNS_CACHE" >&2
              rm -f "$_cache_tmp"
            }
        fi
      fi
      ipset destroy "$new_set" 2>/dev/null || true

      if ! cmp -s "$new_conf" "$DNSMASQ_CONF"; then
        cp "$new_conf" "$DNSMASQ_CONF"
        chmod 640 "$DNSMASQ_CONF"
        # Drain the running dnsmasq and WAIT for it to release UDP/53 before
        # rebinding. Starting a new dnsmasq while the old one still holds the
        # socket fails with EADDRINUSE — a restart race that bites on slower
        # VM-backed Docker (Colima/macOS), where the old process exits a beat
        # after SIGTERM. Polling for the port to free beats a fixed sleep; force
        # a SIGKILL only if it refuses to die within the drain window.
        pkill -x dnsmasq 2>/dev/null || true
        local _drain=0
        while pgrep -x dnsmasq >/dev/null 2>&1; do
          _drain=$((_drain + 1))
          if [[ "$_drain" -ge 40 ]]; then
            pkill -9 -x dnsmasq 2>/dev/null || true
            sleep 0.5
            break
          fi
          sleep 0.25
        done
        if ! restart_dnsmasq 5; then
          # dnsmasq is down and won't return: the workload now has no resolver, so no
          # new egress can be resolved (fail-closed for connections). Exit the refresh
          # child loudly; the static iptables ipset from initial setup still admits
          # already-resolved IPs. The supervisor (supervise_refresher) reaps this exit,
          # logs it, and respawns the loop — which retries dnsmasq, so a transient
          # failure self-heals instead of permanently freezing the allowlist. (`exit`
          # ends only this backgrounded refresh child, not the supervisor or PID 1.)
          echo "CRITICAL: dnsmasq failed to restart after 5 attempts — DNS refresh cycle aborting; workload resolver is down (fail-closed). Supervisor will respawn and retry." >&2
          exit 1
        fi
      fi
      rm -f "$new_conf"

      # Reconcile squid's read-only ACL from base + overlay so an expanded ro
      # domain's method restriction is maintained declaratively here, not left to
      # a one-shot append. Regenerate into a temp file and reconfigure only when
      # it actually changed (write_ro_domains sorts, so the no-expansion steady
      # state is byte-identical and never churns squid).
      local ro_new rw_new _ro=() _rw=()
      for d in "${!_cycle_access[@]}"; do
        [[ "${_cycle_access[$d]}" == "ro" ]] && _ro+=("$d")
        [[ "${_cycle_access[$d]}" == "rw" ]] && _rw+=("$d")
      done
      ro_new=$(mktemp /tmp/ro-domains.XXXXXX)
      rw_new=$(mktemp /tmp/rw-domains.XXXXXX)
      write_ro_domains "$ro_new" "${_ro[@]+"${_ro[@]}"}"
      write_rw_domains "$rw_new" "${_rw[@]+"${_rw[@]}"}"
      if sync_squid_acls "$ro_new" "$rw_new" "$RO_DOMAINS" "$RW_DOMAINS" "$_squid_reconfig_pending"; then
        _squid_reconfig_pending=0
      else
        _squid_reconfig_pending=1
      fi
      rm -f "$ro_new" "$rw_new"
    done
  }
  # Supervise the refresher so its death is detectable and loud (it respawns on exit),
  # then confirm it is provably ALIVE before announcing engagement — a DNS-name
  # allowlist must keep re-resolving (CDN IPs rotate), so a dead refresher silently
  # freezes the allowlist and starves legitimate traffic with no signal otherwise.
  supervise_refresher refresh_dns &
  printf '%s\n' "$!" >"$REFRESH_PID_FILE"
  # Engaged iff ALIVE, not iff spawned: block (briefly) until the refresher is up and has
  # stamped its first heartbeat (proving it started, not merely that the `&` returned). If
  # it never comes up, fail the launch closed — refusing to touch firewall-ready with a
  # frozen allowlist — so the required firewall_refresh_supervised event stays absent and
  # an engagement self-test goes red instead of a starving session looking healthy.
  if ! confirm_refresher_engaged "$REFRESH_PID_FILE" "$REFRESH_HEARTBEAT_FILE" "${REFRESH_ENGAGE_TIMEOUT:-10}"; then
    echo "ERROR: DNS refresher did not become live within ${REFRESH_ENGAGE_TIMEOUT:-10}s — refusing to mark the firewall ready with a frozen allowlist (fail closed)." >&2
    exit 1
  fi
  echo "DNS refresh loop started + supervised (every ${REFRESH_INTERVAL}s)"
  # Announce the refresher ENGAGED and is alive — the firewall's only continuously-running
  # defense, so its liveness is a startup-deterministic engagement a self-test can assert.
  # `:-` keeps the no-trace fallback from tripping set -u; the no-op as_trace ignores the
  # empty arg.
  as_trace "${TRACE_FIREWALL_REFRESH_SUPERVISED:-}" interval="$REFRESH_INTERVAL"

fi

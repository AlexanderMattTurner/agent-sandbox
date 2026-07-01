# shellcheck shell=bash
# ip-validation.bash — IP/domain admission-control helpers: shape validators,
# bogon filter and access-tier checker. Sourced by
# firewall-lib.bash; do not execute directly.

valid_ipv4() {
  local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
  [[ "$1" =~ ^$octet\.$octet\.$octet\.$octet$ ]]
}

# valid_domain_name NAME — true when NAME is a bare hostname: letters/digits/dot/
# hyphen, at least one dot, no leading/trailing dot or hyphen. Rejects URLs, ports,
# IPs-as-domains, whitespace, and shell metacharacters. Vets a domain before it
# reaches DOMAIN_ACCESS, dnsmasq, or the squid dstdomain ACL — so an unvalidated
# value from an untrusted workload record can't seed a junk entry there.
valid_domain_name() {
  local name="$1" label
  # Length bounds (RFC 1035: name <= 253, label <= 63). The shape regex alone is
  # unbounded, so an attacker-influenceable workspace config could
  # otherwise seed a multi-KB dnsmasq `address=`/squid `dstdomain` line that fails
  # the config reload and bricks the launch.
  [[ "${#name}" -le 253 ]] || return 1
  # The shape regex admits a dotted-decimal IPv4 literal (all digits and dots),
  # which has no business seeding a dnsmasq/squid entry — reject it explicitly so
  # the contract above holds.
  [[ "$name" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$name" == *.* ]] || return 1
  ! valid_ipv4 "$name" || return 1
  # Per-label bounds. Splitting on a non-whitespace IFS keeps empty fields, so the
  # `>= 1` check below doubles as the consecutive-dot (`a..b`) rejection the charset
  # regex otherwise admits.
  local -a labels=()
  IFS=. read -ra labels <<<"$name"
  local label
  for label in "${labels[@]}"; do
    [[ "${#label}" -ge 1 && "${#label}" -le 63 ]] || return 1
    # RFC 1035: a label starts and ends with an alnum, never a hyphen. The
    # whole-name shape regex above only bounds the FIRST and LAST char of the
    # entire dotted string, so an interior label like the second one in
    # "foo.-bar.com" or "foo.bar-.com" slipped through unchecked.
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
  return 0
}

# punycode_or_non_ascii NAME — true when NAME carries an `xn--` punycode label or
# any non-ASCII byte: the shapes a homoglyph/IDN lookalike hides behind (e.g.
# `xn--ppl-…` rendering as a near-twin of an allowlisted host). valid_domain_name
# already rejects the raw non-ASCII case, so on the workload-record path this fires on
# punycode; the predicate keeps both arms to mirror the host-side challenge in
# the host-side allowlist-widen path and stay correct for any caller that admits non-ASCII.
punycode_or_non_ascii() {
  [[ "$1" == *xn--* || "$1" == *[^a-zA-Z0-9._-]* ]]
}

# add_workload_domains ACCESS — read newline-separated domains on stdin and record
# each, at tier ACCESS (ro|rw), into the caller's DOMAIN_ACCESS map. The launcher
# feeds the Workload record's egress_allowlist here, partitioned by tier; each name
# is shape-checked (valid_domain_name) before it can seed a dnsmasq address= record
# or a squid dstdomain ACL. A malformed entry is skipped with a warning, not fatal:
# a junk value in a workload record must not brick the launch, and skipping it can
# only ever NARROW egress, never widen it.
# Call ro first then rw so an explicit rw escalation wins when a domain is in both.
add_workload_domains() {
  local access="$1" domain
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    if ! valid_domain_name "$domain"; then
      echo "WARNING: ignoring malformed workload $access domain '$domain'" >&2
      continue
    fi
    # A punycode/non-ASCII entry is REJECTED by default: there is no human retype
    # on this path, so an `xn--` lookalike in a workload record would otherwise
    # seed the firewall with a near-twin of an allowlisted host and no visible
    # cue. A workload record may come from an untrusted repo, so we fail closed
    # (dropping an entry only ever narrows egress). An operator who genuinely
    # needs an IDN host opts in with AGENT_SANDBOX_ALLOW_WORKLOAD_IDN=1, which
    # downgrades this to warn-and-admit.
    if punycode_or_non_ascii "$domain"; then
      if [[ "${AGENT_SANDBOX_ALLOW_WORKLOAD_IDN:-0}" != "1" ]]; then
        echo "WARNING: rejecting workload $access domain '$domain' — it contains punycode (xn--) or non-ASCII characters, a classic lookalike-domain trick, and there is no interactive confirmation on this path. Set AGENT_SANDBOX_ALLOW_WORKLOAD_IDN=1 to admit IDN hosts from workload records." >&2
        continue
      fi
      echo "WARNING: admitting workload $access domain '$domain' with punycode/non-ASCII (AGENT_SANDBOX_ALLOW_WORKLOAD_IDN=1) — a classic lookalike-domain trick. Verify it is the host you intend before trusting this allowlist." >&2
    fi
    # DOMAIN_ACCESS is the caller's global (declared in init-firewall.bash); we only
    # write it here, so shellcheck can't see the reads at the call site.
    # shellcheck disable=SC2034
    DOMAIN_ACCESS["$domain"]="$access"
  done
}

# BOGON_CIDRS — IPv4 ranges an allowlisted domain must never be allowed to reach:
# this-network, loopback, link-local (incl. the 169.254.169.254 cloud-metadata
# endpoint), RFC1918 + CGNAT private space, multicast and reserved. Also the IETF
# protocol-assignment block (192.0.0.0/24, incl. DS-Lite), the three TEST-NET
# documentation ranges, and the 198.18.0.0/15 benchmarking block — all
# non-routable, so a rebound A record pointing into them must not seed the egress
# ipset (some are locally reachable on certain host/router configs). Single source
# of truth, consumed by both the resolve-time filter (is_public_ipv4) and the
# packet-layer egress DROP rules in init-firewall.bash, so the two cannot drift.
# The per-session sandbox subnets (172.30.x.0/24) fall inside 172.16/12, so a
# rebind onto a sandbox-network service is covered.
BOGON_CIDRS=(
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
  172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4
  192.0.0.0/24 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24
)

# is_public_ipv4 IP — false for any address inside BOGON_CIDRS. Delegates the
# range match to grepcidr (a purpose-built IP-in-CIDR matcher) instead of
# hand-rolled octet math. A records are attacker-influenceable — a poisoned or
# rebound answer for ANY allowlisted domain would otherwise enter the egress
# ipset and hand the firewall a route to an internal target — so every resolved
# IP passes through here before `ipset add`. grepcidr exits 0 when the IP matches
# a bogon range (non-public) and 1 when it matches none (public). The helper
# returns "public" only on a literal exit 1, so a missing or killed grepcidr
# (exit 127 / signal) reports non-public and the build/refresh drops the IP
# loudly rather than admitting an unchecked one. BOGON_CIDRS is a hardcoded valid
# pattern and valid_ipv4 already vetted the shape, so the live exit is only ever
# 0 or 1. Operator-configured static CIDRs are trusted and do NOT pass here.
is_public_ipv4() {
  # IFS=' ' so ${BOGON_CIDRS[*]} space-joins into a single grepcidr pattern arg.
  local rc=0 IFS=' '
  printf '%s\n' "$1" | grepcidr "${BOGON_CIDRS[*]}" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -eq 1 ]]
}

# set_mode_then_owner MODE OWNER PATH... — apply MODE to every PATH, THEN hand them
# to OWNER, always in that order. The order is a security invariant, not style:
# while root still owns a path the chmod needs no capability, but once it is chowned
# away from root the chmod would require CAP_FOWNER — which the firewall service does
# NOT hold — and EPERM-abort init-firewall, hanging the launch on a healthcheck that
# never goes green. Funnelling every chmod+chown pair through here makes that order
# impossible to get backwards at a call site.
# chown preserves the mode (the modes here carry no setuid/setgid bits to strip), so
# the result is MODE owned by OWNER. Fails loudly: a denied chmod/chown aborts under
# the caller's `set -e` rather than leaving a half-applied permission.

validate_access() {
  local access="$1" what="${2:-access}"
  [[ "$access" == "ro" || "$access" == "rw" ]] && return 0
  echo "ERROR: $what has invalid access '$access' (expected ro or rw)." >&2
  return 1
}

# essential_domains — the domains resolved synchronously at cold boot, one per
# line: EVERY domain in the live DOMAIN_ACCESS map, all tiers. The tier is a
# method policy (GET/HEAD vs all), not an importance ranking — a workload that
# declared only ro hosts still cannot function until they resolve, so the whole
# declared allowlist is the essential set. init-firewall.bash resolves these
# synchronously to reach "firewall ready" and fails closed when a NON-EMPTY
# allowlist resolves zero of them (broken DNS); an empty allowlist boots a valid
# deny-all firewall with nothing to resolve.
essential_domains() {
  local d
  for d in "${!DOMAIN_ACCESS[@]}"; do
    printf '%s\n' "$d"
  done
  return 0
}

# verify_probe_host DOMAIN... — pick init-firewall's post-lockdown reachability
# allow-probe target from the RESOLVED essential domains passed as arguments.
# Returns the lexicographically-first argument so the choice is DETERMINISTIC:
# essential_domains emits in associative-array hash order, which differs across
# bash builds (Linux CI vs the macOS host), so an unsorted "first resolved"
# silently probed a different target on one host than another. Prints nothing when
# given no arguments (no resolved essential — init-firewall fails closed on that
# separately).
verify_probe_host() {
  (($# == 0)) && return 0
  local sorted
  mapfile -t sorted < <(printf '%s\n' "$@" | LC_ALL=C sort)
  printf '%s\n' "${sorted[0]}"
}

# _probe_tcp HOST — bare TCP SYN→SYN-ACK to HOST:443 with a 5-second bound.
# Uses bash's /dev/tcp pseudo-device (no external binary, no TLS, no HTTP) so
# the probe is as lightweight as possible and tests exactly what the firewall
# enforces: an iptables ACCEPT for the destination IP (via ipset) on port 443.
# Runs in the FIREWALL's netns, whose OUTPUT chain admits every resolved
# allowlist IP (the ipset is tier-blind), so an L4 connect is a valid egress
# assertion for a host of either tier — the ro/rw method split is squid's
# concern and applies to the workload's proxied traffic, not to this netns.
# Extracted as a named function so tests can redefine it rather than faking a
# binary on PATH (bash's /dev/tcp is a builtin; PATH tricks can't intercept it).
_probe_tcp() {
  # shellcheck disable=SC2016  # no-expansion quoting is the point: $0 expands in the inner bash
  timeout 5 bash -c '>"/dev/tcp/$0/443"' "$1" 2>/dev/null
}

# verify_allow_reachable HOST — assert the allowlisted egress path to HOST works,
# RETRYING a few times before giving up. A single slow TCP connect to the
# rw endpoint can exceed one attempt's budget when several sandboxes share an
# uplink (CPU and network contention at boot); without a retry that transient
# slowness false-failed the entire launch with "unable to reach <host>" and forced
# a manual re-run. Returns 0 the instant one attempt connects, so a healthy launch
# pays for no retries and no sleeps; returns non-zero only after EVERY attempt
# fails, so the firewall still fails CLOSED on a genuinely-broken egress path.
# Attempt count and inter-attempt delay are tunable via the two env vars.
verify_allow_reachable() {
  local host="$1"
  local attempts="${AGENT_SANDBOX_ALLOW_PROBE_ATTEMPTS:-3}"
  local delay="${AGENT_SANDBOX_ALLOW_PROBE_DELAY:-1}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    _probe_tcp "$host" && return 0
    ((i < attempts)) && sleep "$delay"
  done
  return 1
}

# write_ro_domains OUTFILE [RO_DOMAIN...] — render squid's dstdomain ACL: one
# `.domain` line per read-only domain. A domain whose parent is also read-only is
# omitted, since dstdomain ".foo.com" already matches every subdomain. Output is
# sorted so the refresh loop's per-cycle regeneration is byte-stable and doesn't
# churn `squid -k reconfigure` when nothing changed.

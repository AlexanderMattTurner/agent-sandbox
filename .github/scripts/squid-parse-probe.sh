#!/bin/bash
# Runs INSIDE the agent-sandbox firewall image: render the squid configs with the
# REAL generators (the exact bytes init-firewall.bash writes) and have the squid
# binary validate each with `squid -k parse` — the config-equivalence pin. Three
# shapes are pinned: a mixed ro/rw allowlist, the empty deny-all boot, and the
# allow-all bypass.
set -Eeuo pipefail

# shellcheck source=/dev/null
source /usr/local/bin/firewall-lib.bash

RO=/etc/squid/readonly-domains.txt
RW=/etc/squid/readwrite-domains.txt
ERR_DIR=/usr/share/squid/errors/en
write_squid_error_page "$ERR_DIR"

parse() { # <label>
  local out
  if out=$(squid -k parse 2>&1); then
    echo "PASS: squid -k parse ($1)"
  else
    echo "FAIL: squid -k parse ($1):" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi
}

write_ro_domains "$RO" ro.example github.com
write_rw_domains "$RW" rw.example
write_squid_conf 172.30.0.2 "$RO" "$RW" >/etc/squid/squid.conf
parse "mixed ro/rw allowlist"

write_ro_domains "$RO"
write_rw_domains "$RW"
write_squid_conf 172.30.0.2 "$RO" "$RW" >/etc/squid/squid.conf
parse "empty deny-all allowlist"

write_squid_allow_all_conf 172.30.0.2 >/etc/squid/squid.conf
parse "allow-all bypass"

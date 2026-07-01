"""Guards for the EGRESS_QUOTA_MB OUTPUT rules.

The actual byte-cap ENFORCEMENT (a kernel `-m quota` match dropping real traffic)
needs NET_ADMIN and a real container, so it is proven by a privileged e2e, never
under pytest here.

What pytest verifies, with no container:
  - The rules live in exactly one place: install_egress_output_rules
    (egress-rules.bash, loaded via firewall-lib.bash), and the load-bearing ordering
    holds in that one source.
  - The rule the function EMITS: by driving the function against a recording
    `iptables` stub (capturing argv), we assert the quota ACCEPT carries
    `--quota <EGRESS_QUOTA_MB * 1048576>` for several budgets — so a regression in
    the byte arithmetic or the matcher is caught here every run. This is a behavioral
    check of the emitted command, not a text grep of the source, so a reword that
    still emits the wrong bytes is caught too.
"""

import re
import subprocess

from tests._helpers import REPO_ROOT

FIREWALL_LIB = REPO_ROOT / "sandbox" / "firewall-lib.bash"
EGRESS_RULES = REPO_ROOT / "sandbox" / "egress-rules.bash"

# The two load-bearing rules as egress-rules.bash writes them, with each line's
# leading indentation stripped (the function body indents them, the continuation
# line is indented again). A reword of the matcher/target/quota breaks this.
QUOTA_ACCEPT = (
    "iptables -A OUTPUT -m set --match-set allowed-domains dst \\\n"
    "-m quota --quota $((EGRESS_QUOTA * 1048576)) -j ACCEPT"
)
OVER_QUOTA_REJECT = (
    "iptables -A OUTPUT -m set --match-set allowed-domains dst \\\n"
    "-j REJECT --reject-with icmp-admin-prohibited"
)
ESTABLISHED_ACCEPT = "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"


def _dedented(path) -> str:
    # Strip leading whitespace from every line so the function-body indentation
    # doesn't defeat the rule-text match.
    return "\n".join(line.lstrip() for line in path.read_text().splitlines())


def test_egress_rules_is_the_single_source_of_the_quota_rules() -> None:
    # The quota ACCEPT and over-quota REJECT live in exactly one place —
    # egress-rules.bash's install_egress_output_rules.
    rules = _dedented(EGRESS_RULES)
    assert "install_egress_output_rules()" in EGRESS_RULES.read_text()
    assert QUOTA_ACCEPT in rules, "quota ACCEPT rule missing from egress-rules.bash"
    assert OVER_QUOTA_REJECT in rules, (
        "over-quota REJECT missing from egress-rules.bash"
    )


def test_firewall_lib_sources_egress_rules() -> None:
    # Consumers reach install_egress_output_rules through the one firewall-lib.bash
    # entry point, so it must source egress-rules.bash.
    assert "egress-rules.bash" in FIREWALL_LIB.read_text(), (
        "firewall-lib.bash must source egress-rules.bash so consumers get the function"
    )


def test_egress_rules_orders_quota_before_established() -> None:
    # The load-bearing invariant, asserted statically against the single source: the
    # quota ACCEPT and its over-quota REJECT must BOTH precede the OUTPUT ESTABLISHED
    # accept. A prior ESTABLISHED accept would short-circuit bulk packets and
    # -m quota would only ever see NEW SYNs.
    rules = _dedented(EGRESS_RULES)
    quota = rules.index(QUOTA_ACCEPT)
    reject = rules.index(OVER_QUOTA_REJECT)
    est = rules.index(ESTABLISHED_ACCEPT, quota)
    assert quota < est, "quota ACCEPT must precede the OUTPUT ESTABLISHED accept"
    assert reject < est, "over-quota REJECT must precede the OUTPUT ESTABLISHED accept"


def _emitted_output_rules(quota_mb: str) -> list:
    """Source egress-rules.bash, replace `iptables` with a recording shell function
    (one rule per stdout line), and run install_egress_output_rules with
    EGRESS_QUOTA_MB=quota_mb against a minimal environment. Returns the emitted rules
    in order. No kernel, no NET_ADMIN — we observe the exact argv the function would
    hand iptables, which is the byte arithmetic the e2e proves enforces."""
    script = f"""
        set -euo pipefail
        source "{EGRESS_RULES}"
        # Record each invocation's full argv as one line, joined by single spaces.
        iptables() {{ printf '%s\\n' "$*"; }}
        SANDBOX_SUBNET="172.30.0.0/24"
        MONITOR_NTFY_HOST=""
        BOGON_CIDRS=("10.0.0.0/8")
        export EGRESS_QUOTA_MB="{quota_mb}"
        install_egress_output_rules
    """
    r = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    )
    return r.stdout.splitlines()


def test_quota_rule_emits_the_byte_value_for_each_budget() -> None:
    # The byte arithmetic IS the cap: --quota must be EGRESS_QUOTA_MB * 1048576.
    # Drive several budgets so the multiplication (not just one hardcoded value) is
    # pinned — a regression to *1024, *1000, or a dropped factor fails here.
    for mb in (1, 5, 100):
        rules = _emitted_output_rules(str(mb))
        quota = [
            r
            for r in rules
            if "--match-set allowed-domains dst" in r and "--quota" in r
        ]
        assert len(quota) == 1, f"expected exactly one quota ACCEPT rule, got {quota}"
        m = re.search(r"--quota (?P<bytes>\d+)", quota[0])
        assert m, f"no --quota byte value in the emitted rule: {quota[0]}"
        assert int(m.group("bytes")) == mb * 1048576, (
            f"EGRESS_QUOTA_MB={mb} emitted --quota {m.group('bytes')}, "
            f"expected {mb * 1048576} ({mb} MiB)"
        )
        # The matched quota ACCEPT targets ACCEPT, and its over-quota sibling REJECTs.
        assert quota[0].rstrip().endswith("-j ACCEPT")
        reject = [
            r for r in rules if "--match-set allowed-domains dst" in r and "REJECT" in r
        ]
        assert reject and "icmp-admin-prohibited" in reject[0]


def test_empty_bogon_cidrs_fails_loud_before_installing_rules() -> None:
    # BOGON_CIDRS is the packet-layer metadata/RFC1918 backstop. An empty (or unset)
    # array would otherwise install the OUTPUT chain WITHOUT it — a silent hole. The
    # function must fail loud (non-zero, named error) before emitting any iptables rule.
    for decl in ("BOGON_CIDRS=()", "# BOGON_CIDRS deliberately unset"):
        script = f"""
            set -euo pipefail
            source "{EGRESS_RULES}"
            iptables() {{ printf 'RULE %s\\n' "$*"; }}
            SANDBOX_SUBNET="172.30.0.0/24"
            MONITOR_NTFY_HOST=""
            {decl}
            install_egress_output_rules
        """
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert r.returncode != 0, f"expected failure for [{decl}], got success"
        assert "BOGON_CIDRS is empty" in r.stderr
        assert "RULE " not in r.stdout  # no partial chain installed


def test_input_validation_errors_return_not_exit() -> None:
    # egress-rules.bash is SOURCED (firewall-lib.bash), so an input-validation arm
    # must `return` non-zero, never `exit` — an `exit` would kill not just
    # init-firewall (which aborts on the non-zero return under set -e all the same)
    # but any other consumer that sources the lib, including the test harness. Prove
    # the contract behaviorally: a caller can CATCH the failure and keep running. A
    # regression to `exit` makes the shell die and the AFTER sentinel never prints.
    # The recoverable-input arm: the empty-BOGON backstop (an unset/empty array must
    # refuse to install the OUTPUT chain without the metadata/RFC1918 packet backstop).
    cases = {
        "BOGON_CIDRS": "BOGON_CIDRS=()",
    }
    for label, setup in cases.items():
        script = f"""
            source "{EGRESS_RULES}"
            iptables() {{ :; }}
            SANDBOX_SUBNET="172.30.0.0/24"
            {setup}
            if install_egress_output_rules; then
              echo "UNEXPECTED-OK"
            else
              echo "CAUGHT-RC-$?"
            fi
            echo "AFTER-SURVIVED"
        """
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        # No `set -e` here on purpose: this models a consumer that wants to handle the
        # failure itself. If the function `exit`ed, AFTER-SURVIVED never prints.
        assert "AFTER-SURVIVED" in r.stdout, (
            f"[{label}] sourcing shell did not survive — the function exited instead "
            f"of returning. stdout={r.stdout!r} stderr={r.stderr!r}"
        )
        assert "CAUGHT-RC-" in r.stdout and "UNEXPECTED-OK" not in r.stdout


def test_quota_disabled_emits_a_plain_accept_with_no_quota() -> None:
    # EGRESS_QUOTA_MB=0 (the default) must install a plain allowed-domains ACCEPT
    # with NO -m quota and NO over-quota REJECT — the opt-in is genuinely off, not a
    # zero-byte cap that would brick all egress instantly.
    rules = _emitted_output_rules("0")
    allowed = [r for r in rules if "--match-set allowed-domains dst" in r]
    assert allowed == ["-A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT"], (
        f"quota off must emit a single plain ACCEPT, got {allowed}"
    )
    assert not any("--quota" in r for r in rules)

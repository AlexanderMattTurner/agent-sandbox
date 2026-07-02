"""Tests for live firewall allowlist expansion.

`sandbox/expand-allowlist.bash` widens the running firewall WITHOUT resetting it —
no `iptables -F`, no `ipset destroy`. These tests drive it with stubbed firewall
binaries (ipset/iptables/dig/dnsmasq/squid) on PATH and temp-file overrides for
every path it writes, so the apply path runs hermetically off a real sandbox.
The host-side `agent-sandbox expand` verb is covered by tests/test_expand_cli.py.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT, run_capture, write_exe

EXPAND = REPO_ROOT / "sandbox" / "expand-allowlist.bash"
INIT_FIREWALL = REPO_ROOT / "sandbox" / "init-firewall.bash"

# Stub firewall binaries. `ipset add` appends the IP to $IPSET_LOG so a test can
# assert the live set was populated; `ipset list -name` reports the set exists
# unless $IPSET_MISSING is set. `dig` answers $FAKE_IP per queried domain unless
# the domain is space-listed in $NORESOLVE (empty FAKE_IP => unresolvable).
_STUBS = {
    "id": "#!/bin/sh\necho 0\n",
    "iptables": "#!/bin/sh\nexit 0\n",
    "ipset": (
        "#!/bin/sh\n"
        'if [ "$1" = "list" ] && [ "$2" = "-name" ]; then\n'
        '  [ -n "$IPSET_MISSING" ] && exit 1\n'
        "  exit 0\n"
        "fi\n"
        # `add` to a destroyed set fails for real, so model that under $IPSET_MISSING —
        # the point-of-use guard in expand-allowlist.bash detects the missing set on the
        # add failure, not via an up-front check.
        'if [ "$1" = "add" ]; then\n'
        '  [ -n "$IPSET_MISSING" ] && exit 1\n'
        '  echo "$3" >>"$IPSET_LOG"\n'
        "fi\n"
        "exit 0\n"
    ),
    # expand-allowlist resolves via the shared batch_resolve_a, which calls
    # `dig +noall +answer -f <file>`. The stub pulls the query file, and for each
    # domain NOT space-listed in $NORESOLVE prints an answer-section A record
    # `<domain>.\t300\tIN\tA\t$FAKE_IP`, so a test can exercise partial resolution
    # within one batch.
    "dig": (
        "#!/bin/sh\n"
        'qfile=""\n'
        "while [ $# -gt 0 ]; do\n"
        '  if [ "$1" = "-f" ]; then qfile="$2"; shift 2; continue; fi\n'
        "  shift\n"
        "done\n"
        '[ -n "$qfile" ] || exit 0\n'
        "while IFS= read -r d; do\n"
        '  [ -n "$d" ] || continue\n'
        '  case " $NORESOLVE " in *" $d "*) continue ;; esac\n'
        '  [ -n "$FAKE_IP" ] && printf \'%s.\\t300\\tIN\\tA\\t%s\\n\' "$d" "$FAKE_IP"\n'
        'done <"$qfile"\n'
        "exit 0\n"
    ),
    "dnsmasq": "#!/bin/sh\nexit 0\n",
    "pkill": "#!/bin/sh\nexit 0\n",
    # Stateful: the drain loop's first probe must see "no dnsmasq left" (exit 1, so
    # the drain never spins), while restart_dnsmasq's follow-up liveness probe must
    # see the restarted daemon running (exit 0) or the restart reads as failed.
    "pgrep": (
        "#!/bin/sh\n"
        'if [ ! -f "$PGREP_STATE" ]; then\n'
        '  : >"$PGREP_STATE"\n'
        "  exit 1\n"
        "fi\n"
        "exit 0\n"
    ),
    "squid": "#!/bin/sh\nexit 0\n",
    # No-op so the config-hardening chown (root:proxy) doesn't depend on a
    # `proxy` group existing on the test host.
    "chown": "#!/bin/sh\nexit 0\n",
}


@pytest.fixture
def fake_fw(tmp_path: Path) -> dict:
    """A stubbed firewall environment: PATH-shadowing binaries plus temp files
    for the overlay, dnsmasq conf, squid ACLs, and Docker resolv.conf."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    for name, body in _STUBS.items():
        write_exe(stub_dir / name, body)

    overlay = tmp_path / "overlay.tsv"
    dnsmasq_conf = tmp_path / "allowlist.conf"
    ro_domains = tmp_path / "readonly-domains.txt"
    ro_domains.write_text("")
    rw_domains = tmp_path / "readwrite-domains.txt"
    rw_domains.write_text("")
    resolv = tmp_path / "resolv.conf.docker"
    resolv.write_text("nameserver 9.9.9.9\n")
    ipset_log = tmp_path / "ipset.log"

    env = {
        **os.environ,
        "PATH": f"{stub_dir}:{os.environ['PATH']}",
        "ALLOWLIST_OVERLAY": str(overlay),
        "DNSMASQ_CONF": str(dnsmasq_conf),
        "RO_DOMAINS": str(ro_domains),
        "RW_DOMAINS": str(rw_domains),
        "RESOLV_DOCKER": str(resolv),
        "IPSET_LOG": str(ipset_log),
        "PGREP_STATE": str(tmp_path / "pgrep.drained"),
        "FAKE_IP": "93.184.216.34",
        "NORESOLVE": "",
    }
    env.pop("DANGEROUSLY_SKIP_FIREWALL", None)
    env.pop("IPSET_MISSING", None)
    return {
        "env": env,
        "overlay": overlay,
        "dnsmasq_conf": dnsmasq_conf,
        "ro_domains": ro_domains,
        "rw_domains": rw_domains,
        "ipset_log": ipset_log,
    }


def run_expand(env: dict, *args: str) -> subprocess.CompletedProcess[str]:
    return run_capture(["bash", str(EXPAND), *args], env=env)


# === Argument validation (pure, runs before any privilege/firewall check) ===


def test_no_args_is_usage_error() -> None:
    r = run_capture(["bash", str(EXPAND)])
    assert r.returncode == 2
    assert "usage:" in r.stderr


@pytest.mark.parametrize(
    "arg,reason",
    [
        ("example.com:rwx", "invalid access"),
        ("example.com:RO", "invalid access"),
        ("nodot", "not a valid bare domain"),
        ("-foo.com", "not a valid bare domain"),
        ("ex ample.com", "not a valid bare domain"),
        ("..", "not a valid bare domain"),
        (":rw", "not a valid bare domain"),
        # A scheme-bearing URL splits on its `:` and is caught as a bad access.
        ("http://example.com", "invalid access"),
        ("a.com/path", "not a valid bare domain"),
    ],
)
def test_rejects_bad_input(arg: str, reason: str) -> None:
    # Bad input is rejected before the root/ipset guards, so this holds for any
    # caller regardless of privilege.
    r = run_capture(["bash", str(EXPAND), arg])
    assert r.returncode == 1
    assert reason in r.stderr


def test_one_bad_arg_aborts_the_whole_batch(fake_fw: dict) -> None:
    # Validation happens up front, so a typo in the second arg must apply none.
    r = run_expand(fake_fw["env"], "good.com", "bad:rwx")
    assert r.returncode == 1
    assert not fake_fw["overlay"].exists() or fake_fw["overlay"].read_text() == ""


# === Firewall-state guards ===


def test_skip_firewall_is_a_noop(fake_fw: dict) -> None:
    # Firewall disabled => everything is already reachable, so expansion is a
    # no-op: it exits 0 without touching the overlay or the live ipset (the
    # apply path would have written both).
    env = {**fake_fw["env"], "DANGEROUSLY_SKIP_FIREWALL": "1"}
    r = run_expand(env, "example.com")
    assert r.returncode == 0
    assert not fake_fw["overlay"].exists() or fake_fw["overlay"].read_text() == ""
    assert not fake_fw["ipset_log"].exists() or fake_fw["ipset_log"].read_text() == ""


def test_errors_when_ipset_absent(fake_fw: dict) -> None:
    env = {**fake_fw["env"], "IPSET_MISSING": "1"}
    r = run_expand(env, "example.com")
    assert r.returncode == 1
    assert "not found" in r.stderr


def test_add_failure_with_set_present_warns_and_does_not_abort(fake_fw: dict) -> None:
    """The point-of-use guard distinguishes a vanished set (fatal) from a plain add
    failure: when the set is still present but `ipset add` fails, the domain resolved yet
    was not admitted — a half-populated allowlist that must be surfaced (WARNING), not
    swallowed by `|| true`, while expansion continues so the next refresh re-adds it."""
    stub_dir = Path(fake_fw["env"]["PATH"].split(":", 1)[0])
    # list -name succeeds (set IS present) but every add fails.
    write_exe(
        stub_dir / "ipset",
        "#!/bin/sh\n"
        'if [ "$1" = "list" ] && [ "$2" = "-name" ]; then exit 0; fi\n'
        'if [ "$1" = "add" ]; then exit 1; fi\n'
        "exit 0\n",
    )
    r = run_expand(fake_fw["env"], "example.com")
    assert r.returncode == 0, r.stderr
    assert "not admitted" in r.stderr
    assert (
        "not found" not in r.stderr
    )  # the set was present — not the vanished-set path


def test_requires_root(fake_fw: dict) -> None:
    # Shadow `id` with one reporting a non-root uid; the guard must fire.
    stub_dir = Path(fake_fw["env"]["PATH"].split(":", 1)[0])
    write_exe(stub_dir / "id", "#!/bin/sh\necho 1000\n")
    r = run_expand(fake_fw["env"], "example.com")
    assert r.returncode == 1
    assert "must run as root" in r.stderr


# === Apply path ===


@pytest.mark.parametrize(
    "arg,domain,access,ro_acl,rw_acl",
    [
        # ro: readonly ACL gains the domain (leading dot = domain + subdomains).
        ("files.example.com", "files.example.com", "ro", ".files.example.com\n", ""),
        # rw: exact entry in the readwrite ACL so it is spliced out of any ro
        # wildcard; never appears in the readonly (method-restricted) list.
        ("api.example.com:rw", "api.example.com", "rw", "", "api.example.com\n"),
    ],
)
def test_domain_applied_across_overlay_dnsmasq_ipset_and_squid(
    fake_fw: dict, arg: str, domain: str, access: str, ro_acl: str, rw_acl: str
) -> None:
    r = run_expand(fake_fw["env"], arg)
    assert r.returncode == 0, r.stderr
    # Overlay (default access ro), dnsmasq record, and live ipset entry are
    # populated for both tiers; only the squid ACL files differ by access.
    assert fake_fw["overlay"].read_text() == f"{domain}\t{access}\n"
    assert f"address=/{domain}/93.184.216.34" in fake_fw["dnsmasq_conf"].read_text()
    assert "93.184.216.34" in fake_fw["ipset_log"].read_text()
    assert fake_fw["ro_domains"].read_text() == ro_acl
    assert fake_fw["rw_domains"].read_text() == rw_acl


def test_repeat_call_is_idempotent(fake_fw: dict) -> None:
    # A second identical expand must not duplicate the overlay or the dnsmasq
    # record (the dedupe that also suppresses a needless DNS restart).
    run_expand(fake_fw["env"], "a.example.com")
    run_expand(fake_fw["env"], "a.example.com")
    assert fake_fw["overlay"].read_text() == "a.example.com\tro\n"
    assert (
        fake_fw["dnsmasq_conf"]
        .read_text()
        .count("address=/a.example.com/93.184.216.34")
        == 1
    )


def test_unresolvable_domain_is_queued_and_reported(fake_fw: dict) -> None:
    env = {**fake_fw["env"], "NORESOLVE": "ghost.example.com"}
    r = run_expand(env, "ghost.example.com")
    assert r.returncode == 1
    assert "queued for retry" in r.stderr
    # Intent is recorded (the refresh loop retries it) but no live IP was added.
    assert fake_fw["overlay"].read_text() == "ghost.example.com\tro\n"
    assert not fake_fw["ipset_log"].exists() or fake_fw["ipset_log"].read_text() == ""
    # A host that never resolved must not leave a live ro ACL: squid ends with
    # `http_access allow all`, so a method-restriction ACL stranded for a host the
    # firewall can never route to is misleading — defer it until the host routes.
    assert fake_fw["ro_domains"].read_text() == ""


def test_non_public_answer_is_refused_not_added(fake_fw: dict) -> None:
    # A domain resolving to an internal address (here the cloud-metadata IP) must
    # not enter the live ipset: the IP is refused with a warning and the domain is
    # queued exactly like an unresolved one, so live expansion can't be tricked
    # into opening an internal route.
    env = {**fake_fw["env"], "FAKE_IP": "169.254.169.254"}
    r = run_expand(env, "meta.example.com")
    assert r.returncode == 1
    assert "non-public" in r.stderr and "169.254.169.254" in r.stderr
    assert not fake_fw["ipset_log"].exists() or fake_fw["ipset_log"].read_text() == ""
    assert fake_fw["overlay"].read_text() == "meta.example.com\tro\n"
    # Resolving only to a non-public address is treated like "didn't resolve": no
    # live ro ACL is left for a host the firewall will never route to.
    assert fake_fw["ro_domains"].read_text() == ""


def test_partial_resolution_applies_the_good_and_flags_the_bad(fake_fw: dict) -> None:
    env = {**fake_fw["env"], "NORESOLVE": "bad.example.com"}
    r = run_expand(env, "good.example.com", "bad.example.com")
    assert r.returncode == 1
    assert "bad.example.com" in r.stderr
    # The resolvable domain is fully applied; both are queued in the overlay.
    assert "93.184.216.34" in fake_fw["ipset_log"].read_text()
    assert (
        "address=/good.example.com/93.184.216.34" in fake_fw["dnsmasq_conf"].read_text()
    )
    overlay = fake_fw["overlay"].read_text()
    assert "good.example.com\tro" in overlay and "bad.example.com\tro" in overlay
    # Only the routable domain gets a live squid ro ACL; the unresolved one does not.
    assert fake_fw["ro_domains"].read_text() == ".good.example.com\n"


def test_success_emits_the_expansion_trace_event(fake_fw: dict, tmp_path: Path) -> None:
    """A widened egress boundary must be OBSERVABLE: a successful expansion emits the
    firewall_allowlist_expanded trace event (metadata-only counts, never the domain
    names) on the opt-in channel."""
    trace_file = tmp_path / "trace.jsonl"
    env = {
        **fake_fw["env"],
        "AGENT_SANDBOX_TRACE": "info",
        "AGENT_SANDBOX_TRACE_FILE": str(trace_file),
    }
    r = run_expand(env, "files.example.com")
    assert r.returncode == 0, r.stderr
    events = [json.loads(line) for line in trace_file.read_text().splitlines()]
    expanded = [e for e in events if e["event"] == "firewall_allowlist_expanded"]
    assert len(expanded) == 1
    assert expanded[0]["layer"] == "firewall"
    assert expanded[0]["domains"] == "1" and expanded[0]["resolved"] == "1"
    # Metadata only: the domain name never rides the trace channel.
    assert "files.example.com" not in trace_file.read_text()


def test_failed_expansion_emits_no_trace_event(fake_fw: dict, tmp_path: Path) -> None:
    # The event announces a WIDENED boundary; an expansion that failed (domain
    # unresolvable) must not claim one.
    trace_file = tmp_path / "trace.jsonl"
    env = {
        **fake_fw["env"],
        "NORESOLVE": "ghost.example.com",
        "AGENT_SANDBOX_TRACE": "info",
        "AGENT_SANDBOX_TRACE_FILE": str(trace_file),
    }
    r = run_expand(env, "ghost.example.com")
    assert r.returncode == 1
    assert (
        not trace_file.exists()
        or "firewall_allowlist_expanded" not in trace_file.read_text()
    )


# === init-firewall.bash integration (structural) ===


def test_init_firewall_initializes_and_merges_overlay() -> None:
    src = INIT_FIREWALL.read_text()
    # Same overlay path constant on both sides, env-overridable.
    const = 'ALLOWLIST_OVERLAY="${ALLOWLIST_OVERLAY:-/run/allowlist/overlay.tsv}"'
    assert const in src
    assert const in EXPAND.read_text()
    # Fresh empty overlay each init, and the refresh loop reads back domain+access.
    assert ': >"$ALLOWLIST_OVERLAY"' in src
    assert "while IFS=$'\\t' read -r d a; do" in src
    assert 'done <"$ALLOWLIST_OVERLAY"' in src
    # The loop reconciles the squid ACLs from the merged access map each cycle.
    assert "sync_squid_acls" in src


def test_both_scripts_source_the_shared_lib() -> None:
    # validate_access / valid_domain_name / write_ro_domains live in one place so the
    # build, the refresh loop, and live expansion can't drift on the
    # fail-open-sensitive rules.
    assert 'source "$SCRIPT_DIR/firewall-lib.bash"' in INIT_FIREWALL.read_text()
    assert 'source "$SCRIPT_DIR/firewall-lib.bash"' in EXPAND.read_text()


def test_all_three_paths_resolve_through_the_shared_function() -> None:
    # The build, the refresh loop, and live expansion must resolve via the one
    # shared resolver (which follows CNAMEs and keys by the queried name), not a
    # private `dig` path — otherwise they drift and a CNAME'd domain resolves in
    # one path but not another. Guards against expand-allowlist regrowing its own
    # `dig +short` loop.
    init_src = INIT_FIREWALL.read_text()
    expand_src = EXPAND.read_text()
    # resolve_with_fallback wraps resolve_a_with_retries (same CNAME-following, keyed
    # by the queried name) and adds the public-resolver fallback; all three paths go
    # through it so they can't drift on either the resolution or the fallback.
    assert "resolve_with_fallback" in init_src
    assert "resolve_with_fallback" in expand_src
    assert "dig +short" not in expand_src, "expand must not resolve via its own dig"


def test_expand_script_ships_in_the_firewall_image() -> None:
    # The `expand` CLI verb docker-execs the script by bare name, so the image must
    # COPY it next to init-firewall.bash on PATH.
    dockerfile = (REPO_ROOT / "sandbox" / "Dockerfile").read_text()
    copy_lines = [
        ln
        for ln in dockerfile.replace("\\\n", " ").splitlines()
        if ln.startswith("COPY") and "expand-allowlist.bash" in ln
    ]
    assert copy_lines, "sandbox/Dockerfile must COPY expand-allowlist.bash"
    assert "/usr/local/bin/" in copy_lines[0]

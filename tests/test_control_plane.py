"""Control-plane attachment contract (docs/control-plane.md).

Three seams, no containers:
  - the launch-path readiness barrier: bin/agent-sandbox is driven with a fake
    docker whose `exec ... test -f /run/control-plane/<name>.ready` answers from
    a host-side marker dir, so "consumer service ready / never ready" is a file
    the test creates (or doesn't);
  - the grants export: the same fake docker records the value of
    CONTROL_PLANE_EGRESS_GRANTS it sees at `up`, pinning the validated
    compact-JSON handoff to the firewall service — and that malformed grants are
    refused BEFORE anything comes up;
  - the firewall's grant rendering: render_control_plane_grants is sliced out of
    init-firewall.bash and run against recording iptables/ipset stubs and a
    canned resolver, so the exact ACCEPT argv and the fail-closed resolution
    posture are asserted without NET_ADMIN.
"""

import json
import os
import subprocess

from tests._helpers import REPO_ROOT, slice_bash_function, write_exe

LAUNCHER = REPO_ROOT / "bin" / "agent-sandbox"
INIT_FIREWALL = REPO_ROOT / "sandbox" / "init-firewall.bash"
IP_VALIDATION = REPO_ROOT / "sandbox" / "ip-validation.bash"

# Fake docker: records every argv; makes `up` succeed and dumps the grants env
# it saw there; yields a workload cid; answers control-plane marker probes from
# $FAKE_CP_DIR so readiness is a plain host file the test controls.
FAKE_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_ARGV_LOG"
cmd="${1:-}"
if [[ "$cmd" == compose ]]; then
  if [[ " $* " == *" up "* ]]; then
    printf 'CPGRANTS<%s>\\n' "${CONTROL_PLANE_EGRESS_GRANTS-unset}" >>"$DOCKER_ARGV_LOG"
  fi
  if [[ "$*" == *" ps -q workload" ]]; then
    echo wl-cid
  fi
  exit 0
fi
if [[ "$cmd" == exec ]]; then
  last=""
  for a in "$@"; do last="$a"; done
  if [[ "$last" == /run/control-plane/*.ready ]]; then
    if [[ -f "$FAKE_CP_DIR/${last##*/}" ]]; then exit 0; fi
    exit 1
  fi
fi
exit 0
"""

BASE_WORKLOAD = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": [],
    "ephemeral": True,
}


def _run(tmp_path, workload: dict, extra_env=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", FAKE_DOCKER)
    cp_dir = tmp_path / "cp-markers"
    cp_dir.mkdir(exist_ok=True)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(workload))
    log = tmp_path / "docker-argv.log"
    log.touch()
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "CONTAINER_RUNTIME": "runc",
        "NO_COLOR": "1",
        "DOCKER_ARGV_LOG": str(log),
        "FAKE_CP_DIR": str(cp_dir),
        "SANDBOX_NET_RESERVE_DIR": str(tmp_path / "reserve"),
        "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        "AGENT_SANDBOX_STATE_DIR": str(tmp_path / "state"),
        **(extra_env or {}),
    }
    env.pop("CONTROL_PLANE_EGRESS_GRANTS", None)
    r = subprocess.run(
        [str(LAUNCHER), "run", str(wl)], capture_output=True, text=True, env=env
    )
    return r, log.read_text().splitlines()


def _with_cp(cp: dict) -> dict:
    return {**BASE_WORKLOAD, "control_plane": cp}


# --- readiness barrier ---


def test_barrier_satisfied_marker_lets_the_run_proceed(tmp_path):
    cp_dir = tmp_path / "cp-markers"
    cp_dir.mkdir()
    (cp_dir / "gate.ready").touch()
    r, lines = _run(tmp_path, _with_cp({"require": ["gate"]}))
    assert r.returncode == 0, r.stderr
    # The marker was actually probed (the pass is not vacuous) and the
    # entrypoint exec happened after it.
    probes = [i for i, ln in enumerate(lines) if "/run/control-plane/gate.ready" in ln]
    assert probes, lines
    entry = [i for i, ln in enumerate(lines) if "echo hi" in ln]
    assert entry and probes[-1] < entry[0], lines


def test_barrier_timeout_fails_closed_names_marker_and_tears_down(tmp_path):
    r, lines = _run(
        tmp_path,
        _with_cp({"require": ["gate"]}),
        extra_env={"AGENT_SANDBOX_READY_TIMEOUT": "2"},
    )
    assert r.returncode != 0
    assert "control-plane readiness timed out" in r.stderr
    assert "gate" in r.stderr
    # The entrypoint never ran, and the stack was torn down (volumes included).
    assert not any("echo hi" in ln for ln in lines)
    downs = [ln for ln in lines if ln.startswith("compose") and " down " in f"{ln} "]
    assert downs and "--volumes" in downs[-1], lines


def test_barrier_names_only_the_missing_marker(tmp_path):
    cp_dir = tmp_path / "cp-markers"
    cp_dir.mkdir()
    (cp_dir / "gate.ready").touch()  # present; relay never appears
    r, _ = _run(
        tmp_path,
        _with_cp({"require": ["gate", "relay"]}),
        extra_env={"AGENT_SANDBOX_READY_TIMEOUT": "2"},
    )
    assert r.returncode != 0
    assert "missing marker(s): relay" in r.stderr


def test_traversal_shaped_marker_name_is_refused(tmp_path):
    # The name lands in the probed path; a workload record is untrusted, so a
    # traversal-shaped value must refuse (and tear down) rather than probe
    # outside /run/control-plane.
    r, lines = _run(tmp_path, _with_cp({"require": ["../../../tmp/x"]}))
    assert r.returncode != 0
    assert "not a valid marker name" in r.stderr
    assert not any("/run/control-plane/" in ln for ln in lines)
    downs = [ln for ln in lines if ln.startswith("compose") and " down " in f"{ln} "]
    assert downs and "--volumes" in downs[-1], lines


def test_garbage_ready_timeout_is_refused_not_an_unbounded_poll(tmp_path):
    r, lines = _run(
        tmp_path,
        _with_cp({"require": ["gate"]}),
        extra_env={"AGENT_SANDBOX_READY_TIMEOUT": "soon"},
    )
    assert r.returncode != 0
    assert "AGENT_SANDBOX_READY_TIMEOUT must be a whole number" in r.stderr
    assert not any("/run/control-plane/" in ln for ln in lines)


def test_no_control_plane_means_no_marker_polling(tmp_path):
    r, lines = _run(tmp_path, dict(BASE_WORKLOAD))
    assert r.returncode == 0, r.stderr
    assert not any("/run/control-plane/" in ln for ln in lines)


def test_empty_require_list_means_no_marker_polling(tmp_path):
    r, lines = _run(tmp_path, _with_cp({"require": []}))
    assert r.returncode == 0, r.stderr
    assert not any("/run/control-plane/" in ln for ln in lines)


# --- grants export (launcher side) ---


def _grants_seen_at_up(lines) -> list:
    return [ln for ln in lines if ln.startswith("CPGRANTS<")]


def test_valid_grants_reach_the_firewall_env_at_up(tmp_path):
    grants = [{"uid": 7777, "hosts": ["gate.example.com"]}]
    r, lines = _run(tmp_path, _with_cp({"egress_grants": grants}))
    assert r.returncode == 0, r.stderr
    seen = _grants_seen_at_up(lines)
    assert seen == [f"CPGRANTS<{json.dumps(grants, separators=(',', ':'))}>"]


def test_no_grants_export_the_empty_string_not_an_empty_array(tmp_path):
    r, lines = _run(tmp_path, dict(BASE_WORKLOAD))
    assert r.returncode == 0, r.stderr
    assert _grants_seen_at_up(lines) == ["CPGRANTS<>"]


def _refused(tmp_path, grants, needle):
    r, lines = _run(tmp_path, _with_cp({"egress_grants": grants}))
    assert r.returncode != 0
    assert needle in r.stderr
    # Refused before anything came up.
    assert not any(ln.startswith("compose") for ln in lines), lines


def test_uid_zero_is_refused_before_up(tmp_path):
    _refused(
        tmp_path,
        [{"uid": 0, "hosts": ["gate.example.com"]}],
        "uid must be an integer >= 1",
    )


def test_non_integer_uid_is_refused_before_up(tmp_path):
    _refused(
        tmp_path,
        [{"uid": 7.5, "hosts": ["gate.example.com"]}],
        "uid must be an integer >= 1",
    )


def test_ip_literal_host_is_refused_before_up(tmp_path):
    _refused(
        tmp_path,
        [{"uid": 7777, "hosts": ["10.0.0.1"]}],
        "HOSTNAMES, not IPs",
    )


def test_non_hostname_shaped_host_is_refused_before_up(tmp_path):
    _refused(
        tmp_path,
        [{"uid": 7777, "hosts": ["bad host!"]}],
        "hostname-shaped",
    )


def test_empty_hosts_list_is_refused_before_up(tmp_path):
    _refused(
        tmp_path,
        [{"uid": 7777, "hosts": []}],
        "non-empty hosts list",
    )


def test_duplicate_uid_is_refused_before_up(tmp_path):
    # The firewall builds each grant's ipset fresh, so a second entry for the
    # same uid would silently wipe the first one's resolved IPs.
    _refused(
        tmp_path,
        [
            {"uid": 7777, "hosts": ["a.example"]},
            {"uid": 7777, "hosts": ["b.example"]},
        ],
        "duplicate uid",
    )


# --- firewall grant rendering (sliced from init-firewall.bash) ---

# Canned resolver bodies. "ok" answers every queried host with one fixed IP —
# the assertions then pin exactly what the renderer does with an answer; "dead"
# answers nothing, the fail-closed path.
RESOLVER = {
    "ok": 'cold_boot_resolve() { shift; local h; for h in "$@"; '
    'do printf "%s\\t203.0.113.7\\n" "$h"; done; }',
    "dead": "cold_boot_resolve() { shift; :; }",
}


def _render(tmp_path, grants_env: str, resolve: str = "ok"):
    body = slice_bash_function(INIT_FIREWALL, "render_control_plane_grants")
    ipv4 = slice_bash_function(IP_VALIDATION, "valid_ipv4")
    log = tmp_path / "render.log"
    log.touch()
    conf = tmp_path / "grants.conf"
    script = "\n".join(
        [
            "set -Eeuo pipefail",
            ipv4,
            RESOLVER[resolve],
            'ensure_fresh_ipset() { printf "ensure_fresh_ipset %s\\n" "$*" >>"$LOG"; }',
            'apply_ipset_batch() { cat "$1" >>"$LOG"; rm -f "$1"; }',
            'iptables() { printf "iptables %s\\n" "$*" >>"$LOG"; }',
            "as_trace() { :; }",
            body,
            "render_control_plane_grants",
        ]
    )
    env = {
        **os.environ,
        "LOG": str(log),
        "CP_GRANTS_DNSMASQ_CONF": str(conf),
        "DNS_BATCH_SIZE": "30",
        "CONTROL_PLANE_EGRESS_GRANTS": grants_env,
    }
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    return r, log.read_text().splitlines(), conf


def test_render_emits_the_exact_accept_argv_per_grant(tmp_path):
    grants = (
        '[{"uid":7777,"hosts":["gate.example.com"]},'
        '{"uid":8888,"hosts":["a.example","b.example"]}]'
    )
    r, log, conf = _render(tmp_path, grants)
    assert r.returncode == 0, r.stderr
    assert [ln for ln in log if ln.startswith("iptables ")] == [
        "iptables -A OUTPUT -m owner --uid-owner 7777 -p tcp --dport 443"
        " -m set --match-set cp-grant-7777 dst -j ACCEPT",
        "iptables -A OUTPUT -m owner --uid-owner 8888 -p tcp --dport 443"
        " -m set --match-set cp-grant-8888 dst -j ACCEPT",
    ]
    # One fresh per-uid set, populated with the resolved IPs, one line per host.
    assert "ensure_fresh_ipset cp-grant-7777" in log
    assert "ensure_fresh_ipset cp-grant-8888" in log
    assert log.count("add cp-grant-7777 203.0.113.7") == 1
    assert log.count("add cp-grant-8888 203.0.113.7") == 2
    # dnsmasq pins, one address record per resolved host.
    assert sorted(conf.read_text().splitlines()) == [
        "address=/a.example/203.0.113.7",
        "address=/b.example/203.0.113.7",
        "address=/gate.example.com/203.0.113.7",
    ]
    # Resolution is not reachability: nothing leaks into the workload set.
    assert not any("allowed-domains" in ln for ln in log)


def test_render_fails_closed_when_a_host_does_not_resolve(tmp_path):
    r, log, conf = _render(
        tmp_path, '[{"uid":7777,"hosts":["gate.example.com"]}]', resolve="dead"
    )
    assert r.returncode != 0
    assert "gate.example.com" in r.stderr
    assert "did not resolve" in r.stderr
    # No half-applied grant: the ACCEPT rule was never emitted.
    assert not any(ln.startswith("iptables ") for ln in log)
    assert not conf.exists() or "address=" not in conf.read_text()


def test_render_is_a_no_op_on_empty_grants(tmp_path):
    r, log, conf = _render(tmp_path, "")
    assert r.returncode == 0, r.stderr
    assert log == []
    assert not conf.exists()


def test_render_refuses_a_non_integer_uid_from_the_raw_env(tmp_path):
    # stack.bash validates upstream, but the env var can be set directly and the
    # uid lands in an ipset name and iptables argv — the firewall re-checks.
    r, log, _ = _render(tmp_path, '[{"uid":"7777; rm -rf /","hosts":["a.example"]}]')
    assert r.returncode != 0
    assert "not a positive integer" in r.stderr
    assert not any(ln.startswith("iptables ") for ln in log)


def test_render_refuses_an_empty_hosts_list_from_the_raw_env(tmp_path):
    r, log, _ = _render(tmp_path, '[{"uid":7777,"hosts":[]}]')
    assert r.returncode != 0
    assert "names no hosts" in r.stderr
    assert not any(ln.startswith("iptables ") for ln in log)

"""Consumer seams on the launch path: --extra-compose overlays, the
AGENT_SANDBOX_PROJECT_NAME identity override, and the firewall hooks runner.

The overlay/project tests drive bin/agent-sandbox with a RECORDING fake docker on
PATH: every docker invocation's argv is appended to a log, so the tests assert the
seam's core invariant — the extra compose files and the pinned project name appear
on EVERY compose invocation of the session (up, ps, logs, down), not just `up`.
A file set that differed between call sites would let teardown or diagnostics
operate on a different stack than the one that booted.
"""

import json
import os
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT, slice_bash_function, write_exe

LAUNCHER = REPO_ROOT / "bin" / "agent-sandbox"
INIT_FIREWALL = REPO_ROOT / "sandbox" / "init-firewall.bash"

RECORDING_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_ARGV_LOG"
exit 0
"""

VALID = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": [],
    "ephemeral": True,
}


def _run(tmp_path, *, argv_tail, extra_env=None, workload=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", RECORDING_DOCKER)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(workload if workload is not None else VALID))
    log = tmp_path / "docker-argv.log"
    log.touch()
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "CONTAINER_RUNTIME": "runc",
        "NO_COLOR": "1",
        "DOCKER_ARGV_LOG": str(log),
        "SANDBOX_NET_RESERVE_DIR": str(tmp_path / "reserve"),
        "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        "AGENT_SANDBOX_STATE_DIR": str(tmp_path / "state"),
        **(extra_env or {}),
    }
    r = subprocess.run(
        [str(LAUNCHER), "run", *argv_tail, str(wl)],
        capture_output=True,
        text=True,
        env=env,
    )
    compose_calls = [
        line for line in log.read_text().splitlines() if line.startswith("compose ")
    ]
    return r, compose_calls


def _overlay(tmp_path, name):
    f = tmp_path / name
    f.write_text('{"services": {}}')
    return f


def test_extra_compose_rides_on_every_compose_invocation(tmp_path):
    """Both overlays appear, in argument order, AFTER the library's three files on
    every compose call the session makes (the silent fake docker yields no workload
    container, so the run traverses up, ps, and the cleanup down — three distinct
    call sites through the choke point)."""
    o1, o2 = _overlay(tmp_path, "a.json"), _overlay(tmp_path, "b.json")
    r, calls = _run(
        tmp_path,
        argv_tail=["--extra-compose", str(o1), "--extra-compose", str(o2)],
    )
    assert r.returncode != 0  # fake docker: no workload container => fail closed
    assert len(calls) >= 3, calls  # up, ps, down at minimum
    for call in calls:
        args = call.split()
        f_args = [args[i + 1] for i, a in enumerate(args) if a == "-f"]
        assert f_args[-2:] == [str(o1), str(o2)], call
        assert len(f_args) == 5, call  # base + override + overmounts + 2 overlays


def test_project_name_override_pins_every_compose_invocation(tmp_path):
    r, calls = _run(
        tmp_path,
        argv_tail=[],
        extra_env={"AGENT_SANDBOX_PROJECT_NAME": "cg-session-42"},
    )
    assert r.returncode != 0
    assert calls, "no compose invocations recorded"
    for call in calls:
        args = call.split()
        assert args[args.index("-p") + 1] == "cg-session-42", call


def test_session_id_derives_the_project_name_on_every_compose_invocation(tmp_path):
    """workload.session_id makes the identity deterministic: every compose call runs
    under agent-sandbox-<session_id>, so a later `run` (or down/expand) can find this
    session's stack by name instead of a random per-launch suffix."""
    r, calls = _run(tmp_path, argv_tail=[], workload={**VALID, "session_id": "alpha-1"})
    assert r.returncode != 0  # fake docker: no workload container => fail closed
    assert calls, "no compose invocations recorded"
    for call in calls:
        args = call.split()
        assert args[args.index("-p") + 1] == "agent-sandbox-alpha-1", call


def test_session_id_and_project_name_env_conflict_refuses(tmp_path):
    """One identity per session: session_id and AGENT_SANDBOX_PROJECT_NAME both name
    the compose project, so setting both is refused before anything comes up."""
    r, calls = _run(
        tmp_path,
        argv_tail=[],
        workload={**VALID, "session_id": "alpha-1"},
        extra_env={"AGENT_SANDBOX_PROJECT_NAME": "cg-session-42"},
    )
    assert r.returncode != 0
    assert "exactly one identity" in r.stderr
    assert calls == []  # refused before any compose invocation


def test_default_project_name_is_randomized_per_session(tmp_path):
    _, calls_a = _run(tmp_path, argv_tail=[])
    projects_a = {c.split()[c.split().index("-p") + 1] for c in calls_a}
    assert len(projects_a) == 1
    assert next(iter(projects_a)).startswith("agent-sandbox-")


def test_extra_compose_missing_file_refuses_the_launch(tmp_path):
    r, calls = _run(tmp_path, argv_tail=["--extra-compose", str(tmp_path / "nope.yml")])
    assert r.returncode != 0
    assert "extra compose file not found" in r.stderr
    assert calls == []  # refused before anything was launched


def test_extra_compose_without_argument_refuses(tmp_path):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", RECORDING_DOCKER)
    log = tmp_path / "docker-argv.log"
    log.touch()
    r = subprocess.run(
        [str(LAUNCHER), "run", "--extra-compose"],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{stub}:{os.environ['PATH']}",
            "NO_COLOR": "1",
            "DOCKER_ARGV_LOG": str(log),
        },
    )
    assert r.returncode != 0
    assert "needs a file argument" in r.stderr


def test_unknown_run_option_refuses(tmp_path):
    r, _ = _run(tmp_path, argv_tail=["--frobnicate"])
    assert r.returncode != 0
    assert "unknown option for run" in r.stderr


def test_two_workload_files_refuse(tmp_path):
    extra = tmp_path / "second.json"
    extra.write_text(json.dumps(VALID))
    r, _ = _run(tmp_path, argv_tail=[str(extra)])
    assert r.returncode != 0
    assert "exactly one workload file" in r.stderr


# --- firewall hooks runner (sliced from init-firewall.bash; no container needed) ---


def _run_hooks(tmp_path, hooks_dir: Path):
    body = slice_bash_function(INIT_FIREWALL, "run_firewall_hooks")
    return subprocess.run(
        [
            "bash",
            "-c",
            f'set -Eeuo pipefail; {body}; run_firewall_hooks "$1"',
            "_",
            str(hooks_dir),
        ],
        capture_output=True,
        text=True,
    )


def test_hooks_runner_is_a_no_op_without_a_hooks_dir(tmp_path):
    r = _run_hooks(tmp_path, tmp_path / "absent")
    assert r.returncode == 0, r.stderr


def test_hooks_runner_is_a_no_op_on_an_empty_dir(tmp_path):
    d = tmp_path / "hooks"
    d.mkdir()
    r = _run_hooks(tmp_path, d)
    assert r.returncode == 0, r.stderr


def test_hooks_run_in_lexical_order(tmp_path):
    d = tmp_path / "hooks"
    d.mkdir()
    out = tmp_path / "order"
    write_exe(d / "50-second", f'#!/bin/sh\necho second >>"{out}"\n')
    write_exe(d / "10-first", f'#!/bin/sh\necho first >>"{out}"\n')
    r = _run_hooks(tmp_path, d)
    assert r.returncode == 0, r.stderr
    assert out.read_text() == "first\nsecond\n"


def test_failing_hook_fails_the_firewall_init(tmp_path):
    """Fail-closed: a consumer policy hook that errors must abort the launch (the
    firewall never reports ready), not ship a firewall silently missing rules."""
    d = tmp_path / "hooks"
    d.mkdir()
    write_exe(d / "10-ok", "#!/bin/sh\nexit 0\n")
    write_exe(d / "20-broken", "#!/bin/sh\nexit 3\n")
    r = _run_hooks(tmp_path, d)
    assert r.returncode != 0
    assert "20-broken failed" in r.stderr
    assert "fail closed" in r.stderr


def test_non_executable_hook_entry_fails_loud(tmp_path):
    """A mounted-but-unrunnable hook is a misconfiguration the operator intended to
    run — refusing beats silently skipping the policy it carries."""
    d = tmp_path / "hooks"
    d.mkdir()
    (d / "10-not-exec").write_text("#!/bin/sh\nexit 0\n")
    r = _run_hooks(tmp_path, d)
    assert r.returncode != 0
    assert "not an executable file" in r.stderr

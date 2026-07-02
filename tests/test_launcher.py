"""Behavioral tests for the bin/agent-sandbox launcher.

Drives the launch sequence's fail-closed validation + orchestration with a fake docker
on PATH (no daemon) and CONTAINER_RUNTIME=runc so the backend needs no runtime probe.
A valid workload gets past validation, selects a runtime, allocates a subnet, and
enters the compose bring-up — where the silent fake docker yields no workload
container, so the launch fails CLOSED (proving every earlier step ran and that a
stack that didn't come up never runs a workload); malformed records are refused
before anything is launched.
"""

import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
LAUNCHER = REPO / "bin" / "agent-sandbox"

FAKE_DOCKER = "#!/usr/bin/env bash\n# subnet alloc lists networks; return none so .0/24 is free\nexit 0\n"


def _run(tmp_path, workload_obj, *, argv=None, extra_env=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    (stub / "docker").write_text(FAKE_DOCKER)
    (stub / "docker").chmod(0o755)
    wl = tmp_path / "workload.json"
    if workload_obj is not None:
        wl.write_text(json.dumps(workload_obj))
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "CONTAINER_RUNTIME": "runc",  # backend returns runc with no docker probe
        "NO_COLOR": "1",
        "SANDBOX_NET_RESERVE_DIR": str(tmp_path / "reserve"),
        "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        "AGENT_SANDBOX_STATE_DIR": str(tmp_path / "state"),
        **(extra_env or {}),
    }
    cmd = argv if argv is not None else ["run", str(wl)]
    return subprocess.run(
        [str(LAUNCHER), *cmd], capture_output=True, text=True, env=env
    )


VALID = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": ["pypi.org"],
    "ephemeral": True,
}


def test_valid_workload_selects_runtime_and_subnet_then_fails_closed_at_bring_up(
    tmp_path,
):
    r = _run(tmp_path, VALID)
    # runtime selected + subnet allocated (both announced), then the bring-up fails
    # closed: the silent fake docker produces no workload container, and a stack
    # that didn't come up must never run a workload.
    assert "runtime=runc" in r.stderr, r.stderr
    assert "network:" in r.stderr and "172.30." in r.stderr, r.stderr
    assert "workload container did not start" in r.stderr, r.stderr
    assert r.returncode != 0


def test_object_allowlist_entries_pass_validation(tmp_path):
    wl = {
        **VALID,
        "egress_allowlist": [
            "pypi.org",
            {"host": "files.pythonhosted.org", "access": "ro"},
        ],
    }
    r = _run(tmp_path, wl)
    # Validation accepted the tiered entries: the launch reached bring-up.
    assert "workload container did not start" in r.stderr, r.stderr


def test_ip_inside_object_entry_is_rejected(tmp_path):
    bad = {**VALID, "egress_allowlist": [{"host": "1.2.3.4"}]}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "HOSTNAMES, not IPs" in r.stderr


def test_invalid_access_tier_is_rejected(tmp_path):
    bad = {**VALID, "egress_allowlist": [{"host": "pypi.org", "access": "write"}]}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "egress_allowlist entry" in r.stderr


def test_missing_file_is_rejected(tmp_path):
    r = _run(tmp_path, None, argv=["run", str(tmp_path / "nope.json")])
    assert r.returncode != 0
    assert "not found" in r.stderr


def test_invalid_json_is_rejected(tmp_path):
    wl = tmp_path / "bad.json"
    wl.write_text("{not json")
    r = _run(tmp_path, None, argv=["run", str(wl)])
    assert r.returncode != 0
    assert "not valid JSON" in r.stderr


def test_missing_image_is_rejected(tmp_path):
    bad = {k: v for k, v in VALID.items() if k != "image"}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "required field 'image'" in r.stderr


def test_empty_entrypoint_is_rejected(tmp_path):
    bad = {**VALID, "entrypoint": []}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "entrypoint" in r.stderr


def test_missing_ephemeral_is_rejected(tmp_path):
    bad = {k: v for k, v in VALID.items() if k != "ephemeral"}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "ephemeral" in r.stderr


def test_ip_in_allowlist_is_rejected(tmp_path):
    bad = {**VALID, "egress_allowlist": ["1.2.3.4"]}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "HOSTNAMES, not IPs" in r.stderr


def test_run_without_workload_arg_is_rejected(tmp_path):
    """`run` with no file argument fails loud (and prints usage) rather than launching."""
    r = _run(tmp_path, None, argv=["run"])
    assert r.returncode != 0
    assert "no workload file given" in r.stderr
    assert "Usage: agent-sandbox run" in r.stderr


def test_missing_egress_allowlist_is_rejected(tmp_path):
    bad = {k: v for k, v in VALID.items() if k != "egress_allowlist"}
    r = _run(tmp_path, bad)
    assert r.returncode != 0
    assert "egress_allowlist must be present" in r.stderr


def test_missing_compose_stack_refuses(tmp_path):
    """Past validation + runtime + subnet, an absent compose stack refuses the launch
    rather than running a workload without the egress boundary. AGENT_SANDBOX_COMPOSE
    points the launcher at a nonexistent stack so the real fail-closed branch runs."""
    r = _run(
        tmp_path,
        VALID,
        extra_env={"AGENT_SANDBOX_COMPOSE": str(tmp_path / "nope.yml")},
    )
    assert r.returncode != 0
    assert "not present in this build" in r.stderr


def test_no_command_prints_usage(tmp_path):
    r = _run(tmp_path, None, argv=[])
    assert "Usage: agent-sandbox run" in r.stderr


def test_unknown_command_is_rejected(tmp_path):
    r = _run(tmp_path, None, argv=["frobnicate"])
    assert r.returncode != 0
    assert "unknown command" in r.stderr

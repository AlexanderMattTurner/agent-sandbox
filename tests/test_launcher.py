"""Behavioral tests for the bin/agent-sandbox launcher.

Drives the launch sequence's fail-closed validation + orchestration with a fake docker
on PATH (no daemon) and CONTAINER_RUNTIME=runc so the backend needs no runtime probe.
A valid workload gets past validation, selects a runtime, allocates a subnet, and then
stops at the compose seam (the firewall+workload stack is a later extraction) — proving
every earlier step ran; malformed records are refused before anything is launched.
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


def _run(tmp_path, workload_obj, *, argv=None):
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


def test_valid_workload_selects_runtime_and_subnet_then_stops_at_compose(tmp_path):
    r = _run(tmp_path, VALID)
    # runtime selected + subnet allocated (both announced), then the compose seam refuses.
    assert "runtime=runc" in r.stderr, r.stderr
    assert "network:" in r.stderr and "172.30." in r.stderr, r.stderr
    assert "compose" in r.stderr
    assert r.returncode != 0  # refuses to run un-firewalled (compose stack not present)


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


def test_no_command_prints_usage(tmp_path):
    r = _run(tmp_path, None, argv=[])
    assert "Usage: agent-sandbox run" in r.stderr


def test_unknown_command_is_rejected(tmp_path):
    r = _run(tmp_path, None, argv=["frobnicate"])
    assert r.returncode != 0
    assert "unknown command" in r.stderr

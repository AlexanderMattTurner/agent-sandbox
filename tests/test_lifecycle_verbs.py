"""Behavioral tests for the bin/agent-sandbox lifecycle verbs `gc` and `down`.

A recording fake docker on PATH logs every argv line it receives, so the tests
assert what the verb actually asked docker to do: `gc` prunes stale sandbox
networks (and its --dry-run records NO `network rm`); `down` tears down a compose
project with --volumes and fails loud on a surviving volume, a missing project
argument, or a project with nothing to tear down.
"""

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
LAUNCHER = REPO / "bin" / "agent-sandbox"

# Responds by argv pattern; env toggles model the docker-side state each test needs.
# `compose ... down` drops a marker file so a later `volume ls` can model "the
# volumes were really removed" (FAKE_VOLUMES=until-down) vs a survivor (=always).
FAKE_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$*" in
  "network ls -q --filter driver=bridge")
    [[ -n "${FAKE_NETWORK_ID:-}" ]] && echo "$FAKE_NETWORK_ID"
    ;;
  "network inspect ${FAKE_NETWORK_ID:-<unset>} "*)
    echo "$FAKE_NETWORK_ID ${FAKE_NETWORK_SUBNET:-172.30.5.0/24} ${FAKE_NETWORK_ENDPOINTS:-0}"
    ;;
  "ps -aq --filter label=com.docker.compose.project="*)
    [[ -n "${FAKE_CONTAINERS:-}" ]] && echo cid1
    ;;
  "volume ls -q --filter label=com.docker.compose.project="*)
    if [[ "${FAKE_VOLUMES:-}" == "always" ]]; then
      echo vol1
    elif [[ "${FAKE_VOLUMES:-}" == "until-down" && ! -f "$FAKE_DOCKER_LOG.down" ]]; then
      echo vol1
    fi
    ;;
  "compose -p "*" down --volumes --timeout 30")
    touch "$FAKE_DOCKER_LOG.down"
    ;;
esac
exit 0
"""


def _run(tmp_path, argv, extra_env=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    (stub / "docker").write_text(FAKE_DOCKER)
    (stub / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    log.touch()
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "NO_COLOR": "1",
        "FAKE_DOCKER_LOG": str(log),
        "SANDBOX_NET_RESERVE_DIR": str(tmp_path / "reserve"),
        "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        **(extra_env or {}),
    }
    r = subprocess.run([str(LAUNCHER), *argv], capture_output=True, text=True, env=env)
    return r, log.read_text()


STALE_NET = {"FAKE_NETWORK_ID": "net1", "FAKE_NETWORK_SUBNET": "172.30.5.0/24"}


def test_gc_prunes_stale_sandbox_network(tmp_path):
    r, log = _run(tmp_path, ["gc"], STALE_NET)
    assert r.returncode == 0, r.stderr
    assert "network ls -q --filter driver=bridge" in log
    assert "network rm net1" in log


def test_gc_dry_run_removes_nothing_and_reports_count(tmp_path):
    r, log = _run(tmp_path, ["gc", "--dry-run"], STALE_NET)
    assert r.returncode == 0, r.stderr
    assert "network rm" not in log
    assert "Would remove: 1 empty sandbox network(s)" in r.stdout


def test_gc_unknown_option_is_rejected(tmp_path):
    r, log = _run(tmp_path, ["gc", "--frobnicate"])
    assert r.returncode != 0
    assert "unknown gc option: --frobnicate" in r.stderr
    assert "Usage: agent-sandbox" in r.stderr
    assert "network" not in log  # refused before touching docker


def test_down_removes_project_with_volumes(tmp_path):
    r, log = _run(tmp_path, ["down", "proj1"], {"FAKE_VOLUMES": "until-down"})
    assert r.returncode == 0, r.stderr
    assert "compose -p proj1 down --volumes --timeout 30" in log


def test_down_removes_project_with_only_containers(tmp_path):
    r, log = _run(tmp_path, ["down", "proj1"], {"FAKE_CONTAINERS": "1"})
    assert r.returncode == 0, r.stderr
    assert "compose -p proj1 down --volumes --timeout 30" in log


def test_down_fails_loud_on_surviving_volume(tmp_path):
    r, log = _run(tmp_path, ["down", "proj1"], {"FAKE_VOLUMES": "always"})
    assert r.returncode != 0
    assert "compose -p proj1 down --volumes --timeout 30" in log  # down was attempted
    assert "left volumes behind" in r.stderr
    assert "vol1" in r.stderr


def test_down_without_project_is_rejected(tmp_path):
    r, log = _run(tmp_path, ["down"])
    assert r.returncode != 0
    assert "no compose project given" in r.stderr
    assert "Usage: agent-sandbox" in r.stderr
    assert "compose" not in log  # refused before touching docker


def test_down_on_empty_project_is_rejected(tmp_path):
    """A project with zero containers AND zero volumes errors — a typo'd project
    name must not look like a clean teardown."""
    r, log = _run(tmp_path, ["down", "ghost"])
    assert r.returncode != 0
    assert "nothing to tear down" in r.stderr
    assert "ghost" in r.stderr
    assert "compose -p ghost down" not in log

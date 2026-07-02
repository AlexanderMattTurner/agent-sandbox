"""Behavioral tests for the bin/agent-sandbox lifecycle verbs `gc` and `down`.

A recording fake docker on PATH logs every argv line it receives, so the tests
assert what the verb actually asked docker to do: `gc` prunes stale sandbox
networks, reaps over-age prewarm spares and dead prewarm claims (and its
--dry-run records NO `network rm`/`down`); `down` tears down a compose project
with --volumes and fails loud on a surviving volume, a missing project argument,
or a project with nothing to tear down.
"""

import os
import subprocess
import time
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
  "ps -q --filter label=agent-sandbox.prewarm=ready")
    [[ -n "${FAKE_SPARE_CID:-}" ]] && echo "$FAKE_SPARE_CID"
    ;;
  "inspect -f "*"com.docker.compose.project"*)
    echo "${FAKE_SPARE_PROJECT:-}"
    ;;
  "inspect -f "*"prewarm-created"*)
    echo "${FAKE_SPARE_CREATED:-}"
    ;;
  "volume ls -q --filter label=com.docker.compose.project="*)
    if [[ "${FAKE_VOLUMES:-}" == "always" ]]; then
      echo vol1
    elif [[ "${FAKE_VOLUMES:-}" == "until-down" && ! -f "$FAKE_DOCKER_LOG.down" ]]; then
      echo vol1
    fi
    ;;
  "compose -p "*" down --volumes --timeout 30")
    [[ -n "${FAKE_DOWN_FAIL:-}" ]] && exit 1
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
        "AGENT_SANDBOX_STATE_DIR": str(tmp_path / "state"),
        "AGENT_SANDBOX_PREWARM_CLAIM_DIR": str(tmp_path / "claims"),
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


# --- gc: prewarm spare reaping + dead-claim removal ---

SPARE_PROJECT = "agent-sandbox-prewarm-00c0ffee"


def _spare_env(created):
    return {
        "FAKE_SPARE_CID": "sparecid",
        "FAKE_SPARE_PROJECT": SPARE_PROJECT,
        "FAKE_SPARE_CREATED": str(created),
    }


def test_gc_reaps_an_over_age_spare_with_volumes_verified(tmp_path):
    r, log = _run(tmp_path, ["gc"], _spare_env(created=1))
    assert r.returncode == 0, r.stderr
    assert f"compose -p {SPARE_PROJECT} down --volumes --timeout 30" in log
    # The reap's claim was released again afterwards.
    assert not (tmp_path / "claims" / SPARE_PROJECT).exists()


def test_gc_keeps_a_fresh_spare(tmp_path):
    r, log = _run(tmp_path, ["gc"], _spare_env(created=int(time.time())))
    assert r.returncode == 0, r.stderr
    assert " down " not in f" {log} "


def test_gc_age_threshold_is_env_tunable(tmp_path):
    recent = int(time.time()) - 5
    r, log = _run(
        tmp_path,
        ["gc"],
        {**_spare_env(created=recent), "AGENT_SANDBOX_PREWARM_MAX_AGE": "0"},
    )
    assert r.returncode == 0, r.stderr
    assert f"compose -p {SPARE_PROJECT} down --volumes --timeout 30" in log


def test_gc_rejects_a_non_numeric_max_age(tmp_path):
    r, _ = _run(
        tmp_path,
        ["gc"],
        {**_spare_env(created=1), "AGENT_SANDBOX_PREWARM_MAX_AGE": "a day"},
    )
    assert r.returncode != 0
    assert "AGENT_SANDBOX_PREWARM_MAX_AGE must be a whole number" in r.stderr


def test_gc_dry_run_reports_the_spare_without_downing_it(tmp_path):
    r, log = _run(tmp_path, ["gc", "--dry-run"], _spare_env(created=1))
    assert r.returncode == 0, r.stderr
    assert " down " not in f" {log} "
    assert "Would remove: 1 over-age prewarm spare(s)" in r.stdout


def test_gc_skips_an_adopted_stack_despite_its_ready_label(tmp_path):
    """Adoption can't remove the immutable ready label; the adopted marker in the
    spare's state dir is what keeps gc off a live (or kept-for-rescue) session."""
    state = tmp_path / "state" / "sessions" / SPARE_PROJECT
    state.mkdir(parents=True)
    (state / "prewarm-adopted").touch()
    r, log = _run(tmp_path, ["gc"], _spare_env(created=1))
    assert r.returncode == 0, r.stderr
    assert " down " not in f" {log} "


def test_gc_skips_a_spare_claimed_by_a_live_process(tmp_path):
    claim = tmp_path / "claims" / SPARE_PROJECT
    claim.mkdir(parents=True)
    (claim / "pid").write_text(f"{os.getpid()}\n")
    r, log = _run(tmp_path, ["gc"], _spare_env(created=1))
    assert r.returncode == 0, r.stderr
    assert " down " not in f" {log} "
    assert (claim / "pid").exists()  # the live claim is untouched


def test_gc_removes_a_dead_pid_claim(tmp_path):
    dead = subprocess.Popen(["true"])
    dead.wait()
    claim = tmp_path / "claims" / "agent-sandbox-prewarm-deadbeef"
    claim.mkdir(parents=True)
    (claim / "pid").write_text(f"{dead.pid}\n")
    r, _ = _run(tmp_path, ["gc"])
    assert r.returncode == 0, r.stderr
    assert not claim.exists()


def test_gc_dry_run_reports_a_dead_claim_without_removing_it(tmp_path):
    dead = subprocess.Popen(["true"])
    dead.wait()
    claim = tmp_path / "claims" / "agent-sandbox-prewarm-deadbeef"
    claim.mkdir(parents=True)
    (claim / "pid").write_text(f"{dead.pid}\n")
    r, _ = _run(tmp_path, ["gc", "--dry-run"])
    assert r.returncode == 0, r.stderr
    assert "Would remove: 1 stale prewarm claim(s)" in r.stdout
    assert claim.exists()


def test_down_removes_project_with_volumes(tmp_path):
    r, log = _run(tmp_path, ["down", "proj1"], {"FAKE_VOLUMES": "until-down"})
    assert r.returncode == 0, r.stderr
    assert "compose -p proj1 down --volumes --timeout 30" in log


def test_down_removes_project_with_only_containers(tmp_path):
    r, log = _run(tmp_path, ["down", "proj1"], {"FAKE_CONTAINERS": "1"})
    assert r.returncode == 0, r.stderr
    assert "compose -p proj1 down --volumes --timeout 30" in log


def test_down_fails_loud_when_compose_down_itself_fails(tmp_path):
    """A non-zero `compose down` is reported as a teardown failure — not silently
    passed through to (or masked by) the survivor check."""
    r, log = _run(
        tmp_path,
        ["down", "proj1"],
        {"FAKE_VOLUMES": "until-down", "FAKE_DOWN_FAIL": "1"},
    )
    assert r.returncode != 0
    assert "compose -p proj1 down --volumes --timeout 30" in log
    assert "teardown failed (compose project proj1)" in r.stderr
    # It failed on the down itself, not on the later survivor verification.
    assert "left volumes behind" not in r.stderr


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

"""Behavioral tests for the `agent-sandbox expand` verb.

Drives the host-side driver of mid-session allowlist expansion with a fake docker on
PATH (no daemon): it must resolve the running firewall container by compose labels
(service=firewall, plus the project label when named) and `docker exec` the
in-container writer with the parsed host:access — and fail CLOSED when the argument
is malformed, when no (or more than one) firewall container is running, when docker
itself is unusable, or when the in-container apply fails.
"""

import os
from pathlib import Path

from tests._helpers import run_capture, write_exe

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
LAUNCHER = REPO / "bin" / "agent-sandbox"

# Logs every invocation to $DOCKER_LOG. `ps` prints $FAKE_FW_CIDS one per line
# (empty => no firewall container) or fails under $FAKE_PS_FAIL; `exec` fails
# under $FAKE_EXEC_FAIL.
FAKE_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_LOG"
if [[ "$1" == "ps" ]]; then
  [[ -n "${FAKE_PS_FAIL:-}" ]] && exit 1
  [[ -n "${FAKE_FW_CIDS:-}" ]] && printf '%s\\n' $FAKE_FW_CIDS
  exit 0
fi
if [[ "$1" == "exec" ]]; then
  [[ -n "${FAKE_EXEC_FAIL:-}" ]] && exit 1
fi
exit 0
"""


def _expand(tmp_path, *args, cids="fwcid123", extra_env=None):
    stub = tmp_path / "stub"
    write_exe(stub / "docker", FAKE_DOCKER)
    log = tmp_path / "docker.log"
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "NO_COLOR": "1",
        "DOCKER_LOG": str(log),
        "FAKE_FW_CIDS": cids,
        **(extra_env or {}),
    }
    env.pop("AGENT_SANDBOX_PROJECT_NAME", None)
    env.update(extra_env or {})
    r = run_capture([str(LAUNCHER), "expand", *args], env=env)
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls


def test_expand_resolves_firewall_by_label_and_execs_the_writer(tmp_path):
    r, calls = _expand(tmp_path, "pypi.org")
    assert r.returncode == 0, r.stderr
    # Resolved by the compose service label, never by name-guessing.
    assert calls[0] == "ps -q --filter label=com.docker.compose.service=firewall"
    # Default access is ro: a bare host must never silently grant full HTTP.
    assert calls[1] == "exec fwcid123 expand-allowlist.bash pypi.org:ro"


def test_expand_passes_explicit_rw_through(tmp_path):
    r, calls = _expand(tmp_path, "api.example.com:rw")
    assert r.returncode == 0, r.stderr
    assert calls[1] == "exec fwcid123 expand-allowlist.bash api.example.com:rw"


def test_expand_scopes_to_project_flag(tmp_path):
    r, calls = _expand(tmp_path, "pypi.org", "--project", "agent-sandbox-abc")
    assert r.returncode == 0, r.stderr
    assert calls[0] == (
        "ps -q --filter label=com.docker.compose.service=firewall"
        " --filter label=com.docker.compose.project=agent-sandbox-abc"
    )


def test_expand_honors_project_env_var(tmp_path):
    r, calls = _expand(
        tmp_path,
        "pypi.org",
        extra_env={"AGENT_SANDBOX_PROJECT_NAME": "agent-sandbox-env"},
    )
    assert r.returncode == 0, r.stderr
    assert "label=com.docker.compose.project=agent-sandbox-env" in calls[0]


def test_expand_without_host_is_rejected(tmp_path):
    r, calls = _expand(tmp_path)
    assert r.returncode != 0
    assert "no host given" in r.stderr
    assert "Usage: agent-sandbox run" in r.stderr
    assert calls == []  # refused before any docker call


def test_expand_with_two_hosts_is_rejected(tmp_path):
    r, calls = _expand(tmp_path, "a.example.com", "b.example.com")
    assert r.returncode != 0
    assert "exactly one" in r.stderr
    assert calls == []


def test_expand_project_flag_without_value_is_rejected(tmp_path):
    r, calls = _expand(tmp_path, "--project")
    assert r.returncode != 0
    assert "--project needs" in r.stderr
    assert calls == []


def test_expand_rejects_bad_access_tier(tmp_path):
    # Fail closed HOST-SIDE on a bad tier, before any docker call: `write` must not
    # reach the container at all (the in-container script would also refuse, but the
    # driver must not depend on that).
    r, calls = _expand(tmp_path, "pypi.org:write")
    assert r.returncode != 0
    assert "invalid access 'write'" in r.stderr
    assert calls == []


def test_expand_rejects_empty_host(tmp_path):
    r, calls = _expand(tmp_path, ":rw")
    assert r.returncode != 0
    assert "empty host" in r.stderr
    assert calls == []


def test_expand_fails_closed_with_no_firewall_container(tmp_path):
    r, calls = _expand(tmp_path, "pypi.org", cids="")
    assert r.returncode != 0
    assert "no running firewall container" in r.stderr
    # It looked (ps) but never exec'd into anything.
    assert len(calls) == 1 and calls[0].startswith("ps -q")


def test_expand_refuses_ambiguous_firewall_containers(tmp_path):
    # Two sessions up and no project named: refusing beats widening the wrong one.
    r, calls = _expand(tmp_path, "pypi.org", cids="fwcid123 fwcid456")
    assert r.returncode != 0
    assert "--project" in r.stderr
    assert not any(c.startswith("exec") for c in calls)


def test_expand_fails_closed_when_docker_ps_fails(tmp_path):
    r, _ = _expand(tmp_path, "pypi.org", extra_env={"FAKE_PS_FAIL": "1"})
    assert r.returncode != 0
    assert "could not list containers" in r.stderr


def test_expand_surfaces_in_container_failure(tmp_path):
    r, calls = _expand(tmp_path, "pypi.org", extra_env={"FAKE_EXEC_FAIL": "1"})
    assert r.returncode != 0
    assert "expansion failed inside the firewall container" in r.stderr
    assert any(c.startswith("exec") for c in calls)  # the failure came from the exec

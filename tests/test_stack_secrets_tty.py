"""Behavioral tests for AS-4: interactive TTY and secret env delivery.

Both features live in stack.bash and are driven end-to-end through the
`agent-sandbox run` launcher with a fake docker on PATH (no daemon), so the exact
argv and on-disk lifecycle are observable:

- **env-file**: the workload's `env` is written to a 0600 env-file referenced by an
  up-only compose override, consumed while the container is created, then unlinked —
  so secrets never persist in the session's on-disk override. The fake docker
  captures the env-file's content + mode at `up`; the test asserts it is gone
  afterwards and that only `up` (never `down`) referenced the env override.
- **tty**: `tty:true` allocates an interactive `docker exec -it` and is a fail-closed
  runtime precondition — the launch refuses BEFORE bring-up when stdin is not a TTY.
"""

import json
import os
import pty
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
LAUNCHER = REPO / "bin" / "agent-sandbox"

# A fake docker that lets a launch reach (and pass) the workload exec:
#   - `network ls` (subnet alloc): silent exit 0 => .0/24 free.
#   - `compose ... up`: optionally capture the referenced env-file's content + mode
#     to $ENV_CAPTURE (proving it existed at up), fail under $FAKE_UP_FAIL.
#   - `compose ... ps -q workload|firewall`: print a fake cid (none for workload under
#     $FAKE_NO_CID, so the no-container fail-closed branch is exercised).
#   - `exec ...`: record the exec argv to $DOCKER_LOG.exec so -it can be asserted.
# Every invocation's argv is logged (one line) to $DOCKER_LOG.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_LOG"
if [[ "$1" == "exec" ]]; then
  printf '%s\n' "$*" >>"$DOCKER_LOG.exec"
  exit 0
fi
if [[ "$1" == "compose" ]]; then
  shift
  files=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -p) shift 2 ;;
    -f)
      files+=("$2")
      shift 2
      ;;
    *) break ;;
    esac
  done
  cmd="${1:-}"
  if [[ "$cmd" == "up" ]]; then
    if [[ -n "${ENV_CAPTURE:-}" ]]; then
      for f in "${files[@]}"; do
        case "$f" in
        *workload-env-override.json)
          ef="$(jq -r '.services.workload.env_file[0]' "$f")"
          cp "$ef" "$ENV_CAPTURE"
          { stat -c '%a' "$ef" 2>/dev/null || stat -f '%Lp' "$ef"; } >"$ENV_CAPTURE.mode"
          ;;
        esac
      done
    fi
    [[ -n "${FAKE_UP_FAIL:-}" ]] && exit 1
    exit 0
  fi
  if [[ "$cmd" == "ps" ]]; then
    case "$*" in
    *workload*) [[ -n "${FAKE_NO_CID:-}" ]] || echo "cid_workload" ;;
    *firewall*) echo "cid_fw" ;;
    esac
    exit 0
  fi
  exit 0
fi
exit 0
"""

VALID = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": ["pypi.org"],
    "ephemeral": True,
}


def _run(tmp_path, workload_obj, *, extra_env=None, stdin_tty=False):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    (stub / "docker").write_text(FAKE_DOCKER)
    (stub / "docker").chmod(0o755)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(workload_obj))
    state = tmp_path / "state"
    # Pin the project name so the per-session state dir ($STATE/sessions/<project>) is
    # deterministic and the env-file lifecycle can be asserted at its real path.
    project = "as4-test"
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "CONTAINER_RUNTIME": "runc",
        "NO_COLOR": "1",
        "SANDBOX_NET_RESERVE_DIR": str(tmp_path / "reserve"),
        "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        "AGENT_SANDBOX_STATE_DIR": str(state),
        "AGENT_SANDBOX_PROJECT_NAME": project,
        "DOCKER_LOG": str(tmp_path / "docker.log"),
        **(extra_env or {}),
    }
    sess = state / "sessions" / project
    kwargs = dict(capture_output=True, text=True, env=env)
    if stdin_tty:
        controller, worker = pty.openpty()
        try:
            r = subprocess.run([str(LAUNCHER), "run", str(wl)], stdin=worker, **kwargs)
        finally:
            os.close(worker)
            os.close(controller)
    else:
        r = subprocess.run(
            [str(LAUNCHER), "run", str(wl)], stdin=subprocess.DEVNULL, **kwargs
        )
    log = tmp_path / "docker.log"
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls, sess


# ── Secret env delivery ─────────────────────────────────────────────


def test_env_delivered_via_0600_envfile_then_unlinked(tmp_path):
    cap = tmp_path / "captured.env"
    wl = {**VALID, "env": {"API_TOKEN": "placeholder-token"}}
    r, calls, sess = _run(tmp_path, wl, extra_env={"ENV_CAPTURE": str(cap)})
    assert r.returncode == 0, r.stderr
    # The env-file existed with exactly the workload's env at `up`, mode 0600.
    assert cap.read_text() == "API_TOKEN=placeholder-token\n"
    assert (tmp_path / "captured.env.mode").read_text().strip() == "600"
    # …and is gone afterwards (unlinked once the container was created).
    assert not (sess / "workload.env").exists()
    assert not (sess / "workload-env-override.json").exists()


def test_env_override_rides_up_but_not_down(tmp_path):
    wl = {**VALID, "env": {"API_TOKEN": "placeholder-token"}}
    r, calls, _ = _run(tmp_path, wl)
    assert r.returncode == 0, r.stderr
    up = [c for c in calls if " up " in f" {c} "]
    down = [c for c in calls if " down " in f" {c} "]
    assert up and all("workload-env-override.json" in c for c in up), up
    assert down and not any("workload-env-override.json" in c for c in down), down


def test_no_env_writes_no_envfile(tmp_path):
    cap = tmp_path / "captured.env"
    r, calls, sess = _run(tmp_path, VALID, extra_env={"ENV_CAPTURE": str(cap)})
    assert r.returncode == 0, r.stderr
    assert not cap.exists()
    assert not any("workload-env-override.json" in c for c in calls)
    assert not (sess / "workload.env").exists()


def test_env_value_with_newline_is_refused_before_bringup(tmp_path):
    wl = {**VALID, "env": {"MULTI": "line1\nline2"}}
    r, calls, sess = _run(tmp_path, wl)
    assert r.returncode != 0
    assert "single-line" in r.stderr, r.stderr
    # Refused before anything was brought up, and no secret file left behind.
    assert not any(" up " in f" {c} " for c in calls)
    assert not (sess / "workload.env").exists()


def test_envfile_removed_even_when_up_fails(tmp_path):
    wl = {**VALID, "env": {"API_TOKEN": "placeholder-token"}}
    r, calls, sess = _run(tmp_path, wl, extra_env={"FAKE_UP_FAIL": "1"})
    assert r.returncode != 0
    assert "did not come up healthy" in r.stderr, r.stderr
    assert not (sess / "workload.env").exists()


def test_envfile_removed_when_no_container_starts(tmp_path):
    wl = {**VALID, "env": {"API_TOKEN": "placeholder-token"}}
    r, calls, sess = _run(tmp_path, wl, extra_env={"FAKE_NO_CID": "1"})
    assert r.returncode != 0
    assert "workload container did not start" in r.stderr, r.stderr
    assert not (sess / "workload.env").exists()


# ── Interactive TTY ─────────────────────────────────────────────────


def test_tty_true_without_a_terminal_fails_closed_before_bringup(tmp_path):
    wl = {**VALID, "tty": True}
    r, calls, _ = _run(tmp_path, wl, stdin_tty=False)
    assert r.returncode != 0
    assert "not a TTY" in r.stderr, r.stderr
    # Fail-fast: refused before the stack was brought up.
    assert not any(" up " in f" {c} " for c in calls)
    assert "workload container did not start" not in r.stderr


def test_tty_false_default_execs_without_it(tmp_path):
    r, _, _ = _run(tmp_path, VALID)
    assert r.returncode == 0, r.stderr
    execs = (tmp_path / "docker.log.exec").read_text().splitlines()
    workload_exec = [e for e in execs if "bash -lc echo hi" in e]
    assert workload_exec, execs
    assert all(" -it " not in f" {e} " for e in workload_exec), workload_exec


def test_tty_true_with_a_terminal_execs_with_it(tmp_path):
    wl = {**VALID, "tty": True}
    r, _, _ = _run(tmp_path, wl, stdin_tty=True)
    assert r.returncode == 0, r.stderr
    execs = (tmp_path / "docker.log.exec").read_text().splitlines()
    workload_exec = [e for e in execs if "bash -lc echo hi" in e]
    assert workload_exec, execs
    assert any(" -it " in f" {e} " for e in workload_exec), workload_exec

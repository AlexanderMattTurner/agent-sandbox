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
- **secret_env**: each value is streamed over an exec's STDIN into /run/secrets/<name>
  on a per-container tmpfs — never argv, never container env, never host disk. The fake
  docker captures the delivery exec's stdin so byte-exactness is observable, and the
  argv log proves the value appears in no docker invocation.
"""

import json
import os
import pty
import subprocess
from pathlib import Path

import pytest

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
#     A secret-delivery exec (argv mentions /run/secrets/) drains stdin like real
#     docker would, captures it to $SECRET_CAPTURE_DIR/<name> when set, and fails
#     under $FAKE_SECRET_FAIL so the delivery fail-closed branch is exercised.
# Every invocation's argv is logged (one line) to $DOCKER_LOG.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_LOG"
if [[ "$1" == "exec" ]]; then
  printf '%s\n' "$*" >>"$DOCKER_LOG.exec"
  if [[ "$*" == *"/run/secrets/"* ]]; then
    # Always drain stdin like real docker exec would — exiting without reading
    # races the writer into an EPIPE under the launcher's pipefail.
    [[ -n "${FAKE_SECRET_FAIL:-}" ]] && { cat >/dev/null; exit 1; }
    if [[ -n "${SECRET_CAPTURE_DIR:-}" ]]; then
      mkdir -p "$SECRET_CAPTURE_DIR"
      # The delivery exec's argv ends `... _ <name> <user>`; its stdin is the value.
      cat >"$SECRET_CAPTURE_DIR/${*: -2:1}"
    else
      cat >/dev/null
    fi
  fi
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


# ── secret_env file delivery ────────────────────────────────────────

SECRET_VALUE = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"


def _read_all_session_bytes(sess):
    return b"".join(
        p.read_bytes() for p in sess.rglob("*") if p.is_file() and not p.is_symlink()
    )


def test_secret_env_streamed_via_stdin_never_argv_env_or_host_disk(tmp_path):
    cap = tmp_path / "secrets"
    wl = {**VALID, "secret_env": {"OAUTH_TOKEN": SECRET_VALUE}}
    r, calls, sess = _run(tmp_path, wl, extra_env={"SECRET_CAPTURE_DIR": str(cap)})
    assert r.returncode == 0, r.stderr
    # The value arrived byte-exact over the delivery exec's stdin…
    assert (cap / "OAUTH_TOKEN").read_text() == SECRET_VALUE
    # …and appears in NO docker argv (exec included) and NO file the session left
    # in the host state dir. `env` would fail both: it rides an env-file override.
    assert all(SECRET_VALUE not in c for c in calls), calls
    assert SECRET_VALUE.encode() not in _read_all_session_bytes(sess)
    # No env-file machinery is involved for secrets.
    assert not any("workload-env-override.json" in c for c in calls)


def test_secret_delivery_exec_shape_and_ordering(tmp_path):
    wl = {**VALID, "secret_env": {"OAUTH_TOKEN": SECRET_VALUE}}
    r, _, _ = _run(tmp_path, wl)
    assert r.returncode == 0, r.stderr
    execs = (tmp_path / "docker.log.exec").read_text().splitlines()
    delivery = [e for e in execs if "/run/secrets/" in e]
    assert len(delivery) == 1, execs
    # Root exec reading stdin, mode 0400 via umask, chowned to the workload user.
    assert delivery[0].startswith("exec -i -u root "), delivery
    assert "umask 377" in delivery[0] and "chown" in delivery[0]
    assert delivery[0].endswith(" _ OAUTH_TOKEN 1000"), delivery
    # Delivered BEFORE the workload's entrypoint ran.
    entry = [i for i, e in enumerate(execs) if "bash -lc echo hi" in e]
    assert entry and execs.index(delivery[0]) < entry[0], execs


def test_secret_env_declares_the_run_secrets_tmpfs_in_the_override(tmp_path):
    wl = {**VALID, "secret_env": {"OAUTH_TOKEN": SECRET_VALUE}}
    r, _, sess = _run(tmp_path, wl)
    assert r.returncode == 0, r.stderr
    override = json.loads((sess / "workload-override.json").read_text())
    assert override["services"]["workload"]["tmpfs"] == [
        "/run/secrets:mode=0755,size=1m"
    ]


@pytest.mark.parametrize(
    "value",
    ["-----BEGIN KEY-----\nline2\nline3\n-----END KEY-----\n", ""],
    ids=["multiline", "empty-string"],
)
def test_secret_value_is_delivered_byte_exact(tmp_path, value):
    cap = tmp_path / "secrets"
    wl = {**VALID, "secret_env": {"SIGNING_KEY": value}}
    r, _, _ = _run(tmp_path, wl, extra_env={"SECRET_CAPTURE_DIR": str(cap)})
    assert r.returncode == 0, r.stderr
    assert (cap / "SIGNING_KEY").read_text() == value


def test_several_secrets_are_each_delivered(tmp_path):
    cap = tmp_path / "secrets"
    wl = {**VALID, "secret_env": {"ALPHA": "a-value", "BETA": "b-value"}}
    r, _, _ = _run(tmp_path, wl, extra_env={"SECRET_CAPTURE_DIR": str(cap)})
    assert r.returncode == 0, r.stderr
    assert (cap / "ALPHA").read_text() == "a-value"
    assert (cap / "BETA").read_text() == "b-value"
    execs = (tmp_path / "docker.log.exec").read_text().splitlines()
    assert len([e for e in execs if "/run/secrets/" in e]) == 2, execs


@pytest.mark.parametrize(
    "workload", [VALID, {**VALID, "secret_env": {}}], ids=["absent", "empty-object"]
)
def test_no_secrets_means_no_tmpfs_and_no_delivery_exec(tmp_path, workload):
    r, _, sess = _run(tmp_path, workload)
    assert r.returncode == 0, r.stderr
    override = json.loads((sess / "workload-override.json").read_text())
    assert "tmpfs" not in override["services"]["workload"]
    execs = (tmp_path / "docker.log.exec").read_text().splitlines()
    assert not any("/run/secrets/" in e for e in execs), execs


@pytest.mark.parametrize(
    "name", ["../evil", "OAUTH_TOKEN\n"], ids=["traversal", "trailing-newline"]
)
def test_unsafe_secret_name_is_refused_before_bringup(tmp_path, name):
    wl = {**VALID, "secret_env": {name: SECRET_VALUE}}
    r, calls, _ = _run(tmp_path, wl)
    assert r.returncode != 0
    assert "secret_env names" in r.stderr, r.stderr
    assert not any(" up " in f" {c} " for c in calls)


def test_library_level_name_check_refuses_an_unshaped_name(tmp_path):
    """stack_run is the documented library entry point, so _stack_deliver_secrets
    revalidates the name below the launcher gate — an unshaped name must never
    choose the path of a root-privileged in-container write."""
    wl = tmp_path / "wl.json"
    wl.write_text(json.dumps({"secret_env": {"bad/name": "v"}}))
    harness = (
        f"source {REPO / 'bin' / 'lib' / 'stack.bash'}\n"
        f"_stack_deliver_secrets {wl} cid_workload 1000\n"
    )
    r = subprocess.run(
        ["bash", "-c", harness],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
    )
    assert r.returncode != 0
    assert "not env-var-shaped" in r.stderr, r.stderr


def test_non_string_secret_value_is_refused_before_bringup(tmp_path):
    wl = {**VALID, "secret_env": {"OAUTH_TOKEN": 42}}
    r, calls, _ = _run(tmp_path, wl)
    assert r.returncode != 0
    assert "string values" in r.stderr, r.stderr
    assert not any(" up " in f" {c} " for c in calls)


def test_failed_secret_delivery_tears_the_stack_down(tmp_path):
    wl = {**VALID, "secret_env": {"OAUTH_TOKEN": SECRET_VALUE}}
    r, calls, _ = _run(tmp_path, wl, extra_env={"FAKE_SECRET_FAIL": "1"})
    assert r.returncode != 0
    assert "could not deliver secret 'OAUTH_TOKEN'" in r.stderr, r.stderr
    assert "refusing to hand over the sandbox" in r.stderr, r.stderr
    down = [c for c in calls if " down " in f" {c} "]
    assert down and all("--volumes" in c for c in down), calls
    # The workload's entrypoint never ran.
    exec_log = tmp_path / "docker.log.exec"
    execs = exec_log.read_text().splitlines() if exec_log.exists() else []
    assert not any("bash -lc echo hi" in e for e in execs), execs


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

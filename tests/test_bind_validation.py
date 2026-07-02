"""Bind-mode (workspace_mount) launch validation, driven end-to-end through
`bin/agent-sandbox run` with a fake docker on PATH (no daemon).

Bind mode has no review-branch quarantine — the workload's writes land directly on
the host — so the launcher must refuse a hostile record BEFORE anything comes up:

- **mode exclusion**: a record carrying both workspace_mount and seed_from_git has
  no coherent write path and is refused loudly (mirrors the schema's top-level `not`).
- **hostile source paths**: a relative path (compose would resolve it against the
  compose file's dir), a symlinked source (dangling included), a missing path or a
  regular file (Docker would fabricate a root-owned dir), and a source resolving to
  or under the library's own state dir all refuse the launch pre-`up`.
- **missing-overmount policy** (post-`up` gate): an EXPLICITLY declared overmount
  path absent from the host workspace refuses the launch and tears the stack down;
  a missing DEFAULT path warns and proceeds; a bind session where no overmount
  applies prints a non-vacuous "nothing is read-only" marker.
- **`$` escaping**: a literal `$` in the bind source reaches the session override
  compose-escaped as `$$`.
"""

import json
import os
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT, write_exe

LAUNCHER = REPO_ROOT / "bin" / "agent-sandbox"

# A fake docker that lets a launch reach (and pass) the workload exec:
#   - `network ls` (subnet alloc): silent exit 0 => .0/24 free.
#   - `compose ... ps -q workload|firewall`: print a fake cid.
#   - `exec ...`: record the exec argv to $DOCKER_LOG.exec (the guardrail write-probe
#     rides an exec, so its paths are observable) and exit 0 (probe verdict: protected).
# Every invocation's argv is logged (one line) to $DOCKER_LOG.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_LOG"
if [[ "$1" == "exec" ]]; then
  printf '%s\n' "$*" >>"$DOCKER_LOG.exec"
  exit 0
fi
if [[ "$1" == "compose" ]]; then
  if [[ "$*" == *" ps "* ]]; then
    case "$*" in
    *workload*) echo "cid_workload" ;;
    *firewall*) echo "cid_fw" ;;
    esac
  fi
  exit 0
fi
exit 0
"""

VALID = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": [],
    "ephemeral": True,
}


def _run(tmp_path, workload_obj, *, state_dir=None, docker_body=FAKE_DOCKER):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", docker_body)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(workload_obj))
    state = Path(state_dir) if state_dir else tmp_path / "state"
    project = "bind-test"
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
    }
    r = subprocess.run(
        [str(LAUNCHER), "run", str(wl)],
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    log = tmp_path / "docker.log"
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls, state / "sessions" / project


def _ups(calls):
    return [c for c in calls if " up " in f" {c} "]


def _bind_ws(tmp_path, name="ws"):
    """A valid bind workspace shipping both default guardrail paths."""
    ws = tmp_path / name
    (ws / ".git" / "hooks").mkdir(parents=True)
    (ws / "node_modules").mkdir()
    return ws


# ── mode exclusion ──────────────────────────────────────────────────


def test_workspace_mount_plus_seed_from_git_is_refused_before_bringup(tmp_path):
    ws = _bind_ws(tmp_path)
    wl = {
        **VALID,
        "workspace_mount": str(ws),
        "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/review"},
    }
    r, calls, _ = _run(tmp_path, wl)
    assert r.returncode != 0
    assert "mutually exclusive" in r.stderr, r.stderr
    assert not _ups(calls)


# ── hostile source paths (all refused before `up`) ──────────────────


def test_relative_workspace_mount_is_refused(tmp_path):
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": "relative/dir"})
    assert r.returncode != 0
    assert "absolute host path" in r.stderr, r.stderr
    assert not _ups(calls)


def test_symlinked_workspace_mount_is_refused(tmp_path):
    real = _bind_ws(tmp_path)
    link = tmp_path / "ws-link"
    link.symlink_to(real)
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": str(link)})
    assert r.returncode != 0
    assert "is a symlink" in r.stderr, r.stderr
    assert not _ups(calls)


def test_symlinked_workspace_mount_with_trailing_slash_is_refused(tmp_path):
    """`[[ -L "/path/link/" ]]` is false for a symlink written with a trailing
    slash — the validator must normalize before the check, or the slash smuggles
    a symlink source past the refusal."""
    real = _bind_ws(tmp_path)
    link = tmp_path / "ws-link"
    link.symlink_to(real)
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": f"{link}/"})
    assert r.returncode != 0
    assert "is a symlink" in r.stderr, r.stderr
    assert not _ups(calls)


def test_dangling_symlink_workspace_mount_is_refused(tmp_path):
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "nonexistent-target")
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": str(link)})
    assert r.returncode != 0
    assert "is a symlink" in r.stderr, r.stderr
    assert not _ups(calls)


def test_missing_workspace_mount_is_refused(tmp_path):
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": str(tmp_path / "nope")})
    assert r.returncode != 0
    assert "does not exist or is not a directory" in r.stderr, r.stderr
    assert not _ups(calls)


def test_regular_file_workspace_mount_is_refused(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": str(f)})
    assert r.returncode != 0
    assert "does not exist or is not a directory" in r.stderr, r.stderr
    assert not _ups(calls)


def test_workspace_mount_equal_to_state_root_is_refused(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    r, calls, _ = _run(
        tmp_path, {**VALID, "workspace_mount": str(state)}, state_dir=state
    )
    assert r.returncode != 0
    assert "library's own state dir" in r.stderr, r.stderr
    assert not _ups(calls)


def test_workspace_mount_under_state_root_is_refused(tmp_path):
    state = tmp_path / "state"
    inner = state / "sessions" / "x"
    inner.mkdir(parents=True)
    r, calls, _ = _run(
        tmp_path, {**VALID, "workspace_mount": str(inner)}, state_dir=state
    )
    assert r.returncode != 0
    assert "library's own state dir" in r.stderr, r.stderr
    assert not _ups(calls)


def test_workspace_mount_reaching_state_root_through_parent_symlink_is_refused(
    tmp_path,
):
    """The source itself is a real directory (not a symlink), but a symlinked path
    component resolves it into the state dir — `cd && pwd -P` sees through it."""
    state = tmp_path / "state"
    inner = state / "sessions" / "x"
    inner.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(state)
    r, calls, _ = _run(
        tmp_path,
        {**VALID, "workspace_mount": str(alias / "sessions" / "x")},
        state_dir=state,
    )
    assert r.returncode != 0
    assert "library's own state dir" in r.stderr, r.stderr
    assert not _ups(calls)


# ── happy path + the post-up guardrail gate ─────────────────────────


def test_valid_bind_launch_reaches_up_and_verifies_guardrails(tmp_path):
    ws = _bind_ws(tmp_path)
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": str(ws)})
    assert r.returncode == 0, r.stderr
    assert _ups(calls)
    assert "overmounts verified read-only (2 paths)" in r.stderr, r.stderr
    # The verify rode a docker exec probing both guardrails' container paths.
    execs = (tmp_path / "docker.log.exec").read_text().splitlines()
    probe = [e for e in execs if "/workspace/.git/hooks" in e]
    assert probe and "/workspace/node_modules" in probe[0], execs


def test_dollar_in_bind_source_is_compose_escaped_in_the_override(tmp_path):
    ws = _bind_ws(tmp_path, name="ws$dollar")
    r, _, sess = _run(tmp_path, {**VALID, "workspace_mount": str(ws)})
    assert r.returncode == 0, r.stderr
    override = json.loads((sess / "workload-override.json").read_text())
    src = override["services"]["workload"]["volumes"][0]["source"]
    assert src == str(ws).replace("$", "$$")
    assert "$$dollar" in src


def test_explicit_missing_overmount_path_refuses_and_tears_down(tmp_path):
    """An explicit overmount_paths entry is a stated security requirement; a member
    absent from the host workspace would silently get no read-only bind, so the
    launch is refused and the stack torn down."""
    ws = _bind_ws(tmp_path)
    wl = {**VALID, "workspace_mount": str(ws), "overmount_paths": ["missing/dir"]}
    r, calls, _ = _run(tmp_path, wl)
    assert r.returncode != 0
    assert "do not exist under the host workspace" in r.stderr, r.stderr
    assert "missing/dir" in r.stderr
    down = [c for c in calls if " down " in f" {c} "]
    assert down and all("--volumes" in c for c in down), calls
    # The workload's entrypoint never ran.
    exec_log = tmp_path / "docker.log.exec"
    execs = exec_log.read_text().splitlines() if exec_log.exists() else []
    assert not any("bash -lc echo hi" in e for e in execs), execs


def test_explicit_present_overmount_path_verifies_and_proceeds(tmp_path):
    ws = _bind_ws(tmp_path)
    (ws / "custom").mkdir()
    wl = {**VALID, "workspace_mount": str(ws), "overmount_paths": ["custom"]}
    r, _, _ = _run(tmp_path, wl)
    assert r.returncode == 0, r.stderr
    assert "overmounts verified read-only (1 paths)" in r.stderr, r.stderr


def test_missing_default_paths_warn_and_proceed_with_marker(tmp_path):
    """No explicit declaration + a workspace shipping neither default path: each
    missing default warns, and the gate still runs, ending in the non-vacuous
    'nothing is read-only' marker instead of silently skipping."""
    ws = tmp_path / "ws"
    ws.mkdir()
    r, calls, _ = _run(tmp_path, {**VALID, "workspace_mount": str(ws)})
    assert r.returncode == 0, r.stderr
    assert "default guardrail path '.git/hooks' does not exist" in r.stderr, r.stderr
    assert "default guardrail path 'node_modules' does not exist" in r.stderr
    assert "nothing under /workspace is mounted read-only" in r.stderr
    assert _ups(calls)


def test_malformed_overmount_paths_is_refused_before_bringup(tmp_path):
    """overmount_paths is the sole kernel-enforced guard in bind mode; a non-array
    value would make the jq iteration yield ZERO guard paths and hand over a
    fully-writable bind, so the launcher refuses it before anything comes up."""
    ws = _bind_ws(tmp_path)
    wl = {**VALID, "workspace_mount": str(ws), "overmount_paths": ".git/hooks"}
    r, calls, _ = _run(tmp_path, wl)
    assert r.returncode != 0
    assert "overmount_paths must be an array of non-empty" in r.stderr, r.stderr
    assert not _ups(calls), calls


def test_writable_guardrail_refuses_tears_down_and_never_execs_entrypoint(tmp_path):
    """The security-critical branch: a guardrail the write-probe proves WRITABLE
    must refuse the hand-over, tear the stack down, and never run the entrypoint."""
    ws = _bind_ws(tmp_path)
    breach_docker = FAKE_DOCKER.replace(
        'if [[ "$1" == "exec" ]]; then',
        'if [[ "$1" == "exec" && "$*" == */workspace/.git/hooks* ]]; then\n'
        '  printf \'%s\\n\' "$*" >>"$DOCKER_LOG.exec"\n'
        "  exit 1\n"
        "fi\n"
        'if [[ "$1" == "exec" ]]; then',
    )
    wl = {**VALID, "workspace_mount": str(ws)}
    r, calls, _ = _run(tmp_path, wl, docker_body=breach_docker)
    assert r.returncode != 0
    assert "read-only guardrail is writable or unverifiable" in r.stderr, r.stderr
    down = [c for c in calls if " down " in f" {c} "]
    assert down and all("--volumes" in c for c in down), calls
    exec_log = tmp_path / "docker.log.exec"
    execs = exec_log.read_text().splitlines() if exec_log.exists() else []
    assert not any("bash -lc echo hi" in e for e in execs), execs


def test_explicit_empty_overmounts_prints_marker_without_warns(tmp_path):
    """[] declares nothing, so nothing is missing (no warns, no refusal) — but the
    marker still states that nothing is held read-only."""
    ws = _bind_ws(tmp_path)
    wl = {**VALID, "workspace_mount": str(ws), "overmount_paths": []}
    r, _, _ = _run(tmp_path, wl)
    assert r.returncode == 0, r.stderr
    assert "nothing under /workspace is mounted read-only" in r.stderr, r.stderr
    assert "default guardrail path" not in r.stderr
    assert "overmounts verified" not in r.stderr

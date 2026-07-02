"""Behavioral slice tests for sandbox/hardener-entrypoint.bash — the generic
hook runner behind the hardener service's fail-closed contract: no hooks means
success, any failing hook means a non-zero exit (so the workload's
service_completed_successfully gate never opens), and hook output lands in the
shared hardened-config target."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)
ENTRYPOINT = REPO / "sandbox" / "hardener-entrypoint.bash"
BASH = shutil.which("bash") or "/bin/bash"


def run_hardener(hooks_dir, config_dir, extra_env=None):
    env = {
        **os.environ,
        "HARDENER_HOOKS_DIR": str(hooks_dir),
        "HARDENED_CONFIG_DIR": str(config_dir),
        **(extra_env or {}),
    }
    return subprocess.run(
        [BASH, str(ENTRYPOINT)], capture_output=True, text=True, env=env
    )


def write_hook(hooks_dir: Path, name: str, body: str, executable: bool = True) -> Path:
    hook = hooks_dir / name
    hook.write_text(f"#!/bin/sh\n{body}\n")
    if executable:
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
    return hook


def test_missing_hooks_dir_is_noop_success(tmp_path):
    res = run_hardener(tmp_path / "absent", tmp_path / "cfg")
    assert res.returncode == 0
    assert "applied 0 hook(s)" in res.stdout


def test_dev_null_hooks_mount_is_noop_success(tmp_path):
    # The compose default binds /dev/null over the hooks dir: a non-directory
    # must mean "no hooks", never an error.
    res = run_hardener("/dev/null", tmp_path / "cfg")
    assert res.returncode == 0
    assert "applied 0 hook(s)" in res.stdout


def test_empty_hooks_dir_is_noop_success(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    res = run_hardener(hooks, tmp_path / "cfg")
    assert res.returncode == 0
    assert "applied 0 hook(s)" in res.stdout


def test_hook_output_lands_in_hardened_config(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    write_hook(hooks, "10-write.sh", 'echo locked > "$HARDENED_CONFIG_DIR/policy"')
    cfg = tmp_path / "cfg"
    res = run_hardener(hooks, cfg)
    assert res.returncode == 0
    assert (cfg / "policy").read_text() == "locked\n"
    assert "applied 1 hook(s)" in res.stdout


def test_hooks_run_in_sorted_order(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    write_hook(hooks, "20-second.sh", 'echo second >> "$HARDENED_CONFIG_DIR/order"')
    write_hook(hooks, "10-first.sh", 'echo first >> "$HARDENED_CONFIG_DIR/order"')
    cfg = tmp_path / "cfg"
    assert run_hardener(hooks, cfg).returncode == 0
    assert (cfg / "order").read_text() == "first\nsecond\n"


def test_failing_hook_fails_closed_with_its_exit_code(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    write_hook(hooks, "10-fail.sh", "exit 7")
    write_hook(hooks, "20-after.sh", 'touch "$HARDENED_CONFIG_DIR/reached"')
    cfg = tmp_path / "cfg"
    res = run_hardener(hooks, cfg)
    assert res.returncode == 7
    assert "hook failed (exit 7)" in res.stderr
    # Fail-closed means fail FAST: the later hook never runs.
    assert not (cfg / "reached").exists()


def test_non_executable_file_is_skipped(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    write_hook(hooks, "notes.txt", "exit 1", executable=False)
    res = run_hardener(hooks, tmp_path / "cfg")
    assert res.returncode == 0
    assert "applied 0 hook(s)" in res.stdout


def test_emits_hardener_lockdown_applied_trace(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    write_hook(hooks, "10-ok.sh", "true")
    trace_file = tmp_path / "trace.jsonl"
    res = run_hardener(
        hooks,
        tmp_path / "cfg",
        {"AGENT_SANDBOX_TRACE": "info", "AGENT_SANDBOX_TRACE_FILE": str(trace_file)},
    )
    assert res.returncode == 0
    lines = trace_file.read_text().splitlines()
    assert len(lines) == 1
    import json

    event = json.loads(lines[0])
    assert event["event"] == "hardener_lockdown_applied"
    assert event["layer"] == "hardener"
    assert event["hooks"] == "1"


def test_no_trace_emitted_on_hook_failure(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    write_hook(hooks, "10-fail.sh", "exit 1")
    trace_file = tmp_path / "trace.jsonl"
    run_hardener(
        hooks,
        tmp_path / "cfg",
        {"AGENT_SANDBOX_TRACE": "info", "AGENT_SANDBOX_TRACE_FILE": str(trace_file)},
    )
    # The lockdown-applied event asserts success; a failed run must not emit it.
    assert not trace_file.exists()

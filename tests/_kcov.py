"""Real line coverage for the bash wrappers, which pytest-cov cannot see.

coverage.py only instruments Python; the `bin/` wrappers run as subprocesses, so
their lines are invisible to it. This module closes the gap by routing subprocess
invocations through `kcov`, which traces bash line-by-line via the DEBUG trap and
enforces 100% real line coverage — not just that a test claims to cover the script.

Coverage is **opt-out**: every bash script discovered under `bin/` is enrolled
automatically. To skip a script, add it to `KCOV_EXCLUDED` with a reason.

Mechanism: when `AGENT_SANDBOX_KCOV_OUT` is set, `install()` monkeypatches
`subprocess.run`/`Popen` so any invocation of an enrolled script is rewritten to

    kcov --bash-method=DEBUG --include-pattern=<script> <rundir> <script> <args...>

Each invocation writes its own `<rundir>`; `kcov --merge` unions them at the end (a
line covered in any run counts as covered). The interceptor is a no-op unless the
env var is set, so the ordinary test run is untouched — only the dedicated kcov pass
(see `tests/run-kcov.sh`) pays the tracing cost.

`--bash-method=DEBUG` is deliberate: the alternative `PS4` method stops tracing at
heredocs (kcov#116), and these wrappers use them.
"""

import ast
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

from tests._helpers import REPO_ROOT

# How many parallel shards the CI kcov pass fans out across (see tests/run-kcov.sh
# and tests/conftest.py). The single source of truth: the workflow DERIVES its
# matrix and KCOV_SHARD_COUNT from this value, so the two can never drift.
KCOV_SHARD_COUNT = 2


def _kcov_bin() -> str:
    """The kcov binary as an absolute path when resolvable, so the wrapped subprocess
    finds it even when a test pins a restricted PATH. Falls back to bare 'kcov' when
    it isn't on PATH — run-kcov.sh guards a real run with an upfront `command -v kcov`,
    so the only caller left then is the in-process harness test, which never execs."""
    return shutil.which("kcov") or "kcov"


def _timeout_bin() -> str:
    """Absolute path to coreutils `timeout`, used to cap a hung kcov; falls back to
    the bare name (the in-process harness test never execs the argv)."""
    return shutil.which("timeout") or "timeout"


_BASH_SHEBANG = re.compile(r"^#!.*\bbash\b")


def _is_bash(path: Path) -> bool:
    """True for .bash files and for extensionless/.sh files with a bash shebang.
    Library files with `# shellcheck shell=bash` (no shebang) are caught by the .bash
    suffix; POSIX sh scripts (.sh with a non-bash shebang) are not."""
    if path.suffix == ".bash":
        return True
    try:
        first_line = (
            path.read_bytes().split(b"\n", 1)[0].decode("ascii", errors="replace")
        )
        return bool(_BASH_SHEBANG.match(first_line))
    except OSError:
        return False


def _discover_bash_files() -> list[str]:
    """All bash scripts under bin/, repo-relative, sorted. Symlinks are skipped:
    every committed bin/ entry is a regular file, so a symlink under bin/ is always a
    transient test artifact whose randomly-derived name would (a) show up as an
    unaccounted 'bash file' and (b) race a mid-teardown unlink against read_text."""
    return sorted(
        str(p.relative_to(REPO_ROOT))
        for p in (REPO_ROOT / "bin").rglob("*")
        if p.is_file() and not p.is_symlink() and _is_bash(p)
    )


# Files opted out of automatic kcov enrollment. All of bin/lib/ is library-only:
# sourced into bin/agent-sandbox (and each other), never invoked as an entry point,
# so a standalone kcov run of the wrapper (--include-pattern scopes each run to one
# file) never traces them. Each is line-gated instead by its own pytest suite, which
# sources the individual functions (test_sandbox_runtime_fs_states.py, test_sandbox_net.py,
# test_runtime_detect*.py, test_stack_entrypoint_argv.py, test_worktree_seed_host.py,
# test_backend_gates.py, test_overmounts.py). stack.bash, worktree-seed.bash, and
# overmounts.bash additionally run seed/exec/probe bodies through `docker exec`, which
# kcov's DEBUG trap cannot follow into, so they could not reach 100% standalone regardless.
KCOV_EXCLUDED: list[str] = [
    "bin/lib/backend.bash",
    "bin/lib/flock.bash",
    "bin/lib/msg.bash",
    "bin/lib/overmounts.bash",
    "bin/lib/runtime-detect.bash",
    "bin/lib/sandbox-net.bash",
    "bin/lib/sandbox-runtime.bash",
    "bin/lib/stack.bash",
    "bin/lib/worktree-seed.bash",
]

# Vehicle entry points: a script run only to carry coverage into a sourced lib we DO
# gate, without gating the script itself. None today — the libs are covered by their
# own sourced-function suites (KCOV_EXCLUDED) rather than through a driver. Kept as the
# SSOT structure so gating a lib later is a one-line addition. Maps entry point -> lib.
KCOV_GATED_VIA_VEHICLE: dict[str, str] = {}

# End-to-end-runnable wrappers gated at 100% real line coverage. Computed from all bash
# files discovered under bin/, minus KCOV_EXCLUDED and the vehicle-gated libs.
KCOV_ENROLLED: list[str] = [
    f
    for f in _discover_bash_files()
    if f not in set(KCOV_EXCLUDED) | set(KCOV_GATED_VIA_VEHICLE.values())
]

# Everything kcov_gate enforces at 100%: directly-enrolled wrappers + vehicle libs.
KCOV_GATED = KCOV_ENROLLED + list(KCOV_GATED_VIA_VEHICLE.values())

# The test files the CI kcov-shard step traces. This is the single source of truth: CI
# reads it from here rather than re-typing the list in YAML, and discover_argv0_feeders()
# + the harness test guard it against drift. A wrapper reaches 100% only from the UNION
# of its suites, so omitting a file silently drops the lines only it covers — the gate
# then reports them uncovered, naming the wrapper rather than the missing test.
KCOV_TEST_FILES = [
    "tests/test_expand_cli.py",
    "tests/test_launcher.py",
    "tests/test_lifecycle_verbs.py",
    "tests/test_stack_seams.py",
]


def discover_argv0_feeders() -> set[str]:
    """Repo-relative test files that invoke an enrolled wrapper as argv[0].

    The kcov interceptor traces a run only when argv[0] resolves to an enrolled wrapper
    (see wrap_argv); a `bash <wrapper>` or `<wrapper>.read_text()` does NOT feed
    coverage. So a static text scan over-matches. This walks each test file's AST and
    flags it only when a subprocess-style call's argv[0] is `str(NAME)`/`NAME` for a
    NAME bound at module level to an enrolled wrapper's path — the interceptor's own
    trigger. Used by the drift test to assert every detected feeder is in KCOV_TEST_FILES.
    One-directional by design: a feeder reached via a shared helper may be listed without
    being detected (the safe direction); the gate's NOT-TRACED check is the backstop."""
    enrolled = set(KCOV_ENROLLED)
    subprocess_callees = {
        "run",
        "Popen",
        "check_output",
        "call",
        "check_call",
        "run_capture",
    }

    def assigned_wrapper(value: ast.expr) -> str | None:
        # A `REPO / "a" / "b"` chain whose string parts join to an enrolled path.
        parts: list[str] = []
        node = value
        while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if isinstance(node.right, ast.Constant) and isinstance(
                node.right.value, str
            ):
                parts.insert(0, node.right.value)
            node = node.left
        rel = "/".join(parts)
        return rel if rel in enrolled else None

    def argv0_name(call: ast.Call) -> str | None:
        # The Name used as argv[0]: first element of a list/tuple first positional,
        # unwrapping one str(...) layer.
        if not call.args:
            return None
        seq = call.args[0]
        if not isinstance(seq, (ast.List, ast.Tuple)) or not seq.elts:
            return None
        first = seq.elts[0]
        if (
            isinstance(first, ast.Call)
            and isinstance(first.func, ast.Name)
            and first.func.id == "str"
            and first.args
        ):
            first = first.args[0]
        return first.id if isinstance(first, ast.Name) else None

    feeders: set[str] = set()
    for path in sorted((REPO_ROOT / "tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text())
        consts: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                wrapper = assigned_wrapper(node.value)
                if wrapper:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            consts[tgt.id] = wrapper
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else (func.attr if isinstance(func, ast.Attribute) else None)
            )
            if name in subprocess_callees and argv0_name(node) in consts:
                feeders.add(str(path.relative_to(REPO_ROOT)))
    return feeders


# Resolved entry-point path -> the file its run is scoped to via --include-pattern. An
# enrolled wrapper traces itself; a vehicle traces the sourced lib it carries.
_INCLUDE_TARGET: dict[str, str] = {
    **{
        str((REPO_ROOT / p).resolve()): str((REPO_ROOT / p).resolve())
        for p in KCOV_ENROLLED
    },
    **{
        str((REPO_ROOT / ep).resolve()): str((REPO_ROOT / lib).resolve())
        for ep, lib in KCOV_GATED_VIA_VEHICLE.items()
    },
}


def _outdir() -> Path:
    return Path(os.environ["AGENT_SANDBOX_KCOV_OUT"])


def wrap_argv(argv: object) -> object:
    """Rewrite an entry-point argv to run under kcov; pass everything else through
    untouched. Only list/tuple argvs whose argv[0] resolves to an enrolled wrapper (or
    a vehicle entry point) are wrapped; the run is scoped to that entry point's target."""
    if not isinstance(argv, (list, tuple)) or not argv:
        return argv
    first = str(argv[0])
    resolved = str(Path(first).resolve()) if os.sep in first else first
    target = _INCLUDE_TARGET.get(resolved)
    if target is None:
        return argv
    rundir = _outdir() / "runs" / uuid.uuid4().hex
    return [
        # Cap every kcov invocation: kcov can hang when the traced wrapper's final exec
        # replaces it with a program that blocks, and its waitpid never returns. timeout
        # kills the stuck kcov; coverage survives (kcov writes the cobertura report every
        # few seconds and the wrapper's own lines ran before it blocked). -k SIGKILLs if
        # SIGTERM is ignored.
        _timeout_bin(),
        "-k",
        "10",
        "90",
        _kcov_bin(),
        "--bash-method=DEBUG",
        # Trace only the enrolled wrapper, not the programs it execs: kcov's execve
        # redirector would otherwise re-wrap every child #!/bin/bash (the fake docker
        # stub). Coverage is unaffected — every enrolled script is traced by its own
        # test's direct invocation (the parent), never only as another's exec'd child.
        "--bash-tracefd-cloexec",
        f"--include-pattern={target}",
        # Inline exclusion markers. Every use must be surfaced and justified in review —
        # it removes a line from the 100% denominator.
        "--exclude-line=kcov-ignore-line",
        "--exclude-region=kcov-ignore-start:kcov-ignore-end",
        str(rundir),
        *(str(a) for a in argv),
    ]


def install() -> None:
    """Patch subprocess.run/Popen to route enrolled scripts through kcov. No-op unless
    AGENT_SANDBOX_KCOV_OUT is set, so the normal test run is unaffected."""
    if not os.environ.get("AGENT_SANDBOX_KCOV_OUT"):
        return
    (_outdir() / "runs").mkdir(parents=True, exist_ok=True)
    real_run = subprocess.run
    real_popen = subprocess.Popen
    subprocess.run = lambda argv, *a, **k: real_run(wrap_argv(argv), *a, **k)
    subprocess.Popen = lambda argv, *a, **k: real_popen(wrap_argv(argv), *a, **k)

"""worktree_container_init_repo must print ONLY the base SHA on stdout.

The function's stdout IS the extract's base ref: the caller captures it and later
runs `git log <captured>..HEAD`, so any stray line that reaches stdout corrupts
the ref and breaks the mandatory pre-teardown extract. The empty-seeded-tree case
is where this bites: the first `git commit -q` attempt has nothing to commit and
prints its status summary to stdout despite -q, before the --allow-empty fallback
succeeds. The invariant asserted here is stdout purity — exactly one 40-hex line —
for both an empty and a populated seeded tree.

The docker stub redirects the in-container script's `cd /workspace` into a host
temp dir (the script is otherwise executed verbatim by the host `sh`), because
the function's contract under test is its stdout, not container plumbing.
"""

import os
import re
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT, write_exe

LIB = REPO_ROOT / "bin" / "lib" / "worktree-seed.bash"

# covers: bin/lib/worktree-seed.bash

_DOCKER_STUB = """#!/bin/bash
# Emulate `docker exec -u USER CID sh -c SCRIPT sh ARGS...`: run SCRIPT with the
# host sh, rehoming its `cd /workspace` into $FAKE_WORKSPACE.
shift 4
script="$3"
script="${script/cd \\/workspace/cd \\"$FAKE_WORKSPACE\\"}"
exec sh -c "$script" "${@:4}"
"""


def _init_repo(tmp_path: Path, workspace: Path) -> subprocess.CompletedProcess[str]:
    stub = tmp_path / "stub"
    write_exe(stub / "docker", _DOCKER_STUB)
    return subprocess.run(
        [
            "bash",
            "-c",
            f'source "{LIB}"; worktree_container_init_repo cid-unused sandbox/test-branch',
        ],
        env={
            **os.environ,
            "PATH": f"{stub}:{os.environ['PATH']}",
            "FAKE_WORKSPACE": str(workspace),
        },
        capture_output=True,
        text=True,
        check=False,
    )


def _assert_stdout_is_one_sha(r: subprocess.CompletedProcess[str]) -> None:
    assert r.returncode == 0, r.stderr
    assert re.fullmatch(r"[0-9a-f]{40}\n", r.stdout), (
        f"stdout must be exactly one 40-hex base-ref line, got: {r.stdout!r}"
    )


def test_init_repo_stdout_is_only_the_sha_for_an_empty_tree(tmp_path: Path) -> None:
    """The --allow-empty fallback path: the failed first commit's status text must
    never reach stdout (it would be captured into the extract's base ref)."""
    workspace = tmp_path / "ws-empty"
    workspace.mkdir()
    _assert_stdout_is_one_sha(_init_repo(tmp_path, workspace))


def test_init_repo_stdout_is_only_the_sha_for_a_populated_tree(tmp_path: Path) -> None:
    workspace = tmp_path / "ws-full"
    workspace.mkdir()
    (workspace / "file.txt").write_text("seeded content\n")
    _assert_stdout_is_one_sha(_init_repo(tmp_path, workspace))

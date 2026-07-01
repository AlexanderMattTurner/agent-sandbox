"""Host-side (macOS/BSD-portable) tests for bin/lib/worktree-seed.bash.

`worktree_secure_mkdir` is the one worktree-seed primitive that runs on the user's
HOST, not inside the Linux sandbox: the launcher sources the lib and calls it to
create the owner-only plaintext store where the extracted .wip.patch lands in the
user's filesystem. It carries the GNU/BSD-divergent `stat -c '%a' || stat -f '%Lp'`
mode read and leans on BSD `mkdir -p`'s dangling-symlink behavior, so its arm is
exercised here (the container-side seed/extract round-trip is Linux+Docker-only).
"""

import os
import subprocess
from pathlib import Path

from tests._helpers import REPO_ROOT, write_exe

LIB = REPO_ROOT / "bin" / "lib" / "worktree-seed.bash"

# covers: bin/lib/worktree-seed.bash


def _mode(p: Path) -> int:
    """The low 12 permission bits of <p>, for an exact-equality assertion."""
    return p.stat().st_mode & 0o7777


def _sourced(snippet: str, *args: str, env: dict | None = None):
    """Run a snippet with the lib sourced; `args` become $1.. inside it."""
    return subprocess.run(
        ["bash", "-c", f'source "{LIB}"; {snippet}', "_", *args],
        env={**os.environ, **(env or {})},
        capture_output=True,
        check=False,
    )


def test_secure_mkdir_creates_owner_only_dir(tmp_path: Path) -> None:
    """worktree_secure_mkdir creates the store 0700 even under a permissive 022 umask."""
    store = tmp_path / "seed-branches"
    r = _sourced('umask 022; worktree_secure_mkdir "$1"', str(store))
    assert r.returncode == 0, r.stderr
    assert store.is_dir()
    assert _mode(store) == 0o700


def test_secure_mkdir_tightens_a_preexisting_loose_dir(tmp_path: Path) -> None:
    """Re-run over a pre-existing world-readable store (the reinstall/second-launch
    case) must TIGHTEN it to 0700, not leave the loose perms a prior umask set."""
    store = tmp_path / "seed-branches"
    store.mkdir(mode=0o755)
    os.chmod(store, 0o755)  # mkdir's mode is umask-masked; force the loose state
    assert _mode(store) == 0o755
    r = _sourced('umask 022; worktree_secure_mkdir "$1"', str(store))
    assert r.returncode == 0, r.stderr
    assert _mode(store) == 0o700


def test_secure_mkdir_fails_loud_on_dangling_symlink(tmp_path: Path) -> None:
    """A store path that is a DANGLING symlink: `mkdir -p` returns 0 on BSD without
    creating a directory, so the helper must verify `-d` and fail loud rather than let
    a later write die cryptically (the ensure-dir doctrine: success = post-condition)."""
    link = tmp_path / "seed-branches"
    link.symlink_to(tmp_path / "missing-target")  # dangling
    r = _sourced('worktree_secure_mkdir "$1"', str(link))
    assert r.returncode != 0
    assert b"could not create the owner-only store directory" in r.stderr


def test_secure_mkdir_fails_loud_when_dir_cannot_be_tightened(tmp_path: Path) -> None:
    """A pre-existing store dir whose mode CANNOT be tightened to 0700 (owned by another
    user, on a no-perm filesystem) must fail LOUD — never return success with the
    plaintext store left group/other-readable. The post-condition (the dir is owner-only),
    not chmod's swallowed exit status, decides success. Modeled by shadowing `chmod` with
    a no-op so the pre-existing 0755 dir stays loose, exactly as a chmod that physically
    can't tighten it would: the helper must read the mode back and refuse."""
    store = tmp_path / "seed-branches"
    store.mkdir(mode=0o755)
    os.chmod(store, 0o755)
    stub = tmp_path / "stub"
    write_exe(stub / "chmod", "#!/bin/sh\nexit 0\n")  # a chmod that does NOT tighten
    r = _sourced(
        'worktree_secure_mkdir "$1"',
        str(store),
        env={"PATH": f"{stub}:{os.environ.get('PATH', '')}"},
    )
    assert r.returncode != 0
    assert b"could not lock the plaintext store directory" in r.stderr
    assert _mode(store) == 0o755  # still loose — the guard refused, not silently passed

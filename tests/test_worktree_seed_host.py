"""Host-side (macOS/BSD-portable) tests for bin/lib/worktree-seed.bash.

Covers the worktree-seed primitives that run on the user's HOST, not inside the
Linux sandbox: `worktree_secure_mkdir` (the owner-only plaintext store; it carries
the GNU/BSD-divergent `stat -c '%a' || stat -f '%Lp'` mode read and leans on BSD
`mkdir -p`'s dangling-symlink behavior), plus the pure-git seed/replay helpers a
persistent session leans on — `worktree_seed_tar_ref`, `worktree_tip_is_wip_fold`,
and `worktree_host_apply`'s existing-branch path — all real-git, no docker (the
container-side seed/extract round-trip is Linux+Docker-only).
"""

import io
import os
import subprocess
import tarfile
from pathlib import Path

from tests._helpers import (
    REPO_ROOT,
    commit_all,
    git_env,
    init_test_repo,
    write_exe,
)

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
    a later write die cryptically (the ensure-dir doctrine: success = post-condition).
    Caught by the symlink pre-check (a symlink is refused outright, whether dangling
    or not) before `mkdir -p` is even attempted."""
    link = tmp_path / "seed-branches"
    link.symlink_to(tmp_path / "missing-target")  # dangling
    r = _sourced('worktree_secure_mkdir "$1"', str(link))
    assert r.returncode != 0
    assert b"it is a symlink" in r.stderr


def test_secure_mkdir_rejects_symlink_planted_between_the_pre_check_and_mkdir(
    tmp_path: Path,
) -> None:
    """The pre-check only catches a symlink that already exists before the call — it
    cannot see one planted in the window between that check and `mkdir -p`. A stubbed
    `mkdir` models exactly that race (a symlink appears at `$dir` where `mkdir -p`
    would have created a real directory), proving the POST-mkdir `-L` recheck — not
    just the pre-check — actually refuses it. The recheck runs BEFORE `chmod 700`,
    so the guard must refuse without ever chmod-ing through the planted link: the
    target starts 0755 precisely so a chmod that followed the link would leave a
    visible 0700 and fail the final assertion."""
    store = tmp_path / "seed-branches"
    target = tmp_path / "attacker-owned"
    target.mkdir(mode=0o755)
    os.chmod(target, 0o755)
    stub = tmp_path / "stub"
    write_exe(
        stub / "mkdir",
        f'#!/bin/sh\nln -s "{target}" "{store}"\n',
    )
    r = _sourced(
        'worktree_secure_mkdir "$1"',
        str(store),
        env={"PATH": f"{stub}:{os.environ.get('PATH', '')}"},
    )
    assert r.returncode != 0
    assert b"it is a symlink" in r.stderr
    # Refused before chmod: the planted target's mode is untouched.
    assert _mode(target) == 0o755


def test_secure_mkdir_rejects_symlink_to_an_existing_owned_directory(
    tmp_path: Path,
) -> None:
    """`-d`/`chmod`/`stat` all follow symlinks, so mode and ownership checks alone
    cannot distinguish a store path that is a symlink to a REAL, already-0700,
    self-owned directory from a planted symlink to an attacker-owned directory
    elsewhere on the host — both look identical up to the mode/ownership check. The
    caller asked for `$dir` itself to be a private directory, not an indirection, so
    the guard refuses ANY symlink outright rather than trying to special-case
    "trustworthy" targets."""
    real = tmp_path / "real-store"
    real.mkdir(mode=0o700)
    os.chmod(real, 0o700)
    link = tmp_path / "seed-branches"
    link.symlink_to(real)
    r = _sourced('worktree_secure_mkdir "$1"', str(link))
    assert r.returncode != 0
    assert b"it is a symlink" in r.stderr
    # The guard refused before ever touching the real target's contents/mode.
    assert _mode(real) == 0o700


def test_secure_mkdir_rejects_directory_owned_by_someone_else(tmp_path: Path) -> None:
    """Regression: mode alone is not enough — a 0700 directory owned by ANOTHER local
    user must still be refused, since that user (not us) controls what lives under it
    (they could swap it for a symlink, or already be watching it) after the check runs.
    `stat` is stubbed to report a different owner uid than ours while keeping the
    reported mode at 700, isolating the ownership check from the mode check."""
    store = tmp_path / "seed-branches"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    foreign_uid = os.getuid() + 1
    stub = tmp_path / "stub"
    write_exe(
        stub / "stat",
        "#!/bin/sh\n"
        'case "$1" in\n'
        f"-c) case \"$2\" in '%a') echo 700 ;; '%u') echo {foreign_uid} ;; esac ;;\n"
        "esac\n",
    )
    r = _sourced(
        'worktree_secure_mkdir "$1"',
        str(store),
        env={"PATH": f"{stub}:{os.environ.get('PATH', '')}"},
    )
    assert r.returncode != 0
    assert b"owned by uid" in r.stderr
    assert str(foreign_uid).encode() in r.stderr


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


# --- worktree_seed_tar_ref: arbitrary-ref committed-tree seeds ---


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=git_env(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _ref_repo(tmp_path: Path) -> Path:
    """base commit (tagged) -> second commit on a branch; dirty working tree on top,
    so the tests can prove the tar carries the COMMITTED tree, never the checkout."""
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "a.txt").write_text("base\n")
    commit_all(repo, "fixture: base")
    _git(repo, "tag", "v-base")
    _git(repo, "switch", "-q", "-c", "feature")
    (repo / "b.txt").write_text("feature\n")
    commit_all(repo, "fixture: feature")
    (repo / "a.txt").write_text("DIRTY uncommitted edit\n")  # never in any commit
    return repo


def _tar_members(raw: bytes) -> dict[str, bytes]:
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for m in tf.getmembers():
            if m.isfile():
                files[m.name] = tf.extractfile(m).read()
    return files


def _seed_tar_ref(repo: Path, ref: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "bash",
            "-c",
            f'source "{LIB}"; worktree_seed_tar_ref "$1" "$2"',
            "_",
            str(repo),
            ref,
        ],
        env=git_env(),
        capture_output=True,
    )


def test_seed_tar_ref_tags_branches_and_shas_all_yield_the_committed_tree(
    tmp_path: Path,
) -> None:
    repo = _ref_repo(tmp_path)
    base_sha = _git(repo, "rev-parse", "v-base")
    # Tag and sha name the base commit: exactly a.txt at its COMMITTED content
    # (the dirty working-tree edit must not leak into a pinned-ref seed).
    for ref in ("v-base", base_sha):
        r = _seed_tar_ref(repo, ref)
        assert r.returncode == 0, r.stderr
        assert _tar_members(r.stdout) == {"a.txt": b"base\n"}
    # A branch ref yields its own committed tree, distinct from the tag's.
    r = _seed_tar_ref(repo, "feature")
    assert r.returncode == 0, r.stderr
    assert _tar_members(r.stdout) == {"a.txt": b"base\n", "b.txt": b"feature\n"}


def test_seed_tar_ref_fails_loud_on_an_unresolvable_ref(tmp_path: Path) -> None:
    repo = _ref_repo(tmp_path)
    r = _seed_tar_ref(repo, "no-such-ref")
    assert r.returncode != 0
    assert r.stdout == b""  # nothing half-written on the seed pipe


# --- worktree_tip_is_wip_fold: the resume soft-reset decision ---


def test_tip_is_wip_fold_matches_only_the_extract_fold_subject(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "f").write_text("1\n")
    commit_all(repo, "feat: real work")
    check = f'source "{LIB}"; worktree_tip_is_wip_fold "$1" "$2"'
    r = subprocess.run(
        ["bash", "-c", check, "_", str(repo), "main"],
        env=git_env(),
        capture_output=True,
    )
    assert r.returncode != 0  # a real commit is not the fold
    (repo / "f").write_text("2\n")
    commit_all(repo, "chore: uncommitted changes at session end")
    r = subprocess.run(
        ["bash", "-c", check, "_", str(repo), "main"],
        env=git_env(),
        capture_output=True,
    )
    assert r.returncode == 0, r.stderr
    # A branch that doesn't resolve is a refusal, not a silent "no".
    r = subprocess.run(
        ["bash", "-c", check, "_", str(repo), "no-such-branch"],
        env=git_env(),
        capture_output=True,
    )
    assert r.returncode != 0


def test_wip_fold_subject_constant_matches_the_extract_emitter(tmp_path: Path) -> None:
    """The constant IS what worktree_container_extract commits with: the extract body
    receives it as a positional arg, so a drifted literal cannot exist — pin that the
    emitter references the shared parameter and the constant has the expected value."""
    src = LIB.read_text()
    assert (
        'WORKTREE_WIP_FOLD_SUBJECT="chore: uncommitted changes at session end"' in src
    )
    assert '\' sh "$base_ref" "$WORKTREE_WIP_FOLD_SUBJECT"' in src


# --- worktree_host_apply: existing-branch (re-attach leg) path ---


def _host_apply(repo: Path, base: str, branch: str, wt: Path, wip: Path, mbox: Path):
    return subprocess.run(
        [
            "bash",
            "-c",
            f'source "{LIB}"; worktree_host_apply "$1" "$2" "$3" "$4" "$5" "$6"',
            "_",
            str(repo),
            base,
            branch,
            str(wt),
            str(wip),
            str(mbox),
        ],
        env=git_env(),
        capture_output=True,
        text=True,
    )


def test_host_apply_extends_an_existing_branch_without_replaying_the_wip(
    tmp_path: Path,
) -> None:
    """A re-attached session's later leg lands on the branch its first leg created:
    no -b (the branch is checked out as-is) and NO wip replay — the leg that created
    the branch already committed it, so replaying a non-empty wip.patch again would
    duplicate (or conflict with) that first commit."""
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "f").write_text("base\n")
    base = commit_all(repo, "fixture: base")
    # Prior leg's branch: base <- leg-1 work.
    _git(repo, "branch", "rb", base)
    scratch = tmp_path / "scratch"
    _git(repo, "worktree", "add", "-q", str(scratch), "rb")
    (scratch / "leg1.txt").write_text("leg1\n")
    commit_all(scratch, "feat: leg one")
    # Leg-2's new commit as an mbox that applies onto leg-1's tip.
    (scratch / "leg2.txt").write_text("leg2\n")
    commit_all(scratch, "feat: leg two")
    mbox = tmp_path / "leg2.mbox"
    mbox.write_bytes(
        subprocess.run(
            [
                "git",
                "-C",
                str(scratch),
                "format-patch",
                "--stdout",
                "--binary",
                "HEAD~1..HEAD",
            ],
            env=git_env(),
            capture_output=True,
            check=True,
        ).stdout
    )
    _git(
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "worktree",
        "remove",
        "--force",
        str(scratch),
    )
    _git(repo, "update-ref", "refs/heads/rb", "rb~1")  # branch tip = leg-1 only
    # A NON-empty wip patch that must be skipped on the existing-branch path.
    wip = tmp_path / "wip.patch"
    wip.write_text("must never be applied\n")
    r = _host_apply(repo, base, "rb", tmp_path / "wt", wip, mbox)
    assert r.returncode == 0, r.stderr
    subjects = _git(repo, "log", "--format=%s", "rb").splitlines()
    assert subjects == ["feat: leg two", "feat: leg one", "fixture: base"]
    assert "uncommitted changes at session start" not in "\n".join(subjects)


def test_host_apply_still_creates_a_fresh_branch_with_wip_replay(
    tmp_path: Path,
) -> None:
    """The cold path is unchanged: branch created from base, wip replayed first."""
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "f").write_text("base\n")
    base = commit_all(repo, "fixture: base")
    wip = tmp_path / "wip.patch"
    wip.write_bytes(
        subprocess.run(
            ["git", "-C", str(repo), "diff", "HEAD", "--binary"],
            env=git_env(),
            capture_output=True,
            check=True,
        ).stdout
    )
    (repo / "f").write_text("edited\n")
    wip.write_bytes(
        subprocess.run(
            ["git", "-C", str(repo), "diff", "HEAD", "--binary"],
            env=git_env(),
            capture_output=True,
            check=True,
        ).stdout
    )
    _git(repo, "checkout", "-q", "--", "f")
    mbox = tmp_path / "empty.mbox"
    mbox.touch()
    r = _host_apply(repo, base, "fresh-rb", tmp_path / "wt", wip, mbox)
    assert r.returncode == 0, r.stderr
    subjects = _git(repo, "log", "--format=%s", "fresh-rb").splitlines()
    assert subjects == ["chore: uncommitted changes at session start", "fixture: base"]

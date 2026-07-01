"""Shared helpers used by multiple test modules.

Lives in a regular module (not `conftest.py`) so it can be imported directly
without manipulating `sys.path` or relying on the conftest plugin loader.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def run_capture(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    """`subprocess.run` with the capture_output/text/check defaults every test
    uses. `kwargs` (env, cwd, input, ...) are forwarded verbatim."""
    return subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)


def write_exe(path: Path, body: str) -> Path:
    """Write `body` to `path`, mark it executable, and return it.

    Writes a temp sibling then atomically renames it onto `path`: opening `path`
    for write directly truncates it, which fails with ETXTBSY ("Text file busy")
    when a prior exec of the same stub path is still draining — a real race when
    a test reruns a stub it just invoked (xdist amplifies it). Rename over the
    busy inode is never blocked, so the rewrite is race-free."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(body)
    tmp.chmod(tmp.stat().st_mode | _EXEC_BITS)
    os.replace(tmp, path)
    return path


def slice_bash_function(script: Path, name: str) -> str:
    """Extract a top-level shell function from `script` as text. Handles both the
    multi-line form (`name() {` … through the first column-0 `}`) and the
    single-line form (`name() { …; }`, returned as that one line). Lets a test
    source one function in isolation without running the whole script and without
    needing `awk` on the child's PATH — so a function built from bash builtins can
    be exercised under a deliberately empty PATH."""
    lines = script.read_text().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith(f"{name}()"))
    # A one-liner closes on its own signature line; a multi-line body closes on
    # the first column-0 `}` below it.
    if lines[start].rstrip().endswith("}"):
        return lines[start]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


def dstdomain_covers(entry: str, host: str) -> bool:
    """squid `dstdomain` semantics for a leading-dot entry `.d` (what write_ro_domains
    renders): it matches the apex `d` AND any subdomain of it, on the full-label
    boundary squid enforces — never a substring or a sibling-label look-alike. Shared
    by the read-only ACL boundary tests so the model has one definition, not a copy
    per file. (rw entries are exact, no leading dot; match those with `==`.)"""
    bare = entry[1:]  # strip the leading dot
    return host == bare or host.endswith("." + bare)


GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def git_env() -> dict[str, str]:
    """Environment for running git in test sandboxes."""
    return {**os.environ, **GIT_IDENTITY_ENV}


def init_test_repo(path: Path) -> None:
    """Init a throwaway repo with signing/hooks disabled so fixtures can commit
    in any environment (including CI runners with enforced commit signing)."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    for k, v in [
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("user.name", "t"),
        ("user.email", "t@t"),
        ("core.hooksPath", "/dev/null"),
    ]:
        subprocess.run(["git", "config", "--local", k, v], cwd=path, check=True)


def commit_all(repo: Path, message: str = "fixture") -> str:
    """Stage everything and create a commit; returns the resulting SHA."""
    env = git_env()
    subprocess.run(["git", "add", "-A"], cwd=repo, env=env, check=True)
    subprocess.run(
        ["git", "commit", "-q", "--allow-empty", "-m", message],
        cwd=repo,
        env=env,
        check=True,
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return sha.stdout.strip()


_SCRIPT_DIRS = [
    REPO_ROOT / ".github" / "scripts",
    REPO_ROOT / ".claude" / "hooks",
    REPO_ROOT / ".hooks",
]


def copy_script_to(script_name: str, dest_dir: Path) -> Path:
    """Copy a repo script into `dest_dir`, preserving the executable bit."""
    for src_dir in _SCRIPT_DIRS:
        src = src_dir / script_name
        if src.exists():
            dest = dest_dir / script_name
            shutil.copy2(src, dest)
            dest.chmod(0o755)
            return dest
    raise FileNotFoundError(f"Could not find {script_name} in any known location")

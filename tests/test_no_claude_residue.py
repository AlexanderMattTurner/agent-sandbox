"""De-claude drift guard.

The extraction's whole point is that the library carries NONE of claude-guard's
identifiers. This asserts the shipped, extracted source stays clean — no
`CLAUDE_GUARD_*`, `claude-guard`, `cg_*`, or the seed/worktree data-name residue
the de-claude transform renames. A single re-introduced token (a future copy that
skips the rename) fails here instead of silently shipping claude-flavoured code.

Scope is the SHIPPED library surface only (bin/, sandbox/, schema/, workloads/,
config/) — NOT tests/ or docs/PROVENANCE.md, which legitimately name claude-guard
to document the lineage.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent

# Each pattern is a token the de-claude transform removes; its presence in shipped
# source means an un-transformed copy leaked in.
RESIDUE = {
    "CLAUDE_GUARD_ env prefix": re.compile(r"CLAUDE_GUARD_"),
    "claude-guard literal": re.compile(r"claude-guard"),
    "cg_ function prefix": re.compile(r"\bcg_[a-z]"),
    "claude-seed data name": re.compile(r"claude-seed"),
    "agent@claude-guard identity": re.compile(r"agent@claude-guard"),
    ".worktrees/claude branch dir": re.compile(r"\.worktrees/claude"),
}

# Directories whose files are part of the shipped library (not test/doc prose).
SHIPPED_DIRS = ["bin", "sandbox", "schema", "workloads", "config"]


_SHIPPED_SUFFIXES = {".bash", ".sh", ".json"}


def _shipped_files():
    for d in SHIPPED_DIRS:
        root = REPO / d
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            # Shell/JSON source, plus the extensionless launcher (bin/agent-sandbox).
            if p.is_file() and (
                p.suffix in _SHIPPED_SUFFIXES or p.parent.name == "bin"
            ):
                yield p


def test_no_claude_residue_in_shipped_source():
    offenders = []
    scanned = 0
    for p in _shipped_files():
        scanned += 1
        text = p.read_text(errors="replace")
        for label, pat in RESIDUE.items():
            if pat.search(text):
                offenders.append(f"{p.relative_to(REPO)}: {label}")
    assert scanned > 0, "drift guard scanned zero files — SHIPPED_DIRS glob is wrong"
    assert not offenders, "de-claude residue found in shipped source:\n" + "\n".join(
        offenders
    )


def test_guard_is_non_vacuous():
    # Prove the patterns actually match what they claim to, so the guard can't
    # pass because a pattern silently stopped matching.
    samples = {
        "CLAUDE_GUARD_ env prefix": "CLAUDE_GUARD_SEED_TAR",
        "claude-guard literal": "~/.config/claude-guard/x",
        "cg_ function prefix": "cg_error hi",
        "claude-seed data name": "/workspace/.git/claude-seed-head",
        "agent@claude-guard identity": "agent@claude-guard.local",
        ".worktrees/claude branch dir": ".worktrees/claude-abc",
    }
    for label, pat in RESIDUE.items():
        assert pat.search(samples[label]), (
            f"pattern {label!r} no longer matches its residue sample"
        )

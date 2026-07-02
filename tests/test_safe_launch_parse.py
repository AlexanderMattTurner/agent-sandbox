"""Tests for `.claude/hooks/safe-launch-parse.py`.

safe-launch.sh runs this parser on the in-flight PreToolUse payload (attacker-
influenced JSON on stdin) to decide whether a tool call is a self-repair edit on
a hook file. A parse mistake here loosens (or needlessly tightens) that gate, so
the parser is mutation-tested (tools/mutation/safe-launch-parse.toml). These
tests are the oracle that gate reads: each pins one observable — the two output
lines and the exit code — so a mutant that changes behaviour is caught.

The parser is invoked exactly as safe-launch.sh invokes it — as a subprocess
(`python3 <script> <project_dir>` with the payload on stdin) — so the whole file
runs, including the `__main__` guard and the process exit code. The filename has
a hyphen and is not importable, which the subprocess form sidesteps.
"""

import json
import sys

from tests._helpers import REPO_ROOT, run_capture

PARSER = REPO_ROOT / ".claude" / "hooks" / "safe-launch-parse.py"


def _run(payload: str, *args: str) -> tuple[int, str]:
    """Invoke the parser with `args` as argv[1:] and `payload` on stdin. Returns
    (returncode, stdout)."""
    r = run_capture([sys.executable, str(PARSER), *args], input=payload)
    return r.returncode, r.stdout


def _run_json(obj: object, project_dir: str = "/proj") -> tuple[int, str]:
    return _run(json.dumps(obj), project_dir)


# === argv arity: the parser needs exactly one project-dir argument ===========


def test_no_project_dir_arg_emits_nothing() -> None:
    """Too few args (script only): return 0 with NO output, even when stdin holds a
    valid payload — proving the arity guard short-circuits before any parse/print."""
    rc, out = _run(json.dumps({"tool_name": "Edit", "tool_input": {"file_path": "/x"}}))
    assert rc == 0
    assert out == ""


def test_extra_arg_emits_nothing() -> None:
    """Too many args: same short-circuit — return 0, no output — with a valid
    payload on stdin so a broken guard would print."""
    rc, out = _run(
        json.dumps({"tool_name": "Edit", "tool_input": {"file_path": "/x"}}),
        "/proj",
        "extra",
    )
    assert rc == 0
    assert out == ""


# === malformed stdin fails safe (exit 0, no output) ==========================


def test_invalid_json_emits_nothing() -> None:
    rc, out = _run("this is not json", "/proj")
    assert rc == 0
    assert out == ""


def test_empty_stdin_emits_nothing() -> None:
    rc, out = _run("", "/proj")
    assert rc == 0
    assert out == ""


# === well-formed payloads: exact two-line output ============================


def test_absolute_file_path_passed_through() -> None:
    """An absolute file_path is emitted verbatim (never re-joined) and the tool
    name is line one — pins output order and the isabs branch."""
    rc, out = _run_json(
        {"tool_name": "Edit", "tool_input": {"file_path": "/etc/passwd"}}
    )
    assert rc == 0
    assert out == "Edit\n/etc/passwd\n"


def test_relative_file_path_joined_to_project_dir() -> None:
    """A relative file_path is resolved against project_dir — the containment check
    downstream depends on this being absolute."""
    rc, out = _run_json(
        {"tool_name": "Write", "tool_input": {"file_path": ".claude/hooks/x.sh"}},
        project_dir="/proj",
    )
    assert rc == 0
    assert out == "Write\n/proj/.claude/hooks/x.sh\n"


def test_notebook_path_used_when_file_path_absent() -> None:
    rc, out = _run_json(
        {"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/n.ipynb"}}
    )
    assert rc == 0
    assert out == "NotebookEdit\n/n.ipynb\n"


def test_relative_notebook_path_joined() -> None:
    rc, out = _run_json(
        {"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "nb.ipynb"}},
        project_dir="/proj",
    )
    assert rc == 0
    assert out == "NotebookEdit\n/proj/nb.ipynb\n"


def test_file_path_takes_precedence_over_notebook_path() -> None:
    """When both keys are present, file_path wins (the first `or` operand) — a
    mutant that flipped the precedence would emit the notebook path."""
    rc, out = _run_json(
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": "/a", "notebook_path": "/b"},
        }
    )
    assert rc == 0
    assert out == "Edit\n/a\n"


# === missing / null / empty fields collapse to empty strings =================


def test_missing_tool_name_yields_empty_first_line() -> None:
    rc, out = _run_json({"tool_input": {"file_path": "/a"}})
    assert rc == 0
    assert out == "\n/a\n"


def test_null_tool_name_yields_empty_first_line() -> None:
    """`tool_name: null` must collapse to "" (the `or ""`), not the string "None"."""
    rc, out = _run_json({"tool_name": None, "tool_input": {"file_path": "/a"}})
    assert rc == 0
    assert out == "\n/a\n"


def test_missing_tool_input_yields_empty_path() -> None:
    rc, out = _run_json({"tool_name": "Bash"})
    assert rc == 0
    assert out == "Bash\n\n"


def test_null_tool_input_yields_empty_path() -> None:
    """`tool_input: null` must collapse to `{}` (the `or {}`) — not crash on
    `None.get` (which would be a non-zero exit)."""
    rc, out = _run_json({"tool_name": "Bash", "tool_input": None})
    assert rc == 0
    assert out == "Bash\n\n"


def test_empty_string_file_path_falls_through_to_empty() -> None:
    """An empty file_path is falsy, so it falls through the `or` chain to "" — and
    an empty path must NOT be joined to project_dir (the `path and` guard)."""
    rc, out = _run_json({"tool_name": "Edit", "tool_input": {"file_path": ""}})
    assert rc == 0
    assert out == "Edit\n\n"


def test_empty_object_yields_two_empty_lines() -> None:
    rc, out = _run_json({})
    assert rc == 0
    assert out == "\n\n"

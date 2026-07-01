"""The launcher must exec a Workload's entrypoint argv verbatim — including an
element that itself contains newlines (a multi-line `bash -c` script, the common
case). A newline-delimited read of jq's output splits such an element into
several argv words and truncates a `-c` body to its first line, so the workload
runs almost nothing and exits 0 — a silent, corrupting failure.

This drives the exact argv-building snippet stack.bash uses (extracted from the
sourced function so the test needs no Docker) against a three-element entrypoint
whose third element spans three lines, and asserts it reconstructs as EXACTLY
three arguments with the multi-line body intact.
"""

import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
STACK = REPO / "bin" / "lib" / "stack.bash"

MULTILINE_BODY = "set -e\necho ONE\necho TWO"


def _read_argv(workload_path: Path) -> list[str]:
    # Mirror stack.bash's argv read, then emit each element NUL-delimited so the
    # test process recovers embedded newlines faithfully.
    script = f"""
    set -euo pipefail
    workload={workload_path}
    local_n=$(jq '.entrypoint | length' "$workload")
    argv=()
    for ((i = 0; i < local_n; i++)); do
      argv+=("$(jq -r ".entrypoint[$i]" "$workload")")
    done
    for a in "${{argv[@]}}"; do printf '%s\\0' "$a"; done
    """
    out = subprocess.run(["bash", "-c", script], capture_output=True, check=True).stdout
    parts = out.split(b"\x00")
    assert parts[-1] == b""  # trailing NUL from the last element
    return [p.decode() for p in parts[:-1]]


def test_stack_reads_entrypoint_argv_snippet_matches_source():
    # Guard against the source drifting to a line-delimited read again: the
    # snippet this test drives must still be the one stack.bash ships.
    src = STACK.read_text()
    assert "for ((_i = 0; _i < _n; _i++)); do" in src
    assert 'argv+=("$(jq -r ".entrypoint[$_i]" "$workload")")' in src
    # The old truncating idiom must be gone.
    assert "jq -r '.entrypoint[]'" not in src


def test_multiline_entrypoint_element_survives_as_one_arg(tmp_path):
    workload = tmp_path / "wl.json"
    workload.write_text(json.dumps({"entrypoint": ["bash", "-c", MULTILINE_BODY]}))
    argv = _read_argv(workload)
    assert argv == ["bash", "-c", MULTILINE_BODY]


def test_multiline_body_actually_executes_every_line(tmp_path):
    workload = tmp_path / "wl.json"
    workload.write_text(json.dumps({"entrypoint": ["bash", "-c", MULTILINE_BODY]}))
    argv = _read_argv(workload)
    out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == ["ONE", "TWO"]

#!/usr/bin/env python3
"""Generate sandbox/trace-events.bash from config/trace-events.json.

config/trace-events.json is the single source of truth for the library's structured
trace events. `as_trace` (sandbox/trace.bash) runs in-container with no JSON parser
available, so it needs the events as a plain-bash map — that map is a GENERATED
artifact, not a second hand-edited copy. This script renders it deterministically.

Usage:
  python3 scripts/gen-trace-events.py           # write the .bash file
  python3 scripts/gen-trace-events.py --check    # exit 1 (with a diff) if out of date

The pre-commit `gen-trace-events` hook runs the writer on commit; CI's
tests/test_trace_events_ssot.py runs `--check` so a hand-edit of the generated file
(or a JSON change without regeneration) fails the build.
"""

import difflib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)
JSON_PATH = REPO / "config" / "trace-events.json"
BASH_PATH = REPO / "sandbox" / "trace-events.bash"

_HEADER = """\
# shellcheck shell=bash
# shellcheck disable=SC2034  # consumed by as_trace (trace.bash) via the maps below, not here.
# GENERATED FROM config/trace-events.json BY scripts/gen-trace-events.py — DO NOT EDIT.
# Change an event in config/trace-events.json, then regenerate:
#   python3 scripts/gen-trace-events.py
# The pre-commit `gen-trace-events` hook regenerates this on commit, and
# tests/test_trace_events_ssot.py fails CI if it is ever out of sync with the JSON.
#
# Sourced by sandbox/trace.bash (co-located, copied into the container beside it).
# as_trace runs in-container with no JSON parser available, so the events must exist
# here as plain bash — this file is that generated in-container mirror. Only
# LIBRARY-emitted events live in the JSON (a consumer's own events belong in the
# consumer's overlay), so only those are generated here.

# Idempotent: a re-source returns early rather than redefining.
[[ -n "${TRACE_EVENTS_LOADED:-}" ]] && return 0
TRACE_EVENTS_LOADED=1"""


def render(events: dict) -> str:
    """Render the .bash file body from the ordered {event: {layer, level}} map."""
    lines = [_HEADER, ""]
    for ev in events:
        lines.append(f'TRACE_{ev.upper()}="{ev}"')
    lines.append("")
    lines.append("declare -A TRACE_EVENT_LAYER=(")
    for ev, spec in events.items():
        lines.append(f'  ["{ev}"]="{spec["layer"]}"')
    lines.append(")")
    lines.append("declare -A TRACE_EVENT_LEVEL=(")
    for ev, spec in events.items():
        lines.append(f'  ["{ev}"]="{spec["level"]}"')
    lines.append(")")
    return "\n".join(lines) + "\n"


def main() -> None:
    events = json.loads(JSON_PATH.read_text())["events"]
    generated = render(events)
    check = "--check" in sys.argv[1:]
    if check:
        current = BASH_PATH.read_text() if BASH_PATH.exists() else ""
        if current != generated:
            diff = difflib.unified_diff(
                current.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                fromfile=f"{BASH_PATH.name} (committed)",
                tofile=f"{BASH_PATH.name} (regenerated)",
            )
            sys.stderr.write("".join(diff))
            sys.stderr.write(
                f"\n{BASH_PATH.relative_to(REPO)} is out of sync with "
                f"{JSON_PATH.relative_to(REPO)}; run: python3 scripts/gen-trace-events.py\n"
            )
            raise SystemExit(1)
        return
    BASH_PATH.write_text(generated)


if __name__ == "__main__":
    main()

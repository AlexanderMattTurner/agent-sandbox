"""Contract tests binding config/trace-events.json (the SSOT) to its two consumers.

1. Round-trip: sandbox/trace-events.bash (the in-container bash mirror as_trace reads)
   must declare EXACTLY the JSON's events — same constant names/values, same layer, same
   level — so the two can never drift. Editing one without the other fails here.
2. Emitter guard: every declared event must have at least one real emitter under
   sandbox/ (the constant used in an `as_trace` call, or the literal in a Python
   `trace(...)` call), so a declared-but-never-emitted event can't accumulate. The guard
   is proven non-vacuous: a fabricated event finds no emitter.
"""

import json
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
JSON_PATH = REPO / "config" / "trace-events.json"
BASH_PATH = REPO / "sandbox" / "trace-events.bash"
SANDBOX = REPO / "sandbox"

EVENTS = json.loads(JSON_PATH.read_text())["events"]


def _bash_dump() -> dict:
    """Source trace-events.bash and dump its layer map, level map, and every TRACE_*
    constant (minus the two maps + the load guard), so the test compares the actual
    runtime state as_trace sees, not a regex over the text."""
    script = f"""
    set -euo pipefail
    source {BASH_PATH}
    for ev in "${{!TRACE_EVENT_LAYER[@]}}"; do printf 'L\\t%s\\t%s\\n' "$ev" "${{TRACE_EVENT_LAYER[$ev]}}"; done
    for ev in "${{!TRACE_EVENT_LEVEL[@]}}"; do printf 'V\\t%s\\t%s\\n' "$ev" "${{TRACE_EVENT_LEVEL[$ev]}}"; done
    for name in ${{!TRACE_@}}; do
      case "$name" in TRACE_EVENT_LAYER | TRACE_EVENT_LEVEL | TRACE_EVENTS_LOADED) continue ;; esac
      printf 'C\\t%s\\t%s\\n' "$name" "${{!name}}"
    done
    """
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    layer, level, consts = {}, {}, {}
    for line in out.splitlines():
        kind, key, val = line.split("\t")
        {"L": layer, "V": level, "C": consts}[kind][key] = val
    return layer, level, consts


def test_bash_mirror_matches_json_exactly():
    layer, level, consts = _bash_dump()
    assert set(layer) == set(EVENTS), "layer map keys drift from JSON events"
    assert set(level) == set(EVENTS), "level map keys drift from JSON events"
    for ev, spec in EVENTS.items():
        assert layer[ev] == spec["layer"], ev
        assert level[ev] == spec["level"], ev
    # The constant set is exactly one TRACE_<UPPER> per event, valued to the event string.
    assert consts == {f"TRACE_{ev.upper()}": ev for ev in EVENTS}


def _emitter_sources() -> list[tuple[str, str]]:
    """(name, comment-stripped text) for every emitter-candidate file under sandbox/ —
    the .bash/.py siblings of trace-events.bash. Comment-only lines are dropped so a
    mention of an event in a comment/doc can't vacuously satisfy the guard."""
    out = []
    for p in sorted(SANDBOX.iterdir()):
        if (
            not p.is_file()
            or p.name == "trace-events.bash"
            or p.suffix
            not in {
                ".bash",
                ".py",
            }
        ):
            continue
        body = "\n".join(
            line
            for line in p.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        out.append((p.name, body))
    return out


def _has_emitter(event: str, sources) -> list[str]:
    const = f"TRACE_{event.upper()}"
    return [name for name, body in sources if const in body or f'"{event}"' in body]


def test_every_event_has_a_library_emitter():
    sources = _emitter_sources()
    assert EVENTS, "no events declared"
    for ev in EVENTS:
        assert _has_emitter(ev, sources), (
            f"{ev} is declared but has no emitter under sandbox/"
        )


def test_emitter_guard_is_non_vacuous():
    # A fabricated event is emitted nowhere: the guard must return an empty match set,
    # proving test_every_event_has_a_library_emitter isn't passing by construction.
    sources = _emitter_sources()
    assert _has_emitter("firewall_totally_not_emitted_zzz", sources) == []

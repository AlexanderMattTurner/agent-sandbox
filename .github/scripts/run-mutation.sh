#!/usr/bin/env bash
# Run the cosmic-ray mutation session for safe-launch-parse.py and enforce a
# zero-survivor floor. safe-launch.sh feeds this parser attacker-influenced
# PreToolUse JSON, so its unit tests must ASSERT behaviour (kill mutants), not
# merely execute lines. CI-only — see .github/workflows/mutation-testing.yaml.
set -euo pipefail

toml="tools/mutation/safe-launch-parse.toml"
session="safe-launch-parse.sqlite"

# Start from a fresh session: `cosmic-ray init` refuses to overwrite an existing
# DB, so a re-run (local iteration, CI retry) would abort at init otherwise.
rm -f "$session"

# baseline mutates the source in place and reverts; a clean baseline proves a
# survivor is a missing assertion, not an already-broken tree.
cosmic-ray baseline "$toml"
cosmic-ray init "$toml" "$session"
# Drop the "# pragma: no mutate" equivalent-mutant catalogue (the __main__ guard,
# whose <=/>=/is-not comparison mutants are indistinguishable from ==).
cr-filter-pragma "$session"
cosmic-ray exec "$toml" "$session"

cr-html "$session" >safe-launch-parse-mutation.html

# --fail-over: a survival rate OVER the floor fails. The parser is small and
# every observable (both output lines + the exit code) is pinned, so the floor
# is zero survivors.
cr-rate --fail-over 0.0 "$session"

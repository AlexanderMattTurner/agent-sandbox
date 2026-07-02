"""Argv-log equivalence pin for the stack_run bring-up/serve split (issue #34).

stack_run was refactored into stack_bring_up (allowlist partition -> profiles ->
images -> overrides -> up -> cid -> env cleanup -> guardrail gate) and
stack_serve_workload (barrier -> seed -> exec -> extract -> export -> teardown).
The refactor must be argv-invariant: a cold seeded run asks docker for EXACTLY
the same things, in the same order, as before the split. GOLDEN below was
captured from the pre-split stack_run with this same harness; the test fails on
any drift — an added, dropped, or reordered docker invocation is a behavior
change, not a refactor.

Normalized (the only run-to-run variance): absolute paths, the random project
suffix, the fixture repo's HEAD sha, and trailing whitespace (multi-line exec
scripts carry a trailing space the repo's hooks would strip from a literal).
"""

import json
import os
import re
import subprocess

from tests._helpers import REPO_ROOT, commit_all, git_env, init_test_repo, write_exe

LAUNCHER = REPO_ROOT / "bin" / "agent-sandbox"

# Same recording stub shape as test_persistent_sessions.py: answers by argv
# pattern, drains `exec -i` stdin so seed pipes never die on EPIPE.
FAKE_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_ARGV_LOG"
if [[ "$1" == exec && "$2" == "-i" ]]; then cat >/dev/null; fi
case "$*" in
  "cp "*) touch "$3" ;;
  "compose "*" ps -q workload") echo wcid ;;
  "compose "*" ps -q firewall") echo fwcid ;;
  "compose "*" ps -q audit") echo acid ;;
  *"git rev-parse HEAD"*) echo 1111111111111111111111111111111111111111 ;;
esac
exit 0
"""

WORKLOAD = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": ["pypi.org"],
    "ephemeral": True,
    "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/pin-rb"},
}

GOLDEN = """\
network ls -q
image inspect agent-sandbox-firewall:local
compose -p <PROJECT> -f <SANDBOX>/docker-compose.yml -f <STATE>/workload-override.json -f <STATE>/overmount-override.json up -d --wait --wait-timeout 240
compose -p <PROJECT> -f <SANDBOX>/docker-compose.yml -f <STATE>/workload-override.json -f <STATE>/overmount-override.json ps -q workload
exec -u root wcid chown 1000:1000 /workspace
exec -i -u 1000 wcid sh -c cd /workspace && tar --warning=no-unknown-keyword -xf -
exec -u 1000 wcid sh -c
    cd /workspace || exit 1
    git init -q || exit 1
    git config user.email "agent@agent-sandbox.local" || exit 1
    git config user.name "agent-sandbox agent" || exit 1
    git checkout -q -b "$1" || exit 1
    git add -A || exit 1
    git commit -q --no-verify -m "$2" >/dev/null 2>&1 || git commit -q --no-verify --allow-empty -m "$2" || exit 1
    git rev-parse HEAD
   sh sandbox/pin-rb chore: seed working tree at session start
exec -i -u 1000 wcid sh -c
    printf "%s\\n" "$1" >/workspace/.git/sandbox-seed-head || exit 1
    cat >/workspace/.git/sandbox-seed-wip
   sh <SHA>
exec -u 1000 -w /workspace wcid bash -lc echo hi
exec -u 1000 wcid sh -c
    cd /workspace || exit 1
    git add -A || exit 1
    if ! git diff --cached --quiet; then
      git commit -q --no-verify -m "$2" || exit 1
    fi
    git format-patch -q --stdout --binary "$1"..HEAD
   sh 1111111111111111111111111111111111111111 chore: uncommitted changes at session end
compose -p <PROJECT> -f <SANDBOX>/docker-compose.yml -f <STATE>/workload-override.json -f <STATE>/overmount-override.json ps -q firewall
cp fwcid:/var/log/squid/access.log <STATE>/egress.log
compose -p <PROJECT> -f <SANDBOX>/docker-compose.yml -f <STATE>/workload-override.json -f <STATE>/overmount-override.json ps -q audit
cp acid:/var/log/agent-sandbox/audit.jsonl <STATE>/audit.jsonl
cp acid:/run/audit-secret/secret <STATE>/audit.secret
compose -p <PROJECT> -f <SANDBOX>/docker-compose.yml -f <STATE>/workload-override.json -f <STATE>/overmount-override.json down --volumes --timeout 30
volume ls -q --filter label=com.docker.compose.project=<PROJECT>
"""


def _normalize(log: str, tmp_path, head: str) -> str:
    # The launcher hands stack_run the compose path relative to bin/ (bin/../sandbox).
    out = log.replace(str(REPO_ROOT / "bin") + "/../sandbox", "<SANDBOX>")
    state_root = str(tmp_path / "state" / "sessions")
    out = re.sub(re.escape(state_root) + r"/agent-sandbox-[0-9a-f]{8}", "<STATE>", out)
    out = re.sub(r"agent-sandbox-[0-9a-f]{8}", "<PROJECT>", out)
    out = out.replace(head, "<SHA>")
    return re.sub(r"[ \t]+$", "", out, flags=re.MULTILINE)


def test_cold_run_docker_argv_log_is_unchanged_by_the_split(tmp_path):
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "tracked.txt").write_text("v1\n")
    head = commit_all(repo, "fixture: base")
    stub = tmp_path / "stub"
    write_exe(stub / "docker", FAKE_DOCKER)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(WORKLOAD))
    log = tmp_path / "docker-argv.log"
    log.touch()
    env = {
        **git_env(),
        "PATH": f"{stub}:{os.environ['PATH']}",
        "CONTAINER_RUNTIME": "runc",
        "NO_COLOR": "1",
        "DOCKER_ARGV_LOG": str(log),
        "SANDBOX_NET_RESERVE_DIR": str(tmp_path / "reserve"),
        "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        "AGENT_SANDBOX_STATE_DIR": str(tmp_path / "state"),
    }
    r = subprocess.run(
        [str(LAUNCHER), "run", str(wl)],
        capture_output=True,
        text=True,
        env=env,
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert _normalize(log.read_text(), tmp_path, head) == GOLDEN

"""Persistent-session lifecycle: deterministic identity, re-attach, resume, audit
continuity (issue #33).

Drives bin/agent-sandbox with a RECORDING fake docker on PATH (no daemon) inside a
real throwaway git repo, so the host-side git machinery (seed manifests, review
branches, format-patch replay) is real while every container interaction is an
argv-recorded stub. Env toggles model the docker-side state each scenario needs
(running containers, kept volumes, in-container HEADs). Unit tests for the pure
helpers (_stack_write_audit_prior_override, _stack_export_audit_log) source
stack.bash directly.
"""

import json
import os
import subprocess

from tests._helpers import (
    REPO_ROOT,
    commit_all,
    git_env,
    init_test_repo,
    write_exe,
)

LAUNCHER = REPO_ROOT / "bin" / "agent-sandbox"
STACK_LIB = REPO_ROOT / "bin" / "lib" / "stack.bash"

FAKE_CONTAINER_HEAD = "1" * 40

# Answers by argv pattern; env toggles model docker-side state. `exec -i` calls
# consume stdin so the launcher's seed/replay pipes never die on EPIPE. Patterns
# are ordered most-specific first (bash `case` takes the first match).
FAKE_DOCKER = f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_ARGV_LOG"
if [[ "$1" == exec && "$2" == "-i" ]]; then cat >/dev/null; fi
case "$*" in
  "ps -q --filter label=com.docker.compose.project="*)
    [[ -n "${{FAKE_RUNNING:-}}" ]] && echo runningcid ;;
  "ps -aq --filter label=com.docker.compose.project="*)
    [[ -n "${{FAKE_STOPPED:-}}" ]] && echo stoppedcid ;;
  "volume ls -q --filter label=com.docker.compose.project="*)
    [[ -n "${{FAKE_VOLUMES:-}}" ]] && echo vol1 ;;
  "cp "*)
    touch "$3" ;;
  *"cat /workspace/.git/sandbox-seed-head"*)
    [[ -n "${{FAKE_SEED_HEAD:-}}" ]] && echo "$FAKE_SEED_HEAD" ;;
  "compose "*" ps -q workload")
    [[ -n "${{FAKE_WORKLOAD_CID:-}}" ]] && echo wcid ;;
  "compose "*" ps -q audit")
    [[ -n "${{FAKE_AUDIT_CID:-}}" ]] && echo acid ;;
  *"git rev-parse HEAD"*)
    echo "{FAKE_CONTAINER_HEAD}" ;;
esac
exit 0
"""

VALID = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": [],
    "ephemeral": True,
}


def _seeded(
    session_id=None, resume_from=None, ephemeral=True, review_branch="sandbox/new-rb"
):
    wl = {
        **VALID,
        "ephemeral": ephemeral,
        "seed_from_git": {"ref": "HEAD", "review_branch": review_branch},
    }
    if session_id is not None:
        wl["session_id"] = session_id
    if resume_from is not None:
        wl["resume_from"] = resume_from
    return wl


def _run(tmp_path, workload_obj, *, argv_tail=(), extra_env=None, cwd=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", FAKE_DOCKER)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(workload_obj))
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
        **(extra_env or {}),
    }
    r = subprocess.run(
        [str(LAUNCHER), "run", *argv_tail, str(wl)],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )
    return r, log.read_text()


def _repo(tmp_path):
    """A throwaway host repo with one committed file (the seed source)."""
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "tracked.txt").write_text("v1\n")
    sha = commit_all(repo, "fixture: base")
    return repo, sha


def _state_dir(tmp_path, project):
    return tmp_path / "state" / "sessions" / project


def _write_manifest(tmp_path, project, **fields):
    state = _state_dir(tmp_path, project)
    state.mkdir(parents=True, exist_ok=True)
    manifest = {
        "project": project,
        "session_id": project.removeprefix("agent-sandbox-"),
        "mode": "seed",
        "seed_ref": "HEAD",
        "created": "2026-01-01T00:00:00Z",
        **fields,
    }
    (state / "session.json").write_text(json.dumps(manifest))
    return state


# --- cmd_run runtime gates (jq mirrors of the schema pattern) ---


def test_bad_session_id_is_rejected_before_launch(tmp_path):
    r, log = _run(tmp_path, {**VALID, "session_id": "Bad;Id"})
    assert r.returncode != 0
    assert "session_id must match" in r.stderr
    assert "compose" not in log


def test_bad_resume_from_is_rejected_before_launch(tmp_path):
    r, log = _run(tmp_path, _seeded(resume_from="Bad;Id"))
    assert r.returncode != 0
    assert "resume_from must match" in r.stderr
    assert "compose" not in log


def test_resume_from_without_seed_from_git_is_rejected(tmp_path):
    r, _ = _run(tmp_path, {**VALID, "resume_from": "old1"})
    assert r.returncode != 0
    assert "requires seed_from_git" in r.stderr


def test_resume_from_equal_to_session_id_is_rejected(tmp_path):
    r, _ = _run(tmp_path, _seeded(session_id="same", resume_from="same"))
    assert r.returncode != 0
    assert "cannot resume itself" in r.stderr


# --- deterministic identity: pre-up probes ---


def test_running_session_with_same_id_is_refused(tmp_path):
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False),
        extra_env={"FAKE_RUNNING": "1"},
    )
    assert r.returncode != 0
    assert "already running" in r.stderr
    # Refused before any compose invocation (only the probe `ps` ran).
    assert not [line for line in log.splitlines() if line.startswith("compose ")]


def test_reattach_with_ephemeral_true_is_refused(tmp_path):
    r, _ = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=True),
        extra_env={"FAKE_VOLUMES": "1"},
    )
    assert r.returncode != 0
    assert "re-attach needs ephemeral:false" in r.stderr


def test_resume_into_a_project_with_leftovers_is_refused(tmp_path):
    r, _ = _run(
        tmp_path,
        _seeded(session_id="sid1", resume_from="old1"),
        extra_env={"FAKE_VOLUMES": "1"},
    )
    assert r.returncode != 0
    assert "needs a FRESH session" in r.stderr


def test_resume_with_missing_prior_manifest_is_refused(tmp_path):
    r, log = _run(tmp_path, _seeded(session_id="sid1", resume_from="old1"))
    assert r.returncode != 0
    assert "nothing to resume" in r.stderr
    assert not [line for line in log.splitlines() if line.startswith("compose ")]


# --- cold seed writes the session manifest ---


def test_cold_seed_writes_the_session_manifest(tmp_path):
    repo, head = _repo(tmp_path)
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        extra_env={"FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    manifest = json.loads(
        (_state_dir(tmp_path, "agent-sandbox-sid1") / "session.json").read_text()
    )
    assert manifest == {
        "project": "agent-sandbox-sid1",
        "session_id": "sid1",
        "mode": "seed",
        "seed_ref": "HEAD",
        "base_commit": head,
        "base_ref": FAKE_CONTAINER_HEAD,
        "review_branch": "sandbox/rb1",
        "repo_root": str(repo),
        "created": manifest["created"],
        "last_exit": 0,
        "extracted": True,
    }
    # The cold seed stamps the fingerprint a later re-attach checks.
    assert "sandbox-seed-head" in log


# --- re-attach ---


def _reattach_fixture(tmp_path, **manifest_overrides):
    repo, head = _repo(tmp_path)
    _write_manifest(
        tmp_path,
        "agent-sandbox-sid1",
        base_commit=head,
        base_ref=FAKE_CONTAINER_HEAD,
        review_branch="sandbox/rb1",
        repo_root=str(repo),
        **manifest_overrides,
    )
    # Leg 1's extract left the review branch on the host; re-attach depends on it.
    subprocess.run(["git", "branch", "sandbox/rb1", head], cwd=repo, check=True)
    return repo, head


def test_reattach_restarts_the_stack_and_skips_seeding(tmp_path):
    repo, head = _reattach_fixture(tmp_path)
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        extra_env={
            "FAKE_VOLUMES": "1",
            "FAKE_WORKLOAD_CID": "1",
            "FAKE_SEED_HEAD": head,  # fingerprint matches -> not stale
        },
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "re-attaching to the stopped session agent-sandbox-sid1" in r.stderr
    assert "up -d --wait" in log
    assert "test -d /workspace/.git" in log
    # Seeding skipped: no /workspace chown (the cold seed's first exec), no tar
    # extract, no in-container git init.
    assert "chown" not in log
    assert "git init" not in log
    assert "was seeded from an older state" not in r.stderr


def test_reattach_warns_when_the_seed_is_stale_but_continues(tmp_path):
    repo, _head = _reattach_fixture(tmp_path)
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        extra_env={
            "FAKE_VOLUMES": "1",
            "FAKE_WORKLOAD_CID": "1",
            "FAKE_SEED_HEAD": "0" * 40,  # stamped head != repo HEAD -> stale
        },
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "was seeded from an older state" in r.stderr
    assert "--reseed" in r.stderr
    assert "git init" not in log  # warn-and-continue, never an implicit re-seed


def test_reseed_flag_discards_and_reseeds_the_workspace(tmp_path):
    repo, head = _reattach_fixture(tmp_path)
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        argv_tail=("--reseed",),
        extra_env={"FAKE_VOLUMES": "1", "FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "discarding agent-sandbox-sid1's seeded workspace" in r.stderr
    # The destructive wipe + fresh in-container repo both ran ...
    assert "find . -mindepth 1 -maxdepth 1 ! -name node_modules" in log
    assert "git init" in log
    # ... and the manifest was rewritten for the new seed.
    manifest = json.loads(
        (_state_dir(tmp_path, "agent-sandbox-sid1") / "session.json").read_text()
    )
    assert manifest["base_commit"] == head
    assert manifest["seed_ref"] == "HEAD"


def test_reattach_refuses_a_manifest_that_is_not_a_seeded_session(tmp_path):
    repo, _head = _reattach_fixture(tmp_path, mode="bind")
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        extra_env={"FAKE_VOLUMES": "1", "FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r.returncode != 0
    assert "not a seeded session" in r.stderr
    # Volumes are deliberately kept: the stop is a plain down, never --volumes.
    assert "down --volumes" not in log


# --- resume ---


def _resume_fixture(tmp_path, *, tip_is_wip_fold):
    """A prior session's outputs: manifest + review branch (base <- commit A
    [<- uncommitted-changes fold]) + exported audit log."""
    repo, base = _repo(tmp_path)
    env = git_env()
    subprocess.run(
        ["git", "switch", "-q", "-c", "sandbox/old-rb", base],
        cwd=repo,
        env=env,
        check=True,
    )
    (repo / "agent-work.txt").write_text("agent\n")
    commit_all(repo, "feat: agent work")
    if tip_is_wip_fold:
        (repo / "overlay.txt").write_text("overlay\n")
        commit_all(repo, "chore: uncommitted changes at session end")
    subprocess.run(["git", "switch", "-q", "main"], cwd=repo, env=env, check=True)
    tip = subprocess.run(
        ["git", "rev-parse", "sandbox/old-rb"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    state = _write_manifest(
        tmp_path,
        "agent-sandbox-old1",
        base_commit=base,
        base_ref=FAKE_CONTAINER_HEAD,
        review_branch="sandbox/old-rb",
        repo_root=str(repo),
    )
    # Deliberately EMPTY: a quiet prior session exports an empty chain, and the
    # resume mount must key on existence, not size (the -s regression class).
    (state / "audit.jsonl").write_text("")
    return repo, base, tip


def test_resume_seeds_prior_base_replays_the_branch_and_mounts_prior_audit(tmp_path):
    repo, base, tip = _resume_fixture(tmp_path, tip_is_wip_fold=False)
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid2", resume_from="old1", review_branch="sandbox/new-rb"),
        extra_env={"FAKE_WORKLOAD_CID": "1", "FAKE_AUDIT_CID": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "seed_from_git.ref 'HEAD' is ignored on resume" in r.stderr
    # Prior work replayed into the fresh container ...
    assert "git am -q" in log
    assert "git reset -q --mixed HEAD~1" not in log  # tip is a real commit: no reset
    state = _state_dir(tmp_path, "agent-sandbox-sid2")
    # ... the prior audit log rides read-only on the audit service ...
    override = json.loads((state / "audit-prior-override.json").read_text())
    prior_log = str(_state_dir(tmp_path, "agent-sandbox-old1") / "audit.jsonl")
    assert override == {
        "services": {
            "audit": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": prior_log,
                        "target": "/var/log/agent-sandbox/audit.prior.jsonl",
                        "read_only": True,
                    }
                ]
            }
        }
    }
    up_call = next(line for line in log.splitlines() if " up -d " in line)
    assert str(state / "audit-prior-override.json") in up_call
    # ... and the new session's extract branches from the prior work's tip.
    manifest = json.loads((state / "session.json").read_text())
    assert manifest["base_commit"] == tip
    assert manifest["seed_ref"] == base  # actual provenance, not the ignored "HEAD"
    assert manifest["review_branch"] == "sandbox/new-rb"
    # This session exported its own audit log + secret beside the manifest.
    assert (state / "audit.jsonl").exists() and (state / "audit.secret").exists()
    assert (state / "audit.jsonl").stat().st_mode & 0o777 == 0o600


def test_resume_soft_resets_an_uncommitted_changes_fold(tmp_path):
    repo, base, tip = _resume_fixture(tmp_path, tip_is_wip_fold=True)
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid2", resume_from="old1", review_branch="sandbox/new-rb"),
        extra_env={"FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "git reset -q --mixed HEAD~1" in log
    manifest = json.loads(
        (_state_dir(tmp_path, "agent-sandbox-sid2") / "session.json").read_text()
    )
    parent = subprocess.run(
        ["git", "rev-parse", "sandbox/old-rb~1"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert manifest["base_commit"] == parent  # the fold's parent, not the fold


def test_resume_review_branch_must_differ_from_the_priors(tmp_path):
    repo, _base, _tip = _resume_fixture(tmp_path, tip_is_wip_fold=False)
    r, _ = _run(
        tmp_path,
        _seeded(session_id="sid2", resume_from="old1", review_branch="sandbox/old-rb"),
        cwd=repo,
    )
    assert r.returncode != 0
    assert "must differ from the prior session's" in r.stderr


def test_resume_warns_when_the_prior_session_exported_no_audit_log(tmp_path):
    repo, _base, _tip = _resume_fixture(tmp_path, tip_is_wip_fold=False)
    prior_log = _state_dir(tmp_path, "agent-sandbox-old1") / "audit.jsonl"
    prior_log.unlink()
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid2", resume_from="old1", review_branch="sandbox/new-rb"),
        extra_env={"FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "exported no audit log" in r.stderr
    assert "audit-prior-override" not in log


# --- helper units (sourced from stack.bash; no launcher) ---


def _source_stack(tmp_path, snippet, *args, extra_env=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", FAKE_DOCKER)
    log = tmp_path / "docker-argv.log"
    log.touch()
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "NO_COLOR": "1",
        "DOCKER_ARGV_LOG": str(log),
        **(extra_env or {}),
    }
    r = subprocess.run(
        [
            "bash",
            "-c",
            f'set -Eeuo pipefail; source "{STACK_LIB}"; {snippet}',
            "_",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    return r, log.read_text()


def test_audit_prior_override_escapes_dollars_for_compose(tmp_path):
    """Compose interpolates every file it loads, so a literal `$` in the prior log's
    path must ride as `$$` — same treatment as the workspace-bind override."""
    out = tmp_path / "override.json"
    prior = "/state/$weird$path/audit.jsonl"
    r, _ = _source_stack(
        tmp_path, '_stack_write_audit_prior_override "$1" "$2"', prior, str(out)
    )
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text()) == {
        "services": {
            "audit": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/state/$$weird$$path/audit.jsonl",
                        "target": "/var/log/agent-sandbox/audit.prior.jsonl",
                        "read_only": True,
                    }
                ]
            }
        }
    }


def test_export_audit_log_copies_log_and_secret_owner_only(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    r, log = _source_stack(
        tmp_path,
        '_stack_export_audit_log proj compose.yml o.json m.json "$1"',
        str(state),
        extra_env={"FAKE_AUDIT_CID": "1"},
    )
    assert r.returncode == 0, r.stderr
    assert "cp acid:/var/log/agent-sandbox/audit.jsonl" in log
    assert "cp acid:/run/audit-secret/secret" in log
    for name in ("audit.jsonl", "audit.secret"):
        assert (state / name).stat().st_mode & 0o777 == 0o600


def test_export_audit_log_warns_when_no_audit_container(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    r, _ = _source_stack(
        tmp_path,
        '_stack_export_audit_log proj compose.yml o.json m.json "$1" && echo SURVIVED',
        str(state),
    )
    # Non-blocking by contract: the helper returns non-zero (callers `|| true` it)
    # and warns; nothing is exported.
    assert "could not export the audit log" in r.stderr
    assert "SURVIVED" not in r.stdout  # the non-zero return is part of the contract
    assert not (state / "audit.jsonl").exists()


def test_manifest_roundtrip_write_read_update(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    snippet = (
        '_stack_write_manifest "$1" proj "" seed HEAD c0ffee beef sandbox/rb /repo'
        ' && _stack_read_manifest_field "$1" review_branch'
        ' && _stack_update_manifest "$1" 3 false'
    )
    r, _ = _source_stack(tmp_path, snippet, str(state))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "sandbox/rb"
    manifest = json.loads((state / "session.json").read_text())
    assert manifest["session_id"] is None  # empty -> null, not ""
    assert manifest["last_exit"] == 3 and manifest["extracted"] is False
    assert (state / "session.json").stat().st_mode & 0o777 == 0o600


def test_read_manifest_field_fails_on_missing_field(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    snippet = (
        '_stack_write_manifest "$1" proj sid seed HEAD c0ffee beef sandbox/rb /repo'
        ' && _stack_read_manifest_field "$1" no_such_field'
    )
    r, _ = _source_stack(tmp_path, snippet, str(state))
    assert r.returncode != 0
    assert r.stdout.strip() == ""


def test_reattach_with_deleted_review_branch_is_refused(tmp_path):
    """The re-attach extract lands this leg's commits on the existing review
    branch; if the user deleted it (the merge hint's `git branch -d`), a rebuilt
    branch would misapply the new patches — refuse with the --reseed remedy."""
    repo, head = _reattach_fixture(tmp_path)
    subprocess.run(
        ["git", "branch", "-D", "sandbox/rb1"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    r, log = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        extra_env={
            "FAKE_VOLUMES": "1",
            "FAKE_WORKLOAD_CID": "1",
            "FAKE_SEED_HEAD": head,
        },
        cwd=repo,
    )
    assert r.returncode != 0
    assert "no longer exists" in r.stderr and "--reseed" in r.stderr
    # The workload's entrypoint never ran.
    assert "bash -lc echo hi" not in log


def test_merge_hint_keeps_the_branch_for_persistent_sessions(tmp_path):
    """A persistent session's next leg extracts onto the same review branch, so
    its hint must not instruct `git branch -d`; an ephemeral session's hint does."""
    repo, _head = _repo(tmp_path)
    r, _ = _run(
        tmp_path,
        _seeded(session_id="sid1", ephemeral=False, review_branch="sandbox/rb1"),
        extra_env={"FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    hint = r.stdout + r.stderr
    assert "keep the branch" in hint and "git branch -d" not in hint
    r2, _ = _run(
        tmp_path,
        _seeded(review_branch="sandbox/rb2"),
        extra_env={"FAKE_WORKLOAD_CID": "1"},
        cwd=repo,
    )
    assert r2.returncode == 0, r2.stderr
    assert "git branch -d sandbox/rb2" in r2.stdout + r2.stderr

"""Launcher-level behavior of `agent-sandbox prewarm` and spare adoption in
`run` (issue #34), driven end-to-end with a RECORDING fake docker on PATH (no
daemon) inside a real throwaway git repo — the host-side git machinery is real,
every container interaction is an argv-recorded stub. Env toggles model the
docker-side state each scenario needs (a matching spare, its workspace probe's
verdict); the spare's on-disk state (prewarm.json + override files) is staged
the way a real `prewarm` leaves it.
"""

import json
import os
import re
import subprocess

from tests._helpers import (
    REPO_ROOT,
    commit_all,
    git_env,
    init_test_repo,
    write_exe,
)

LAUNCHER = REPO_ROOT / "bin" / "agent-sandbox"

SPARE_PROJECT = "agent-sandbox-prewarm-00c0ffee"

# Answers by argv pattern (most-specific first); env toggles model docker-side
# state. `exec -i` drains stdin so seed pipes never die on EPIPE. compose `up`
# also records the interpolation env it would consume (SANDBOX_SUBNET), so the
# tests can see which subnet an adoption re-up ran under. An exec carrying
# --env-file snapshots the file + its mode (real docker reads it at exec start).
FAKE_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_ARGV_LOG"
if [[ "$1" == exec ]]; then
  if [[ -n "${ENV_CAPTURE:-}" ]]; then
    prev=""
    for a in "$@"; do
      if [[ "$prev" == "--env-file" ]]; then
        cp "$a" "$ENV_CAPTURE"
        { stat -c '%a' "$a" 2>/dev/null || stat -f '%Lp' "$a"; } >"$ENV_CAPTURE.mode"
      fi
      prev="$a"
    done
  fi
  if [[ "$2" == "-i" ]]; then cat >/dev/null; fi
fi
case "$*" in
  "image inspect -f {{.Id}} "*)
    [[ -n "${FAKE_IMAGE_INSPECT_FAIL:-}" ]] && exit 1
    echo "sha256:fake-${*: -1}" ;;
  "ps -q --filter label=agent-sandbox.prewarm=ready --filter label=agent-sandbox.prewarm-spec="*)
    # FAKE_SPARE_CID may name several space-separated candidates, one per line.
    [[ -n "${FAKE_SPARE_CID:-}" ]] && printf '%s\\n' $FAKE_SPARE_CID ;;
  "inspect -f "*"com.docker.compose.project"*)
    key="FAKE_PROJECT_${*: -1}"
    echo "${!key:-${FAKE_SPARE_PROJECT:-}}" ;;
  *"ls -A /workspace"*)
    # `-` not `:-`: an explicitly EMPTY value models a broken probe printing nothing.
    echo "${FAKE_WORKSPACE_PROBE-EMPTY}" ;;
  "compose "*" up -d --wait --wait-timeout 240")
    printf 'UPENV SANDBOX_SUBNET=%s SANDBOX_IP_AUDIT=%s\\n' "${SANDBOX_SUBNET:-}" "${SANDBOX_IP_AUDIT:-}" >>"$DOCKER_ARGV_LOG"
    for p in ${FAKE_UP_FAIL_PROJECTS:-}; do
      [[ "$*" == *"-p $p "* ]] && exit 1
    done ;;
  "compose "*" ps -q workload")
    echo wcid ;;
  "compose "*" ps -q firewall")
    echo fwcid ;;
  "compose "*" ps -q audit")
    echo acid ;;
  "cp "*)
    touch "$3" ;;
  *"git rev-parse HEAD"*)
    echo 1111111111111111111111111111111111111111 ;;
esac
exit 0
"""

SEEDED = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": ["pypi.org"],
    "ephemeral": True,
    "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/prewarm-rb"},
}


def _run(tmp_path, verb, workload_obj, *, extra_env=None, cwd=None, argv_tail=()):
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
        "AGENT_SANDBOX_PREWARM_CLAIM_DIR": str(tmp_path / "claims"),
        **(extra_env or {}),
    }
    r = subprocess.run(
        [str(LAUNCHER), verb, *argv_tail, str(wl)],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )
    return r, log.read_text()


def _repo(tmp_path):
    repo = tmp_path / "repo"
    init_test_repo(repo)
    (repo / "tracked.txt").write_text("v1\n")
    commit_all(repo, "fixture: base")
    return repo


def _stage_spare(tmp_path, project=SPARE_PROJECT, subnet="172.30.9.0/24"):
    """The on-disk state a real `prewarm` leaves for an adopter."""
    state = tmp_path / "state" / "sessions" / project
    state.mkdir(parents=True)
    (state / "prewarm.json").write_text(
        json.dumps(
            {
                "project": project,
                "spec": "0" * 16,
                "subnet": subnet,
                "created": 1700000000,
            }
        )
    )
    (state / "workload-override.json").write_text('{"services": {}}')
    (state / "overmount-override.json").write_text('{"services": {}}')
    (state / "prewarm-override.json").write_text('{"services": {}}')
    return state


def _spare_env():
    return {"FAKE_SPARE_CID": "sparecid", "FAKE_SPARE_PROJECT": SPARE_PROJECT}


def _projects(log):
    return {
        line.split()[line.split().index("-p") + 1]
        for line in log.splitlines()
        if line.startswith("compose ")
    }


# ── prewarm verb: refusals ──────────────────────────────────────────


def test_prewarm_refuses_workspace_mount(tmp_path):
    wl = {k: v for k, v in SEEDED.items() if k != "seed_from_git"}
    r, log = _run(tmp_path, "prewarm", {**wl, "workspace_mount": str(tmp_path)})
    assert r.returncode != 0
    assert "prewarm refuses workspace_mount" in r.stderr
    assert "compose" not in log


def test_prewarm_refuses_session_id(tmp_path):
    r, log = _run(tmp_path, "prewarm", {**SEEDED, "session_id": "sid1"})
    assert r.returncode != 0
    assert "prewarm refuses session_id/resume_from" in r.stderr
    assert "compose" not in log


def test_prewarm_refuses_resume_from(tmp_path):
    r, log = _run(tmp_path, "prewarm", {**SEEDED, "resume_from": "old1"})
    assert r.returncode != 0
    assert "prewarm refuses session_id/resume_from" in r.stderr
    assert "compose" not in log


def test_prewarm_refuses_an_invalid_record_like_run_does(tmp_path):
    r, _ = _run(tmp_path, "prewarm", {"image": "debian:stable-slim"})
    assert r.returncode != 0
    assert "entrypoint must be a non-empty array" in r.stderr


def test_prewarm_unknown_option_is_rejected(tmp_path):
    r, log = _run(tmp_path, "prewarm", SEEDED, argv_tail=("--frobnicate",))
    assert r.returncode != 0
    assert "unknown option for prewarm" in r.stderr
    assert "compose" not in log


def test_prewarm_without_a_workload_file_is_rejected(tmp_path):
    r, log = _run_bare(tmp_path, ["prewarm"])
    assert r.returncode != 0
    assert "no workload file given" in r.stderr


def test_prewarm_with_two_workload_files_is_rejected(tmp_path):
    wl2 = tmp_path / "second.json"
    wl2.write_text(json.dumps(SEEDED))
    r, _ = _run(tmp_path, "prewarm", SEEDED, argv_tail=(str(wl2),))
    assert r.returncode != 0
    assert "exactly one workload file" in r.stderr


def test_prewarm_extra_compose_without_argument_is_rejected(tmp_path):
    r, _ = _run_bare(tmp_path, ["prewarm", "--extra-compose"])
    assert r.returncode != 0
    assert "--extra-compose needs a file argument" in r.stderr


def test_prewarm_extra_compose_missing_file_is_rejected(tmp_path):
    r, log = _run(
        tmp_path,
        "prewarm",
        SEEDED,
        argv_tail=("--extra-compose", str(tmp_path / "nope.yml")),
    )
    assert r.returncode != 0
    assert "extra compose file not found" in r.stderr
    assert "compose" not in log


def _run_bare(tmp_path, argv):
    """The launcher with the recording stub but no workload file appended."""
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
    }
    r = subprocess.run([str(LAUNCHER), *argv], capture_output=True, text=True, env=env)
    return r, log.read_text()


# ── prewarm verb: happy path ────────────────────────────────────────


def test_prewarm_extra_compose_rides_before_the_prewarm_override(tmp_path):
    overlay = tmp_path / "overlay.json"
    overlay.write_text('{"services": {}}')
    r, log = _run(
        tmp_path, "prewarm", SEEDED, argv_tail=("--extra-compose", str(overlay))
    )
    assert r.returncode == 0, r.stderr
    up = next(c for c in log.splitlines() if " up -d " in c)
    args = up.split()
    f_args = [args[i + 1] for i, a in enumerate(args) if a == "-f"]
    # base + workload override + overmounts + consumer overlay + prewarm override,
    # the prewarm override LAST so a consumer overlay can never strip the labels.
    assert f_args[-2] == str(overlay)
    assert f_args[-1].endswith("/prewarm-override.json")


def test_prewarm_leaves_a_labeled_spare_up_and_prints_its_project(tmp_path):
    wl = {
        **SEEDED,
        "env": {"FOO": "bar"},
        "secret_env": {"TOKEN": "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"},
    }
    r, log = _run(tmp_path, "prewarm", wl)
    assert r.returncode == 0, r.stderr
    project = r.stdout.strip().splitlines()[-1]
    assert re.fullmatch(r"agent-sandbox-prewarm-[0-9a-f]{8}", project), r.stdout
    state = tmp_path / "state" / "sessions" / project

    up = [c for c in log.splitlines() if " up -d " in c]
    assert len(up) == 1
    # The labels override rides the up; the spare is left running (no down) and
    # no entrypoint exec ever happens.
    assert str(state / "prewarm-override.json") in up[0]
    assert " down " not in f" {log} "
    assert "bash -lc echo hi" not in log

    # env/secret_env are NOT baked: no env-file override at up, no secret exec.
    assert "workload-env-override.json" not in log
    assert "/run/secrets/" not in log

    override = json.loads((state / "prewarm-override.json").read_text())
    labels = override["services"]["workload"]["labels"]
    assert labels["agent-sandbox.prewarm"] == "ready"
    assert re.fullmatch(r"[0-9a-f]{16}", labels["agent-sandbox.prewarm-spec"])
    assert labels["agent-sandbox.prewarm-created"].isdigit()
    assert override["services"]["workload"]["tmpfs"] == [
        "/run/secrets:mode=0755,size=1m"
    ]
    # The tmpfs is declared ONCE, by the prewarm override: the per-session
    # workload override must not repeat it (two override files emitting the same
    # destination is daemon-reconciliation behavior the launcher refuses to bet on).
    wl_override = json.loads((state / "workload-override.json").read_text())
    assert "tmpfs" not in wl_override["services"].get("workload", {})

    manifest = json.loads((state / "prewarm.json").read_text())
    assert manifest["project"] == project
    assert manifest["spec"] == labels["agent-sandbox.prewarm-spec"]
    assert re.fullmatch(r"172\.\d+\.\d+\.0/24", manifest["subnet"])
    assert (state / "prewarm.json").stat().st_mode & 0o777 == 0o600


# ── adoption in run ─────────────────────────────────────────────────


def test_run_adopts_a_matching_spare(tmp_path):
    repo = _repo(tmp_path)
    state = _stage_spare(tmp_path)
    r, log = _run(tmp_path, "run", SEEDED, extra_env=_spare_env(), cwd=repo)
    assert r.returncode == 0, r.stderr
    assert f"adopted prewarmed spare {SPARE_PROJECT}" in r.stderr
    # The whole session runs under the SPARE's project — no second cold `up`
    # under a fresh random identity.
    assert _projects(log) == {SPARE_PROJECT}
    # The re-up ran under the spare's recorded subnet — the WHOLE address family,
    # not just the /24: a stale audit .4 outside it would fail the static claim.
    assert "UPENV SANDBOX_SUBNET=172.30.9.0/24 SANDBOX_IP_AUDIT=172.30.9.4" in log
    # The spare's prewarm override rode the adoption re-up.
    up = next(c for c in log.splitlines() if " up -d " in c)
    assert str(state / "prewarm-override.json") in up
    # Seeded into the already-running container, entrypoint ran, spare torn down
    # as the session's own ephemeral stack.
    assert "chown 1000:1000 /workspace" in log
    assert "bash -lc echo hi" in log
    assert f"compose -p {SPARE_PROJECT}" in log
    assert any(" down --volumes " in f" {c} " for c in log.splitlines())
    # The adopted marker was written; the claim was released at teardown.
    assert (state / "prewarm-adopted").exists()
    assert not (tmp_path / "claims" / SPARE_PROJECT).exists()


def test_adopted_run_delivers_env_via_exec_env_file(tmp_path):
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    cap = tmp_path / "captured.env"
    r, log = _run(
        tmp_path,
        "run",
        {**SEEDED, "env": {"API_TOKEN": "placeholder-token"}},
        extra_env={**_spare_env(), "ENV_CAPTURE": str(cap)},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert f"adopted prewarmed spare {SPARE_PROJECT}" in r.stderr
    # Delivered at exec time (not baked at up), 0600, then unlinked.
    entry = next(c for c in log.splitlines() if "bash -lc echo hi" in c)
    assert "--env-file" in entry
    assert cap.read_text() == "API_TOKEN=placeholder-token\n"
    assert (tmp_path / "captured.env.mode").read_text().strip() == "600"
    assert "workload-env-override.json" not in log
    state = tmp_path / "state" / "sessions" / SPARE_PROJECT
    assert not (state / "workload.env").exists()


def test_adopted_run_delivers_secrets_before_the_entrypoint(tmp_path):
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    r, log = _run(
        tmp_path,
        "run",
        {**SEEDED, "secret_env": {"TOKEN": "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"}},
        extra_env=_spare_env(),
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    lines = log.splitlines()
    delivery = [i for i, c in enumerate(lines) if "/run/secrets/" in c]
    entry = [i for i, c in enumerate(lines) if "bash -lc echo hi" in c]
    assert delivery and entry and delivery[0] < entry[0], log


def test_no_matching_spare_falls_back_to_cold_boot(tmp_path):
    repo = _repo(tmp_path)
    r, log = _run(tmp_path, "run", SEEDED, cwd=repo)
    assert r.returncode == 0, r.stderr
    # The probe ran (hash computed, spares queried) and found nothing.
    assert "label=agent-sandbox.prewarm=ready" in log
    assert "adopted prewarmed spare" not in r.stderr
    projects = _projects(log)
    assert len(projects) == 1
    assert re.fullmatch(r"agent-sandbox-[0-9a-f]{8}", projects.pop())


def test_hash_failure_falls_back_to_cold_boot(tmp_path):
    """A spec hash that cannot be computed (an uninspectable image) must cold-boot,
    never block the launch — even with a willing spare on offer."""
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    r, log = _run(
        tmp_path,
        "run",
        SEEDED,
        extra_env={**_spare_env(), "FAKE_IMAGE_INSPECT_FAIL": "1"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "adopted prewarmed spare" not in r.stderr
    # Never even queried for spares (no hash to match on).
    assert "label=agent-sandbox.prewarm=ready" not in log
    assert SPARE_PROJECT not in _projects(log)


def test_lost_claim_race_falls_back_to_cold_boot(tmp_path):
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    # Another live process already holds the claim (this pytest's own pid).
    claim = tmp_path / "claims" / SPARE_PROJECT
    claim.mkdir(parents=True)
    (claim / "pid").write_text(f"{os.getpid()}\n")
    r, log = _run(tmp_path, "run", SEEDED, extra_env=_spare_env(), cwd=repo)
    assert r.returncode == 0, r.stderr
    assert "adopted prewarmed spare" not in r.stderr
    assert SPARE_PROJECT not in _projects(log)
    # The loser never touched the winner's claim.
    assert (claim / "pid").read_text().strip() == str(os.getpid())


def test_corrupt_spare_with_nonempty_workspace_is_released_and_skipped(tmp_path):
    repo = _repo(tmp_path)
    state = _stage_spare(tmp_path)
    r, log = _run(
        tmp_path,
        "run",
        SEEDED,
        extra_env={**_spare_env(), "FAKE_WORKSPACE_PROBE": "NONEMPTY"},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "non-empty or unverifiable /workspace" in r.stderr
    assert "adopted prewarmed spare" not in r.stderr
    # Released for gc (claim gone, marker rolled back), session cold-booted.
    assert not (tmp_path / "claims" / SPARE_PROJECT).exists()
    assert not (state / "prewarm-adopted").exists()
    cold = _projects(log) - {SPARE_PROJECT}
    assert len(cold) == 1 and re.fullmatch(r"agent-sandbox-[0-9a-f]{8}", cold.pop())


def test_unverifiable_workspace_probe_reads_as_corrupt(tmp_path):
    """Fail-closed probe: a broken exec printing NOTHING must be treated as
    corrupt (positively prove emptiness), never adopted as if empty."""
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    r, _ = _run(
        tmp_path,
        "run",
        SEEDED,
        extra_env={**_spare_env(), "FAKE_WORKSPACE_PROBE": ""},
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "non-empty or unverifiable /workspace" in r.stderr
    assert "adopted prewarmed spare" not in r.stderr


def test_all_candidates_failing_re_up_cold_boots_with_a_clean_file_set(tmp_path):
    """Two matching spares both fail their adoption re-up: every rollback must be
    complete — the cold boot's compose file set carries the consumer overlay but
    NO spare's prewarm override, and both claims are released."""
    repo = _repo(tmp_path)
    proj_a = "agent-sandbox-prewarm-000000aa"
    proj_b = "agent-sandbox-prewarm-000000bb"
    _stage_spare(tmp_path, project=proj_a)
    _stage_spare(tmp_path, project=proj_b, subnet="172.30.8.0/24")
    overlay = tmp_path / "overlay.json"
    overlay.write_text('{"services": {}}')
    r, log = _run(
        tmp_path,
        "run",
        SEEDED,
        argv_tail=("--extra-compose", str(overlay)),
        extra_env={
            "FAKE_SPARE_CID": "cida cidb",
            "FAKE_PROJECT_cida": proj_a,
            "FAKE_PROJECT_cidb": proj_b,
            "FAKE_UP_FAIL_PROJECTS": f"{proj_a} {proj_b}",
        },
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "adopted prewarmed spare" not in r.stderr
    cold_ups = [
        c
        for c in log.splitlines()
        if " up -d " in c and proj_a not in c and proj_b not in c
    ]
    assert len(cold_ups) == 1, log
    args = cold_ups[0].split()
    f_args = [args[i + 1] for i, a in enumerate(args) if a == "-f"]
    assert "prewarm-override.json" not in " ".join(f_args)
    assert f_args[-1] == str(overlay)
    assert len(f_args) == 4  # base + workload override + overmounts + overlay
    assert not (tmp_path / "claims" / proj_a).exists()
    assert not (tmp_path / "claims" / proj_b).exists()


def test_session_id_workload_never_probes_for_spares(tmp_path):
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    r, log = _run(
        tmp_path,
        "run",
        {**SEEDED, "ephemeral": False, "session_id": "sid1"},
        extra_env=_spare_env(),
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "label=agent-sandbox.prewarm=ready" not in log
    assert "adopted prewarmed spare" not in r.stderr


def test_non_ephemeral_workload_never_probes_for_spares(tmp_path):
    repo = _repo(tmp_path)
    _stage_spare(tmp_path)
    r, log = _run(
        tmp_path,
        "run",
        {**SEEDED, "ephemeral": False},
        extra_env=_spare_env(),
        cwd=repo,
    )
    assert r.returncode == 0, r.stderr
    assert "label=agent-sandbox.prewarm=ready" not in log

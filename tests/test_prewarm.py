"""Sourced-function tests for bin/lib/prewarm.bash (issue #34): the claim locks
that make adopting/reaping a spare single-winner, and the spec hash that gates
adoption on bring-up equality.

The claim tests exercise the real mkdir-based lock in a throwaway claim dir; the
hash tests run against a fake `docker image inspect` on PATH so image identity is
a controlled input. The hash's input set is enumerated: one test per hashed input
(the hash must move) and one per deliberately-excluded field (the hash must NOT
move) — a member dropped from either side is a real adoption-gate change.
"""

import json
import os
import subprocess
import time

import pytest

from tests._helpers import REPO_ROOT, write_exe

PREWARM_LIB = REPO_ROOT / "bin" / "lib" / "prewarm.bash"

# Answers `docker image inspect -f {{.Id}} <image>` with a per-image fake digest
# (overridable via FAKE_IMAGE_ID_<name> for the sensitivity tests) and fails for
# images marked missing — the shape prewarm_spec_hash consumes.
FAKE_DOCKER = """#!/usr/bin/env bash
if [[ "$1 $2" == "image inspect" ]]; then
  img="${*: -1}"
  [[ -n "${FAKE_IMAGE_MISSING:-}" && "$img" == "$FAKE_IMAGE_MISSING" ]] && exit 1
  key="FAKE_IMAGE_ID_${img//[^A-Za-z0-9]/_}"
  echo "${!key:-sha256:fake-$img}"
  exit 0
fi
exit 0
"""

BASE_WORKLOAD = {
    "image": "debian:stable-slim",
    "entrypoint": ["bash", "-lc", "echo hi"],
    "egress_allowlist": ["pypi.org", {"host": "github.com", "access": "ro"}],
    "ephemeral": True,
    "seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/rb"},
}


def _bash(tmp_path, snippet, *args, extra_env=None):
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    write_exe(stub / "docker", FAKE_DOCKER)
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "NO_COLOR": "1",
        "AGENT_SANDBOX_PREWARM_CLAIM_DIR": str(tmp_path / "claims"),
        **(extra_env or {}),
    }
    return subprocess.run(
        [
            "bash",
            "-c",
            f'set -Eeuo pipefail; source "{PREWARM_LIB}"; {snippet}',
            "_",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


# ── claim locks ─────────────────────────────────────────────────────


def test_claim_wins_once_and_records_the_claimer_pid(tmp_path):
    r = _bash(tmp_path, '_prewarm_claim "$1" && echo CLAIMED', "proj-a")
    assert r.returncode == 0, r.stderr
    assert "CLAIMED" in r.stdout
    pid_file = tmp_path / "claims" / "proj-a" / "pid"
    assert pid_file.read_text().strip().isdigit()


def test_second_claim_on_the_same_project_loses_the_race(tmp_path):
    r = _bash(
        tmp_path,
        '_prewarm_claim "$1" || exit 9; if _prewarm_claim "$1"; then echo DOUBLE; fi',
        "proj-a",
    )
    assert r.returncode == 0, r.stderr
    assert "DOUBLE" not in r.stdout


def test_release_makes_the_project_claimable_again(tmp_path):
    r = _bash(
        tmp_path,
        '_prewarm_claim "$1" && _prewarm_release "$1" && _prewarm_claim "$1" && echo RECLAIMED',
        "proj-a",
    )
    assert r.returncode == 0, r.stderr
    assert "RECLAIMED" in r.stdout


def test_claim_dir_parent_is_owner_only(tmp_path):
    r = _bash(tmp_path, '_prewarm_claim "$1"', "proj-a")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "claims").stat().st_mode & 0o777 == 0o700


def test_stale_claim_detection_by_dead_pid(tmp_path):
    # A pid that HAS existed but is certainly dead now: a reaped child of ours.
    dead = subprocess.Popen(["true"])
    dead.wait()
    claim = tmp_path / "claims" / "proj-a"
    claim.mkdir(parents=True)
    (claim / "pid").write_text(f"{dead.pid}\n")
    r = _bash(tmp_path, '_prewarm_claim_is_stale "$1" && echo STALE', "proj-a")
    assert "STALE" in r.stdout, r.stderr


def test_live_claim_is_not_stale(tmp_path):
    r = _bash(
        tmp_path,
        # The claimer (this bash) is alive while it asks, so its own claim is live.
        '_prewarm_claim "$1"; if _prewarm_claim_is_stale "$1"; then echo STALE; fi',
        "proj-a",
    )
    assert r.returncode == 0, r.stderr
    assert "STALE" not in r.stdout


def test_absent_claim_is_not_stale(tmp_path):
    r = _bash(tmp_path, 'if _prewarm_claim_is_stale "$1"; then echo STALE; fi', "ghost")
    assert r.returncode == 0, r.stderr
    assert "STALE" not in r.stdout


def test_claim_with_unreadable_pid_is_stale(tmp_path):
    claim = tmp_path / "claims" / "proj-a"
    claim.mkdir(parents=True)  # no pid file: the claimer died mid-claim
    r = _bash(tmp_path, '_prewarm_claim_is_stale "$1" && echo STALE', "proj-a")
    assert "STALE" in r.stdout, r.stderr


# ── spec hash ───────────────────────────────────────────────────────


def _hash(tmp_path, workload_obj, *, extra_env=None, runtime="runc", extras=()):
    wl = tmp_path / f"wl-{abs(hash(json.dumps(workload_obj, sort_keys=True)))}.json"
    wl.write_text(json.dumps(workload_obj))
    compose = tmp_path / "compose.yml"
    if not compose.exists():
        compose.write_text("services: {}\n")
    r = _bash(
        tmp_path,
        'prewarm_spec_hash "$@"',
        str(wl),
        str(compose),
        runtime,
        *[str(e) for e in extras],
        extra_env=extra_env,
    )
    assert r.returncode == 0, r.stderr
    out = r.stdout.strip()
    assert len(out) == 16 and all(c in "0123456789abcdef" for c in out)
    return out


def test_spec_hash_is_stable_across_runs(tmp_path):
    assert _hash(tmp_path, BASE_WORKLOAD) == _hash(tmp_path, BASE_WORKLOAD)


def test_spec_hash_ignores_allowlist_order_and_spelling(tmp_path):
    """Canonical normalization: entry order and string-vs-object spelling of the
    same {host, access} set must hash identically."""
    respelled = {
        **BASE_WORKLOAD,
        "egress_allowlist": [
            {"host": "github.com", "access": "ro"},
            {"host": "pypi.org", "access": "rw"},
        ],
    }
    assert _hash(tmp_path, BASE_WORKLOAD) == _hash(tmp_path, respelled)


@pytest.mark.parametrize(
    "mutate",
    [
        {"egress_allowlist": ["pypi.org"]},
        {"egress_allowlist": ["pypi.org", {"host": "github.com", "access": "rw"}]},
        {"user": "1001"},
        {"hardener": False},
        {"audit": False},
        {"backend": "hosted"},
        {"control_plane": {"egress_grants": [{"uid": 7, "hosts": ["api.foo.dev"]}]}},
    ],
    ids=[
        "allowlist-member-dropped",
        "allowlist-access-tier",
        "user",
        "hardener",
        "audit",
        "backend",
        "egress-grants",
    ],
)
def test_spec_hash_moves_with_each_baked_input(tmp_path, mutate):
    assert _hash(tmp_path, BASE_WORKLOAD) != _hash(
        tmp_path, {**BASE_WORKLOAD, **mutate}
    )


def test_spec_hash_defaults_equal_their_explicit_spelling(tmp_path):
    explicit = {
        **BASE_WORKLOAD,
        "user": "1000",
        "hardener": True,
        "audit": True,
        "backend": "local",
    }
    assert _hash(tmp_path, BASE_WORKLOAD) == _hash(tmp_path, explicit)


def test_spec_hash_moves_with_the_workload_image_id(tmp_path):
    moved = _hash(
        tmp_path,
        BASE_WORKLOAD,
        extra_env={"FAKE_IMAGE_ID_debian_stable_slim": "sha256:rebuilt"},
    )
    assert _hash(tmp_path, BASE_WORKLOAD) != moved


def test_spec_hash_moves_with_the_firewall_image_id(tmp_path):
    moved = _hash(
        tmp_path,
        BASE_WORKLOAD,
        extra_env={"FAKE_IMAGE_ID_agent_sandbox_firewall_local": "sha256:rebuilt"},
    )
    assert _hash(tmp_path, BASE_WORKLOAD) != moved


def test_spec_hash_moves_with_the_runtime(tmp_path):
    assert _hash(tmp_path, BASE_WORKLOAD) != _hash(
        tmp_path, BASE_WORKLOAD, runtime="runsc"
    )


def test_spec_hash_moves_with_compose_file_content(tmp_path):
    before = _hash(tmp_path, BASE_WORKLOAD)
    (tmp_path / "compose.yml").write_text("services: {changed: {}}\n")
    assert before != _hash(tmp_path, BASE_WORKLOAD)


def test_spec_hash_moves_with_referenced_seccomp_profile_content(tmp_path):
    """security_opt applies the profile's CONTENT at container-create, but compose
    only stores the path — so the profile files must be hashed themselves, or an
    edited profile would be invisible to the adoption gate."""
    compose = tmp_path / "compose.yml"
    seccomp = tmp_path / "seccomp-default.json"
    compose.write_text(
        "services:\n  workload:\n    security_opt:\n      - seccomp:./seccomp-default.json\n"
    )
    seccomp.write_text('{"defaultAction": "SCMP_ACT_ERRNO"}\n')
    before = _hash(tmp_path, dict(BASE_WORKLOAD))
    seccomp.write_text('{"defaultAction": "SCMP_ACT_ALLOW"}\n')
    assert _hash(tmp_path, dict(BASE_WORKLOAD)) != before


def test_spec_hash_fails_closed_on_a_missing_referenced_seccomp_profile(tmp_path):
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n  workload:\n    security_opt:\n      - seccomp:./absent.json\n"
    )
    wl = tmp_path / "wl-missing-seccomp.json"
    wl.write_text(json.dumps(BASE_WORKLOAD))
    r = _bash(tmp_path, 'prewarm_spec_hash "$@"', str(wl), str(compose), "runc")
    assert r.returncode != 0


def test_spec_hash_covers_extra_compose_content_and_order(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text('{"services": {"x": {}}}')
    b.write_text('{"services": {"y": {}}}')
    plain = _hash(tmp_path, BASE_WORKLOAD)
    ab = _hash(tmp_path, BASE_WORKLOAD, extras=[a, b])
    ba = _hash(tmp_path, BASE_WORKLOAD, extras=[b, a])
    assert len({plain, ab, ba}) == 3


@pytest.mark.parametrize(
    "mutate",
    [
        {"entrypoint": ["bash", "-lc", "echo other"]},
        {"tty": True},
        {"env": {"FOO": "bar"}},
        {"secret_env": {"TOKEN": "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"}},
        {"ephemeral": False},
        {"seed_from_git": {"ref": "HEAD", "review_branch": "sandbox/other"}},
        {"overmount_paths": [".git/hooks"]},
        {"control_plane": {"require": ["broker"]}},
    ],
    ids=[
        "entrypoint",
        "tty",
        "env",
        "secret_env",
        "ephemeral",
        "seed_from_git",
        "overmount_paths",
        "control-plane-require",
    ],
)
def test_spec_hash_ignores_each_exec_or_teardown_time_field(tmp_path, mutate):
    """The excluded set, one case per member: these fields are exec-, adoption-, or
    teardown-time and must not fragment the spare pool."""
    assert _hash(tmp_path, BASE_WORKLOAD) == _hash(
        tmp_path, {**BASE_WORKLOAD, **mutate}
    )


def test_spec_hash_fails_closed_when_an_image_is_not_inspectable(tmp_path):
    wl = tmp_path / "wl.json"
    wl.write_text(json.dumps(BASE_WORKLOAD))
    compose = tmp_path / "compose.yml"
    compose.write_text("services: {}\n")
    r = _bash(
        tmp_path,
        'prewarm_spec_hash "$1" "$2" runc',
        str(wl),
        str(compose),
        extra_env={"FAKE_IMAGE_MISSING": "debian:stable-slim"},
    )
    assert r.returncode != 0
    assert r.stdout.strip() == ""


# ── prewarm_spawn_next (run --prewarm-next replenishment) ───────────


def test_spawn_next_launches_prewarm_with_extra_compose_and_workload(tmp_path):
    """The default (no CMD override) builds `<self> prewarm --extra-compose <f>...
    <workload>` and detaches it. A recorder stands in for the launcher self-path."""
    recorder = tmp_path / "self"
    write_exe(recorder, '#!/usr/bin/env bash\nprintf "%s\\n" "$@" >>"$SPAWN_MARKER"\n')
    marker = tmp_path / "spawned.txt"
    _bash(
        tmp_path,
        'as_info() { :; }; prewarm_spawn_next "$@"',
        str(recorder),
        "/wl.json",
        "/overlay.yml",
        extra_env={"SPAWN_MARKER": str(marker)},
    )
    deadline = time.time() + 5
    while time.time() < deadline and not marker.exists():
        time.sleep(0.05)
    assert marker.exists(), "the detached command never ran"
    assert marker.read_text().splitlines() == [
        "prewarm",
        "--extra-compose",
        "/overlay.yml",
        "/wl.json",
    ]


def test_spawn_next_is_a_noop_under_no_prewarm(tmp_path):
    recorder = tmp_path / "self"
    write_exe(recorder, '#!/usr/bin/env bash\ntouch "$SPAWN_MARKER"\n')
    marker = tmp_path / "spawned.txt"
    _bash(
        tmp_path,
        'as_info() { :; }; prewarm_spawn_next "$@"',
        str(recorder),
        "/wl.json",
        extra_env={"SPAWN_MARKER": str(marker), "AGENT_SANDBOX_NO_PREWARM": "1"},
    )
    time.sleep(0.3)
    assert not marker.exists()

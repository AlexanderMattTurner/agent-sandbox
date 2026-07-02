"""Host-side coverage for bin/lib/overmounts.bash — no Docker required.

The read-only guardrail overmounts are a security control, so every generator and gate
is driven through its real input domain and asserted against the INVARIANT a bug would
violate, never a symptom:

  overmount_applies          Gates on host existence so we never fabricate empty dirs. The
                             pre-state domain (missing / regular file / dir / DANGLING
                             symlink) each yields a well-defined apply/skip.

  write_overmount_compose    Emits exactly one read-only bind per applicable path, and the
                             no-op `{"services":{}}` (never an empty volumes list that would
                             clear the base /workspace mount) when nothing applies — seed
                             mode, an explicit [], or a workspace shipping none of the paths.
                             A `$` in the host source is escaped to `$$` for compose.

  _overmount_write_atomic    Refuses to install an empty override, leaving any existing file
                             intact and no temp sibling behind — a truncated override would
                             silently drop the :ro binds.

  verify_guardrails_readonly One batched docker exec; the probe's exit code maps to the
                             verdict, and an exec that could not run (rc >= 125) fails closed
                             as unverifiable.

  _overmount_probe_body      The in-container write-probe: writable => WRITABLE + exit 1,
                             missing => UNVERIFIABLE + exit 2, kernel-ro => PROTECTED + 0.
"""

# covers: bin/lib/overmounts.bash

import json
import os
import shlex
import shutil
from pathlib import Path

import pytest

from tests._helpers import REPO_ROOT, run_capture, write_exe

OVERMOUNTS = REPO_ROOT / "bin" / "lib" / "overmounts.bash"
BASH = shutil.which("bash") or "/bin/bash"


def _source(call: str) -> str:
    return f"set -uo pipefail\nsource {shlex.quote(str(OVERMOUNTS))}\n{call}\n"


def _run(call: str, **env: str):
    return run_capture(
        [BASH, "-c", _source(call)],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env},
    )


def _workload(tmp_path: Path, **fields: object) -> Path:
    base = {
        "image": "x",
        "entrypoint": ["bash"],
        "egress_allowlist": [],
        "ephemeral": True,
    }
    base.update(fields)
    wl = tmp_path / "workload.json"
    wl.write_text(json.dumps(base))
    return wl


# ---------------------------------------------------------------------------
# overmount_applies — the host-existence gate.
# ---------------------------------------------------------------------------


def test_applies_true_for_directory(tmp_path: Path) -> None:
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    r = _run(f"overmount_applies {shlex.quote(str(tmp_path))} .git/hooks")
    assert r.returncode == 0, r.stderr


def test_applies_true_for_regular_file(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("x")
    r = _run(f"overmount_applies {shlex.quote(str(tmp_path))} AGENTS.md")
    assert r.returncode == 0, r.stderr


def test_applies_false_for_missing(tmp_path: Path) -> None:
    r = _run(f"overmount_applies {shlex.quote(str(tmp_path))} node_modules")
    assert r.returncode == 1


def test_applies_false_for_dangling_symlink(tmp_path: Path) -> None:
    """`[[ -e ]]` follows the link, so a symlink to a missing target does NOT apply —
    binding it would be nonsensical and would materialize the missing target."""
    (tmp_path / "node_modules").symlink_to(tmp_path / "nonexistent-target")
    r = _run(f"overmount_applies {shlex.quote(str(tmp_path))} node_modules")
    assert r.returncode == 1


# ---------------------------------------------------------------------------
# write_overmount_compose — the compose-override generator.
# ---------------------------------------------------------------------------


def _write_compose(wl: Path, out: Path):
    return _run(
        f"write_overmount_compose {shlex.quote(str(wl))} {shlex.quote(str(out))}"
    )


def test_compose_default_paths_when_field_absent(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / ".git" / "hooks").mkdir(parents=True)
    (ws / "node_modules").mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws))
    out = tmp_path / "override.json"
    r = _write_compose(wl, out)
    assert r.returncode == 0, r.stderr
    vols = json.loads(out.read_text())["services"]["workload"]["volumes"]
    assert vols == [
        {
            "type": "bind",
            "source": f"{ws}/.git/hooks",
            "target": "/workspace/.git/hooks",
            "read_only": True,
        },
        {
            "type": "bind",
            "source": f"{ws}/node_modules",
            "target": "/workspace/node_modules",
            "read_only": True,
        },
    ]


def test_compose_only_emits_applicable_paths(tmp_path: Path) -> None:
    """A default path that does not exist on the host is skipped (no fabricated bind)."""
    ws = tmp_path / "ws"
    (ws / "node_modules").mkdir(parents=True)  # .git/hooks absent
    wl = _workload(tmp_path, workspace_mount=str(ws))
    out = tmp_path / "override.json"
    assert _write_compose(wl, out).returncode == 0
    vols = json.loads(out.read_text())["services"]["workload"]["volumes"]
    assert [v["target"] for v in vols] == ["/workspace/node_modules"]


def test_compose_honors_explicit_list(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "custom").mkdir(parents=True)
    (ws / "node_modules").mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=["custom"])
    out = tmp_path / "override.json"
    assert _write_compose(wl, out).returncode == 0
    vols = json.loads(out.read_text())["services"]["workload"]["volumes"]
    assert [v["target"] for v in vols] == ["/workspace/custom"]


def test_compose_explicit_empty_list_is_noop(tmp_path: Path) -> None:
    """An explicit [] means 'no overmounts' even though the default paths exist."""
    ws = tmp_path / "ws"
    (ws / ".git" / "hooks").mkdir(parents=True)
    (ws / "node_modules").mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=[])
    out = tmp_path / "override.json"
    assert _write_compose(wl, out).returncode == 0
    assert json.loads(out.read_text()) == {"services": {}}


def test_compose_nothing_applies_is_bare_noop(tmp_path: Path) -> None:
    """Nothing applicable => exactly {"services": {}} with NO volumes key — never an
    empty volumes list, which compose would merge as clearing the base mount."""
    ws = tmp_path / "ws"
    ws.mkdir()  # neither default path exists
    wl = _workload(tmp_path, workspace_mount=str(ws))
    out = tmp_path / "override.json"
    assert _write_compose(wl, out).returncode == 0
    parsed = json.loads(out.read_text())
    assert parsed == {"services": {}}
    assert "volumes" not in json.dumps(parsed)


def test_compose_seed_mode_is_noop(tmp_path: Path) -> None:
    """No workspace_mount (seed mode) => no host binds apply => the no-op override."""
    wl = _workload(tmp_path)  # no workspace_mount
    out = tmp_path / "override.json"
    assert _write_compose(wl, out).returncode == 0
    assert json.loads(out.read_text()) == {"services": {}}


def test_compose_escapes_dollar_in_source(tmp_path: Path) -> None:
    """A literal `$` in the host workspace path is escaped to `$$` so compose's
    interpolation pass leaves it verbatim."""
    ws = tmp_path / "ws$dollar"
    (ws / "node_modules").mkdir(parents=True)
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=["node_modules"])
    out = tmp_path / "override.json"
    assert _write_compose(wl, out).returncode == 0
    src = json.loads(out.read_text())["services"]["workload"]["volumes"][0]["source"]
    assert src == f"{ws}/node_modules".replace("$", "$$")
    assert "$$dollar" in src


@pytest.mark.parametrize("bad", ["/etc/passwd", "../escape", "a/../../etc"])
def test_compose_rejects_traversal_entry(tmp_path: Path, bad: str) -> None:
    """An absolute path or one containing `..` is refused loudly — it would bind a host
    path outside the workspace."""
    ws = tmp_path / "ws"
    ws.mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=[bad])
    out = tmp_path / "override.json"
    r = _write_compose(wl, out)
    assert r.returncode != 0, f"traversal entry {bad!r} must be rejected"
    assert "refusing" in r.stderr.lower()
    assert not out.exists(), "no override should be written on refusal"


# ---------------------------------------------------------------------------
# overmount_missing_declared_paths — the complement of applicability.
# ---------------------------------------------------------------------------


def _missing(wl: Path):
    return _run(f"overmount_missing_declared_paths {shlex.quote(str(wl))}")


def test_missing_reports_absent_default_paths(tmp_path: Path) -> None:
    """Field absent => the DEFAULT set is what was declared; the member not on the
    host is reported missing, the present one is not."""
    ws = tmp_path / "ws"
    (ws / "node_modules").mkdir(parents=True)  # .git/hooks absent
    wl = _workload(tmp_path, workspace_mount=str(ws))
    r = _missing(wl)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == [".git/hooks"]


def test_missing_reports_absent_explicit_paths(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "present").mkdir(parents=True)
    wl = _workload(
        tmp_path, workspace_mount=str(ws), overmount_paths=["present", "absent/dir"]
    )
    r = _missing(wl)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["absent/dir"]


def test_missing_empty_when_all_declared_paths_exist(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / ".git" / "hooks").mkdir(parents=True)
    (ws / "node_modules").mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws))
    r = _missing(wl)
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""


def test_missing_empty_for_explicit_empty_list(tmp_path: Path) -> None:
    """[] declares nothing, so nothing can be missing."""
    ws = tmp_path / "ws"
    ws.mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=[])
    r = _missing(wl)
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""


def test_missing_empty_in_seed_mode(tmp_path: Path) -> None:
    wl = _workload(tmp_path)  # no workspace_mount
    r = _missing(wl)
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""


def test_missing_fails_loud_on_traversal_entry(tmp_path: Path) -> None:
    """Shares overmount_paths_for, so a hostile entry fails here too instead of being
    silently classified as merely 'missing'."""
    ws = tmp_path / "ws"
    ws.mkdir()
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=["../escape"])
    r = _missing(wl)
    assert r.returncode != 0
    assert "refusing" in r.stderr.lower()


def test_missing_dangling_symlink_counts_as_missing(tmp_path: Path) -> None:
    """A dangling symlink does not apply (overmount_applies follows the link), so it
    must be REPORTED missing — the bind that would guard it will not exist."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "guard").symlink_to(ws / "nonexistent-target")
    wl = _workload(tmp_path, workspace_mount=str(ws), overmount_paths=["guard"])
    r = _missing(wl)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["guard"]


# ---------------------------------------------------------------------------
# _overmount_write_atomic — refuse-empty, atomic, no leftovers.
# ---------------------------------------------------------------------------


def test_atomic_refuses_empty_content(tmp_path: Path) -> None:
    out = tmp_path / "override.json"
    r = _run(f"printf '' | _overmount_write_atomic {shlex.quote(str(out))}")
    assert r.returncode != 0
    assert "empty" in r.stderr.lower()
    assert not out.exists()


def test_atomic_leaves_existing_file_intact_on_refusal(tmp_path: Path) -> None:
    out = tmp_path / "override.json"
    out.write_text('{"services":{"workload":{}}}')
    r = _run(f"printf '' | _overmount_write_atomic {shlex.quote(str(out))}")
    assert r.returncode != 0
    assert out.read_text() == '{"services":{"workload":{}}}', (
        "existing override clobbered"
    )
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "override.json"]
    assert not leftovers, f"left a temp file behind: {leftovers}"


def test_atomic_installs_nonempty_content(tmp_path: Path) -> None:
    out = tmp_path / "override.json"
    r = _run(f"printf '{{\"ok\":1}}' | _overmount_write_atomic {shlex.quote(str(out))}")
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text()) == {"ok": 1}
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "override.json"]
    assert not leftovers, f"left a temp file behind: {leftovers}"


# ---------------------------------------------------------------------------
# verify_guardrails_readonly — single batched exec, rc mapping, fail-closed.
# ---------------------------------------------------------------------------


def _run_verify(tmp_path: Path, docker_rc: int, paths: list[str]):
    bindir = tmp_path / "bin"
    # A docker stub that records ONE line per invocation (with its first arg) so the test
    # can assert a single batched exec, and exits with a controllable code.
    write_exe(
        bindir / "docker",
        f'#!/usr/bin/env bash\nprintf "INVOKED %s\\n" "$1" >> "$REC"\nexit {docker_rc}\n',
    )
    rec = tmp_path / "rec"
    rec.write_text("")
    call = "verify_guardrails_readonly cid 1000 " + " ".join(
        shlex.quote(p) for p in paths
    )
    r = run_capture(
        [BASH, "-c", _source(call)],
        env={
            "PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "REC": str(rec),
        },
    )
    return r, rec.read_text().splitlines()


@pytest.mark.parametrize(
    "docker_rc,expected",
    [(0, 0), (1, 1), (2, 2), (125, 2), (126, 2), (127, 2)],
    ids=["protected", "writable", "unverifiable", "exec-125", "exec-126", "exec-127"],
)
def test_verify_maps_probe_rc(tmp_path: Path, docker_rc: int, expected: int) -> None:
    r, invocations = _run_verify(tmp_path, docker_rc, ["/workspace/.git/hooks"])
    assert r.returncode == expected, (
        f"rc {docker_rc} -> {r.returncode}, want {expected}"
    )


def test_verify_is_a_single_batched_exec(tmp_path: Path) -> None:
    _, invocations = _run_verify(
        tmp_path, 0, ["/workspace/.git/hooks", "/workspace/node_modules"]
    )
    assert invocations == ["INVOKED exec"], f"expected one exec, got {invocations!r}"


def test_verify_no_paths_is_trivially_protected(tmp_path: Path) -> None:
    """No applicable paths => nothing to prove => return 0 without any docker exec."""
    r, invocations = _run_verify(tmp_path, 1, [])
    assert r.returncode == 0
    assert invocations == [], "no docker exec should run when there are no paths"


# ---------------------------------------------------------------------------
# _overmount_probe_body — run the in-container probe locally, no Docker.
# ---------------------------------------------------------------------------


def _probe_body() -> str:
    r = _run("_overmount_probe_body")
    assert r.returncode == 0, r.stderr
    return r.stdout


def _run_probe(paths: list[str]):
    body = _probe_body()
    return run_capture(
        ["sh", "-c", body, "sh", *paths],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )


def test_probe_writable_dir_is_breach(tmp_path: Path) -> None:
    d = tmp_path / "writable"
    d.mkdir()
    r = _run_probe([str(d)])
    assert r.returncode == 1, "a writable path must exit 1 (WRITABLE outranks all)"
    assert f"{d}\tWRITABLE" in r.stdout
    assert not list(d.glob(".as-write-probe.*")), "probe left its marker behind"


def test_probe_missing_path_is_unverifiable(tmp_path: Path) -> None:
    p = tmp_path / "nope"
    r = _run_probe([str(p)])
    assert r.returncode == 2
    assert f"{p}\tUNVERIFIABLE" in r.stdout


def test_probe_writable_outranks_unverifiable(tmp_path: Path) -> None:
    """Given a writable path AND a missing one, the breach (exit 1) wins over
    unverifiable (exit 2)."""
    d = tmp_path / "writable"
    d.mkdir()
    missing = tmp_path / "nope"
    r = _run_probe([str(d), str(missing)])
    assert r.returncode == 1


@pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores mode bits, so a 0555 dir is still writable"
)
def test_probe_readonly_dir_is_protected(tmp_path: Path) -> None:
    d = tmp_path / "ro"
    d.mkdir()
    d.chmod(0o555)
    r = _run_probe([str(d)])
    assert r.returncode == 0, "a non-writable dir must be PROTECTED (exit 0)"
    assert f"{d}\tPROTECTED" in r.stdout

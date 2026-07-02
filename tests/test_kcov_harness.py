"""Unit tests for the kcov harness logic (interceptor + gate helpers).

These decide whether the bash-coverage CI gate passes, so they are tested in process
rather than only exercised end-to-end by run-kcov.sh.
"""

import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tests import _kcov, kcov_gate
from tests._helpers import REPO_ROOT

ENV = "AGENT_SANDBOX_KCOV_OUT"


# ---------------------------------------------------------------------------
# wrap_argv — the interceptor's argv rewrite.
# ---------------------------------------------------------------------------


def test_wrap_argv_wraps_enrolled_script(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    enrolled = str(REPO_ROOT / _kcov.KCOV_GATED[0])
    wrapped = _kcov.wrap_argv([enrolled, "--flag"])
    basenames = [os.path.basename(a) for a in wrapped]
    assert basenames[0] == "timeout"
    assert "kcov" in basenames
    assert "--bash-method=DEBUG" in wrapped
    assert "--bash-tracefd-cloexec" in wrapped
    assert wrapped[-2:] == [enrolled, "--flag"]
    assert any(a.startswith("--exclude-region=") for a in wrapped)
    assert any(a.startswith("--exclude-line=") for a in wrapped)


def test_wrap_argv_passes_through_non_enrolled(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    argv = ["/usr/bin/git", "status"]
    assert _kcov.wrap_argv(argv) is argv


@pytest.mark.parametrize("argv", ["a string", [], None])
def test_wrap_argv_ignores_non_list_argv(monkeypatch, tmp_path, argv) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    assert _kcov.wrap_argv(argv) is argv


def test_wrap_argv_accepts_tuple(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    enrolled = str(REPO_ROOT / _kcov.KCOV_GATED[0])
    wrapped = _kcov.wrap_argv((enrolled,))
    assert "kcov" in [os.path.basename(a) for a in wrapped]
    assert wrapped[-1] == enrolled


def test_wrap_argv_bare_basename_not_wrapped(monkeypatch, tmp_path) -> None:
    """argv[0] with no path separator is never resolved, so a bare 'agent-sandbox' is
    not wrapped — we can't confirm it refers to the enrolled file."""
    monkeypatch.setenv(ENV, str(tmp_path))
    argv = [Path(_kcov.KCOV_GATED[0]).name, "--arg"]
    assert _kcov.wrap_argv(argv) is argv


def test_wrap_argv_symlink_to_enrolled_is_wrapped(monkeypatch, tmp_path) -> None:
    """A symlink whose resolution lands on the enrolled script is wrapped: resolve()
    follows symlinks before the entry-point lookup."""
    monkeypatch.setenv(ENV, str(tmp_path))
    link = tmp_path / "link-to-launcher"
    link.symlink_to((REPO_ROOT / _kcov.KCOV_GATED[0]).resolve())
    assert "kcov" in [os.path.basename(a) for a in _kcov.wrap_argv([str(link)])]


def test_wrap_argv_produces_unique_rundirs(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    enrolled = str(REPO_ROOT / _kcov.KCOV_GATED[0])
    prefix = str(tmp_path / "runs" / "")
    rundirs = [
        next(a for a in _kcov.wrap_argv([enrolled]) if a.startswith(prefix))
        for _ in range(5)
    ]
    assert len(set(rundirs)) == 5, "each wrap must produce a distinct rundir"


def test_wrap_argv_include_pattern_is_resolved_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    enrolled = str((REPO_ROOT / _kcov.KCOV_GATED[0]).resolve())
    wrapped = _kcov.wrap_argv([enrolled])
    assert [a for a in wrapped if a.startswith("--include-pattern=")] == [
        f"--include-pattern={enrolled}"
    ]


# ---------------------------------------------------------------------------
# install — the subprocess.run/Popen patch.
# ---------------------------------------------------------------------------


def test_install_is_noop_without_env(monkeypatch) -> None:
    monkeypatch.delenv(ENV, raising=False)
    before = subprocess.run
    _kcov.install()
    assert subprocess.run is before


def test_install_patches_subprocess_run_and_popen(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    monkeypatch.setattr(subprocess, "run", subprocess.run)
    monkeypatch.setattr(subprocess, "Popen", subprocess.Popen)
    orig_run, orig_popen = subprocess.run, subprocess.Popen
    _kcov.install()
    assert subprocess.run is not orig_run
    assert subprocess.Popen is not orig_popen


def test_install_creates_runs_subdir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(ENV, str(tmp_path))
    monkeypatch.setattr(subprocess, "run", subprocess.run)
    monkeypatch.setattr(subprocess, "Popen", subprocess.Popen)
    assert not (tmp_path / "runs").exists()
    _kcov.install()
    assert (tmp_path / "runs").is_dir()


def test_install_routes_entrypoint_invocation_through_kcov(
    monkeypatch, tmp_path
) -> None:
    """The wiring, not just the swap: after install(), calling the patched
    subprocess.run with an entry-point argv reaches the real runner with kcov prepended."""
    monkeypatch.setenv(ENV, str(tmp_path))
    received: dict[str, object] = {}
    monkeypatch.setattr(
        subprocess, "run", lambda argv, *a, **k: received.setdefault("argv", argv)
    )
    monkeypatch.setattr(subprocess, "Popen", subprocess.Popen)
    _kcov.install()
    entrypoint = str((REPO_ROOT / _kcov.KCOV_ENROLLED[0]).resolve())
    subprocess.run([entrypoint, "--x"])
    assert os.path.basename(received["argv"][0]) == "timeout"
    assert "kcov" in [os.path.basename(a) for a in received["argv"]]
    assert received["argv"][-2:] == [entrypoint, "--x"]


# ---------------------------------------------------------------------------
# kcov_gate helpers.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "nums,expected",
    [
        ([5], "5"),
        ([1, 2, 3], "1-3"),
        ([1, 3, 4, 5, 9], "1, 3-5, 9"),
        ([2, 4, 6], "2, 4, 6"),
    ],
)
def test_ranges(nums, expected) -> None:
    assert kcov_gate._ranges(nums) == expected


def test_relpath_normalizes_absolute_and_relative() -> None:
    rel = _kcov.KCOV_GATED[0]
    assert kcov_gate._relpath(str(REPO_ROOT / rel)) == rel
    assert kcov_gate._relpath(rel) == rel


def _cobertura(tmp_path: Path, entries: list[tuple[str, dict[int, int]]]) -> Path:
    """Build a minimal cobertura XML with the given (filename, {line: hits}) entries."""
    root = ET.Element("coverage")
    classes_el = ET.SubElement(
        ET.SubElement(ET.SubElement(root, "packages"), "package"), "classes"
    )
    for filename, lines in entries:
        cls = ET.SubElement(classes_el, "class")
        cls.set("filename", filename)
        lines_el = ET.SubElement(cls, "lines")
        for num, hits in sorted(lines.items()):
            ln = ET.SubElement(lines_el, "line")
            ln.set("number", str(num))
            ln.set("hits", str(hits))
    p = tmp_path / "cobertura.xml"
    ET.ElementTree(root).write(str(p))
    return p


@pytest.mark.parametrize("rel", _kcov.KCOV_GATED)
def test_uncovered_all_covered_is_empty(rel, tmp_path) -> None:
    xml = _cobertura(tmp_path, [(rel, {1: 3, 2: 1, 5: 7})])
    assert kcov_gate._uncovered_by_file(xml)[rel] == []


@pytest.mark.parametrize("rel", _kcov.KCOV_GATED)
def test_uncovered_returns_sorted_uncovered_lines(rel, tmp_path) -> None:
    xml = _cobertura(tmp_path, [(rel, {1: 1, 2: 0, 3: 0, 4: 1, 7: 0})])
    assert kcov_gate._uncovered_by_file(xml)[rel] == [2, 3, 7]


@pytest.mark.parametrize("rel", _kcov.KCOV_GATED)
def test_uncovered_absent_is_sentinel(rel, tmp_path) -> None:
    xml = _cobertura(tmp_path, [("some/other/script.sh", {1: 1})])
    assert kcov_gate._uncovered_by_file(xml)[rel] == [-1]


def test_uncovered_duplicate_entries_union_max(tmp_path) -> None:
    """Two <class> elements for one file: covered-in-any wins."""
    rel = _kcov.KCOV_GATED[0]
    root = ET.Element("coverage")
    classes_el = ET.SubElement(
        ET.SubElement(ET.SubElement(root, "packages"), "package"), "classes"
    )
    for hit_count in (0, 1):
        cls = ET.SubElement(classes_el, "class")
        cls.set("filename", rel)
        ln = ET.SubElement(ET.SubElement(cls, "lines"), "line")
        ln.set("number", "10")
        ln.set("hits", str(hit_count))
    p = tmp_path / "cobertura.xml"
    ET.ElementTree(root).write(str(p))
    assert kcov_gate._uncovered_by_file(p)[rel] == []


def test_uncovered_source_dir_plus_basename(tmp_path) -> None:
    """The real kcov format: a <source> dir plus a bare-basename `filename`. The
    enrolled relpath is `<source>/<filename>` made repo-relative — matching the basename
    alone would miss every script."""
    rel = _kcov.KCOV_GATED[0]
    root = ET.Element("coverage")
    ET.SubElement(ET.SubElement(root, "sources"), "source").text = (
        str((REPO_ROOT / rel).parent) + "/"
    )
    classes_el = ET.SubElement(
        ET.SubElement(ET.SubElement(root, "packages"), "package"), "classes"
    )
    cls = ET.SubElement(classes_el, "class")
    cls.set("filename", Path(rel).name)
    lines_el = ET.SubElement(cls, "lines")
    for num, hits in ((1, 1), (2, 0)):
        ln = ET.SubElement(lines_el, "line")
        ln.set("number", str(num))
        ln.set("hits", str(hits))
    p = tmp_path / "cobertura.xml"
    ET.ElementTree(root).write(str(p))
    assert kcov_gate._uncovered_by_file(p)[rel] == [2]


def test_gate_main_all_covered_returns_0(tmp_path, capsys) -> None:
    xml = _cobertura(tmp_path, [(rel, {1: 1, 2: 1}) for rel in _kcov.KCOV_GATED])
    assert kcov_gate.main(["kcov_gate.py", str(xml)]) == 0
    assert "100%" in capsys.readouterr().out


def test_gate_main_not_traced_returns_1(tmp_path, capsys) -> None:
    xml = _cobertura(tmp_path, [("unrelated/script.sh", {1: 1})])
    assert kcov_gate.main(["kcov_gate.py", str(xml)]) == 1
    assert "NOT TRACED" in capsys.readouterr().out


def test_gate_main_uncovered_lines_returns_1(tmp_path, capsys) -> None:
    rel = _kcov.KCOV_GATED[0]
    xml = _cobertura(tmp_path, [(rel, {1: 1, 5: 0, 6: 0, 9: 0})])
    assert kcov_gate.main(["kcov_gate.py", str(xml)]) == 1
    assert "5-6, 9" in capsys.readouterr().out  # _ranges([5, 6, 9])


def test_exclusion_markers_are_well_formed() -> None:
    """No enrolled script carries a kcov-ignore marker today; if one is added, each
    returned item must be 'rel:line: <text>' naming a gated file with 'kcov-ignore'."""
    for m in kcov_gate._exclusion_markers():
        rel, rest = m.split(":", 1)
        assert rel in _kcov.KCOV_GATED
        lineno, text = rest.split(":", 1)
        assert lineno.strip().isdigit()
        assert "kcov-ignore" in text


# ---------------------------------------------------------------------------
# Enrollment bookkeeping — opt-out completeness and SSOT drift.
# ---------------------------------------------------------------------------


def test_shard_count_is_a_positive_int() -> None:
    assert isinstance(_kcov.KCOV_SHARD_COUNT, int) and _kcov.KCOV_SHARD_COUNT >= 1


def test_gated_is_enrolled_plus_vehicle_libs() -> None:
    assert (
        _kcov.KCOV_ENROLLED + list(_kcov.KCOV_GATED_VIA_VEHICLE.values())
    ) == _kcov.KCOV_GATED


def test_all_bash_scripts_are_accounted_for() -> None:
    """Opt-out enforcement: every bash script discovered under bin/ must be enrolled,
    excluded, or vehicle-gated. A script that slips through is auto-enrolled but has no
    tests — add it to KCOV_EXCLUDED with a reason, or write tests to keep it enrolled."""
    accounted = (
        set(_kcov.KCOV_ENROLLED)
        | set(_kcov.KCOV_EXCLUDED)
        | set(_kcov.KCOV_GATED_VIA_VEHICLE.values())
    )
    unaccounted = set(_kcov._discover_bash_files()) - accounted
    assert not unaccounted, (
        "bash scripts in bin/ neither enrolled, excluded, nor vehicle-gated "
        f"(add to KCOV_EXCLUDED with a reason): {sorted(unaccounted)}"
    )


def test_kcov_excluded_files_exist_and_are_discovered() -> None:
    discovered = set(_kcov._discover_bash_files())
    missing = [f for f in _kcov.KCOV_EXCLUDED if not (REPO_ROOT / f).is_file()]
    not_discovered = [f for f in _kcov.KCOV_EXCLUDED if f not in discovered]
    assert not missing, f"KCOV_EXCLUDED names nonexistent files: {missing}"
    assert not not_discovered, (
        f"KCOV_EXCLUDED entries not discovered as bash: {not_discovered}"
    )


def test_kcov_excluded_and_enrolled_are_disjoint() -> None:
    overlap = set(_kcov.KCOV_EXCLUDED) & set(_kcov.KCOV_ENROLLED)
    assert not overlap, f"files in both KCOV_EXCLUDED and KCOV_ENROLLED: {overlap}"


def test_discovery_skips_symlinks(tmp_path) -> None:
    """A transient symlink beside a real wrapper (a test artifact) is never discovered
    as a source file — committed bin/ has no symlinks, so this loses no real coverage."""
    link = REPO_ROOT / "bin" / "agent-sandbox-kcov-symlink-probe"
    link.symlink_to("agent-sandbox")
    try:
        assert str(link.relative_to(REPO_ROOT)) not in _kcov._discover_bash_files()
    finally:
        link.unlink()


def test_executable_bin_lib_bash_is_kcov_enrolled() -> None:
    """bin/lib/ holds sourced libraries (no exec bit). The exec bit is the only thing
    that would distinguish a runnable entry point, so an executable bash file in bin/lib/
    is a promise of a runnable entry point and must carry a coverage gate. A sourced-only
    lib must stay non-executable; a runnable one must be enrolled — no third option."""
    enrolled = set(_kcov.KCOV_ENROLLED)
    offenders = [
        str(p.relative_to(REPO_ROOT))
        for p in sorted((REPO_ROOT / "bin" / "lib").glob("*.bash"))
        if os.access(p, os.X_OK) and str(p.relative_to(REPO_ROOT)) not in enrolled
    ]
    assert not offenders, (
        f"executable bin/lib bash scripts missing from KCOV_ENROLLED: {offenders}. "
        "Drop the exec bit (sourced-only lib) or enroll it (tests/_kcov.py)."
    )


# ---------------------------------------------------------------------------
# KCOV_TEST_FILES — the CI shard slice, guarded against drift.
# ---------------------------------------------------------------------------


def test_kcov_test_files_exist_and_are_unique() -> None:
    missing = [f for f in _kcov.KCOV_TEST_FILES if not (REPO_ROOT / f).is_file()]
    assert not missing, f"KCOV_TEST_FILES names nonexistent files: {missing}"
    assert len(_kcov.KCOV_TEST_FILES) == len(set(_kcov.KCOV_TEST_FILES))


def test_discover_argv0_feeders_finds_the_launcher_suite() -> None:
    """Non-vacuity: test_launcher.py runs bin/agent-sandbox as argv[0], so the detector
    must find it."""
    assert "tests/test_launcher.py" in _kcov.discover_argv0_feeders()


def test_no_kcov_drift_every_argv0_feeder_is_listed() -> None:
    """Any test that invokes an enrolled wrapper as argv[0] must be in KCOV_TEST_FILES,
    or the CI shard never traces it and the gate reports the lines only it covers as
    uncovered."""
    unlisted = _kcov.discover_argv0_feeders() - set(_kcov.KCOV_TEST_FILES)
    assert not unlisted, (
        "these tests invoke an enrolled wrapper as argv[0] but are missing from "
        f"KCOV_TEST_FILES (add them so the kcov gate traces them): {sorted(unlisted)}"
    )


def test_enrolled_wrapper_has_a_listed_test_file() -> None:
    """Each enrolled wrapper must be referenced by at least one KCOV_TEST_FILES entry,
    else it is traced by nothing and the gate only flags it NOT TRACED after a full run.
    Fail fast in the unit suite instead."""
    import re

    for rel in _kcov.KCOV_ENROLLED:
        name = Path(rel).name
        token = re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])")
        referencing = [
            f
            for f in _kcov.KCOV_TEST_FILES
            if token.search((REPO_ROOT / f).read_text(encoding="utf-8"))
        ]
        assert referencing, f"{rel}: no KCOV_TEST_FILES entry references {name!r}"

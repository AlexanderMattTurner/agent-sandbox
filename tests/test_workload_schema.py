"""Contract tests for the Workload schema and the shipped workload records.

The schema is the SSOT for what a Workload is; every record under workloads/ must
validate against it, and the required-field / enum boundaries are pinned so a silent
loosening of the contract fails here.
"""

import json
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
SCHEMA = json.loads((REPO / "schema" / "workload.schema.json").read_text())
WORKLOADS = sorted((REPO / "workloads").glob("*.json"))
OVERMOUNTS_LIB = REPO / "bin" / "lib" / "overmounts.bash"
BASH = shutil.which("bash") or "/bin/bash"


def test_schema_is_well_formed():
    jsonschema.Draft7Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("path", WORKLOADS, ids=lambda p: p.name)
def test_shipped_workload_validates(path):
    jsonschema.validate(json.loads(path.read_text()), SCHEMA)


def test_required_fields_are_enforced():
    assert set(SCHEMA["required"]) == {
        "image",
        "entrypoint",
        "egress_allowlist",
        "ephemeral",
    }


def test_backend_enum_is_local_or_hosted():
    assert SCHEMA["properties"]["backend"]["enum"] == ["local", "hosted"]


def test_missing_required_field_is_rejected():
    bad = {
        "entrypoint": ["bash"],
        "egress_allowlist": [],
        "ephemeral": True,
    }  # no image
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, SCHEMA)


def test_unknown_field_is_rejected():
    bad = {
        "image": "x",
        "entrypoint": ["bash"],
        "egress_allowlist": [],
        "ephemeral": True,
        "not_a_field": 1,
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, SCHEMA)


def test_seed_from_git_requires_review_branch():
    bad = {
        "image": "x",
        "entrypoint": ["bash"],
        "egress_allowlist": [],
        "ephemeral": True,
        "seed_from_git": {"ref": "HEAD"},  # missing review_branch
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, SCHEMA)


def _with_allowlist(entries):
    return {
        "image": "x",
        "entrypoint": ["bash"],
        "egress_allowlist": entries,
        "ephemeral": True,
    }


@pytest.mark.parametrize(
    "entries",
    [
        ["pypi.org"],
        [{"host": "pypi.org"}],
        [{"host": "pypi.org", "access": "ro"}],
        [{"host": "pypi.org", "access": "rw"}],
        ["a.example", {"host": "b.example", "access": "ro"}],
        [],
    ],
    ids=["bare-string", "object-default", "object-ro", "object-rw", "mixed", "empty"],
)
def test_allowlist_accepts_string_and_tiered_object_entries(entries):
    jsonschema.validate(_with_allowlist(entries), SCHEMA)


@pytest.mark.parametrize("field", ["hardener", "audit"])
def test_default_service_optouts_default_true(field):
    assert SCHEMA["properties"][field]["type"] == "boolean"
    assert SCHEMA["properties"][field]["default"] is True


@pytest.mark.parametrize("field", ["hardener", "audit"])
@pytest.mark.parametrize("value", [True, False])
def test_default_service_optouts_accept_booleans(field, value):
    jsonschema.validate({**_with_allowlist([]), field: value}, SCHEMA)


@pytest.mark.parametrize("field", ["hardener", "audit"])
@pytest.mark.parametrize("value", ["false", 0, None], ids=["string", "int", "null"])
def test_default_service_optouts_reject_non_booleans(field, value):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**_with_allowlist([]), field: value}, SCHEMA)


def _overmount_paths_schema() -> dict:
    return SCHEMA["properties"]["overmount_paths"]


def test_overmount_paths_default_is_pinned():
    assert _overmount_paths_schema()["default"] == [".git/hooks", "node_modules"]


def test_overmount_paths_default_matches_bash_ssot(tmp_path):
    """The schema default and bin/lib/overmounts.bash must not drift: a Workload with no
    overmount_paths gets exactly the schema's declared default. Invoke the function rather
    than re-reading a constant, so the actual runtime behavior is what's pinned."""
    wl = tmp_path / "wl.json"
    wl.write_text(json.dumps(_with_allowlist([])))  # no overmount_paths field
    harness = f"source {OVERMOUNTS_LIB}\novermount_paths_for {wl}\n"
    out = subprocess.run(
        [BASH, "-c", harness], capture_output=True, text=True, check=True
    ).stdout
    assert out.split() == _overmount_paths_schema()["default"]


@pytest.mark.parametrize(
    "paths",
    [[".git/hooks", "node_modules"], ["custom/dir"], []],
    ids=["default-like", "single", "empty"],
)
def test_overmount_paths_accepts_string_lists(paths):
    jsonschema.validate({**_with_allowlist([]), "overmount_paths": paths}, SCHEMA)


@pytest.mark.parametrize(
    "paths",
    [[123], [""], "node_modules"],
    ids=["non-string-entry", "empty-string-entry", "not-an-array"],
)
def test_overmount_paths_rejects_malformed(paths):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**_with_allowlist([]), "overmount_paths": paths}, SCHEMA)


@pytest.mark.parametrize(
    "entries",
    [
        [{"host": "pypi.org", "access": "write"}],  # not a valid tier
        [{"access": "ro"}],  # object form requires host
        [{"host": "pypi.org", "port": 443}],  # no undeclared keys
        [123],  # neither string nor object
    ],
    ids=["bad-tier", "missing-host", "extra-key", "non-string"],
)
def test_allowlist_rejects_malformed_entries(entries):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_with_allowlist(entries), SCHEMA)

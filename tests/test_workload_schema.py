"""Contract tests for the Workload schema and the shipped workload records.

The schema is the SSOT for what a Workload is; every record under workloads/ must
validate against it, and the required-field / enum boundaries are pinned so a silent
loosening of the contract fails here.
"""

import json
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve()
while not (REPO / ".git").exists():
    REPO = REPO.parent
SCHEMA = json.loads((REPO / "schema" / "workload.schema.json").read_text())
WORKLOADS = sorted((REPO / "workloads").glob("*.json"))


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

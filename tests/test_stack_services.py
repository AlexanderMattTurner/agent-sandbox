"""Render contracts for the compose stack's default library services.

`docker compose config` (no daemon needed) is the ground truth: the default
state (COMPOSE_PROFILES=hardener,audit — what stack_run exports for a workload
with no opt-outs) must render all four services with the fail-closed gates, and
the opted-out state must render only firewall+workload without breaking the
workload's optional depends_on. Also asserts every file compose OPENS at `up`
(seccomp profiles) resolves relative to the compose file — `config` renders
paths without opening them, so existence must be checked here.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)
COMPOSE = REPO / "sandbox" / "docker-compose.yml"
SCHEMA = json.loads((REPO / "schema" / "workload.schema.json").read_text())

# stack_run activates one profile per schema opt-out field; the two sets must
# not drift (a new default service means a schema field AND a profile).
DEFAULT_SERVICE_FIELDS = ("hardener", "audit")


def render(profiles: str) -> dict:
    env = {**os.environ, "WORKLOAD_IMAGE": "busybox", "COMPOSE_PROFILES": profiles}
    out = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "config", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        cwd=COMPOSE.parent,
    ).stdout
    return json.loads(out)


@pytest.fixture(scope="module")
def default_state() -> dict:
    return render("hardener,audit")


@pytest.fixture(scope="module")
def opted_out_state() -> dict:
    return render("")


def test_schema_optout_fields_exist_default_true():
    for field in DEFAULT_SERVICE_FIELDS:
        assert SCHEMA["properties"][field]["type"] == "boolean"
        assert SCHEMA["properties"][field]["default"] is True


def test_default_state_renders_all_four_services(default_state):
    assert sorted(default_state["services"]) == [
        "audit",
        "firewall",
        "hardener",
        "workload",
    ]


def test_opted_out_state_renders_only_firewall_and_workload(opted_out_state):
    assert sorted(opted_out_state["services"]) == ["firewall", "workload"]


def test_workload_depends_on_gates(default_state):
    deps = default_state["services"]["workload"]["depends_on"]
    assert deps["firewall"] == {"condition": "service_healthy", "required": True}
    # required:false is what lets a profile opt-out drop the service without
    # breaking `up`; the condition is the fail-closed gate when it is present.
    assert deps["hardener"] == {
        "condition": "service_completed_successfully",
        "required": False,
    }
    assert deps["audit"] == {"condition": "service_healthy", "required": False}


def test_opted_out_up_would_not_break_on_missing_deps(opted_out_state):
    deps = opted_out_state["services"]["workload"]["depends_on"]
    for svc in DEFAULT_SERVICE_FIELDS:
        assert deps[svc]["required"] is False


def test_service_profiles_match_schema_fields(default_state):
    for field in DEFAULT_SERVICE_FIELDS:
        assert default_state["services"][field]["profiles"] == [field]


def _volumes(cfg: dict, service: str) -> list:
    return cfg["services"][service].get("volumes", [])


def test_hardened_config_volume_writable_only_in_hardener(default_state):
    hardener = {
        v["target"]: v
        for v in _volumes(default_state, "hardener")
        if v["type"] == "volume"
    }
    workload = {
        v["target"]: v
        for v in _volumes(default_state, "workload")
        if v["type"] == "volume"
    }
    assert hardener["/run/hardened-config"]["source"] == "hardened-config"
    assert not hardener["/run/hardened-config"].get("read_only", False)
    assert workload["/run/hardened-config"]["source"] == "hardened-config"
    assert workload["/run/hardened-config"]["read_only"] is True


def test_hooks_mount_is_read_only_dev_null_by_default(default_state):
    binds = {
        v["target"]: v
        for v in _volumes(default_state, "hardener")
        if v["type"] == "bind"
    }
    hooks = binds["/run/hardener-hooks.d"]
    assert hooks["source"] == "/dev/null"
    assert hooks["read_only"] is True


def test_workload_never_mounts_audit_volumes(default_state):
    workload_sources = {
        v.get("source")
        for v in _volumes(default_state, "workload")
        if v["type"] == "volume"
    }
    audit_sources = {
        v["source"] for v in _volumes(default_state, "audit") if v["type"] == "volume"
    }
    assert audit_sources == {"audit-log", "audit-secret"}
    assert not (workload_sources & audit_sources)


def test_audit_static_ip_and_healthcheck(default_state):
    audit = default_state["services"]["audit"]
    assert audit["networks"]["sandbox"]["ipv4_address"] == "172.30.0.4"
    probe = audit["healthcheck"]["test"]
    assert probe[0] == "CMD-SHELL"
    assert "test -f /run/audit-secret/secret" in probe[1]


def test_topology_invariants_hold(default_state):
    # sandbox stays internal; the firewall stays the ONLY dual-homed service.
    assert default_state["networks"]["sandbox"]["internal"] is True
    for name, svc in default_state["services"].items():
        nets = set(svc.get("networks", {}) or {})
        if name == "firewall":
            assert nets == {"sandbox", "egress"}
        else:
            assert "egress" not in nets
    # The hardener has no netns at all — it can't race a static IP claim.
    assert default_state["services"]["hardener"]["network_mode"] == "none"


def test_new_services_are_hardened(default_state):
    for name in DEFAULT_SERVICE_FIELDS:
        svc = default_state["services"][name]
        assert svc["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in svc["security_opt"]
        assert any(s.startswith("seccomp:") for s in svc["security_opt"])
        assert svc["pids_limit"] == 64
    assert default_state["services"]["hardener"]["cap_add"] == [
        "CHOWN",
        "DAC_OVERRIDE",
    ]
    assert "cap_add" not in default_state["services"]["audit"]
    assert default_state["services"]["audit"]["read_only"] is True


def test_every_file_compose_opens_resolves(default_state):
    """The relocated-compose class: `config` renders seccomp/env_file paths
    without opening them, so `up` is the first thing that would notice a broken
    relative path. Assert every such path exists relative to the compose dir."""
    opened = []
    for svc in default_state["services"].values():
        for opt in svc.get("security_opt", []):
            if opt.startswith("seccomp:") and opt != "seccomp:unconfined":
                opened.append(opt.split(":", 1)[1])
        for ef in svc.get("env_file", []):
            opened.append(ef["path"] if isinstance(ef, dict) else ef)
    assert opened, "no compose-opened files found — the invariant check went vacuous"
    for path in opened:
        resolved = Path(path)
        if not resolved.is_absolute():
            resolved = COMPOSE.parent / resolved
        assert resolved.is_file(), f"compose would fail to open {path} at `up`"


def test_dockerfile_bakes_the_new_entrypoints():
    dockerfile = (REPO / "sandbox" / "Dockerfile").read_text()
    assert "hardener-entrypoint.bash" in dockerfile
    assert "audit_sink.py" in dockerfile

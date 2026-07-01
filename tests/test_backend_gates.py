"""Fail-closed runtime-gate tests for bin/lib/backend.bash.

The backend's job is to refuse an unusable runtime BEFORE anything is launched, so a
broken backend fails loudly instead of hanging on a healthcheck that can never pass.
These drive the three gates (registration / provider / execution) with a fake `docker`
on PATH — no Docker daemon required — asserting each gate fails closed and the happy
path prints the verified runtime.
"""

import os
import subprocess
from pathlib import Path

REPO = Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)
BACKEND = REPO / "bin" / "lib" / "backend.bash"

FAKE_DOCKER = r"""#!/usr/bin/env bash
# Fake `docker` driven by FAKE_* env vars; enough of the surface for the gate probes.
case "$1" in
info)
  if [[ "$*" == *OperatingSystem* ]]; then printf '%s\n' "${FAKE_OS:-Ubuntu}"; exit 0; fi
  if [[ "$*" == *Runtimes* ]]; then for r in ${FAKE_RUNTIMES:-runc}; do printf '%s\n' "$r"; done; exit 0; fi
  exit 0 ;;
image) exit "${FAKE_IMAGE_PRESENT_RC:-0}" ;;
pull)  exit "${FAKE_PULL_RC:-0}" ;;
run)   exit "${FAKE_RUN_RC:-0}" ;;
ps)    exit 0 ;;
*)     exit 0 ;;
esac
"""

FAKE_SLEEP = "#!/usr/bin/env bash\nexit 0\n"  # no-op so registration polling is instant


def run_backend(tmp_path, backend, *, runtime="runsc", env=None):
    """Source backend.bash with a fake docker/sleep on PATH and select the runtime."""
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    (stub / "docker").write_text(FAKE_DOCKER)
    (stub / "docker").chmod(0o755)
    (stub / "sleep").write_text(FAKE_SLEEP)
    (stub / "sleep").chmod(0o755)
    full_env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "CONTAINER_RUNTIME": runtime,  # explicit choice -> deterministic ladder, no KVM/kata probe
        "NO_COLOR": "1",
        **(env or {}),
    }
    harness = (
        f'set -euo pipefail; source "{BACKEND}"; backend_select_runtime "{backend}"'
    )
    return subprocess.run(
        ["bash", "-c", harness], capture_output=True, text=True, env=full_env
    )


def test_runc_needs_no_gate(tmp_path):
    # runc is Docker's built-in default; it is returned with no registration/exec probe.
    r = run_backend(tmp_path, "local", runtime="runc")
    assert r.returncode == 0
    assert r.stdout.strip() == "runc"


def test_happy_path_prints_verified_runtime(tmp_path):
    r = run_backend(
        tmp_path,
        "local",
        runtime="runsc",
        env={"FAKE_RUNTIMES": "runc runsc", "FAKE_OS": "Ubuntu"},
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "runsc"


def test_unregistered_runtime_fails_closed(tmp_path):
    # runsc requested but NOT listed by `docker info` -> registration gate refuses.
    r = run_backend(tmp_path, "local", runtime="runsc", env={"FAKE_RUNTIMES": "runc"})
    assert r.returncode != 0
    assert "not registered" in r.stderr
    assert r.stdout.strip() == ""


def test_docker_desktop_refuses_hardened_runtime(tmp_path):
    # Registered, but the provider is Docker Desktop -> provider gate refuses.
    r = run_backend(
        tmp_path,
        "local",
        runtime="runsc",
        env={"FAKE_RUNTIMES": "runc runsc", "FAKE_OS": "Docker Desktop"},
    )
    assert r.returncode != 0
    assert "hang" in r.stderr


def test_registered_but_unbootable_fails_closed(tmp_path):
    # Listed + provider OK, but a throwaway container won't start -> execution gate refuses.
    r = run_backend(
        tmp_path,
        "local",
        runtime="runsc",
        env={"FAKE_RUNTIMES": "runc runsc", "FAKE_OS": "Ubuntu", "FAKE_RUN_RC": "1"},
    )
    assert r.returncode != 0
    assert "won't execute" in r.stderr


def test_hosted_backend_is_documented_stub(tmp_path):
    r = run_backend(tmp_path, "hosted", runtime="runc")
    assert r.returncode != 0
    assert "not implemented" in r.stderr


def test_unknown_backend_fails_closed(tmp_path):
    r = run_backend(tmp_path, "nonsense", runtime="runc")
    assert r.returncode != 0
    assert "unknown backend" in r.stderr

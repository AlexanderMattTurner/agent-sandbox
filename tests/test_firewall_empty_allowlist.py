"""The deny-all default must BOOT — an empty egress allowlist is the true default
(a workload reaches only what it declares), so the firewall init has to survive a
DOMAIN_ACCESS map with zero entries.

bash treats an associative array declared with `declare -A` that never received an
element as UNSET, so `${#DOMAIN_ACCESS[@]}` trips `set -u` with "DOMAIN_ACCESS: unbound
variable" and kills the firewall on exactly the empty-allowlist path. This drives the
REAL populate+emptiness-check block extracted from init-firewall.bash (so a revert to the
crashing form is caught here, not just in the Docker acceptance job) through both the
empty and the populated case.
"""

# covers: sandbox/init-firewall.bash

import shutil

from tests._helpers import REPO_ROOT, run_capture

INIT_FW = REPO_ROOT / "sandbox" / "init-firewall.bash"
IP_VALIDATION = REPO_ROOT / "sandbox" / "ip-validation.bash"
BASH = shutil.which("bash") or "/bin/bash"


def _domain_access_block() -> str:
    """Extract the real `declare -A DOMAIN_ACCESS` … `fi` block from init-firewall.bash,
    so the test exercises the shipped source rather than a copy that could drift."""
    lines = INIT_FW.read_text().splitlines()
    start = next(
        i for i, ln in enumerate(lines) if ln.startswith("declare -A DOMAIN_ACCESS")
    )
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "fi")
    return "\n".join(lines[start : end + 1])


def _run_block(ro: str, rw: str):
    harness = (
        "set -euo pipefail\n"
        f'source "{IP_VALIDATION}"\n'
        f'export WORKLOAD_ALLOWED_DOMAINS_RO="{ro}"\n'
        f'export WORKLOAD_ALLOWED_DOMAINS_RW="{rw}"\n'
        + _domain_access_block()
        + "\n"
        # Prove the map is usable afterwards (the loops downstream read it); count via a
        # nounset-safe copy so THIS assertion can't reintroduce the very bug under test.
        + 'keys=("${!DOMAIN_ACCESS[@]}"); echo "COUNT=${#keys[@]}"\n'
    )
    return run_capture([BASH, "-c", harness])


def test_empty_allowlist_boots_deny_all():
    """The class bug: an empty allowlist must not crash the init under `set -u`."""
    r = _run_block("", "")
    assert r.returncode == 0, f"deny-all boot crashed: {r.stderr!r}"
    assert "DOMAIN_ACCESS: unbound variable" not in r.stderr
    assert "empty egress allowlist" in r.stdout, "deny-all notice not emitted"
    assert "COUNT=0" in r.stdout


def test_populated_allowlist_does_not_warn_empty():
    """A non-empty allowlist populates the map and skips the deny-all notice — the guard
    discriminates, it isn't wired to always/never fire."""
    r = _run_block("ro.example", "rw.example\nother.example")
    assert r.returncode == 0, r.stderr
    assert "empty egress allowlist" not in r.stdout
    assert "COUNT=3" in r.stdout


def test_block_uses_nounset_safe_form():
    """Guard against a silent revert to `${#DOMAIN_ACCESS[@]}` (the crashing form): the
    extracted block must test emptiness with the `+set` alternate-expansion idiom. Strip
    comment lines first — the block's own comment names the crashing form to explain it."""
    code = "\n".join(
        ln
        for ln in _domain_access_block().splitlines()
        if not ln.lstrip().startswith("#")
    )
    assert "${DOMAIN_ACCESS[*]+set}" in code
    assert "${#DOMAIN_ACCESS[@]}" not in code

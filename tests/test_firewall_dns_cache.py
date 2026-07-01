"""Behavioral tests for the cross-session DNS-resolution cache freshness gate.

`dns_cache_fresh` (dns-resolver.bash, loaded via firewall-lib.bash) gates whether
a launch may seed its allowlist from a previous session's resolved IPs: the file
must exist, be non-empty, be younger than TTL seconds, and its first record must
have the `domain<TAB>ip` shape resolve_with_fallback emits. A stale, missing,
empty, or malformed cache is refused so the caller resolves live (the safe
fallback). Driven directly with backdated cache files, asserting only on exit
codes — never on the script's source text.

# covers: sandbox/firewall-lib.bash
"""

import os
import time
from pathlib import Path

from tests._helpers import REPO_ROOT, run_capture

FIREWALL_LIB = REPO_ROOT / "sandbox" / "firewall-lib.bash"

# A well-formed cache: one `domain<TAB>ip` record per line, the shape
# resolve_with_fallback (and the cache write-through) emit.
_VALID_CACHE = "api.example.com\t203.0.113.7\ngithub.com\t203.0.113.8\n"


def _write_cache(path: Path, text: str, age_secs: int = 0) -> None:
    path.write_text(text)
    if age_secs:
        mtime = time.time() - age_secs
        os.utime(path, (mtime, mtime))


def _fresh(cache: Path, ttl: int) -> int:
    """Exit code of `dns_cache_fresh CACHE TTL` (0 = usable, 1 = refuse)."""
    return run_capture(
        [
            "bash",
            "-c",
            f"source '{FIREWALL_LIB}'; dns_cache_fresh '{cache}' {ttl}",
        ]
    ).returncode


def test_fresh_cache_is_accepted(tmp_path: Path) -> None:
    cache = tmp_path / "dns.tsv"
    _write_cache(cache, _VALID_CACHE, age_secs=1)
    assert _fresh(cache, ttl=3600) == 0


def test_cache_older_than_ttl_is_refused(tmp_path: Path) -> None:
    # Past TTL: refuse, so the caller resolves live (the safe fallback) and a
    # since-reassigned IP cannot stay allowlisted beyond TTL + one refresh cycle.
    cache = tmp_path / "dns.tsv"
    _write_cache(cache, _VALID_CACHE, age_secs=7200)
    assert _fresh(cache, ttl=3600) == 1


def test_missing_cache_is_refused(tmp_path: Path) -> None:
    assert _fresh(tmp_path / "absent.tsv", ttl=3600) == 1


def test_empty_cache_is_refused(tmp_path: Path) -> None:
    # An empty file is fresh by mtime but would seed an EMPTY allowlist — refuse it
    # so boot resolves live instead of leaving the workload with no egress.
    cache = tmp_path / "dns.tsv"
    _write_cache(cache, "", age_secs=1)
    assert _fresh(cache, ttl=3600) == 1


def test_malformed_first_record_is_refused(tmp_path: Path) -> None:
    # Garbage that isn't `name<TAB>ip` (corruption / wrong file) is refused rather
    # than parsed into bogus dnsmasq records.
    cache = tmp_path / "dns.tsv"
    _write_cache(cache, "this is not a tsv record\n", age_secs=1)
    assert _fresh(cache, ttl=3600) == 1

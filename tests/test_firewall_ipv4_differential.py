"""Generative (fuzz) differential test for the IPv4/bogon firewall validators.

`is_public_ipv4` in `sandbox/firewall-lib.bash` gates every DNS-resolved A
record before it enters the egress ipset: an address it wrongly reports "public"
is one the firewall would route to. The security-critical invariant is one-sided
— it must NEVER classify a bogon/internal address as public. A false "public"
lets an internal/SSRF/cloud-metadata target through; a false "private" only
over-blocks (fail-safe).

This test fuzzes the bash validators against an INDEPENDENT Python oracle. The
oracle re-encodes the same BOGON_CIDRS list (read from firewall-lib.bash, below)
as stdlib `ipaddress` networks and tests membership itself — the independent
reimplementation is the whole point of a *differential* test. For every IP the
oracle places inside a bogon range, bash `is_public_ipv4` MUST agree it is
non-public; a single violation fails loudly with the offending IP.

Corpus generation is driven by Hypothesis rather than a hand-rolled RNG so a
failure reports the minimal shrunk counterexample plus a reproducible seed. To
stay fast under per-example forking, each Hypothesis example is a *batch* of IPs
classified in ONE bash invocation (the harness sources the lib and classifies
every line), so Hypothesis shrinks a failing batch toward a single offending IP
while a passing batch costs one fork, not one-per-IP.

# covers: sandbox/firewall-lib.bash
"""

import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from tests._helpers import REPO_ROOT, run_capture

FIREWALL_LIB = REPO_ROOT / "sandbox" / "firewall-lib.bash"

# Independent re-encoding of BOGON_CIDRS from firewall-lib.bash. This is the
# oracle's source of truth; it deliberately duplicates the bash list so a drift
# between the two surfaces as a test failure rather than passing silently.
BOGON_CIDRS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
]

_BOGON_NETS = [ipaddress.ip_network(c) for c in BOGON_CIDRS]

# Known-public anchors: the oracle and bash must both call these public, or the
# allowlist build would refuse legitimate egress.
KNOWN_PUBLIC = ["8.8.8.8", "1.1.1.1"]


def _oracle_is_bogon(ip: str) -> bool:
    """Independent oracle: True when `ip` falls inside any encoded bogon range."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _BOGON_NETS)


# === Hypothesis strategies ===============================================


def _u32_to_ip(n: int) -> str:
    return str(ipaddress.ip_address(n))


# A single dotted-quad drawn uniformly from the whole u32 space. Integer
# strategies bias toward their bounds, so 0.0.0.0 / 255.255.255.255 and the
# adjacent values are hit deterministically.
_any_ipv4 = st.integers(min_value=0, max_value=0xFFFFFFFF).map(_u32_to_ip)


def _ip_in_net(net: ipaddress.IPv4Network) -> st.SearchStrategy[str]:
    """Addresses drawn from within `net` — the integer bounds are the network and
    broadcast addresses, so Hypothesis exercises each range's edges by design."""
    return st.integers(
        min_value=int(net.network_address),
        max_value=int(net.broadcast_address),
    ).map(_u32_to_ip)


# Every draw is guaranteed to fall inside SOME bogon range, so the security
# assertion is never vacuous and needs no `assume()` filtering.
_bogon_ipv4 = st.one_of(*[_ip_in_net(net) for net in _BOGON_NETS])

# Batches keep the bash fork amortized: one invocation classifies up to 64 IPs,
# and Hypothesis shrinks a failing batch toward the single offending address.
_bogon_batch = st.lists(_bogon_ipv4, min_size=1, max_size=64)
_any_batch = st.lists(_any_ipv4, min_size=1, max_size=64)


def _curated_ips() -> list[str]:
    """Edge cases: each bogon boundary's network/broadcast address and the
    addresses +/-1 around each, plus named internal endpoints and public anchors."""
    ips: set[str] = {"0.0.0.0", "255.255.255.255"}
    for net in _BOGON_NETS:
        first = int(net.network_address)
        last = int(net.broadcast_address)
        # Boundaries and the addresses straddling them; clamp to the valid u32
        # range so we never form an out-of-range address.
        for n in (first - 1, first, first + 1, last - 1, last, last + 1):
            if 0 <= n <= 0xFFFFFFFF:
                ips.add(str(ipaddress.ip_address(n)))
    ips.update(_cidr_edge_ips())
    ips.update(
        [
            "169.254.0.1",
            "169.254.169.254",  # cloud metadata endpoint
            "127.0.0.1",
            "10.0.0.0",
            "100.64.0.1",
            "192.0.2.1",
            "172.30.0.2",  # a per-session sandbox subnet address
        ]
    )
    ips.update(KNOWN_PUBLIC)
    return sorted(ips)


def _cidr_edge_ips() -> set[str]:
    """Single-host (/32, /31) and netmask-boundary edge cases the random corpus is
    unlikely to hit. grepcidr does the IP-in-CIDR match inside is_public_ipv4; a
    matcher that mishandled a /31 or /32 prefix, or the network/broadcast address
    of a wider prefix, would mis-classify exactly these. We enumerate, for several
    bogon ranges AND a public range, the network and broadcast addresses plus the
    two halves of the final /31 — the cases where prefix-length arithmetic is most
    error-prone. The oracle (membership in BOGON_CIDRS) decides each; the test only
    needs the boundary IPs to be PRESENT in the corpus, not labelled here."""
    ips: set[str] = set()
    # /32 single-host: every byte set, and a single bogon host. A /32 is the
    # degenerate prefix where network == broadcast == the host itself.
    for host in ("8.8.8.8", "10.255.255.255", "127.255.255.255", "192.168.255.255"):
        ips.add(host)
    # /31 point-to-point (RFC3021): both addresses of the final pair inside and
    # straddling a bogon edge — no network/broadcast distinction at /31.
    for base in ("10.0.0.0", "172.31.255.254", "169.254.255.254", "192.0.2.0"):
        net = ipaddress.ip_network(f"{base}/31", strict=False)
        ips.add(str(net.network_address))
        ips.add(str(net.broadcast_address))
    # Network and broadcast addresses of representative bogon prefixes of differing
    # widths (/8, /10, /12, /16, /4): a netmask off-by-one would leak the broadcast.
    for cidr in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "240.0.0.0/4",
    ):
        net = ipaddress.ip_network(cidr)
        ips.add(str(net.network_address))
        ips.add(str(net.broadcast_address))
        # First address just OUTSIDE the prefix's upper edge (must be public when
        # the next range up is public) — a /12 boundary the random corpus rarely
        # lands on exactly.
        nxt = int(net.broadcast_address) + 1
        if nxt <= 0xFFFFFFFF:
            ips.add(str(ipaddress.ip_address(nxt)))
    return ips


def _classify_ips(ips: list[str]) -> dict[str, str]:
    """Bulk-classify every IP through bash in ONE invocation. Writes the corpus to
    the bash process's stdin; the harness sources the lib and prints, per line,
    `<ip>\\t<valid>\\t<public>` where each flag is 1/0 — so per-IP forks are
    avoided. Returns {ip: "<valid><public>"} (e.g. "1 1", "1 0", "0 0")."""
    harness = (
        f"set -euo pipefail; source '{FIREWALL_LIB}'\n"
        "while IFS= read -r ip; do\n"
        '  if valid_ipv4 "$ip"; then v=1; else v=0; fi\n'
        '  if is_public_ipv4 "$ip"; then p=1; else p=0; fi\n'
        '  printf \'%s\\t%s\\t%s\\n\' "$ip" "$v" "$p"\n'
        "done\n"
    )
    r = run_capture(["bash", "-c", harness], input="\n".join(ips) + "\n")
    assert r.returncode == 0, r.stderr
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        ip, v, p = line.split("\t")
        out[ip] = f"{v} {p}"
    return out


# === is_public_ipv4 differential ===


def test_curated_bogon_edges_are_never_public() -> None:
    """Deterministic boundary sweep: every network/broadcast/straddling address of
    every bogon prefix (plus the cloud-metadata endpoint and named internals) must
    be reported non-public by bash. These are the exact IPs a netmask off-by-one
    would leak, so they are pinned explicitly rather than left to random sampling."""
    corpus = _curated_ips()
    classified = _classify_ips(corpus)

    leaks = [
        ip
        for ip in corpus
        if _oracle_is_bogon(ip) and classified[ip].split(" ")[1] == "1"
    ]
    assert not leaks, (
        "is_public_ipv4 classified bogon/internal addresses as PUBLIC "
        f"(egress leak): {sorted(set(leaks))}"
    )
    # Guard against the corpus going degenerate (oracle wiring breaks, exercising
    # zero bogons), which would make the assertion above vacuous.
    assert any(_oracle_is_bogon(ip) for ip in corpus)


@settings(max_examples=200, deadline=None)
@given(_bogon_batch)
def test_bogon_addresses_are_never_public(ips: list[str]) -> None:
    """THE security gate (no-leak direction): every IP Hypothesis draws from inside
    a bogon range MUST be reported non-public by bash. A single violation = the
    egress firewall would admit an internal/SSRF target. On failure Hypothesis
    shrinks the batch to the minimal offending address and prints a repro seed."""
    classified = _classify_ips(ips)
    # "<valid> <public>"; public flag is the second field.
    leaks = [ip for ip in ips if classified[ip].split(" ")[1] == "1"]
    assert not leaks, (
        "is_public_ipv4 classified bogon/internal addresses as PUBLIC "
        f"(egress leak): {sorted(set(leaks))}"
    )


@settings(max_examples=100, deadline=None)
@given(_any_batch)
def test_wellformed_dotted_quads_are_always_valid(ips: list[str]) -> None:
    """Every syntactically well-formed dotted quad (any of the 2^32 addresses) must
    pass valid_ipv4 — the shape gate must never reject a legal address, or a
    legitimate A record would be dropped before it reaches the public/bogon split.
    The public flag is left unchecked here: over-blocking a public address is
    fail-safe and is pinned only for the known-public anchors below."""
    classified = _classify_ips(ips)
    invalid = [ip for ip in ips if classified[ip].split(" ")[0] != "1"]
    assert not invalid, f"valid_ipv4 rejected well-formed dotted quads: {invalid}"


def test_known_public_samples_are_public() -> None:
    """Over-blocking is fail-safe, so a random "oracle says public, bash says
    private" divergence is informational, not a failure. But the curated
    known-public anchors MUST be seen as public — otherwise legitimate egress
    breaks. Pin only those."""
    classified = _classify_ips(KNOWN_PUBLIC)
    for ip in KNOWN_PUBLIC:
        assert _oracle_is_bogon(ip) is False  # oracle agrees they are public
        assert classified[ip] == "1 1", f"{ip} should be valid + public"


def test_reverse_divergences_are_only_informational() -> None:
    """Sanity-check the softer direction: where the oracle says public but bash
    says private, that is fail-safe over-blocking and must NOT fail the suite. We
    assert the divergence set (over the curated boundary corpus) excludes the
    known-public anchors — those are pinned in their own test — rather than
    asserting it is empty."""
    corpus = _curated_ips()
    classified = _classify_ips(corpus)
    over_blocked = [
        ip
        for ip in corpus
        if not _oracle_is_bogon(ip) and classified[ip].split(" ")[1] == "0"
    ]
    # Informational only — over-blocking is safe. The one hard requirement is that
    # no known-public anchor is among the over-blocked.
    assert not (set(over_blocked) & set(KNOWN_PUBLIC))


# === valid_ipv4 anchoring / robustness ===


def _run_validator(fn: str, token: str) -> bool:
    """Run a firewall-lib boolean validator (`fn`) against one token (arg-passed,
    so embedded newlines/spaces reach the function intact) and assert it exits
    cleanly true/false."""
    r = run_capture(
        [
            "bash",
            "-c",
            f"source '{FIREWALL_LIB}'; if {fn} \"$1\"; then echo ok; else echo no; fi",
            "_",
            token,
        ]
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() in ("ok", "no")
    return r.stdout.strip() == "ok"


def _valid_ipv4(token: str) -> bool:
    return _run_validator("valid_ipv4", token)


def test_valid_ipv4_rejects_smuggling_and_malformed() -> None:
    """The shape check must ANCHOR (^...$) so a multi-value or padded string can't
    smuggle a second token past it into `ipset add`. Each of these must be
    rejected."""
    rejected = [
        "10.0.0.1\n8.8.8.8",  # newline-separated pair — anchoring must reject
        " 8.8.8.8",  # leading space
        "8.8.8.8 ",  # trailing space
        "1.2.3.4.5",  # five octets
        "256.1.1.1",  # octet over 255
        "999.1.1.1",  # the value a shape-only [0-9]{1,3} would wrongly accept
        "1.2.3",  # too few octets
        "",  # empty
    ]
    for token in rejected:
        assert _valid_ipv4(token) is False, f"valid_ipv4 wrongly accepted {token!r}"


def test_valid_ipv4_accepts_well_formed() -> None:
    for token in ("8.8.8.8", "0.0.0.0", "255.255.255.255", "192.168.1.1"):
        assert _valid_ipv4(token) is True, f"valid_ipv4 wrongly rejected {token!r}"


# Metacharacter-heavy alphabet (no NUL — it cannot ride in an argv slot): a
# quoting/regex bug in valid_ipv4 would surface as a bash error rather than a
# clean true/false on exactly these bytes.
_IPISH_ALPHABET = "0123456789.abcf:/ -\t*$`\\\n"


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=_IPISH_ALPHABET, max_size=16))
def test_valid_ipv4_never_errors_on_fuzzed_strings(token: str) -> None:
    """valid_ipv4 must return cleanly true/false for arbitrary junk, never a bash
    error (a regex/quoting bug here would crash the resolve loop). `_valid_ipv4`
    asserts the call exits 0 and prints exactly ok/no, so simply invoking it over
    fuzzed input is the assertion."""
    _valid_ipv4(token)


# === valid_domain_name robustness ===


def _valid_domain(name: str) -> bool:
    return _run_validator("valid_domain_name", name)


def test_valid_domain_name_accepts_known_good() -> None:
    for name in ("example.com", "a.b.c.example.org"):
        assert _valid_domain(name) is True, f"valid_domain_name rejected {name!r}"


def test_valid_domain_name_rejects_known_bad() -> None:
    bad = [
        "ex ample.com",  # embedded space
        "evil.com\naddress=/x/1.2.3.4",  # newline injection
        ".foo.com",  # leading dot
        "..",  # bare consecutive dots
        "",  # empty
        "-leadinghyphen.com",  # leading hyphen
        "1.2.3.4",  # IPv4 literal — a domain validator must not admit a raw IP
        "127.0.0.1",  # loopback IPv4 literal
    ]
    for name in bad:
        assert _valid_domain(name) is False, f"valid_domain_name accepted {name!r}"


def test_valid_domain_name_rejects_embedded_empty_label() -> None:
    """A middle empty label (consecutive dots) like `a..b.com` is REJECTED: every
    label must be 1..63 chars (RFC 1035), so an empty interior label fails the
    per-label bound. The shape regex alone would admit it (it anchors only the first
    and last characters to alphanumerics), but an empty-label `address=`/`dstdomain`
    line seeded from a workspace `.claude/settings.json` would fail the dnsmasq/squid
    config reload and brick the launch — so the validator rejects it before it can."""
    assert _valid_domain("a..b.com") is False
    assert _valid_domain("a..com") is False


_DOMAINISH_ALPHABET = "abc.-_0129 \t\n/:@*$`\\"


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=_DOMAINISH_ALPHABET, max_size=16))
def test_valid_domain_name_never_errors_on_fuzzed_input(name: str) -> None:
    """Like valid_ipv4: arbitrary junk must yield a clean true/false, never a bash
    error from an unescaped metacharacter reaching the regex."""
    _valid_domain(name)

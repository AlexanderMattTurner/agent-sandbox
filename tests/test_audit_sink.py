"""In-process tests of sandbox/audit_sink.py — the HMAC chain (append, verify,
tamper/reorder/drop detection), the secret bootstrap, and the HTTP append
surface. The module is imported directly (never a subprocess) so coverage and
the mutation gate see every line."""

import hashlib
import hmac as hmac_mod
import http.client
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from subprocess import run

import pytest

REPO = Path(
    run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)
sys.path.insert(0, str(REPO / "sandbox"))

import audit_sink  # noqa: E402


@pytest.fixture
def log(tmp_path):
    return str(tmp_path / "audit.jsonl")


SECRET = b"test-secret"


def append_all(log, records):
    state = audit_sink.make_state()
    return [audit_sink.append_record(log, SECRET, r, state) for r in records]


def test_append_and_verify_roundtrip(log):
    records = [{"n": 0}, {"n": 1}, {"n": 2}]
    entries = append_all(log, records)
    assert [e["seq"] for e in entries] == [0, 1, 2]
    assert audit_sink.verify_chain(log, SECRET) == records


def test_chain_mac_is_exact_hmac_sha256(log):
    # Exact-equality pin of the link construction so a silent change to the
    # mac'd material (seq/prev/record framing) cannot pass.
    mac = audit_sink.chain_mac(SECRET, "prev", 3, '{"a":1}')
    expected = hmac_mod.new(SECRET, b'3\nprev\n{"a":1}', hashlib.sha256).hexdigest()
    assert mac == expected


def test_first_record_chains_from_seed(log):
    (entry,) = append_all(log, [{"n": 0}])
    assert entry["seq"] == 0
    assert entry["mac"] == audit_sink.chain_mac(
        SECRET, audit_sink.CHAIN_SEED, 0, '{"n":0}'
    )


def test_edited_record_is_detected(log):
    append_all(log, [{"n": 0}, {"n": 1}, {"n": 2}])
    lines = Path(log).read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["record"]["n"] = 999
    lines[1] = json.dumps(tampered, sort_keys=True)
    Path(log).write_text("\n".join(lines) + "\n")
    with pytest.raises(audit_sink.AuditChainError, match="mac mismatch at seq 1"):
        audit_sink.verify_chain(log, SECRET)


def test_reordered_records_are_detected(log):
    append_all(log, [{"n": 0}, {"n": 1}, {"n": 2}])
    lines = Path(log).read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    Path(log).write_text("\n".join(lines) + "\n")
    with pytest.raises(audit_sink.AuditChainError, match="seq discontinuity at line 0"):
        audit_sink.verify_chain(log, SECRET)


def test_interior_drop_is_detected(log):
    append_all(log, [{"n": 0}, {"n": 1}, {"n": 2}])
    lines = Path(log).read_text().splitlines()
    del lines[1]
    Path(log).write_text("\n".join(lines) + "\n")
    with pytest.raises(audit_sink.AuditChainError, match="seq discontinuity at line 1"):
        audit_sink.verify_chain(log, SECRET)


def test_forged_tail_under_wrong_key_is_detected(log):
    append_all(log, [{"n": 0}])
    state = audit_sink.make_state()
    audit_sink.append_record(log, b"other-key", {"n": 1}, state)
    with pytest.raises(audit_sink.AuditChainError, match="mac mismatch at seq 1"):
        audit_sink.verify_chain(log, SECRET)


def test_tail_truncation_verifies_shorter(log):
    """Documented boundary: chopping the TAIL still verifies — detection needs
    an out-of-band expected count. The chain guarantees integrity of what
    remains, exactly."""
    append_all(log, [{"n": 0}, {"n": 1}, {"n": 2}])
    lines = Path(log).read_text().splitlines()
    Path(log).write_text("\n".join(lines[:2]) + "\n")
    assert audit_sink.verify_chain(log, SECRET) == [{"n": 0}, {"n": 1}]


def test_chain_continues_across_restart(log):
    append_all(log, [{"n": 0}, {"n": 1}])
    # A fresh state (a restarted sink) seeds from disk and keeps the chain.
    state = audit_sink.make_state()
    entry = audit_sink.append_record(log, SECRET, {"n": 2}, state)
    assert entry["seq"] == 2
    assert audit_sink.verify_chain(log, SECRET) == [{"n": 0}, {"n": 1}, {"n": 2}]


def test_chain_tail_of_absent_log_starts_chain(log):
    assert audit_sink.chain_tail(log) == (0, audit_sink.CHAIN_SEED)


def test_empty_log_verifies_empty(log):
    Path(log).touch()
    assert audit_sink.verify_chain(log, SECRET) == []
    assert audit_sink.chain_tail(log) == (0, audit_sink.CHAIN_SEED)


def test_bootstrap_secret_mints_owner_only_and_is_idempotent(tmp_path):
    secret_dir = tmp_path / "audit-secret"
    path = audit_sink.bootstrap_secret(str(secret_dir))
    first = Path(path).read_text()
    assert len(first) == 64  # 256-bit hex
    assert Path(path).stat().st_mode & 0o777 == 0o600
    assert audit_sink.bootstrap_secret(str(secret_dir)) == path
    assert Path(path).read_text() == first  # kept, not re-minted


def test_load_secret_strips_trailing_newline(tmp_path):
    p = tmp_path / "secret"
    p.write_bytes(b"abc\r\n")
    assert audit_sink.load_secret(str(p)) == b"abc"


@pytest.mark.parametrize(
    ("header", "secret_bytes", "expected"),
    [
        ("", b"key", False),
        ("bogus", b"key", False),
        ("bogus", b"", False),
        (hmac_mod.new(b"key", b"body", "sha256").hexdigest(), b"key", True),
        (hmac_mod.new(b"key", b"body", "sha256").hexdigest() + " ", b"key", True),
    ],
    ids=["no-header", "wrong-mac", "empty-secret", "valid", "valid-strips-space"],
)
def test_http_verify_boundaries(tmp_path, header, secret_bytes, expected):
    p = tmp_path / "secret"
    p.write_bytes(secret_bytes)
    assert audit_sink.http_verify(b"body", header, str(p)) is expected


def test_http_verify_missing_secret_fails_closed(tmp_path):
    assert audit_sink.http_verify(b"body", "abc", str(tmp_path / "nope")) is False


@pytest.fixture
def sink(tmp_path):
    secret_file = audit_sink.bootstrap_secret(str(tmp_path / "sec"))
    log = str(tmp_path / "audit.jsonl")
    handler = audit_sink.AuditSinkHandler
    handler.audit_log = log
    handler.secret_path = secret_file
    handler.state = audit_sink.make_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server.server_address[1], secret_file, log
    server.shutdown()


def post(port, body: bytes, headers: dict) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=body, headers=headers)
    resp = conn.getresponse()
    payload = json.loads(resp.read())
    conn.close()
    return resp.status, payload


def sign(secret_file: str, body: bytes) -> dict:
    secret = audit_sink.load_secret(secret_file)
    return {audit_sink.AUTH_HEADER: hmac_mod.new(secret, body, "sha256").hexdigest()}


def test_http_signed_post_appends_chained_record(sink):
    port, secret_file, log = sink
    body = json.dumps({"tool": "Bash", "argv": ["ls"]}).encode()
    status, payload = post(port, body, sign(secret_file, body))
    assert (status, payload) == (200, {"ok": True, "seq": 0})
    secret = audit_sink.load_secret(secret_file)
    assert audit_sink.verify_chain(log, secret) == [{"tool": "Bash", "argv": ["ls"]}]


def test_http_unsigned_post_is_rejected_and_unrecorded(sink):
    port, _, log = sink
    status, payload = post(port, b"{}", {})
    assert status == 401
    assert payload["ok"] is False
    assert not Path(log).exists()


def test_http_oversize_body_is_rejected_before_auth(sink):
    port, secret_file, _ = sink
    body = b"x" * (audit_sink.MAX_BODY_SIZE + 1)
    status, payload = post(port, body, sign(secret_file, body))
    assert (status, payload["ok"]) == (413, False)


def test_http_invalid_json_body_is_rejected(sink):
    port, secret_file, _ = sink
    body = b"not json"
    status, payload = post(port, body, sign(secret_file, body))
    assert (status, payload["ok"]) == (400, False)


def test_http_empty_body_is_rejected(sink):
    port, secret_file, _ = sink
    status, payload = post(port, b"", sign(secret_file, b""))
    assert (status, payload["ok"]) == (400, False)


def test_trace_emits_as_trace_wire_shape(tmp_path, monkeypatch):
    sinkfile = tmp_path / "trace.jsonl"
    monkeypatch.setenv("AGENT_SANDBOX_TRACE", "info")
    monkeypatch.setenv("AGENT_SANDBOX_TRACE_FILE", str(sinkfile))
    audit_sink.trace("audit_sink_started", {"bind": "0.0.0.0", "port": 9198})
    event = json.loads(sinkfile.read_text())
    assert event["event"] == "audit_sink_started"
    assert event["layer"] == "audit"
    assert event["level"] == "info"
    assert (event["bind"], event["port"]) == ("0.0.0.0", 9198)


def test_trace_is_silent_when_channel_off(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("AGENT_SANDBOX_TRACE", raising=False)
    sinkfile = tmp_path / "trace.jsonl"
    monkeypatch.setenv("AGENT_SANDBOX_TRACE_FILE", str(sinkfile))
    audit_sink.trace("audit_sink_started", {})
    assert not sinkfile.exists()
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    ("level", "threshold"),
    [
        ("", 0),
        ("off", 0),
        ("info", 1),
        ("1", 1),
        ("true", 1),
        ("on", 1),
        ("debug", 2),
        ("2", 2),
    ],
)
def test_trace_threshold_mapping(monkeypatch, level, threshold):
    monkeypatch.setenv("AGENT_SANDBOX_TRACE", level)
    assert audit_sink._trace_threshold() == threshold


def test_main_creates_empty_log_at_startup(tmp_path, monkeypatch):
    """A session with zero audit events still has a chain (an empty one): main()
    must create the log file up front so the launcher's pre-teardown docker cp
    export always finds it — a quiet session must not lose its host copy."""
    log_path = tmp_path / "log" / "audit.jsonl"
    secret_path = tmp_path / "secret" / "secret"
    monkeypatch.setenv("AUDIT_LOG", str(log_path))
    monkeypatch.setenv("AUDIT_SECRET_PATH", str(secret_path))
    served = {}
    monkeypatch.setattr(audit_sink, "serve", lambda *a, **kw: served.update(kw))
    audit_sink.main()
    assert log_path.exists() and log_path.stat().st_size == 0
    assert served["audit_log"] == str(log_path)

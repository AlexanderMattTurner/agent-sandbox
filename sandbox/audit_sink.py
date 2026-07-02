"""Tamper-evident append-only audit sink.

The audit log is a chain of HMAC-linked records: each appended line carries a
monotonic ``seq`` and a ``mac`` computed over (seq, previous record's mac,
record body) with a per-session secret minted at startup onto the sink's own
volume. Editing, reordering, or dropping an interior record breaks the chain;
``verify_chain`` proves it. Truncating the TAIL of the log still verifies —
detecting tail loss needs an out-of-band expected record count (e.g. the last
mac exported elsewhere).

The writer runs OUTSIDE the workload container (the ``audit`` compose service),
so the workload cannot forge or rewrite history: it never mounts the log or the
secret. The HTTP listener appends records POSTed with a valid transport HMAC
(header ``X-Audit-Auth`` = HMAC-SHA256 of the body under the same secret).
Stdlib only — it runs in the firewall image, which bakes no extra deps.
"""

import contextlib
import hmac
import http.server
import json
import os
import secrets
import sys
import threading
import time

AUTH_HEADER = "X-Audit-Auth"
MAX_BODY_SIZE = 64 * 1024
CHAIN_SEED = ""  # the "previous mac" of the first record


class AuditChainError(Exception):
    """The on-disk audit log fails chain verification (tamper evidence)."""


def _trace_threshold() -> int:
    """Numeric verbosity from AGENT_SANDBOX_TRACE: 0 off, 1 info, 2 debug.
    Mirrors trace.bash's threshold mapping."""
    level = os.environ.get("AGENT_SANDBOX_TRACE", "")
    if level in ("debug", "2"):
        return 2
    if level in ("info", "1", "true", "on"):
        return 1
    return 0


def trace(event: str, fields: dict) -> None:
    """Emit one structured trace line in the as_trace wire shape (layer
    ``audit``, level ``info``) to AGENT_SANDBOX_TRACE_FILE when set, else
    stderr. Best-effort: a sink that can't be written never fails the caller."""
    if _trace_threshold() < 1:
        return
    line = json.dumps(
        {
            "ts": int(time.time() * 1000),
            "layer": "audit",
            "event": event,
            "level": "info",
            **fields,
        }
    )
    sink = os.environ.get("AGENT_SANDBOX_TRACE_FILE", "")
    with contextlib.suppress(OSError):
        if sink:
            with open(sink, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        else:
            print(line, file=sys.stderr)


def bootstrap_secret(secret_dir: str) -> str:
    """Mint the per-session HMAC secret onto the sink's own volume; the
    healthcheck's readiness signal is this file existing. Idempotent: an
    existing secret is kept so records already chained under it stay
    verifiable. Owner-only (0600 root) — no other service reads it."""
    secret_file = os.path.join(secret_dir, "secret")
    os.makedirs(secret_dir, mode=0o700, exist_ok=True)
    if not os.path.exists(secret_file):
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32))
    return secret_file


def load_secret(secret_path: str) -> bytes:
    """Read the HMAC key, stripping a trailing newline so a shell-written and a
    Python-written secret produce the same key."""
    with open(secret_path, "rb") as f:
        return f.read().rstrip(b"\r\n")


def chain_mac(secret: bytes, prev_mac: str, seq: int, record_json: str) -> str:
    """The link: HMAC-SHA256 over (seq, previous mac, canonical record JSON)."""
    material = f"{seq}\n{prev_mac}\n{record_json}".encode()
    return hmac.new(secret, material, "sha256").hexdigest()


def _canonical(record: object) -> str:
    """One byte-stable JSON form per record, so the mac'd bytes and the stored
    bytes cannot disagree."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def chain_tail(path: str) -> tuple[int, str]:
    """(next seq, last mac) from the log on disk — seeds the appender so the
    chain continues across restarts. An absent log starts the chain."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return 0, CHAIN_SEED
    if not lines:
        return 0, CHAIN_SEED
    last = json.loads(lines[-1])
    return last["seq"] + 1, last["mac"]


def append_record(path: str, secret: bytes, record: object, state: dict) -> dict:
    """Append one chained record; ``state`` (from :func:`make_state`) holds the
    in-memory tail so appends are O(1). The seq assignment, mac computation, and
    file append happen under one lock so concurrent writers can neither reorder
    nor interleave — either would read as tamper evidence. Raises OSError on a
    failed write so the caller fails closed."""
    with state["lock"]:
        if state["next_seq"] is None:
            state["next_seq"], state["last_mac"] = chain_tail(path)
        record_json = _canonical(record)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seq": state["next_seq"],
            "record": record,
            "mac": chain_mac(secret, state["last_mac"], state["next_seq"], record_json),
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        state["next_seq"] += 1
        state["last_mac"] = entry["mac"]
        return entry


def verify_chain(path: str, secret: bytes) -> list:
    """Re-walk the log, recomputing every link. Returns the records when the
    chain holds; raises AuditChainError naming the first broken link on any
    edit, reorder, insertion, or interior drop (seq gap or mac mismatch)."""
    records = []
    prev_mac = CHAIN_SEED
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f.read().splitlines()):
            entry = json.loads(line)
            if entry["seq"] != i:
                raise AuditChainError(f"seq discontinuity at line {i}: {entry['seq']}")
            expected = chain_mac(secret, prev_mac, i, _canonical(entry["record"]))
            if not hmac.compare_digest(expected, entry["mac"]):
                raise AuditChainError(f"mac mismatch at seq {i}")
            prev_mac = entry["mac"]
            records.append(entry["record"])
    return records


def make_state() -> dict:
    """Per-process appender state: the lazily-seeded chain tail and the lock
    serializing seq assignment with the file append."""
    return {"next_seq": None, "last_mac": CHAIN_SEED, "lock": threading.Lock()}


def http_verify(body: bytes, header_value: str, secret_path: str) -> bool:
    """Constant-time transport-HMAC check on a POST body. Missing/empty secret
    or header → fail closed."""
    if not header_value:
        return False
    try:
        secret = load_secret(secret_path)
    except OSError:
        return False
    if not secret:
        return False
    expected = hmac.new(secret, body, "sha256").hexdigest()
    return hmac.compare_digest(expected, header_value.strip())


class AuditSinkHandler(http.server.BaseHTTPRequestHandler):
    """Append-only HTTP surface: HMAC-verify the POST, chain-append the JSON
    body as one record. Record-only — it never gates anything. Config is bound
    by :func:`serve` as class attributes."""

    audit_log = "/var/log/agent-sandbox/audit.jsonl"
    secret_path = "/run/audit-secret/secret"  # noqa: S105 — a file path, not a secret value
    state: dict = {}
    # Socket timeout (applied by StreamRequestHandler in setup()) so a peer that
    # announces a body but withholds it cannot park a handler thread — the read
    # happens before HMAC verify, so an UNauthenticated peer could otherwise
    # slowloris the always-on sink.
    timeout = 30.0

    def _reply(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        err = code = None
        body = b""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                # A negative length slips under the size cap yet is truthy, and
                # rfile.read(-1) reads to EOF — an unbounded pre-auth read that
                # would defeat MAX_BODY_SIZE. Zero-length carries no record.
                err, code = "invalid Content-Length", 400
            elif length > MAX_BODY_SIZE:
                err, code = "request body too large", 413
            else:
                body = self.rfile.read(length)
        except (ValueError, TypeError):
            err, code = "invalid Content-Length", 400
        except TimeoutError:
            err, code = "request body read timed out", 408
        if err:
            return self._reply(code, {"ok": False, "error": err})

        if not http_verify(body, self.headers.get(AUTH_HEADER, ""), self.secret_path):
            return self._reply(
                401, {"ok": False, "error": "unauthorized: missing or invalid HMAC"}
            )

        try:
            record = json.loads(body)
        except ValueError as e:
            return self._reply(400, {"ok": False, "error": f"invalid JSON body: {e}"})

        try:
            entry = append_record(
                self.audit_log, load_secret(self.secret_path), record, self.state
            )
        except OSError as e:
            print(f"audit-sink: FATAL — audit write failed: {e}", file=sys.stderr)
            return self._reply(500, {"ok": False, "error": str(e)})
        return self._reply(200, {"ok": True, "seq": entry["seq"]})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — stdlib signature
        pass


def serve(bind_host: str, port: int, *, audit_log: str, secret_path: str) -> None:
    """Run the sink forever. Binds the listening socket FIRST, then announces
    engagement — ``audit_sink_started`` is startup-deterministic, so a launch
    self-test can assert the audit layer came up. Metadata only on the trace."""
    AuditSinkHandler.audit_log = audit_log
    AuditSinkHandler.secret_path = secret_path
    AuditSinkHandler.state = make_state()
    AuditSinkHandler.timeout = float(os.environ.get("AUDIT_READ_TIMEOUT", "30"))
    server = http.server.ThreadingHTTPServer((bind_host, port), AuditSinkHandler)
    print(f"audit sink listening on {bind_host}:{port}", file=sys.stderr)
    trace("audit_sink_started", {"bind": bind_host, "port": port})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


def main() -> None:
    """Entry point for the audit compose service: mint the secret (the
    healthcheck's readiness signal), then bind and serve. A secret that can't
    be minted raises — a sink that can authenticate nothing is a blind audit
    that looks alive."""
    audit_log = os.environ.get("AUDIT_LOG", "/var/log/agent-sandbox/audit.jsonl")
    secret_path = os.environ.get("AUDIT_SECRET_PATH", "/run/audit-secret/secret")
    bind_host = os.environ.get("AUDIT_BIND", "0.0.0.0")  # noqa: S104 — the sandbox net is internal
    port = int(os.environ.get("AUDIT_SINK_PORT", "9198"))
    os.makedirs(os.path.dirname(audit_log), exist_ok=True)
    bootstrap_secret(os.path.dirname(secret_path))
    serve(bind_host, port, audit_log=audit_log, secret_path=secret_path)


if __name__ == "__main__":
    main()

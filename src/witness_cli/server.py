"""HTTP authority endpoints (spec §8-§10) on the standard library server.

TLS is out of scope: the server binds loopback by default, and refusing a
non-loopback bind without an explicit acknowledgment enforces spec §3 —
non-loopback deployments MUST put HTTPS in front of this process.
"""

from __future__ import annotations

import ipaddress
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .authority import Authority
from .errors import IdempotencyConflictError, WitnessError
from .model import MAX_STATEMENT_BYTES, parse_statement_bytes

IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._:-]{16,128}")
_RECEIPT_PATH = re.compile(r"/v1/receipts/([0-9A-HJKMNP-TV-Z]{26})")
_KEY_PATH = re.compile(r"/v1/keys/(ed25519:[0-9a-f]{64})")


def host_is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class WitnessServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host: str, port: int, authority: Authority):
        self.authority = authority
        super().__init__((host, port), _Handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: WitnessServer

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_body(self, status: int, message: str) -> None:
        self._send(status, json.dumps({"error": message}).encode("utf-8") + b"\n")

    def do_POST(self) -> None:  # noqa: N802 (stdlib handler naming)
        if self.path != "/v1/receipts":
            self._send_error_body(404, "unknown resource")
            return
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
            self._send_error_body(
                400, "Idempotency-Key header must be 16-128 characters of A-Z a-z 0-9 . _ : -"
            )
            return
        length_header = self.headers.get("Content-Length")
        if length_header is None or not length_header.isdigit():
            self._send_error_body(411, "Content-Length is required")
            return
        length = int(length_header)
        if length > MAX_STATEMENT_BYTES:
            self._send_error_body(413, f"statement exceeds {MAX_STATEMENT_BYTES} bytes")
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_error_body(400, "request body is shorter than Content-Length")
            return
        try:
            statement = parse_statement_bytes(body)
            receipt_json, created = self.server.authority.submit(statement, idempotency_key)
        except IdempotencyConflictError as exc:
            self._send_error_body(409, str(exc))
            return
        except WitnessError as exc:
            self._send_error_body(400, str(exc))
            return
        self._send(201 if created else 200, receipt_json)

    def do_GET(self) -> None:  # noqa: N802 (stdlib handler naming)
        receipt_match = _RECEIPT_PATH.fullmatch(self.path)
        if receipt_match is not None:
            receipt_json = self.server.authority.get_receipt(receipt_match.group(1))
            if receipt_json is None:
                self._send_error_body(404, "unknown receipt")
            else:
                self._send(200, receipt_json)
            return
        key_match = _KEY_PATH.fullmatch(self.path)
        if key_match is not None:
            authority = self.server.authority
            if key_match.group(1) != authority.key_id:
                self._send_error_body(404, "unknown key")
                return
            material = {
                "algorithm": "ed25519",
                "authority_id": authority.authority_id,
                "key_id": authority.key_id,
                "public_key_hex": authority.public_key_hex,
            }
            # Spec §10: fetching this endpoint does not itself make the key trusted.
            self._send(200, json.dumps(material, sort_keys=True).encode("ascii") + b"\n")
            return
        self._send_error_body(404, "unknown resource")

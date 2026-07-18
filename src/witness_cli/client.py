"""Submission client (spec §15): POST a statement, return the signed receipt."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .authority import canonical_statement_sha256
from .errors import SubmissionError
from .model import parse_receipt_bytes, parse_statement_bytes
from .server import host_is_loopback


def default_idempotency_key(statement: dict) -> str:
    """Deterministic key from the canonical statement: safe to retry blindly."""
    return "sha256:" + canonical_statement_sha256(statement)


def submit_statement(
    url: str,
    statement_bytes: bytes,
    idempotency_key: str | None = None,
    timeout: float = 30.0,
) -> tuple[bytes, bool]:
    """Submit a statement; return (receipt bytes, created).

    The statement is validated locally before it leaves the machine, and the
    returned receipt is validated and checked to carry the same statement —
    an authority that alters the statement is reported, not trusted.
    """
    statement = parse_statement_bytes(statement_bytes)
    if idempotency_key is None:
        idempotency_key = default_idempotency_key(statement)

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise SubmissionError(f"unsupported URL scheme: {parsed.scheme!r}")
    if parsed.scheme == "http" and not host_is_loopback(parsed.hostname or ""):
        raise SubmissionError("plain HTTP to a non-loopback authority is refused (spec §3: use HTTPS)")

    request = urllib.request.Request(
        url.rstrip("/") + "/v1/receipts",
        data=statement_bytes,
        headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            created = response.status == 201
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise SubmissionError(f"authority rejected the statement: HTTP {exc.code} {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SubmissionError(f"cannot reach the authority: {exc}") from exc

    receipt = parse_receipt_bytes(body)
    if receipt["signed"]["statement"] != statement:
        raise SubmissionError("authority returned a receipt for a different statement")
    return body, created

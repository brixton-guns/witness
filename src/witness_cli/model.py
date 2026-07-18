"""Strict parsing and validation for the closed Witness v0.1 receipt schema."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from .errors import ReceiptValidationError

MAX_RECEIPT_BYTES = 128 * 1024
MAX_STATEMENT_BYTES = 16 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ULID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_AUTHORITY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")
_UTC_SECONDS = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _parse_strict_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError) as exc:
        raise ReceiptValidationError(f"{label} is not strict UTF-8 JSON: {exc}") from exc


def parse_receipt_bytes(raw: bytes) -> dict[str, Any]:
    """Decode strict UTF-8 JSON, rejecting duplicate keys and non-JSON constants."""
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptValidationError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes")
    document = _parse_strict_json(raw, "receipt")
    validate_receipt(document)
    return document


def parse_statement_bytes(raw: bytes) -> dict[str, Any]:
    """Decode and validate a standalone v0.1 statement (the authority's request body)."""
    if len(raw) > MAX_STATEMENT_BYTES:
        raise ReceiptValidationError(f"statement exceeds {MAX_STATEMENT_BYTES} bytes")
    document = _parse_strict_json(raw, "statement")
    validate_statement(document, "statement")
    return document


def _object(value: Any, path: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptValidationError(f"{path} must be an object")
    actual = set(value)
    missing = keys - actual
    unknown = actual - keys
    if missing:
        raise ReceiptValidationError(f"{path} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ReceiptValidationError(f"{path} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise ReceiptValidationError(f"{path} must be a string")
    return value


def _const(value: Any, expected: str, path: str) -> None:
    if value != expected:
        raise ReceiptValidationError(f"{path} must be {expected!r}")


def _pattern(value: Any, pattern: re.Pattern[str], path: str) -> str:
    text = _string(value, path)
    if pattern.fullmatch(text) is None:
        raise ReceiptValidationError(f"{path} has an invalid format")
    return text


def validate_statement(value: Any, path: str = "statement") -> None:
    """Validate a v0.1 statement, standalone or embedded in a signed payload."""
    statement = _object(value, path, {"artifact", "statement_version", "subject"})
    _const(statement["statement_version"], "witness.statement/0.1", f"{path}.statement_version")

    artifact = _object(
        statement["artifact"],
        f"{path}.artifact",
        {"byte_scope", "digest", "media_type"},
    )
    _const(
        artifact["byte_scope"],
        "entire-file-including-final-newline",
        f"{path}.artifact.byte_scope",
    )
    _const(
        artifact["media_type"],
        "application/vnd.cornerstone.ledger+jsonl",
        f"{path}.artifact.media_type",
    )
    digest = _object(
        artifact["digest"],
        f"{path}.artifact.digest",
        {"algorithm", "value"},
    )
    _const(digest["algorithm"], "sha256", f"{path}.artifact.digest.algorithm")
    _pattern(digest["value"], _HEX_64, f"{path}.artifact.digest.value")

    subject = _object(
        statement["subject"],
        f"{path}.subject",
        {"session_id", "spec_version"},
    )
    _pattern(subject["session_id"], _ULID, f"{path}.subject.session_id")
    _const(subject["spec_version"], "cornerstone/0.1", f"{path}.subject.spec_version")


def validate_receipt(value: Any) -> None:
    """Validate every field and reject any extension to protocol v0.1."""
    receipt = _object(value, "receipt", {"receipt_version", "signature", "signed"})
    _const(receipt["receipt_version"], "witness.receipt/0.1", "receipt.receipt_version")

    signature = _object(receipt["signature"], "receipt.signature", {"algorithm", "value"})
    _const(signature["algorithm"], "ed25519", "receipt.signature.algorithm")
    _pattern(signature["value"], _SIGNATURE, "receipt.signature.value")

    signed = _object(
        receipt["signed"],
        "receipt.signed",
        {"authority", "log_index", "receipt_id", "received_at", "statement"},
    )
    authority = _object(signed["authority"], "receipt.signed.authority", {"id", "key_id"})
    authority_id = _pattern(authority["id"], _AUTHORITY_ID, "receipt.signed.authority.id")
    if len(authority_id) > 128:
        raise ReceiptValidationError("receipt.signed.authority.id exceeds 128 characters")
    _pattern(authority["key_id"], _KEY_ID, "receipt.signed.authority.key_id")

    log_index = signed["log_index"]
    if isinstance(log_index, bool) or not isinstance(log_index, int):
        raise ReceiptValidationError("receipt.signed.log_index must be an integer")
    if not 1 <= log_index <= MAX_SAFE_INTEGER:
        raise ReceiptValidationError("receipt.signed.log_index is outside the supported range")

    _pattern(signed["receipt_id"], _ULID, "receipt.signed.receipt_id")
    received_at = _pattern(signed["received_at"], _UTC_SECONDS, "receipt.signed.received_at")
    try:
        datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReceiptValidationError("receipt.signed.received_at is not a real UTC date") from exc

    validate_statement(signed["statement"], "signed.statement")

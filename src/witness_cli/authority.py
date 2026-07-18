"""The signing authority (spec §8): validate, allocate, sign, durably commit."""

from __future__ import annotations

import base64
import hashlib
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from ._ulid import ulid
from .errors import IdempotencyConflictError, ReceiptValidationError
from .keys import SigningKey
from .model import MAX_SAFE_INTEGER, validate_receipt
from .store import ReceiptStore
from .verify import canonical_signed_payload, signing_message

RECEIPT_VERSION = "witness.receipt/0.1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _assert_signable(value: Any, path: str = "signed") -> None:
    """Enforce the closed JCS domain of canonical_signed_payload before signing.

    The M1 audit noted that helper's precondition (ASCII strings, safe
    non-negative integers, nothing else) was documented but not asserted on the
    future signing path. This is that assertion.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ReceiptValidationError(f"{path} has a non-ASCII object key")
            _assert_signable(item, f"{path}.{key}")
    elif isinstance(value, str):
        if not value.isascii():
            raise ReceiptValidationError(f"{path} is not ASCII")
    elif isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptValidationError(f"{path} is not a string, integer, or object")
    elif not 0 <= value <= MAX_SAFE_INTEGER:
        raise ReceiptValidationError(f"{path} is outside the safe integer range")


def canonical_statement_sha256(statement: dict[str, Any]) -> str:
    """The idempotency digest (spec §9): SHA-256 of the canonical statement."""
    return hashlib.sha256(canonical_signed_payload(statement)).hexdigest()


class Authority:
    """Signs validated statements into receipts, one atomic commit each.

    Callers must pass statements that already passed parse_statement_bytes.
    The clock and receipt-id generator are injectable so tests can reproduce
    the committed vector byte for byte.
    """

    def __init__(
        self,
        authority_id: str,
        signing_key: SigningKey,
        store: ReceiptStore,
        *,
        clock: Callable[[], str] = _utc_now,
        new_receipt_id: Callable[[], str] = ulid,
    ):
        self.authority_id = authority_id
        self.key_id = signing_key.key_id
        self.public_key_hex = signing_key.public_key_hex
        self._private_key = signing_key.private_key
        self._store = store
        self._clock = clock
        self._new_receipt_id = new_receipt_id
        self._lock = threading.Lock()

    def submit(self, statement: dict[str, Any], idempotency_key: str) -> tuple[bytes, bool]:
        """Return (receipt bytes, created). A replay returns the original bytes."""
        statement_sha256 = canonical_statement_sha256(statement)
        with self._lock:
            existing = self._store.find_idempotent(idempotency_key)
            if existing is not None:
                stored_sha256, receipt_json = existing
                if stored_sha256 != statement_sha256:
                    raise IdempotencyConflictError(
                        "idempotency key was already used with a different statement"
                    )
                return receipt_json, False

            signed = {
                "authority": {"id": self.authority_id, "key_id": self.key_id},
                "log_index": self._store.next_log_index(),
                "receipt_id": self._new_receipt_id(),
                "received_at": self._clock(),
                "statement": statement,
            }
            _assert_signable(signed)
            signature = self._private_key.sign(signing_message(signed))
            receipt = {
                "receipt_version": RECEIPT_VERSION,
                "signature": {
                    "algorithm": "ed25519",
                    "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
                },
                "signed": signed,
            }
            validate_receipt(receipt)  # never commit a receipt our own verifier would reject
            receipt_json = canonical_signed_payload(receipt) + b"\n"
            self._store.commit_receipt(
                log_index=signed["log_index"],
                receipt_id=signed["receipt_id"],
                received_at=signed["received_at"],
                statement_sha256=statement_sha256,
                receipt_json=receipt_json,
                idempotency_key=idempotency_key,
            )
            return receipt_json, True

    def get_receipt(self, receipt_id: str) -> bytes | None:
        return self._store.get_receipt(receipt_id)

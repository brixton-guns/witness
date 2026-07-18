"""Offline verification of Witness v0.1 receipts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ArtifactMismatchError, InputError, ReceiptValidationError, SignatureError, TrustError
from .model import parse_receipt_bytes

DOMAIN_SEPARATOR = b"WITNESS-RECEIPT-V0.1\n"
_PUBLIC_KEY_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_HASH_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class VerificationResult:
    authority_id: str
    key_id: str
    receipt_id: str
    received_at: str
    session_id: str
    artifact_digest: str
    artifact_verified: bool


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {label} {path}: {exc}") from exc


def load_receipt(path: Path) -> dict[str, Any]:
    return parse_receipt_bytes(_read_bytes(path, "receipt"))


def load_public_key(path: Path) -> tuple[bytes, Ed25519PublicKey]:
    raw = _read_bytes(path, "public key")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InputError("public key file must contain ASCII hexadecimal text") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if _PUBLIC_KEY_HEX.fullmatch(text) is None:
        raise InputError("public key file must contain exactly 64 hexadecimal characters")
    key_bytes = bytes.fromhex(text)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as exc:
        raise InputError("public key is not a valid raw Ed25519 public key") from exc
    return key_bytes, public_key


def canonical_signed_payload(signed: dict[str, Any]) -> bytes:
    """Return the RFC 8785 bytes for a schema-validated v0.1 signed payload.

    The v0.1 schema admits only ASCII strings, fixed ASCII object keys, and one
    safe positive integer. In that closed domain, this serialization is exactly
    RFC 8785 JCS. Callers must validate the receipt before invoking this helper.
    """
    try:
        return json.dumps(
            signed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ReceiptValidationError(f"signed payload cannot be canonicalized: {exc}") from exc


def signing_message(signed: dict[str, Any]) -> bytes:
    return DOMAIN_SEPARATOR + canonical_signed_payload(signed)


def _decode_signature(value: str) -> bytes:
    try:
        signature = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReceiptValidationError("receipt.signature.value is not strict unpadded base64url") from exc
    if len(signature) != 64:
        raise ReceiptValidationError("receipt.signature.value does not decode to 64 bytes")
    canonical = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(canonical, value):
        raise ReceiptValidationError("receipt.signature.value is not canonical base64url")
    return signature


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(_HASH_CHUNK):
                digest.update(chunk)
    except OSError as exc:
        raise InputError(f"cannot read ledger {path}: {exc}") from exc
    return digest.hexdigest()


def verify_receipt(receipt_path: Path, key_path: Path, ledger_path: Path | None = None) -> VerificationResult:
    """Verify signature trust and, optionally, exact ledger bytes."""
    receipt = load_receipt(receipt_path)
    signed = receipt["signed"]
    key_bytes, public_key = load_public_key(key_path)

    actual_key_id = "ed25519:" + hashlib.sha256(key_bytes).hexdigest()
    expected_key_id = signed["authority"]["key_id"]
    if not hmac.compare_digest(actual_key_id, expected_key_id):
        raise TrustError(
            f"trusted public key id {actual_key_id} does not match receipt key id {expected_key_id}"
        )

    signature = _decode_signature(receipt["signature"]["value"])
    try:
        public_key.verify(signature, signing_message(signed))
    except InvalidSignature as exc:
        raise SignatureError("receipt signature is invalid") from exc

    expected_digest = signed["statement"]["artifact"]["digest"]["value"]
    artifact_verified = False
    if ledger_path is not None:
        actual_digest = _hash_file(ledger_path)
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ArtifactMismatchError(
                f"ledger SHA-256 {actual_digest} does not match signed digest {expected_digest}"
            )
        artifact_verified = True

    return VerificationResult(
        authority_id=signed["authority"]["id"],
        key_id=expected_key_id,
        receipt_id=signed["receipt_id"],
        received_at=signed["received_at"],
        session_id=signed["statement"]["subject"]["session_id"],
        artifact_digest=expected_digest,
        artifact_verified=artifact_verified,
    )

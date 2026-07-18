"""Protocol-vector and adversarial tests for offline receipt verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from witness_cli.errors import (
    ArtifactMismatchError,
    ReceiptValidationError,
    SignatureError,
    TrustError,
)
from witness_cli.model import parse_receipt_bytes
from witness_cli.verify import load_receipt, signing_message, verify_receipt

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors"
RECEIPT = VECTORS / "receipt-v0.1.json"
KEY = VECTORS / "public-key.hex"
LEDGER = VECTORS / "sample-events.jsonl"


def _receipt_document() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _write_receipt(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_standalone_fixtures_match_the_protocol_vector():
    vector = json.loads((VECTORS / "vector-v0.1.json").read_text(encoding="utf-8"))
    receipt = load_receipt(RECEIPT)

    assert receipt == vector["receipt"]
    assert KEY.read_text(encoding="ascii").strip() == vector["public_key_hex"]
    assert hashlib.sha256(LEDGER.read_bytes()).hexdigest() == vector["sample_ledger_sha256"]
    assert hashlib.sha256(signing_message(receipt["signed"])).hexdigest() == vector["signing_message_sha256"]


def test_verify_receipt_with_matching_ledger():
    result = verify_receipt(RECEIPT, KEY, LEDGER)

    assert result.authority_id == "witness.test"
    assert result.receipt_id == "01ARZ3NDEKTSV4RRFFQ69G5FAW"
    assert result.session_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    assert result.artifact_verified is True


def test_verify_receipt_without_ledger_checks_only_signature():
    result = verify_receipt(RECEIPT, KEY)
    assert result.artifact_verified is False


def test_valid_but_mutated_signed_field_fails_signature(tmp_path):
    receipt = _receipt_document()
    receipt["signed"]["statement"]["subject"]["session_id"] = "01ARZ3NDEKTSV4RRFFQ69G5FAW"

    with pytest.raises(SignatureError, match="signature is invalid"):
        verify_receipt(_write_receipt(tmp_path, receipt), KEY)


def test_wrong_explicitly_supplied_key_fails_trust(tmp_path):
    wrong_public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    wrong_key = tmp_path / "wrong-key.hex"
    wrong_key.write_text(wrong_public.hex() + "\n", encoding="ascii")

    with pytest.raises(TrustError, match="does not match receipt key id"):
        verify_receipt(RECEIPT, wrong_key)


def test_modified_ledger_fails_artifact_matching(tmp_path):
    ledger = tmp_path / "events.jsonl"
    ledger.write_bytes(LEDGER.read_bytes() + b"\n")

    with pytest.raises(ArtifactMismatchError, match="does not match signed digest"):
        verify_receipt(RECEIPT, KEY, ledger)


def test_duplicate_json_key_is_rejected():
    raw = RECEIPT.read_bytes()
    duplicate = b'{"receipt_version":"witness.receipt/0.1",' + raw.lstrip()[1:]

    with pytest.raises(ReceiptValidationError, match="duplicate object key"):
        parse_receipt_bytes(duplicate)


def test_unknown_field_is_rejected(tmp_path):
    receipt = _receipt_document()
    receipt["signed"]["claim"] = "extra"

    with pytest.raises(ReceiptValidationError, match="unknown fields: claim"):
        load_receipt(_write_receipt(tmp_path, receipt))


def test_invalid_calendar_timestamp_is_rejected(tmp_path):
    receipt = _receipt_document()
    receipt["signed"]["received_at"] = "2026-02-31T12:00:00Z"

    with pytest.raises(ReceiptValidationError, match="not a real UTC date"):
        load_receipt(_write_receipt(tmp_path, receipt))


def test_non_json_numeric_constant_is_rejected():
    raw = RECEIPT.read_text(encoding="utf-8").replace('"log_index": 1', '"log_index": NaN')

    with pytest.raises(ReceiptValidationError, match="non-JSON numeric constant"):
        parse_receipt_bytes(raw.encode("utf-8"))


def test_noncanonical_base64url_signature_is_rejected(tmp_path):
    receipt = _receipt_document()
    signature = receipt["signature"]["value"]
    assert signature.endswith("Q")
    receipt["signature"]["value"] = signature[:-1] + "R"

    with pytest.raises(ReceiptValidationError, match="invalid format"):
        verify_receipt(_write_receipt(tmp_path, receipt), KEY)

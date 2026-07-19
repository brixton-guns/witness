"""witness.statement/0.2: cornerstone/0.2 subjects, closed version dispatch."""

import json
from pathlib import Path

import pytest

from witness_cli.authority import Authority
from witness_cli.errors import ReceiptValidationError
from witness_cli.keys import generate_seed_file
from witness_cli.model import parse_statement_bytes
from witness_cli.store import ReceiptStore
from witness_cli.verify import verify_receipt

VECTORS = Path(__file__).parent.parent / "test-vectors"
VECTOR = json.loads((VECTORS / "vector-v0.1.json").read_text())


def statement_v02(spec_version: str = "cornerstone/0.2") -> dict:
    statement = json.loads(json.dumps(VECTOR["receipt"]["signed"]["statement"]))
    statement["statement_version"] = "witness.statement/0.2"
    statement["subject"]["spec_version"] = spec_version
    return statement


def test_v02_statement_signs_and_verifies_offline(tmp_path):
    signing_key = generate_seed_file(tmp_path / "seed.hex")
    store = ReceiptStore(tmp_path / "receipts.db")
    authority = Authority("witness.dev", signing_key, store)
    receipt_json, created = authority.submit(statement_v02(), "v02-statement-key-0001")
    assert created

    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt_json)
    key_path = tmp_path / "public.hex"
    key_path.write_text(signing_key.public_key_hex + "\n")
    result = verify_receipt(receipt_path, key_path, VECTORS / "sample-events.jsonl")
    assert result.session_id == VECTOR["receipt"]["signed"]["statement"]["subject"]["session_id"]


def test_v02_statement_admits_both_cornerstone_specs():
    parse_statement_bytes(json.dumps(statement_v02("cornerstone/0.2")).encode())
    parse_statement_bytes(json.dumps(statement_v02("cornerstone/0.1")).encode())


def test_v01_statement_rejects_cornerstone_02():
    statement = statement_v02("cornerstone/0.2")
    statement["statement_version"] = "witness.statement/0.1"
    with pytest.raises(ReceiptValidationError, match="spec_version"):
        parse_statement_bytes(json.dumps(statement).encode())


def test_unknown_statement_versions_fail_closed():
    statement = statement_v02()
    statement["statement_version"] = "witness.statement/0.3"
    with pytest.raises(ReceiptValidationError, match="statement_version"):
        parse_statement_bytes(json.dumps(statement).encode())


def test_v02_schema_file_matches_the_model():
    schema = json.loads((Path(__file__).parent.parent / "schemas" / "statement-v0.2.schema.json").read_text())
    assert schema["properties"]["statement_version"]["const"] == "witness.statement/0.2"
    assert schema["properties"]["subject"]["properties"]["spec_version"]["enum"] == [
        "cornerstone/0.1",
        "cornerstone/0.2",
    ]

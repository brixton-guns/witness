"""The signing authority: vector reproduction, idempotency, durability."""

import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from witness_cli.authority import Authority, _assert_signable
from witness_cli.errors import IdempotencyConflictError, InputError, ReceiptValidationError
from witness_cli.keys import SigningKey, generate_seed_file, load_seed_file
from witness_cli.store import ReceiptStore
from witness_cli.verify import verify_receipt

VECTORS = Path(__file__).parent.parent / "test-vectors"
VECTOR = json.loads((VECTORS / "vector-v0.1.json").read_text())
STATEMENT = VECTOR["receipt"]["signed"]["statement"]
IDEMPOTENCY_KEY = "test-idempotency-key-0001"


def vector_signing_key() -> SigningKey:
    seed = bytes.fromhex(VECTOR["private_seed_hex"])
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public = private_key.public_key().public_bytes_raw()
    import hashlib

    return SigningKey(
        private_key=private_key,
        key_id="ed25519:" + hashlib.sha256(public).hexdigest(),
        public_key_hex=public.hex(),
    )


def vector_authority(store: ReceiptStore) -> Authority:
    return Authority(
        "witness.test",
        vector_signing_key(),
        store,
        clock=lambda: "2026-07-18T12:00:00Z",
        new_receipt_id=lambda: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
    )


def test_authority_reproduces_the_committed_vector(tmp_path):
    store = ReceiptStore(tmp_path / "receipts.db")
    receipt_json, created = vector_authority(store).submit(STATEMENT, IDEMPOTENCY_KEY)
    assert created
    receipt = json.loads(receipt_json)
    assert receipt == VECTOR["receipt"]
    assert receipt["signature"]["value"] == VECTOR["receipt"]["signature"]["value"]


def test_receipt_bytes_are_canonical(tmp_path):
    store = ReceiptStore(tmp_path / "receipts.db")
    receipt_json, _ = vector_authority(store).submit(STATEMENT, IDEMPOTENCY_KEY)
    canonical = json.dumps(json.loads(receipt_json), sort_keys=True, separators=(",", ":"))
    assert receipt_json == canonical.encode("ascii") + b"\n"


def test_fresh_key_receipt_verifies_offline_with_the_sample_ledger(tmp_path):
    signing_key = generate_seed_file(tmp_path / "seed.hex")
    store = ReceiptStore(tmp_path / "receipts.db")
    receipt_json, _ = Authority("witness.dev", signing_key, store).submit(STATEMENT, IDEMPOTENCY_KEY)

    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt_json)
    key_path = tmp_path / "public.hex"
    key_path.write_text(signing_key.public_key_hex + "\n")

    result = verify_receipt(receipt_path, key_path, VECTORS / "sample-events.jsonl")
    assert result.authority_id == "witness.dev"
    assert result.artifact_verified
    assert result.session_id == STATEMENT["subject"]["session_id"]


def test_idempotent_replay_returns_the_original_bytes(tmp_path):
    store = ReceiptStore(tmp_path / "receipts.db")
    authority = Authority("witness.dev", generate_seed_file(tmp_path / "seed.hex"), store)
    first, created_first = authority.submit(STATEMENT, IDEMPOTENCY_KEY)
    replay, created_replay = authority.submit(STATEMENT, IDEMPOTENCY_KEY)
    assert created_first and not created_replay
    assert replay == first
    assert store.next_log_index() == 2  # no second index was allocated


def test_key_reuse_with_a_different_statement_conflicts(tmp_path):
    store = ReceiptStore(tmp_path / "receipts.db")
    authority = Authority("witness.dev", generate_seed_file(tmp_path / "seed.hex"), store)
    authority.submit(STATEMENT, IDEMPOTENCY_KEY)
    other = json.loads(json.dumps(STATEMENT))
    other["artifact"]["digest"]["value"] = "0" * 64
    with pytest.raises(IdempotencyConflictError):
        authority.submit(other, IDEMPOTENCY_KEY)


def test_log_index_is_monotonic(tmp_path):
    store = ReceiptStore(tmp_path / "receipts.db")
    authority = Authority("witness.dev", generate_seed_file(tmp_path / "seed.hex"), store)
    indices = []
    for number in range(3):
        receipt_json, _ = authority.submit(STATEMENT, f"monotonic-key-{number:04d}-padding")
        indices.append(json.loads(receipt_json)["signed"]["log_index"])
    assert indices == [1, 2, 3]


def test_committed_receipts_survive_a_restart(tmp_path):
    db = tmp_path / "receipts.db"
    store = ReceiptStore(db)
    authority = Authority("witness.dev", generate_seed_file(tmp_path / "seed.hex"), store)
    receipt_json, _ = authority.submit(STATEMENT, IDEMPOTENCY_KEY)
    receipt_id = json.loads(receipt_json)["signed"]["receipt_id"]
    store.close()

    reopened = ReceiptStore(db)
    assert reopened.get_receipt(receipt_id) == receipt_json
    assert reopened.next_log_index() == 2
    assert reopened.find_idempotent(IDEMPOTENCY_KEY) is not None


def test_signable_domain_is_asserted():
    with pytest.raises(ReceiptValidationError):
        _assert_signable({"note": "café"})
    with pytest.raises(ReceiptValidationError):
        _assert_signable({"value": 0.5})
    with pytest.raises(ReceiptValidationError):
        _assert_signable({"value": -1})
    with pytest.raises(ReceiptValidationError):
        _assert_signable({"value": True})
    _assert_signable({"nested": {"text": "plain", "number": 7}})


def test_keygen_writes_an_owner_only_seed_and_refuses_overwrite(tmp_path):
    seed_path = tmp_path / "seed.hex"
    generate_seed_file(seed_path)
    assert stat.S_IMODE(seed_path.stat().st_mode) == 0o600
    with pytest.raises(InputError):
        generate_seed_file(seed_path)


def test_exposed_seed_files_are_refused(tmp_path):
    seed_path = tmp_path / "seed.hex"
    generate_seed_file(seed_path)
    os.chmod(seed_path, 0o644)
    with pytest.raises(InputError):
        load_seed_file(seed_path)
    os.chmod(seed_path, 0o600)
    assert load_seed_file(seed_path).key_id.startswith("ed25519:")

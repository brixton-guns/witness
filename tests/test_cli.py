"""End-to-end behavior and stable exit codes for the verifier CLI."""

from __future__ import annotations

import json
from pathlib import Path

from witness_cli.cli import main

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors"
RECEIPT = VECTORS / "receipt-v0.1.json"
KEY = VECTORS / "public-key.hex"
LEDGER = VECTORS / "sample-events.jsonl"


def test_cli_verifies_signature_and_artifact(capsys):
    code = main(["verify", str(RECEIPT), "--key", str(KEY), "--ledger", str(LEDGER)])

    assert code == 0
    output = capsys.readouterr().out
    assert "Receipt verified." in output
    assert "Signature: verified" in output
    assert "Artifact: verified" in output


def test_cli_distinguishes_unchecked_artifact(capsys):
    assert main(["verify", str(RECEIPT), "--key", str(KEY)]) == 0
    assert "Artifact: not checked" in capsys.readouterr().out


def test_cli_returns_4_for_signature_failure(tmp_path, capsys):
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    receipt["signed"]["log_index"] = 2
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")

    assert main(["verify", str(path), "--key", str(KEY)]) == 4
    assert "signature is invalid" in capsys.readouterr().err


def test_cli_returns_5_for_artifact_mismatch(tmp_path, capsys):
    ledger = tmp_path / "events.jsonl"
    ledger.write_text("different\n", encoding="utf-8")

    assert main(["verify", str(RECEIPT), "--key", str(KEY), "--ledger", str(ledger)]) == 5
    assert "does not match signed digest" in capsys.readouterr().err


def test_cli_returns_3_for_malformed_receipt(tmp_path, capsys):
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")

    assert main(["verify", str(receipt), "--key", str(KEY)]) == 3
    assert "missing fields" in capsys.readouterr().err

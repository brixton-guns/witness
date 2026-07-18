"""Command-line interface for offline Witness receipt verification."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .errors import WitnessError
from .verify import VerificationResult, verify_receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="witness",
        description="Verify a signed Witness receipt using an explicitly trusted public key.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify a receipt offline")
    verify.add_argument("receipt", type=Path, help="path to a Witness receipt JSON file")
    verify.add_argument(
        "--key",
        type=Path,
        required=True,
        help="trusted raw Ed25519 public key as a 64-character hexadecimal file",
    )
    verify.add_argument(
        "--ledger",
        type=Path,
        help="optional events.jsonl whose exact bytes must match the signed digest",
    )
    return parser


def _render(result: VerificationResult) -> str:
    artifact = (
        f"verified (sha256:{result.artifact_digest})"
        if result.artifact_verified
        else "not checked (no ledger supplied)"
    )
    return "\n".join(
        [
            "Receipt verified.",
            f"Authority: {result.authority_id}",
            f"Key: {result.key_id}",
            f"Receipt: {result.receipt_id}",
            f"Accepted: {result.received_at}",
            f"Session: {result.session_id}",
            "Signature: verified",
            f"Artifact: {artifact}",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_receipt(args.receipt, args.key, args.ledger)
            print(_render(result))
            return 0
    except WitnessError as exc:
        print(f"witness: {exc}", file=sys.stderr)
        return exc.exit_code
    raise AssertionError(f"unhandled command: {args.command}")


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()

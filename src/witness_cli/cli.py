"""Command-line interface: witness verify / keygen / serve / submit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .errors import InputError, WitnessError
from .keys import NON_PRODUCTION_WARNING, generate_seed_file, load_seed_file
from .verify import VerificationResult, verify_receipt

_AUTHORITY_DEFAULT_PORT = 8899


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="witness",
        description="Signed receipts for Cornerstone ledger digests: verify, issue, submit.",
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

    keygen = commands.add_parser("keygen", help="generate a development Ed25519 seed file")
    keygen.add_argument("seed", type=Path, help="path for the new owner-only seed file")
    keygen.add_argument(
        "--public-out",
        type=Path,
        help="also write the public key as a 64-character hexadecimal file",
    )

    serve = commands.add_parser("serve", help="run a receipt authority")
    serve.add_argument("--db", type=Path, required=True, help="SQLite receipt database path")
    serve.add_argument("--seed", type=Path, required=True, help="Ed25519 seed file (owner-only)")
    serve.add_argument(
        "--authority-id",
        required=True,
        help="stable authority identifier recorded in every receipt",
    )
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=_AUTHORITY_DEFAULT_PORT)
    serve.add_argument(
        "--behind-https-proxy",
        action="store_true",
        help="acknowledge that a non-loopback bind is reached only through HTTPS (spec §3)",
    )

    submit = commands.add_parser("submit", help="submit a statement, print or save the receipt")
    submit.add_argument(
        "statement",
        nargs="?",
        type=Path,
        help="statement JSON file; omit or use - to read stdin (e.g. from stone attest)",
    )
    submit.add_argument("--url", required=True, help="authority base URL")
    submit.add_argument(
        "--idempotency-key",
        help="override the default key derived from the canonical statement digest",
    )
    submit.add_argument(
        "--out",
        type=Path,
        help="write the receipt to a new file instead of stdout (refuses to overwrite)",
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


def _cmd_keygen(args: argparse.Namespace) -> int:
    signing_key = generate_seed_file(args.seed)
    if args.public_out is not None:
        try:
            with open(args.public_out, "x", encoding="ascii") as fh:
                fh.write(signing_key.public_key_hex + "\n")
        except OSError as exc:
            raise InputError(f"cannot write public key file: {exc}") from exc
    print(f"witness: {NON_PRODUCTION_WARNING}", file=sys.stderr)
    print(f"Seed: {args.seed} (mode 600)")
    print(f"Key id: {signing_key.key_id}")
    print(f"Public key: {signing_key.public_key_hex}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .authority import Authority
    from .server import WitnessServer, host_is_loopback
    from .store import ReceiptStore

    if not host_is_loopback(args.host) and not args.behind_https_proxy:
        print(
            f"witness: refusing to bind {args.host} over plain HTTP; non-loopback deployments"
            " MUST sit behind HTTPS (spec §3). Pass --behind-https-proxy to acknowledge.",
            file=sys.stderr,
        )
        return 2
    signing_key = load_seed_file(args.seed)
    store = ReceiptStore(args.db)
    authority = Authority(args.authority_id, signing_key, store)
    server = WitnessServer(args.host, args.port, authority)
    host, port = server.server_address[:2]
    print(f"witness: {NON_PRODUCTION_WARNING}", file=sys.stderr)
    print(f"witness: authority {args.authority_id} ({authority.key_id})", file=sys.stderr)
    print(f"witness: listening on http://{host}:{port} (db: {args.db})", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("witness: shutting down", file=sys.stderr)
    finally:
        server.server_close()
        store.close()
    return 0


def _cmd_submit(args: argparse.Namespace) -> int:
    from .client import submit_statement

    if args.statement is None or str(args.statement) == "-":
        statement_bytes = sys.stdin.buffer.read()
    else:
        try:
            statement_bytes = args.statement.read_bytes()
        except OSError as exc:
            raise InputError(f"cannot read statement {args.statement}: {exc}") from exc
    receipt_json, created = submit_statement(args.url, statement_bytes, args.idempotency_key)
    if args.out is not None:
        try:
            with open(args.out, "xb") as fh:
                fh.write(receipt_json)
        except OSError as exc:
            raise InputError(f"cannot write receipt to {args.out}: {exc}") from exc
        print(f"Receipt {'accepted' if created else 'replayed'}: {args.out}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(receipt_json)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_receipt(args.receipt, args.key, args.ledger)
            print(_render(result))
            return 0
        if args.command == "keygen":
            return _cmd_keygen(args)
        if args.command == "serve":
            return _cmd_serve(args)
        if args.command == "submit":
            return _cmd_submit(args)
    except WitnessError as exc:
        print(f"witness: {exc}", file=sys.stderr)
        return exc.exit_code
    raise AssertionError(f"unhandled command: {args.command}")


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()

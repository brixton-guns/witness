# Witness

Witness is an independent receipt authority for Cornerstone ledgers.

It accepts the SHA-256 digest of an exact `events.jsonl` byte sequence and
returns a signed, timestamped receipt. The receipt can later be verified
offline against a separately trusted public key and, when available, the
original ledger.

Witness answers one narrow question:

> Can I verify that this authority accepted this exact ledger digest no later
> than the time recorded in the receipt?

It does not decide whether the ledger is truthful, whether the recorded command
caused the effects, or when those effects occurred.

## Status

Protocol v0.1 is specified. Milestone M1 implements offline verification only:
there is no signing authority, network service, database, or private-key code.

The repository contains:

- [`WITNESS_SPEC_v0.1.md`](WITNESS_SPEC_v0.1.md)
- [`schemas/statement-v0.1.schema.json`](schemas/statement-v0.1.schema.json)
- [`schemas/receipt-v0.1.schema.json`](schemas/receipt-v0.1.schema.json)
- [`test-vectors/vector-v0.1.json`](test-vectors/vector-v0.1.json)
- [`test-vectors/sample-events.jsonl`](test-vectors/sample-events.jsonl)
- the `witness verify` CLI and its verification library

## Install for development

Requires Python 3.11 or later.

```sh
python -m pip install -e .
```

## Verify a receipt

The public key file is an explicitly trusted raw Ed25519 public key encoded as
exactly 64 hexadecimal characters. It is not extracted from the receipt.

```sh
witness verify test-vectors/receipt-v0.1.json \
  --key test-vectors/public-key.hex \
  --ledger test-vectors/sample-events.jsonl
```

With `--ledger`, success means both the signature and the exact ledger bytes
were verified. Without it, the CLI reports that the signature was verified but
the artifact was not checked.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | requested verification succeeded |
| `2` | invalid command-line usage |
| `3` | unreadable or malformed input |
| `4` | key trust or signature failure |
| `5` | ledger digest mismatch |

## Test

```sh
python -m pytest -q
```

Cornerstone remains independent. Witness consumes a digest; it does not need to
be embedded in the observed workspace or trusted by the observed process.

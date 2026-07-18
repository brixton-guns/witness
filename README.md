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

Protocol v0.1 is specified and fully implemented:

- **M1** — offline verification (`witness verify`);
- **M2** — the signing authority (`witness serve`), a development key tool
  (`witness keygen`), and a submission client (`witness submit`).

The authority reproduces the committed Ed25519 test vector byte for byte, and
every receipt it issues is validated against the same closed schema the
verifier enforces before it is committed or returned.

The repository contains:

- [`WITNESS_SPEC_v0.1.md`](WITNESS_SPEC_v0.1.md)
- [`schemas/statement-v0.1.schema.json`](schemas/statement-v0.1.schema.json)
- [`schemas/receipt-v0.1.schema.json`](schemas/receipt-v0.1.schema.json)
- [`test-vectors/vector-v0.1.json`](test-vectors/vector-v0.1.json)
- [`test-vectors/sample-events.jsonl`](test-vectors/sample-events.jsonl)
- the `witness` CLI: `verify`, `keygen`, `serve`, `submit`

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
| `0` | requested operation succeeded |
| `2` | invalid command-line usage |
| `3` | unreadable or malformed input |
| `4` | key trust or signature failure |
| `5` | ledger digest mismatch |
| `6` | idempotency conflict, or the authority rejected / cannot be reached |

## Run a development authority

```sh
witness keygen authority-seed.hex --public-out authority-public.hex
witness serve --db receipts.db --seed authority-seed.hex --authority-id witness.dev
```

The seed file is created with owner-only permissions and refused if anything
else can read it. A file-based key under the same user account as the observed
workspace is a development arrangement, not a strong trust boundary (spec §3):
keep it outside any observed workspace and out of source control.

The server binds `127.0.0.1` by default. A non-loopback bind is refused unless
`--behind-https-proxy` acknowledges that clients reach it only through HTTPS.

Endpoints (spec §10): `POST /v1/receipts` (requires an `Idempotency-Key`
header; `201` on acceptance, `200` on an idempotent replay, `409` on key reuse
with a different statement), `GET /v1/receipts/{receipt_id}`, and
`GET /v1/keys/{key_id}` — fetching the key endpoint does not make the key
trusted.

## The full chain with Cornerstone

`stone attest` emits the statement; Witness signs it; verification is offline:

```sh
stone attest latest | witness submit --url http://127.0.0.1:8899 --out receipt.json
witness verify receipt.json \
  --key authority-public.hex \
  --ledger .stone/sessions/<session_id>/events.jsonl
```

`witness submit` validates the statement locally before it leaves the machine,
derives a deterministic idempotency key from the canonical statement digest
(so blind retries are safe), and refuses plain HTTP to non-loopback hosts. It
also checks that the returned receipt carries exactly the submitted statement:
an authority that alters it is reported, not trusted.

## Test

```sh
python -m pytest -q
```

Cornerstone remains independent. Witness consumes a digest; it does not need to
be embedded in the observed workspace or trusted by the observed process.

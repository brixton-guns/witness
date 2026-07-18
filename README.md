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

Protocol v0.1 is specified. No server or CLI implementation exists yet.

The first milestone deliberately contains only the protocol contract, schemas,
threat model, and a deterministic Ed25519 test vector:

- [`WITNESS_SPEC_v0.1.md`](WITNESS_SPEC_v0.1.md)
- [`schemas/statement-v0.1.schema.json`](schemas/statement-v0.1.schema.json)
- [`schemas/receipt-v0.1.schema.json`](schemas/receipt-v0.1.schema.json)
- [`test-vectors/vector-v0.1.json`](test-vectors/vector-v0.1.json)
- [`test-vectors/sample-events.jsonl`](test-vectors/sample-events.jsonl)

Cornerstone remains independent. Witness consumes a digest; it does not need to
be embedded in the observed workspace or trusted by the observed process.

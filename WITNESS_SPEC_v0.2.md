# Witness Protocol Specification v0.2

Status: **frozen for implementation**
Protocol identifier: `witness/0.2`

This is a delta specification. Everything in `WITNESS_SPEC_v0.1.md` remains in
force except as amended below.

## 1. Motivation

Cornerstone spec v0.2 introduces ledgers whose `session.started` record
declares `spec: "0.2"` (confinement fields). The v0.1 statement fixes
`subject.spec_version` to the constant `cornerstone/0.1` and therefore cannot
describe them.

## 2. Statement v0.2

A new statement version, `witness.statement/0.2`, defined exactly by
`schemas/statement-v0.2.schema.json`. It is identical to v0.1 except:

- `statement_version` is the constant `witness.statement/0.2`;
- `subject.spec_version` admits `cornerstone/0.1` and `cornerstone/0.2`.

Nothing else changes. In particular the digest algorithm remains the constant
`sha256`: algorithm agility lives in statement version bumps, never in a
negotiable field.

## 3. Authority and verifier behavior

- Authorities MUST accept statements of either version, validating each
  against the schema its `statement_version` declares, and MUST reject any
  other version.
- Receipts embed the statement unchanged; `receipt_version` remains
  `witness.receipt/0.1`. The embedded statement is validated per its own
  declared version.
- Verifiers MUST accept receipts embedding either statement version and MUST
  fail closed on any other.
- A v0.1-only verifier rejects v0.2 statements: that is fail-closed behavior,
  not an interoperability bug.

## 4. Compatibility

Receipts already issued for v0.1 statements remain valid indefinitely: every
receipt declares its statement version, and old public keys stay in the
verifier's trusted set per v0.1 §13.

## 5. Ordering

This protocol version MUST be implemented and released before any client emits
`witness.statement/0.2` (Cornerstone spec v0.2, cornerstone-cli 0.3.0).

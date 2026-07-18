# Witness Protocol Specification v0.1

Status: **frozen for implementation**
Protocol identifier: `witness/0.1`

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in RFC 2119
and RFC 8174 when, and only when, they appear in all capitals.

## 1. Purpose

Witness is an independent authority that accepts a statement binding a
Cornerstone session identifier to the SHA-256 digest of its ledger and returns
an Ed25519-signed receipt with an authority-assigned acceptance time.

The receipt is portable. Verification does not require access to the authority
after the verifier has obtained and trusted the corresponding public key.

## 2. The exact claim

A valid receipt means:

> The authority identified in the signed payload accepted the exact statement
> in this receipt no later than `received_at`, assigned it `log_index`, and
> signed it with the private key corresponding to `key_id`.

The verifier trusts the authority for:

1. custody of the private signing key;
2. the accuracy of its clock;
3. durable storage of accepted receipts;
4. monotonic allocation of `log_index` within that authority.

A receipt does **not** prove:

- that the ledger is structurally valid or truthful;
- that the declared session produced the submitted digest;
- that the effects in the ledger were caused by the declared actor;
- that the ledger existed before `received_at`;
- that `received_at` is trustworthy if the authority clock is dishonest;
- that no other receipt was deleted or withheld;
- that the signing key was never compromised;
- that the submitter owns or authored the artifact.

## 3. Trust boundary and threat model

The observed process and its workspace are untrusted. They MAY know the
protocol, read public verification keys, delete or rewrite local ledgers, and
submit arbitrary digests to a publicly reachable authority.

The observed process MUST NOT be able to:

- read or use the authority's private signing key directly;
- rewrite the authority's receipt database;
- change the authority's trusted clock or key configuration;
- cause the verifier to trust a public key merely because that key appears in a
  receipt.

The authority therefore MUST run outside the observed workspace and outside the
observed process's filesystem authority. A second process with a key stored
under the same writable user account is a development arrangement, not a strong
trust boundary.

Transport authentication and receipt signatures solve different problems.
Non-loopback deployments MUST use HTTPS even though receipts are signed.

## 4. Artifact bytes and digest

For protocol v0.1 the only accepted artifact is a Cornerstone ledger with media
type:

`application/vnd.cornerstone.ledger+jsonl`

The digest is SHA-256 over the **entire byte sequence** of `events.jsonl`,
including its final newline. The ledger MUST NOT be parsed, normalized,
re-encoded, or newline-converted before hashing.

Pseudocode:

```text
digest = lowercase_hex(SHA256(read_all_bytes("events.jsonl")))
```

The authority receives only the digest and metadata in v0.1. It cannot verify
the ledger's structure. A client SHOULD verify the Cornerstone ledger locally
before submitting its digest.

## 5. Statement

The request body MUST conform exactly to
`schemas/statement-v0.1.schema.json`. Unknown fields are rejected.

Example:

```json
{
  "artifact": {
    "byte_scope": "entire-file-including-final-newline",
    "digest": {
      "algorithm": "sha256",
      "value": "eeb163873b7a68a19ce2b5eb974ba5968b491c8e9135b25ed749bce60e14c90d"
    },
    "media_type": "application/vnd.cornerstone.ledger+jsonl"
  },
  "statement_version": "witness.statement/0.1",
  "subject": {
    "session_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "spec_version": "cornerstone/0.1"
  }
}
```

`session_id` is client-supplied metadata. The authority binds it to the digest
but does not independently establish that relationship.

## 6. Receipt

The response body MUST conform exactly to
`schemas/receipt-v0.1.schema.json`. Unknown fields are rejected.

The receipt contains three top-level fields:

- `receipt_version`: protocol discriminator;
- `signed`: the complete signed payload;
- `signature`: algorithm and encoded signature.

The signed payload contains:

- `authority.id`: stable operator-chosen authority identifier;
- `authority.key_id`: fingerprint of the signing public key;
- `log_index`: positive, monotonically increasing integer;
- `receipt_id`: authority-generated ULID;
- `received_at`: authority acceptance time in UTC;
- `statement`: the exact validated client statement.

The authority MUST copy the statement without semantic additions or removals.
Object member order is immaterial because signing uses canonical JSON.

## 7. Canonicalization and signature

### 7.1 Canonical payload

The value of the receipt's `signed` member MUST be serialized using the JSON
Canonicalization Scheme defined by RFC 8785 (JCS), encoded as UTF-8.

Protocol v0.1 restricts numeric values in the signed payload to non-negative
integers no greater than `9007199254740991`. Floating-point values are absent.

The exact signature message is:

```text
ASCII("WITNESS-RECEIPT-V0.1\n") || UTF8(JCS(receipt.signed))
```

The prefix is mandatory domain separation. It is part of the signed bytes.

### 7.2 Ed25519

The authority MUST sign the message with Ed25519. The raw 64-byte signature is
encoded as unpadded base64url, as defined by RFC 4648 section 5.

`signature.algorithm` MUST be `ed25519`.

### 7.3 Key identifier

The Ed25519 public key is its raw 32-byte representation. Its identifier is:

```text
"ed25519:" || lowercase_hex(SHA256(raw_public_key))
```

The receipt does not embed the public key. A verifier MUST obtain it from a
separately trusted source and MUST confirm that its computed identifier equals
`authority.key_id`.

Trusting a key supplied alongside an untrusted receipt, without an independent
pin or trust decision, proves only self-consistency and is invalid verification.

## 8. Authority behavior

For `POST /v1/receipts`, the authority MUST perform these steps in order:

1. read the complete request body within the configured size limit;
2. decode UTF-8 JSON and reject duplicate object keys;
3. validate the statement against the v0.1 schema;
4. enforce idempotency rules;
5. allocate `receipt_id`, `received_at`, and the next `log_index`;
6. construct and sign the receipt;
7. durably commit the statement, receipt, and idempotency mapping in one
   transaction;
8. return the committed receipt.

`received_at` records acceptance after validation, not connection time or an
untrusted client timestamp. It MUST use the form `YYYY-MM-DDTHH:MM:SSZ`.

The authority MUST NOT return a successful response before the receipt is
durable. It MUST NOT update or delete committed receipt rows during normal
operation.

## 9. Idempotency

`POST /v1/receipts` requires an `Idempotency-Key` header containing 16 to 128
ASCII characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, and `-`.

Within one authority:

- the first accepted key is stored with the SHA-256 digest of the canonical
  statement and the resulting receipt;
- a retry with the same key and same canonical statement returns the original
  receipt without allocating a new index;
- the same key with a different statement returns HTTP `409`.

Idempotency keys are operational identifiers, not authentication credentials.

## 10. HTTP interface

### `POST /v1/receipts`

Creates or idempotently retrieves a receipt.

- Request: statement JSON plus `Idempotency-Key` header.
- Success: `201 Created` for a new receipt, `200 OK` for an idempotent replay.
- Response: receipt JSON.

### `GET /v1/receipts/{receipt_id}`

Returns a committed receipt or `404 Not Found`.

### `GET /v1/keys/{key_id}`

Returns public verification material and authority metadata. Fetching this
endpoint does not itself make the key trusted.

The v0.1 protocol does not prescribe submitter authentication. A deployment MAY
require it. Public deployments SHOULD rate-limit submissions.

## 11. Verification algorithm

Given a receipt, a trusted Ed25519 public key, and optionally a ledger:

1. decode JSON while rejecting duplicate object keys;
2. validate the receipt against the v0.1 schema;
3. compute the key identifier and compare it to `authority.key_id`;
4. construct the domain-separated canonical signature message;
5. decode the unpadded base64url signature strictly;
6. verify the Ed25519 signature;
7. if a ledger is supplied, hash its exact bytes and compare the lowercase
   digest to `statement.artifact.digest.value`;
8. report the signed authority, receipt ID, acceptance time, session ID, and
   whether artifact matching was performed.

Verification MUST fail closed on an unknown receipt version, unknown algorithm,
unknown key, malformed schema, signature failure, or artifact mismatch.

A successful signature check without a separately trusted public key MUST NOT be
reported as trusted verification.

## 12. Persistence and crash behavior

The reference implementation MAY use SQLite, but the protocol does not require
a particular database.

Receipt creation, `log_index` allocation, and idempotency storage MUST be one
atomic transaction. A crash after commit and before response is resolved by an
idempotent retry.

The database is logically append-only, but v0.1 does not provide a Merkle tree,
gossip protocol, or externally anchored log head. Consequently, a receipt held
by a client remains verifiable if the authority later deletes it, but v0.1 does
not cryptographically prove global log completeness or non-equivocation.

## 13. Key management

Production private keys MUST NOT be stored in the observed workspace, in the
receipt database, or in source control. File-based development keys MUST use
owner-only permissions and MUST be clearly marked non-production.

Every receipt identifies its key, so old receipts remain verifiable after key
rotation as long as the corresponding public key remains in the verifier's
trusted key set.

Key generation, secure hardware, revocation distribution, and compromise
recovery policy are deployment responsibilities in v0.1. Retroactive re-signing
of old receipts is forbidden.

## 14. Privacy

Witness does not require ledger upload in v0.1. The statement still exposes a
session identifier, protocol version, artifact type, and stable digest.

Digests are not encryption. They reveal equality and may permit confirmation of
guessed low-entropy artifacts. Operators MUST treat receipt metadata according
to their deployment's privacy requirements.

## 15. Cornerstone integration

Integration is client-side and optional:

```text
verify local ledger
→ hash exact events.jsonl bytes
→ submit statement to Witness
→ save receipt outside or beside the ledger
→ pin the authority public key independently
```

Cornerstone success MUST NOT be redefined by Witness availability in protocol
v0.1. A wrapper MAY choose fail-open or fail-closed policy, but it MUST report
whether attestation actually succeeded.

Attesting later remains valid, but proves only the later `received_at` bound.

## 16. Non-goals of v0.1

- ledger upload or archival;
- Cornerstone ledger parsing by the authority;
- actor identity or submitter identity claims;
- proof of effect causality;
- trusted hardware requirements;
- a public transparency log or Merkle inclusion proofs;
- consensus timestamps or blockchain anchoring;
- dashboards, accounts, teams, billing, or multi-region replication;
- automatic changes to Cornerstone.

## 17. Acceptance criteria

An implementation conforms to v0.1 only if:

1. its schemas reject unknown fields and malformed identifiers;
2. it reproduces the committed Ed25519 test vector byte-for-byte;
3. changing any signed field invalidates the signature;
4. changing the sample ledger invalidates artifact matching;
5. verification fails with an untrusted or wrong public key;
6. idempotent retries return the original receipt;
7. conflicting reuse of an idempotency key returns `409`;
8. committed receipts survive process restart;
9. no private key is written into a receipt or the receipt database;
10. all successful responses refer to durably committed receipts.

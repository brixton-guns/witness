"""Durable receipt storage (spec §12): one atomic transaction per acceptance."""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    log_index INTEGER PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE,
    received_at TEXT NOT NULL,
    statement_sha256 TEXT NOT NULL,
    receipt_json BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    idempotency_key TEXT PRIMARY KEY,
    statement_sha256 TEXT NOT NULL,
    log_index INTEGER NOT NULL REFERENCES receipts(log_index)
);
"""


class ReceiptStore:
    """SQLite-backed, logically append-only receipt log.

    Callers must serialize submissions externally; the store guarantees that a
    receipt, its idempotency mapping, and its log index become durable in one
    transaction, with synchronous=FULL so a successful commit survives a crash.
    """

    def __init__(self, path: Path | str):
        self._connection = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def next_log_index(self) -> int:
        row = self._connection.execute("SELECT COALESCE(MAX(log_index), 0) + 1 FROM receipts").fetchone()
        return row[0]

    def find_idempotent(self, idempotency_key: str) -> tuple[str, bytes] | None:
        """Return (statement_sha256, receipt_json) for a known key, else None."""
        row = self._connection.execute(
            "SELECT i.statement_sha256, r.receipt_json FROM idempotency i"
            " JOIN receipts r ON r.log_index = i.log_index"
            " WHERE i.idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        return None if row is None else (row[0], row[1])

    def commit_receipt(
        self,
        *,
        log_index: int,
        receipt_id: str,
        received_at: str,
        statement_sha256: str,
        receipt_json: bytes,
        idempotency_key: str,
    ) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "INSERT INTO receipts (log_index, receipt_id, received_at, statement_sha256, receipt_json)"
                " VALUES (?, ?, ?, ?, ?)",
                (log_index, receipt_id, received_at, statement_sha256, receipt_json),
            )
            self._connection.execute(
                "INSERT INTO idempotency (idempotency_key, statement_sha256, log_index) VALUES (?, ?, ?)",
                (idempotency_key, statement_sha256, log_index),
            )
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")

    def get_receipt(self, receipt_id: str) -> bytes | None:
        row = self._connection.execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        return None if row is None else row[0]

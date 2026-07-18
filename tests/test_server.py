"""The HTTP authority and the submission client, over a live loopback server."""

import http.client
import json
import threading
from pathlib import Path

import pytest

from witness_cli.authority import Authority
from witness_cli.client import submit_statement
from witness_cli.errors import SubmissionError
from witness_cli.keys import generate_seed_file
from witness_cli.server import WitnessServer, host_is_loopback
from witness_cli.store import ReceiptStore
from witness_cli.verify import verify_receipt

VECTORS = Path(__file__).parent.parent / "test-vectors"
VECTOR = json.loads((VECTORS / "vector-v0.1.json").read_text())
STATEMENT_BYTES = json.dumps(VECTOR["receipt"]["signed"]["statement"]).encode()
IDEMPOTENCY_KEY = "server-test-key-0001"


@pytest.fixture()
def live_server(tmp_path, monkeypatch):
    monkeypatch.setattr("http.server.BaseHTTPRequestHandler.log_message", lambda *args: None)
    signing_key = generate_seed_file(tmp_path / "seed.hex")
    store = ReceiptStore(tmp_path / "receipts.db")
    authority = Authority("witness.dev", signing_key, store)
    server = WitnessServer("127.0.0.1", 0, authority)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        store.close()
        thread.join(timeout=5)


def request(server, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, payload


def post_statement(server, body=STATEMENT_BYTES, key=IDEMPOTENCY_KEY):
    return request(
        server,
        "POST",
        "/v1/receipts",
        body=body,
        headers={"Content-Type": "application/json", "Idempotency-Key": key},
    )


def test_post_issues_a_receipt_and_get_returns_it(live_server):
    status, body = post_statement(live_server)
    assert status == 201
    receipt = json.loads(body)
    assert receipt["signed"]["statement"] == json.loads(STATEMENT_BYTES)

    status, fetched = request(live_server, "GET", f"/v1/receipts/{receipt['signed']['receipt_id']}")
    assert status == 200
    assert fetched == body


def test_idempotent_replay_is_200_with_identical_bytes(live_server):
    status_first, first = post_statement(live_server)
    status_replay, replay = post_statement(live_server)
    assert (status_first, status_replay) == (201, 200)
    assert replay == first


def test_key_conflict_is_409(live_server):
    post_statement(live_server)
    other = json.loads(STATEMENT_BYTES)
    other["artifact"]["digest"]["value"] = "0" * 64
    status, body = post_statement(live_server, body=json.dumps(other).encode())
    assert status == 409
    assert "idempotency" in json.loads(body)["error"]


def test_missing_or_malformed_idempotency_key_is_400(live_server):
    status, _ = request(live_server, "POST", "/v1/receipts", body=STATEMENT_BYTES)
    assert status == 400
    status, _ = post_statement(live_server, key="short")
    assert status == 400


def test_invalid_statements_are_400(live_server):
    unknown_field = json.loads(STATEMENT_BYTES)
    unknown_field["extra"] = 1
    status, body = post_statement(live_server, body=json.dumps(unknown_field).encode())
    assert status == 400
    assert "unknown fields" in json.loads(body)["error"]

    duplicate_keys = b'{"statement_version":"witness.statement/0.1","statement_version":"witness.statement/0.1"}'
    status, body = post_statement(live_server, body=duplicate_keys)
    assert status == 400
    assert "duplicate" in json.loads(body)["error"]


def test_oversized_bodies_are_413(live_server):
    status, _ = request(
        live_server,
        "POST",
        "/v1/receipts",
        body=b"x",
        headers={"Idempotency-Key": IDEMPOTENCY_KEY, "Content-Length": str(10**6)},
    )
    assert status == 413


def test_key_endpoint_serves_material_only_for_its_own_key(live_server):
    authority = live_server.authority
    status, body = request(live_server, "GET", f"/v1/keys/{authority.key_id}")
    assert status == 200
    material = json.loads(body)
    assert material["public_key_hex"] == authority.public_key_hex
    assert material["authority_id"] == "witness.dev"

    status, _ = request(live_server, "GET", "/v1/keys/ed25519:" + "0" * 64)
    assert status == 404


def test_unknown_resources_are_404(live_server):
    assert request(live_server, "GET", "/v1/receipts/not-a-ulid")[0] == 404
    assert request(live_server, "GET", "/nowhere")[0] == 404
    assert request(live_server, "POST", "/nowhere")[0] == 404


def test_client_round_trip_and_offline_verification(live_server, tmp_path):
    url = f"http://127.0.0.1:{live_server.server_address[1]}"
    receipt_json, created = submit_statement(url, STATEMENT_BYTES)
    replay_json, replayed = submit_statement(url, STATEMENT_BYTES)
    assert created and not replayed
    assert replay_json == receipt_json

    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt_json)
    key_path = tmp_path / "public.hex"
    key_path.write_text(live_server.authority.public_key_hex + "\n")
    result = verify_receipt(receipt_path, key_path, VECTORS / "sample-events.jsonl")
    assert result.artifact_verified


def test_client_refuses_plain_http_to_non_loopback_hosts():
    with pytest.raises(SubmissionError):
        submit_statement("http://example.com", STATEMENT_BYTES)


def test_loopback_detection():
    assert host_is_loopback("127.0.0.1")
    assert host_is_loopback("::1")
    assert host_is_loopback("localhost")
    assert not host_is_loopback("0.0.0.0")
    assert not host_is_loopback("192.168.1.10")
    assert not host_is_loopback("example.com")

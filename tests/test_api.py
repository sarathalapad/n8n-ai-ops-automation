from typing import Any

import pytest
from fastapi.testclient import TestClient

from opsguard.audit import AuditLog
from opsguard.main import Settings, create_app

TOKEN = "test-token"
HDR = {"X-OpsGuard-Token": TOKEN}

GOOD_TRIAGE: dict[str, Any] = {
    "category": "application",
    "priority": "P1",
    "team": "payments",
    "summary": "Checkout returns 502 for all customers since 09:05.",
    "confidence": 0.9,
    "proposed_action": {"action": "restart_service", "target": "payments-api", "reason": "hung workers"},
}


@pytest.fixture
def client() -> TestClient:
    app = create_app(Settings(api_token=TOKEN, approvers=frozenset({"bob"})), AuditLog())
    return TestClient(app)


def test_healthz_is_public(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"


def test_token_is_required(client: TestClient) -> None:
    assert client.post("/v1/redact", json={"fields": {}}).status_code == 401
    bad = client.post("/v1/redact", json={"fields": {}}, headers={"X-OpsGuard-Token": "nope"})
    assert bad.status_code == 401


def test_unconfigured_token_fails_closed_unless_dev_mode() -> None:
    closed = TestClient(create_app(Settings(), AuditLog()))
    assert closed.get("/v1/catalog").status_code == 503
    dev = TestClient(create_app(Settings(dev_mode=True), AuditLog()))
    assert dev.get("/v1/catalog").status_code == 200


def test_redact_endpoint(client: TestClient) -> None:
    body = {"fields": {"title": "VPN down", "description": "ping me at ops.lead@example.com"}}
    resp = client.post("/v1/redact", json=body, headers=HDR).json()
    assert resp["fields"]["description"] == "ping me at [EMAIL_1]"
    assert resp["findings"] == {"EMAIL": 1} and resp["redacted"] is True


def test_validate_triage_accepts_good_output(client: TestClient) -> None:
    resp = client.post("/v1/validate/triage", json={"output": GOOD_TRIAGE}, headers=HDR).json()
    assert resp["valid"] and not resp["needs_human_review"]
    assert resp["data"]["proposed_action"]["action"] == "restart_service"


def test_validate_triage_accepts_fenced_json_string(client: TestClient) -> None:
    import json

    raw = "```json\n" + json.dumps(GOOD_TRIAGE) + "\n```"
    assert client.post("/v1/validate/triage", json={"output": raw}, headers=HDR).json()["valid"]


@pytest.mark.parametrize(
    ("patch", "fragment"),
    [
        ({"priority": "urgent"}, "priority"),
        ({"team": "wizards"}, "unknown team"),
        ({"summary": "Customer bob@example.com is angry about checkout"}, "unredacted"),
        ({"proposed_action": {"action": "drop_database", "target": "orders-db", "reason": "x"}},
         "unknown action"),
        ({"proposed_action": {"action": "restart_service", "target": "mainframe", "reason": "x"}},
         "unknown service"),
        ({"category": "security"}, "security team"),
        ({"extra_field": 1}, "extra_field"),
    ],
)
def test_validate_triage_rejects_bad_output(client: TestClient, patch: dict, fragment: str) -> None:
    resp = client.post("/v1/validate/triage", json={"output": {**GOOD_TRIAGE, **patch}}, headers=HDR).json()
    assert not resp["valid"] and resp["needs_human_review"] and resp["data"] is None
    assert any(fragment in e for e in resp["errors"]), resp["errors"]


def test_validate_triage_handles_garbage_and_null(client: TestClient) -> None:
    for output in ["I think it's a network issue", None, 42]:
        resp = client.post("/v1/validate/triage", json={"output": output}, headers=HDR).json()
        assert resp["valid"] is False


def test_low_confidence_is_valid_but_needs_review(client: TestClient) -> None:
    out = {**GOOD_TRIAGE, "confidence": 0.4}
    resp = client.post("/v1/validate/triage", json={"output": out}, headers=HDR).json()
    assert resp["valid"] and resp["needs_human_review"]


def test_validate_digest(client: TestClient) -> None:
    good = {"headline": "3 incidents, 1 P1", "summary": "Payments had a short outage, now resolved."}
    assert client.post("/v1/validate/digest", json={"output": good}, headers=HDR).json()["valid"]
    leaky = {**good, "highlights": ["call +1 415 555 0100 for details"]}
    resp = client.post("/v1/validate/digest", json={"output": leaky}, headers=HDR).json()
    assert not resp["valid"] and "unredacted" in resp["errors"][0]


def test_schema_and_catalog(client: TestClient) -> None:
    schema = client.get("/v1/schema/triage", headers=HDR).json()
    assert set(schema["required"]) >= {"category", "priority", "team", "summary", "confidence"}
    services = client.get("/v1/catalog", headers=HDR).json()["services"]
    assert {"service": "payments-api", "team": "payments", "tier": 1} in services


def test_policy_and_approval_endpoints(client: TestClient) -> None:
    pol = client.post("/v1/policy/evaluate", headers=HDR, json={
        "action": "restart_service", "target": "payments-api", "requested_by": "alice"}).json()
    assert pol["decision"] == "approval_required" and pol["risk"] == "medium"
    same = client.post("/v1/approvals/verify", headers=HDR, json={
        "requested_by": "alice", "approver": "alice", "decision": "approve"}).json()
    assert same["approved"] is False
    outsider = client.post("/v1/approvals/verify", headers=HDR, json={
        "requested_by": "alice", "approver": "mallory", "decision": "approve"}).json()
    assert outsider["approved"] is False  # not in configured approver group
    ok = client.post("/v1/approvals/verify", headers=HDR, json={
        "requested_by": "alice", "approver": "bob", "decision": "approve"}).json()
    assert ok["approved"] is True


def test_audit_append_and_verify(client: TestClient) -> None:
    for i in range(3):
        resp = client.post("/v1/audit", headers=HDR, json={
            "workflow": "incident-triage", "event_type": "incident.triaged", "details": {"i": i}})
        assert resp.status_code == 201 and resp.json()["seq"] == i + 1
    assert client.get("/v1/audit/verify", headers=HDR).json() == {
        "ok": True, "records": 3, "first_bad_seq": None, "reason": ""}

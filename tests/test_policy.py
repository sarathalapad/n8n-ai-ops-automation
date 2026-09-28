import pytest

from opsguard.policy import evaluate, verify_approval


@pytest.mark.parametrize(
    ("action", "target", "env", "expected"),
    [
        ("run_diagnostics", "payments-api", "production", "auto_approved"),
        ("clear_cache", "email-relay", "production", "auto_approved"),
        ("clear_cache", "payments-api", "production", "approval_required"),  # tier-1 prod
        ("restart_service", "email-relay", "staging", "auto_approved"),
        ("restart_service", "email-relay", "production", "approval_required"),
        ("rollback_deployment", "reporting-batch", "dev", "approval_required"),  # high risk anywhere
        ("run_diagnostics", "mystery-service", "dev", "approval_required"),  # unknown blast radius
        ("drop_database", "orders-db", "dev", "denied"),  # forbidden
        ("reboot_the_world", "orders-db", "dev", "denied"),  # unknown -> fail closed
    ],
)
def test_policy_matrix(action: str, target: str, env: str, expected: str) -> None:
    assert evaluate(action, target, env, "alice").decision == expected


def test_missing_requester_is_denied() -> None:
    assert evaluate("run_diagnostics", "payments-api", "dev", "  ").decision == "denied"


def test_approval_timeouts_are_shorter_for_higher_risk() -> None:
    assert evaluate("failover_database", "orders-db", "production", "a").timeout_minutes == 15
    assert evaluate("restart_service", "orders-db", "production", "a").timeout_minutes == 30


def test_four_eyes_rule_is_case_insensitive() -> None:
    check = verify_approval("Alice.Ops", " alice.ops ", "approve")
    assert not check.approved
    assert "different" in check.reason


def test_valid_approval_and_rejection() -> None:
    assert verify_approval("alice", "bob", "approve").approved
    rejected = verify_approval("alice", "bob", "reject")
    assert not rejected.approved and rejected.reason == "rejected by approver"


@pytest.mark.parametrize(("approver", "decision"), [("", "approve"), ("bob", "yes"), ("bob", "")])
def test_malformed_approvals_fail(approver: str, decision: str) -> None:
    assert not verify_approval("alice", approver, decision).approved


def test_approver_group_is_enforced_when_configured() -> None:
    group = frozenset({"bob"})
    assert verify_approval("alice", "BOB", "approve", group).approved
    assert not verify_approval("alice", "carol", "approve", group).approved

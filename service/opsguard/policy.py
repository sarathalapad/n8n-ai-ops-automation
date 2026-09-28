"""Service catalog and the remediation policy engine.

Why policy lives here and not in the n8n canvas: an IF node on a canvas is
easy to rewire by accident and hard to unit-test. Keeping "which actions need
a human" as code gives one reviewed, tested source of truth that every
workflow asks, and lets the static workflow validator assume the workflow
only has to *honour* the decision rather than compute it.

The engine fails closed: unknown actions are denied, unknown services always
need a human, and nothing an LLM proposes is executed on its say-so alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Risk = Literal["low", "medium", "high"]
Decision = Literal["auto_approved", "approval_required", "denied"]

# service -> (owning team, tier). Tier 1 = customer-facing / revenue.
SERVICE_CATALOG: dict[str, tuple[str, int]] = {
    "payments-api": ("payments", 1),
    "checkout-web": ("payments", 1),
    "auth-service": ("identity", 1),
    "orders-db": ("database", 1),
    "vpn-gateway": ("network", 2),
    "email-relay": ("platform", 2),
    "reporting-batch": ("platform", 3),
}

TEAMS: frozenset[str] = frozenset(
    {team for team, _ in SERVICE_CATALOG.values()} | {"security", "service-desk"}
)

ACTION_RISK: dict[str, Risk] = {
    "run_diagnostics": "low",
    "clear_cache": "low",
    "restart_service": "medium",
    "scale_out": "medium",
    "rollback_deployment": "high",
    "rotate_credentials": "high",
    "failover_database": "high",
}

# Never automated, never approvable through chat: these go to a change board.
FORBIDDEN_ACTIONS: frozenset[str] = frozenset(
    {"drop_database", "delete_backups", "disable_monitoring", "disable_firewall"}
)

APPROVAL_TIMEOUT_MINUTES: dict[Risk, int] = {"low": 0, "medium": 30, "high": 15}


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    risk: Risk | None
    reason: str
    timeout_minutes: int = 0


def evaluate(action: str, target: str, environment: str, requested_by: str) -> PolicyDecision:
    """Decide whether a proposed remediation may run, needs approval, or is denied."""
    if not requested_by.strip():
        return PolicyDecision("denied", None, "requester identity is required")
    if action in FORBIDDEN_ACTIONS:
        return PolicyDecision("denied", None, f"'{action}' is forbidden for automation")
    risk = ACTION_RISK.get(action)
    if risk is None:
        return PolicyDecision("denied", None, f"'{action}' is not a known action (fail closed)")

    def needs_human(reason: str) -> PolicyDecision:
        # Low-risk actions escalated for other reasons still get a sane timeout.
        return PolicyDecision(
            "approval_required", risk, reason, APPROVAL_TIMEOUT_MINUTES[risk] or 30
        )

    if target not in SERVICE_CATALOG:
        return needs_human(f"'{target}' is not in the service catalog (unknown blast radius)")
    if risk == "high":
        return needs_human("high-risk action")
    if risk == "medium" and environment == "production":
        return needs_human("medium-risk action in production")
    _, tier = SERVICE_CATALOG[target]
    if tier == 1 and environment == "production" and action != "run_diagnostics":
        return needs_human("tier-1 production service")
    return PolicyDecision("auto_approved", risk, f"{risk}-risk action within policy")


@dataclass(frozen=True)
class ApprovalCheck:
    approved: bool
    reason: str


def _norm(identity: str) -> str:
    return identity.strip().casefold()


def verify_approval(
    requested_by: str,
    approver: str,
    decision: str,
    allowed_approvers: frozenset[str] = frozenset(),
) -> ApprovalCheck:
    """Four-eyes check on an approval that resumed a waiting workflow.

    ``allowed_approvers`` is optional; when empty any identity other than the
    requester may approve (fine for a demo, configure it for real use).
    """
    if decision not in {"approve", "reject"}:
        return ApprovalCheck(False, f"unknown decision '{decision}'")
    if not approver.strip():
        return ApprovalCheck(False, "approver identity is required")
    if _norm(approver) == _norm(requested_by):
        return ApprovalCheck(False, "approver must be different from requester")
    if allowed_approvers and _norm(approver) not in {_norm(a) for a in allowed_approvers}:
        return ApprovalCheck(False, "approver is not in the approver group")
    if decision == "reject":
        return ApprovalCheck(False, "rejected by approver")
    return ApprovalCheck(True, "approved by a second person")

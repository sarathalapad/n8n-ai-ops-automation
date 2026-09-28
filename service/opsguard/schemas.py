"""Contracts for LLM output, plus the validation that enforces them.

Why validate even though n8n's Structured Output Parser already asks the
model for JSON: a parser *requests* a shape, it does not guarantee business
meaning. A model can return a well-formed object that names a team that does
not exist, invents an action, echoes a customer's email back into the
summary, or is confidently wrong. Every AI result therefore passes through
``validate_triage`` / ``validate_digest`` before any workflow acts on it, and
anything that fails is routed to a human instead of being "best-effort" used.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .pii import find_pii
from .policy import ACTION_RISK, SERVICE_CATALOG, TEAMS

MIN_CONFIDENCE = 0.6

Category = Literal[
    "network", "database", "application", "access", "infrastructure", "security", "other"
]
Priority = Literal["P1", "P2", "P3", "P4"]


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str
    target: str
    reason: str = Field(max_length=300)


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Category
    priority: Priority
    team: str
    summary: str = Field(min_length=10, max_length=280)
    confidence: float = Field(ge=0, le=1)
    proposed_action: ProposedAction | None = None


class DigestSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    headline: str = Field(min_length=5, max_length=120)
    summary: str = Field(min_length=20, max_length=1200)
    highlights: list[str] = Field(default_factory=list, max_length=5)
    risk_callouts: list[str] = Field(default_factory=list, max_length=5)


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def _coerce(raw: Any) -> Any:
    """Accept a dict, or a JSON string optionally wrapped in markdown fences -
    the two shapes small local models most commonly return."""
    if isinstance(raw, str):
        return json.loads(_FENCE.sub("", raw))
    return raw


def _errors(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()]


def validate_triage(raw: Any) -> dict[str, Any]:
    """Return ``{valid, errors, needs_human_review, data}`` - never raises,
    because the workflow needs a routable answer even for garbage input."""
    try:
        result = TriageResult.model_validate(_coerce(raw))
    except (ValueError, TypeError) as exc:
        errs = _errors(exc) if isinstance(exc, ValidationError) else [f"not JSON: {exc}"]
        return {"valid": False, "errors": errs, "needs_human_review": True, "data": None}

    errors: list[str] = []
    if result.team not in TEAMS:
        errors.append(f"team: unknown team '{result.team}'")
    if leaked := find_pii(result.summary):
        errors.append(f"summary: contains unredacted data {sorted(leaked)}")
    if pa := result.proposed_action:
        if pa.action not in ACTION_RISK:
            errors.append(f"proposed_action.action: unknown action '{pa.action}'")
        if pa.target not in SERVICE_CATALOG:
            errors.append(f"proposed_action.target: unknown service '{pa.target}'")
    if result.category == "security" and result.team != "security":
        errors.append("team: security incidents must be routed to the security team")

    needs_review = bool(errors) or result.confidence < MIN_CONFIDENCE
    return {
        "valid": not errors,
        "errors": errors,
        "needs_human_review": needs_review,
        "data": result.model_dump() if not errors else None,
    }


def validate_digest(raw: Any) -> dict[str, Any]:
    try:
        digest = DigestSummary.model_validate(_coerce(raw))
    except (ValueError, TypeError) as exc:
        errs = _errors(exc) if isinstance(exc, ValidationError) else [f"not JSON: {exc}"]
        return {"valid": False, "errors": errs, "data": None}
    text = " ".join([digest.headline, digest.summary, *digest.highlights, *digest.risk_callouts])
    if leaked := find_pii(text):
        return {"valid": False, "errors": [f"contains unredacted data {sorted(leaked)}"], "data": None}
    return {"valid": True, "errors": [], "data": digest.model_dump()}

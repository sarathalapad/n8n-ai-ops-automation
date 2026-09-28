"""OpsGuard: the governance helper service the n8n workflows call.

Why a separate service instead of n8n Code nodes: redaction, validation,
policy and audit are the parts that must be *correct*, so they live in plain
Python with unit tests and a CI gate. n8n stays responsible for what it is
good at - orchestration, retries, waiting for humans, integrations.

Every endpoint except ``/healthz`` requires the ``X-OpsGuard-Token`` header.
If no token is configured the service refuses requests (503) rather than
silently running open, unless ``OPSGUARD_DEV_MODE=1`` is set explicitly.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .audit import AuditLog
from .pii import redact_fields
from .policy import SERVICE_CATALOG, evaluate, verify_approval
from .schemas import TriageResult, validate_digest, validate_triage


@dataclass
class Settings:
    api_token: str = ""
    dev_mode: bool = False
    audit_path: Path | None = None
    approvers: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls) -> Settings:
        path = os.getenv("OPSGUARD_AUDIT_PATH", "")
        approvers = os.getenv("OPSGUARD_APPROVERS", "")
        return cls(
            api_token=os.getenv("OPSGUARD_API_TOKEN", ""),
            dev_mode=os.getenv("OPSGUARD_DEV_MODE", "") == "1",
            audit_path=Path(path) if path else None,
            approvers=frozenset(a.strip() for a in approvers.split(",") if a.strip()),
        )


class RedactRequest(BaseModel):
    fields: dict[str, str] = Field(max_length=50)


class ValidateRequest(BaseModel):
    output: Any


class PolicyRequest(BaseModel):
    action: str
    target: str
    environment: str = "production"
    requested_by: str


class ApprovalRequest(BaseModel):
    requested_by: str
    approver: str = ""
    decision: str = ""


class AuditRequest(BaseModel):
    workflow: str
    event_type: str
    actor: str = "n8n"
    details: dict[str, Any] = Field(default_factory=dict)


def create_app(settings: Settings | None = None, audit: AuditLog | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    audit_log = audit or AuditLog(settings.audit_path)
    app = FastAPI(title="OpsGuard helper service", version=__version__)

    def require_token(x_opsguard_token: Annotated[str, Header()] = "") -> None:
        if not settings.api_token:
            if settings.dev_mode:
                return
            raise HTTPException(503, "OPSGUARD_API_TOKEN is not configured")
        if not hmac.compare_digest(x_opsguard_token, settings.api_token):
            raise HTTPException(401, "invalid or missing X-OpsGuard-Token")

    auth = [Depends(require_token)]

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "audit_records": audit_log.verify().records}

    @app.post("/v1/redact", dependencies=auth)
    def redact(req: RedactRequest) -> dict[str, Any]:
        fields, findings = redact_fields(req.fields)
        return {"fields": fields, "findings": findings, "redacted": bool(findings)}

    @app.post("/v1/validate/triage", dependencies=auth)
    def validate_triage_output(req: ValidateRequest) -> dict[str, Any]:
        return validate_triage(req.output)

    @app.post("/v1/validate/digest", dependencies=auth)
    def validate_digest_output(req: ValidateRequest) -> dict[str, Any]:
        return validate_digest(req.output)

    @app.get("/v1/schema/triage", dependencies=auth)
    def triage_schema() -> dict[str, Any]:
        """Published so the n8n output parser and this validator share one contract."""
        return TriageResult.model_json_schema()

    @app.get("/v1/catalog", dependencies=auth)
    def catalog() -> dict[str, Any]:
        """Exposed as an agent tool so the model picks real services and teams."""
        return {
            "services": [
                {"service": name, "team": team, "tier": tier}
                for name, (team, tier) in sorted(SERVICE_CATALOG.items())
            ]
        }

    @app.post("/v1/policy/evaluate", dependencies=auth)
    def policy_evaluate(req: PolicyRequest) -> dict[str, Any]:
        decision = evaluate(req.action, req.target, req.environment, req.requested_by)
        return asdict(decision)

    @app.post("/v1/approvals/verify", dependencies=auth)
    def approvals_verify(req: ApprovalRequest) -> dict[str, Any]:
        check = verify_approval(req.requested_by, req.approver, req.decision, settings.approvers)
        return asdict(check)

    @app.post("/v1/audit", dependencies=auth, status_code=201)
    def audit_append(req: AuditRequest) -> dict[str, Any]:
        return audit_log.append(req.model_dump())

    @app.get("/v1/audit/verify", dependencies=auth)
    def audit_verify() -> dict[str, Any]:
        return asdict(audit_log.verify())

    return app


app = create_app()

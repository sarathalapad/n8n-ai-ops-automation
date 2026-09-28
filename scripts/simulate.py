"""Offline end-to-end run of the triage -> policy -> approval -> audit flow.

Why: the n8n workflows need Docker, a model and credentials to run, which is
too heavy for CI and for a reviewer who just wants to see the behaviour. This
script replays the same decision path the workflows take, against the real
helper service (in-process, via FastAPI's TestClient), with a deterministic
fake classifier standing in for the LLM. Every decision printed here comes
from the production code paths: redaction, validation, policy, four-eyes
check and the hash-chained audit log.

Usage: ``python scripts/simulate.py``  (no network, no model, no Docker)
"""

from __future__ import annotations

import json
import sys
import tempfile
import warnings
from collections import Counter
from itertools import count
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "service"))
warnings.filterwarnings("ignore", message=".*httpx2.*")  # starlette TestClient notice

from fastapi.testclient import TestClient  # noqa: E402

from opsguard.audit import AuditLog  # noqa: E402
from opsguard.main import Settings, create_app  # noqa: E402

TOKEN = "simulation-only-token"


def fake_llm(title: str, description: str, service: str) -> dict[str, Any]:
    """Keyword classifier standing in for the model. Deliberately naive: it
    obeys an injected instruction, to show the validator catching it."""
    text = f"{title} {description}".lower()
    if "ignore all previous instructions" in text:
        return {"category": "database", "priority": "P4", "team": "database",
                "summary": "Orders database slow; destructive action requested in ticket.",
                "confidence": 0.9, "proposed_action": {
                    "action": "drop_database", "target": service, "reason": "as instructed"}}
    if "[secret" in text:
        return {"category": "security", "priority": "P1", "team": "security",
                "summary": "Credentials for auth-service exposed in a public channel.",
                "confidence": 0.95, "proposed_action": {
                    "action": "rotate_credentials", "target": service,
                    "reason": "exposed secrets must be rotated"}}
    if "502" in text or "down" in text or "unresponsive" in text:
        action = "failover_database" if service == "orders-db" else "restart_service"
        return {"category": "application" if service != "orders-db" else "database",
                "priority": "P1", "team": {"payments-api": "payments"}.get(service, "database"),
                "summary": f"Customer-facing outage on {service}; {title.lower()}.",
                "confidence": 0.88, "proposed_action": {
                    "action": action, "target": service, "reason": "restore service quickly"}}
    if "vpn" in text:
        return {"category": "network", "priority": "P2", "team": "network",
                "summary": "Intermittent VPN drops in staging, DNS timeouts on gateway.",
                "confidence": 0.81, "proposed_action": {
                    "action": "run_diagnostics", "target": service, "reason": "collect DNS traces"}}
    return {"category": "other", "priority": "P3", "team": "service-desk",
            "summary": "Unclear report with no service or symptoms given.", "confidence": 0.3}


def main() -> int:
    ticks = count()
    clock = lambda: f"2026-01-15T09:{next(ticks):02d}:00+00:00"  # noqa: E731 - deterministic demo
    workdir = Path(tempfile.mkdtemp(prefix="opsguard-sim-"))
    audit_log = AuditLog(workdir / "audit.jsonl", clock=clock)
    client = TestClient(create_app(Settings(api_token=TOKEN), audit_log))
    client.headers["X-OpsGuard-Token"] = TOKEN
    approvals = json.loads((ROOT / "samples" / "approvals.json").read_text(encoding="utf-8"))
    stored: list[dict[str, Any]] = []

    def post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = client.post(path, json=body)
        resp.raise_for_status()
        return resp.json()

    def log(workflow: str, event_type: str, details: dict[str, Any], actor: str = "n8n") -> None:
        post("/v1/audit", {"workflow": workflow, "event_type": event_type,
                           "actor": actor, "details": details})

    for path in sorted((ROOT / "samples" / "incidents").glob("*.json")):
        inc = json.loads(path.read_text(encoding="utf-8"))
        print(f"\n=== {path.stem}  [{inc['service'] or 'no service'} / {inc['environment']}]")
        red = post("/v1/redact", {"fields": {"title": inc["title"],
                                             "description": inc["description"]}})
        print(f"  redact      : {red['findings'] or 'nothing found'}")
        if red["redacted"]:
            print(f"                -> {red['fields']['description'][:96]}")
        raw = fake_llm(red["fields"]["title"], red["fields"]["description"], inc["service"])
        val = post("/v1/validate/triage", {"output": raw})
        if not val["valid"] or val["needs_human_review"]:
            why = val["errors"] or [f"confidence {raw['confidence']} below threshold"]
            print(f"  validate    : REJECTED {why}")
            print("  route       : manual triage queue (AI output not used)")
            stored.append({"priority": None, "team": None, "status": "manual_triage"})
            log("incident-triage", "incident.manual_triage", {"sample": path.stem, "errors": why})
            continue
        data = val["data"]
        stored.append({**data, "status": "triaged", "service": inc["service"]})
        print(f"  triage      : {data['priority']} {data['category']} -> team {data['team']} "
              f"(confidence {data['confidence']})")
        log("incident-triage", "incident.triaged", {"sample": path.stem, "priority": data["priority"],
                                                     "team": data["team"],
                                                     "pii_findings": red["findings"]})
        if data["priority"] == "P1":
            print("  notify      : paged on-call via chat webhook")
        pa = data["proposed_action"]
        if not pa:
            continue
        req = {"action": pa["action"], "target": pa["target"],
               "environment": inc["environment"], "requested_by": inc["reporter"]}
        pol = post("/v1/policy/evaluate", req)
        print(f"  policy      : {pa['action']} on {pa['target']} -> {pol['decision']} ({pol['reason']})")
        log("remediation", "policy.evaluated", {"request": req, "decision": pol["decision"]})
        if pol["decision"] == "denied":
            log("remediation", "remediation.denied", {"request": req, "reason": pol["reason"]})
            continue
        approver = "policy:auto"
        if pol["decision"] == "approval_required":
            reply = approvals.get(path.stem)
            print(f"  approval    : requested, Wait node paused for {pol['timeout_minutes']} min")
            if reply is None:
                print("  approval    : TIMEOUT -> escalated to duty manager, nothing executed")
                log("remediation", "approval.timeout", {"request": req})
                continue
            chk = post("/v1/approvals/verify", {"requested_by": inc["reporter"], **reply})
            print(f"  approval    : {reply['decision']} by {reply['approver']} -> "
                  f"{'ACCEPTED' if chk['approved'] else 'REFUSED'} ({chk['reason']})")
            if not chk["approved"]:
                log("remediation", "remediation.rejected", {"request": req, "reason": chk["reason"]},
                    actor=reply["approver"])
                continue
            approver = reply["approver"]
        print(f"  execute     : runbook '{pa['action']}' submitted for {pa['target']}")
        log("remediation", "remediation.executed", {"request": req, "approver": approver})

    print("\n=== daily digest")
    triaged = [s for s in stored if s["status"] == "triaged"]
    stats = {"total": len(stored), "manual_triage": len(stored) - len(triaged),
             "by_priority": dict(Counter(s["priority"] for s in triaged))}
    digest = {"headline": f"{stats['total']} incidents in the last 24h, "
                          f"{stats['by_priority'].get('P1', 0)} P1",
              "summary": "Payments and orders had customer-facing outages; one credential "
                         "exposure was contained pending rotation approval.",
              "highlights": [f"{stats['manual_triage']} tickets need manual triage"]}
    dv = post("/v1/validate/digest", {"output": digest})
    print(f"  stats       : {stats}")
    print(f"  validate    : {'OK' if dv['valid'] else dv['errors']} -> posted: {digest['headline']}")
    log("daily-digest", "digest.posted", {"total": stats["total"], "ai_summary_used": dv["valid"]})

    print("\n=== audit log")
    ver = client.get("/v1/audit/verify").json()
    print(f"  verify      : ok={ver['ok']} records={ver['records']}")
    lines = audit_log.path.read_text(encoding="utf-8").splitlines()  # type: ignore[union-attr]
    rec = json.loads(lines[1])
    rec["event"]["details"]["priority"] = "P4"  # an insider quietly downgrades an incident
    lines[1] = json.dumps(rec, sort_keys=True)
    audit_log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")  # type: ignore[union-attr]
    ver = client.get("/v1/audit/verify").json()
    print(f"  tamper test : edited record 2 -> ok={ver['ok']} first_bad_seq={ver['first_bad_seq']} "
          f"({ver['reason']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

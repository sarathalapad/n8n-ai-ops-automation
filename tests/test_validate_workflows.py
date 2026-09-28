import copy
import json
from pathlib import Path
from typing import Any

import pytest

from validate_workflows import main, validate_workflow

WORKFLOWS = sorted((Path(__file__).resolve().parent.parent / "workflows").glob("*.json"))


def load(stem: str) -> dict[str, Any]:
    path = next(p for p in WORKFLOWS if p.stem.startswith(stem))
    return json.loads(path.read_text(encoding="utf-8"))


def node(wf: dict[str, Any], name: str) -> dict[str, Any]:
    return next(n for n in wf["nodes"] if n["name"] == name)


def test_there_are_real_workflows() -> None:
    assert len(WORKFLOWS) >= 4


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.stem)
def test_real_workflows_pass(path: Path) -> None:
    assert validate_workflow(json.loads(path.read_text(encoding="utf-8")), path.name) == []


def test_cli_returns_zero_for_repo_workflows(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "workflows valid" in capsys.readouterr().out


def test_broken_connection_is_caught() -> None:
    wf = load("01")
    wf["connections"]["Redact PII"]["main"][0][0]["node"] = "Does Not Exist"
    assert any("unknown node 'Does Not Exist'" in e for e in validate_workflow(wf))


def test_duplicate_names_and_ids_are_caught() -> None:
    wf = load("99")
    wf["nodes"].append(copy.deepcopy(wf["nodes"][0]))
    errors = validate_workflow(wf)
    assert any("duplicate node name" in e for e in errors)
    assert any("duplicate node id" in e for e in errors)


def test_missing_top_level_key_is_caught() -> None:
    wf = load("99")
    del wf["connections"]
    assert validate_workflow(wf) == ["workflow: missing top-level key 'connections'"]


@pytest.mark.parametrize(
    "value",
    [
        "Bearer abcdefghijklmnopqrstuvwxyz012345",
        "https://hooks.slack.com/services/T000/B000/XXXX",
        "https://api.example.com/v1/items?api_key=abc123",
        "https://admin:hunter2@db.internal:5432",
        "sk-demo-0123456789abcdefghij",
    ],
)
def test_hardcoded_secrets_are_caught(value: str) -> None:
    wf = load("99")
    node(wf, "Alert Ops Chat")["parameters"]["url"] = value
    assert any("hardcoded secret" in e for e in validate_workflow(wf))


def test_literal_password_parameter_and_inline_credentials_are_caught() -> None:
    wf = load("99")
    node(wf, "Build Failure Record")["parameters"]["password"] = "letmein"
    node(wf, "Audit Failure")["credentials"]["httpHeaderAuth"]["value"] = "secret"
    errors = validate_workflow(wf)
    assert any("literal secret" in e for e in errors)
    assert any("{id, name} reference only" in e for e in errors)


def test_expression_urls_with_query_tokens_are_allowed() -> None:
    wf = load("99")
    node(wf, "Alert Ops Chat")["parameters"]["url"] = "={{ $env.X }}?token={{ $env.T }}"
    assert validate_workflow(wf) == []


def test_ai_output_bypassing_validation_is_caught() -> None:
    wf = load("01")
    wf["connections"]["Triage Agent"]["main"][0].append(
        {"node": "Save Triaged Incident", "type": "main", "index": 0})
    errors = validate_workflow(wf)
    assert any("'Triage Agent' feeds 'Save Triaged Incident'" in e for e in errors)


def test_ai_node_without_successor_is_caught() -> None:
    wf = load("03")
    del wf["connections"]["Summarise Digest"]
    assert any("no successor" in e for e in validate_workflow(wf))


def test_denied_branch_wired_to_runbook_is_caught() -> None:
    wf = load("02")
    wf["connections"]["Route by Decision"]["main"][2] = [
        {"node": "Remediate: Execute Runbook", "type": "main", "index": 0}]
    assert any("reachable without approval" in e for e in validate_workflow(wf))


def test_rejected_approval_wired_to_runbook_is_caught() -> None:
    wf = load("02")
    wf["connections"]["Approved?"]["main"][1] = [
        {"node": "Remediate: Execute Runbook", "type": "main", "index": 0}]
    assert any("reachable without approval" in e for e in validate_workflow(wf))


def test_timeout_path_wired_to_runbook_is_caught() -> None:
    wf = load("02")
    wf["connections"]["Approval Received?"]["main"][1] = [
        {"node": "Remediate: Execute Runbook", "type": "main", "index": 0}]
    assert any("reachable without approval" in e for e in validate_workflow(wf))

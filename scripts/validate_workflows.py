"""Static validator for the n8n workflow exports in ``workflows/``.

Why: n8n workflows are code, but they are usually reviewed by eyeballing a
canvas. This script turns the governance rules of this project into CI
checks, so a rewired connection that lets an LLM's output skip validation,
or a remediation step that skips the approval gate, fails the build instead
of reaching production. It checks:

1. structure - valid JSON, required keys, unique node names and ids;
2. wiring - every connection points at an existing node and a known type;
3. secrets - no tokens, passwords or credential-bearing URLs in parameters,
   and credentials are referenced by name/id only;
4. AI output - every LLM node's output goes straight into a validation call;
5. approval - every path from a trigger to a risky action passes through
   either the human-approval check or the policy's ``auto_approved`` branch.

Usage: ``python scripts/validate_workflows.py [workflow.json ...]``
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

CONNECTION_TYPES = {"main", "ai_languageModel", "ai_tool", "ai_outputParser", "ai_memory"}
AI_NODE_TYPES = {"@n8n/n8n-nodes-langchain.agent", "@n8n/n8n-nodes-langchain.chainLlm"}
HTTP = "n8n-nodes-base.httpRequest"
VALIDATION_PATH = "/v1/validate/"
APPROVAL_VERIFY_PATH = "/v1/approvals/verify"
RISKY_URL_MARKER = "RUNBOOK_API_URL"  # remediation calls go to the runbook engine
AUTO_APPROVED_KEY = "auto_approved"

SECRET_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"https?://[^/\s:@]+:[^/\s@]+@"),  # user:password@host
    re.compile(r"(?i)[?&](?:token|key|api_key|apikey|access_token|secret|sig)=(?!\{\{)[^&\s\"']+"),
    re.compile(r"(?i)hooks\.slack\.com/|discord(?:app)?\.com/api/webhooks/|webhook\.office\.com/"),
]
SECRET_PARAM_KEYS = re.compile(r"(?i)^(password|passwd|secret|api_?key|token|access_?token)$")


def _strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}" if path else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")


def _url(node: dict[str, Any]) -> str:
    return str(node.get("parameters", {}).get("url", ""))


def _edges(conns: dict[str, Any]) -> Iterator[tuple[str, str, int, str]]:
    """Yield (source, connection_type, output_index, target)."""
    for src, by_type in conns.items():
        for ctype, outputs in (by_type or {}).items():
            for idx, targets in enumerate(outputs or []):
                for t in targets or []:
                    yield src, ctype, idx, t.get("node", "")


def _is_gate_edge(src: dict[str, Any], out_idx: int, preds: dict[str, set[str]],
                  nodes: dict[str, dict[str, Any]]) -> bool:
    """An edge that proves authorisation: the ``true`` branch of an IF fed by
    the approval-verify call, or the ``auto_approved`` output of a Switch."""
    if src["type"] == "n8n-nodes-base.if" and out_idx == 0:
        return any(APPROVAL_VERIFY_PATH in _url(nodes[p]) for p in preds.get(src["name"], ()))
    if src["type"] == "n8n-nodes-base.switch":
        rules = src.get("parameters", {}).get("rules", {}).get("values", [])
        return out_idx < len(rules) and rules[out_idx].get("outputKey") == AUTO_APPROVED_KEY
    return False


def validate_workflow(wf: Any, label: str = "workflow") -> list[str]:
    """Return a list of human-readable errors (empty list = valid)."""
    if not isinstance(wf, dict):
        return [f"{label}: top level must be an object"]
    errors: list[str] = []
    for key in ("name", "nodes", "connections", "settings"):
        if key not in wf:
            errors.append(f"{label}: missing top-level key '{key}'")
    if errors:
        return errors

    nodes: dict[str, dict[str, Any]] = {}
    ids: set[str] = set()
    for i, node in enumerate(wf["nodes"]):
        missing = [k for k in ("id", "name", "type", "typeVersion", "position", "parameters")
                   if k not in node]
        if missing:
            errors.append(f"{label}: node #{i} missing {missing}")
            continue
        if node["name"] in nodes:
            errors.append(f"{label}: duplicate node name '{node['name']}'")
        if node["id"] in ids:
            errors.append(f"{label}: duplicate node id '{node['id']}'")
        nodes[node["name"]] = node
        ids.add(node["id"])
        for cred_type, ref in (node.get("credentials") or {}).items():
            if not isinstance(ref, dict) or set(ref) - {"id", "name"}:
                errors.append(f"{label}: '{node['name']}' credential '{cred_type}' must be "
                              "a {id, name} reference only")

    for src, ctype, _idx, dst in _edges(wf["connections"]):
        if src not in nodes:
            errors.append(f"{label}: connection from unknown node '{src}'")
        if dst not in nodes:
            errors.append(f"{label}: connection from '{src}' to unknown node '{dst}'")
        if ctype not in CONNECTION_TYPES:
            errors.append(f"{label}: unknown connection type '{ctype}' from '{src}'")

    for name, node in nodes.items():
        for path, text in _strings(node["parameters"]):
            if any(p.search(text) for p in SECRET_PATTERNS):
                errors.append(f"{label}: '{name}' parameter '{path}' looks like a hardcoded secret/URL")
            leaf = path.rsplit(".", 1)[-1]
            if SECRET_PARAM_KEYS.match(leaf) and text and not text.startswith("="):
                errors.append(f"{label}: '{name}' parameter '{path}' holds a literal secret")
    if errors:
        return errors  # graph checks below assume a consistent graph

    succ: dict[str, list[tuple[int, str]]] = {}
    preds: dict[str, set[str]] = {}
    for src, ctype, idx, dst in _edges(wf["connections"]):
        if ctype == "main":
            succ.setdefault(src, []).append((idx, dst))
            preds.setdefault(dst, set()).add(src)

    triggers = [n for n, node in nodes.items()
                if node["type"].lower().endswith(("trigger", ".webhook")) and n not in preds]
    if not triggers:
        errors.append(f"{label}: no trigger node found")

    for name, node in nodes.items():
        if node["type"] not in AI_NODE_TYPES:
            continue
        nexts = [nodes[d] for _, d in succ.get(name, [])]
        if not nexts:
            errors.append(f"{label}: AI node '{name}' output is not validated (no successor)")
        for nxt in nexts:
            if not (nxt["type"] == HTTP and VALIDATION_PATH in _url(nxt)):
                errors.append(f"{label}: AI node '{name}' feeds '{nxt['name']}' without "
                              f"passing through a {VALIDATION_PATH} call")

    risky = {n for n, node in nodes.items() if RISKY_URL_MARKER in _url(node)}
    if risky:
        # Walk from every trigger without crossing gate edges; reaching a
        # risky node means some path executes it without authorisation.
        stack, seen = list(triggers), set(triggers)
        while stack:
            cur = stack.pop()
            if cur in risky:
                errors.append(f"{label}: risky node '{cur}' is reachable without approval")
                continue
            for idx, dst in succ.get(cur, []):
                if dst in seen or _is_gate_edge(nodes[cur], idx, preds, nodes):
                    continue
                seen.add(dst)
                stack.append(dst)
        if not any(n["type"] == "n8n-nodes-base.wait" for n in nodes.values()):
            errors.append(f"{label}: risky actions present but no Wait (approval) node")
    return errors


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or sorted((ROOT / "workflows").glob("*.json"))
    if not paths:
        print("no workflow files found")
        return 1
    failed = 0
    for path in paths:
        try:
            wf = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"FAIL {path.name}: cannot load JSON ({exc})")
            failed += 1
            continue
        errors = validate_workflow(wf, path.name)
        if errors:
            failed += 1
            print(f"FAIL {path.name}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"OK   {path.name}  ({len(wf['nodes'])} nodes)")
    print(f"\n{len(paths) - failed}/{len(paths)} workflows valid")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

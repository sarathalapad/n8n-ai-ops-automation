import json
from itertools import pairwise
from pathlib import Path

from opsguard.audit import GENESIS, AuditLog


def make_log(tmp_path: Path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-01-01T00:00:00+00:00")
    for i in range(4):
        log.append({"workflow": "w", "event_type": f"e{i}", "details": {"n": i}})
    return log


def rewrite(log: AuditLog, fn) -> None:
    assert log.path is not None
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text("\n".join(fn(lines)) + "\n", encoding="utf-8")


def test_chain_links_and_verifies(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    records = [json.loads(ln) for ln in log.path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["prev_hash"] == GENESIS
    assert all(b["prev_hash"] == a["hash"] for a, b in pairwise(records))
    result = log.verify()
    assert result.ok and result.records == 4


def test_modified_record_is_detected(tmp_path: Path) -> None:
    log = make_log(tmp_path)

    def edit(lines: list[str]) -> list[str]:
        rec = json.loads(lines[2])
        rec["event"]["details"]["n"] = 99
        lines[2] = json.dumps(rec)
        return lines

    rewrite(log, edit)
    result = log.verify()
    assert not result.ok and result.first_bad_seq == 3 and "modified" in result.reason


def test_deleted_record_is_detected(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    rewrite(log, lambda lines: lines[:1] + lines[2:])
    result = log.verify()
    assert not result.ok and result.first_bad_seq == 2


def test_rehashing_one_record_still_breaks_the_next_link(tmp_path: Path) -> None:
    """An attacker who recomputes the edited record's own hash is still caught."""
    log = make_log(tmp_path)
    from opsguard.audit import _digest

    def forge(lines: list[str]) -> list[str]:
        rec = json.loads(lines[1])
        rec["event"]["event_type"] = "forged"
        rec["hash"] = _digest(rec["seq"], rec["ts"], rec["event"], rec["prev_hash"])
        lines[1] = json.dumps(rec)
        return lines

    rewrite(log, forge)
    result = log.verify()
    assert not result.ok and result.first_bad_seq == 3 and "link" in result.reason


def test_garbage_line_is_detected(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    rewrite(log, lambda lines: [*lines, "not json"])
    assert log.verify().reason == "unparseable record"


def test_pii_is_scrubbed_before_it_is_written() -> None:
    log = AuditLog()
    rec = log.append({"details": {"note": "customer bob@example.com", "list": ["10.0.0.1"]}})
    assert rec["event"]["details"] == {"note": "customer [EMAIL_1]", "list": ["[IP_ADDRESS_1]"]}
    assert log.verify().ok

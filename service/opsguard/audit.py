"""Append-only, hash-chained audit log.

Why a hash chain instead of "just a table": n8n's execution history can be
pruned or edited by anyone with admin access, and an auditor asking "did a
human approve this restart?" needs evidence that the record was not altered
after the fact. Each record commits to the previous record's hash, so editing
or deleting any line breaks verification from that point on. This is
tamper-*evident*, not tamper-*proof*: pair it with shipping the log to WORM
storage or a SIEM for the latter.

Event payloads are PII-redacted before they are written, because audit logs
tend to be retained for years and read by many people.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .pii import Redactor

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(seq: int, ts: str, event: dict[str, Any], prev_hash: str) -> str:
    # Canonical JSON (sorted keys, no whitespace) so the hash is reproducible
    # by any other tool that re-reads the file.
    body = json.dumps(
        {"seq": seq, "ts": ts, "event": event, "prev_hash": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


def _scrub(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, str):
        return redactor.redact(value)
    if isinstance(value, dict):
        return {k: _scrub(v, redactor) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, redactor) for v in value]
    return value


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    """JSON-lines file (or in-memory list when ``path`` is None)."""

    def __init__(self, path: Path | None = None, clock: Callable[[], str] = _now) -> None:
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()
        self._memory: list[str] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)

    def _lines(self) -> list[str]:
        if self.path is None:
            return list(self._memory)
        return [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            lines = self._lines()
            prev = json.loads(lines[-1]) if lines else None
            seq = prev["seq"] + 1 if prev else 1
            prev_hash = prev["hash"] if prev else GENESIS
            ts = self.clock()
            clean = _scrub(event, Redactor())
            record = {
                "seq": seq,
                "ts": ts,
                "event": clean,
                "prev_hash": prev_hash,
                "hash": _digest(seq, ts, clean, prev_hash),
            }
            line = json.dumps(record, sort_keys=True)
            if self.path is None:
                self._memory.append(line)
            else:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            return record

    def verify(self) -> VerifyResult:
        prev_hash = GENESIS
        lines = self._lines()
        for expected_seq, line in enumerate(lines, start=1):
            try:
                rec = json.loads(line)
                seq, ts, event, stored_prev, stored = (
                    rec["seq"], rec["ts"], rec["event"], rec["prev_hash"], rec["hash"],
                )
            except (ValueError, KeyError, TypeError):
                return VerifyResult(False, len(lines), expected_seq, "unparseable record")
            if seq != expected_seq:
                return VerifyResult(False, len(lines), expected_seq, "sequence gap")
            if stored_prev != prev_hash:
                return VerifyResult(False, len(lines), seq, "broken link to previous record")
            if _digest(seq, ts, event, stored_prev) != stored:
                return VerifyResult(False, len(lines), seq, "record content was modified")
            prev_hash = stored
        return VerifyResult(True, len(lines))

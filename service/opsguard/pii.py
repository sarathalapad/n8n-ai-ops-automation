"""PII and secret redaction applied before any text reaches an LLM.

Why this exists: incident descriptions routinely contain customer emails,
phone numbers, internal IPs and - far too often - pasted credentials.
Redacting at the edge, before the prompt is built, means neither a hosted
model provider nor the model's own logs ever see the originals. The redacted
text is also what gets stored, so downstream workflows (e.g. the daily
digest) inherit the protection instead of having to re-implement it.

Placeholders are numbered per value (``[EMAIL_1]``, ``[EMAIL_2]``) and the
same value always maps to the same placeholder within one call, so the model
can still reason about "the same user reported twice" without seeing who.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field


def _luhn_ok(candidate: str) -> bool:
    """Luhn checksum - avoids redacting order numbers that merely look long."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class Rule:
    """One detector. ``group`` lets a rule redact only part of a match
    (the value of ``password=...``) so the surrounding context survives."""

    kind: str
    pattern: re.Pattern[str]
    group: str | int = 0
    accept: Callable[[str], bool] | None = None


# Order matters: secrets first, so a token that happens to contain an
# email-like or digit-heavy fragment is removed as one unit.
RULES: tuple[Rule, ...] = (
    Rule(
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    Rule("SECRET", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("SECRET", re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b")),
    Rule("SECRET", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    Rule("SECRET", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("SECRET", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/=-]{16,})"), group="v"),
    Rule(
        "SECRET",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*(?P<v>(?!\[)[^\s,;\"']+)"
        ),
        group="v",
    ),
    Rule("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Rule("CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), accept=_luhn_ok),
    Rule(
        "PHONE",
        re.compile(
            r"(?<![\w+])(?:\+\d{1,3}[ -]?\d{2,5}(?:[ -]?\d{2,5}){1,3}"
            r"|\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4})(?![\w])"
        ),
    ),
    Rule(
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    ),
)


@dataclass
class Redactor:
    """Stateful across one request so placeholders stay consistent between
    fields (the same email in title and description gets the same tag)."""

    rules: tuple[Rule, ...] = RULES
    _seen: dict[tuple[str, str], str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    def _placeholder(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._seen:
            n = sum(1 for k, _ in self._seen if k == kind) + 1
            self._seen[key] = f"[{kind}_{n}]"
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return self._seen[key]

    def redact(self, text: str) -> str:
        for rule in self.rules:
            text = self._apply(rule, text)
        return text

    def _apply(self, rule: Rule, text: str) -> str:
        out: list[str] = []
        last = 0
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if rule.accept and not rule.accept(value):
                continue
            start, end = m.span(rule.group)
            out.append(text[last:start])
            out.append(self._placeholder(rule.kind, value))
            last = end
        out.append(text[last:])
        return "".join(out)


def redact_fields(fields: dict[str, str]) -> tuple[dict[str, str], dict[str, int]]:
    """Redact every field with one shared placeholder namespace."""
    r = Redactor()
    return {k: r.redact(v) for k, v in fields.items()}, dict(r.counts)


def find_pii(text: str) -> dict[str, int]:
    """Detection-only helper used to check LLM *output* for leaks."""
    r = Redactor()
    r.redact(text)
    return dict(r.counts)

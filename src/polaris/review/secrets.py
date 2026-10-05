"""Hardcoded credential detection shared by every language analyzer.

Only high-signal token formats and secret-named assignments with long, high-entropy values are
reported. Matched values are always masked before they reach a finding, snippet or log.
"""

from __future__ import annotations

import math
import re
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import accumulate
from typing import cast

from polaris.review.catalog import Severity


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern[str]
    severity: Severity
    label: str
    literals: tuple[str, ...] = ()  # every match contains one of these (a cheap pre-check)


PATTERNS: tuple[SecretPattern, ...] = tuple(
    SecretPattern(kind, re.compile(pattern), cast(Severity, severity), label, literals)
    for kind, pattern, severity, label, literals in (
        ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high", "AWS access key", ("AKIA", "ASIA")),
        ("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", "high", "GitHub token",
         ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
        ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "high", "Slack token", ("xox",)),
        ("stripe_live_key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b", "critical", "Stripe live secret key", ("_live_",)),
        ("openai_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b", "high", "OpenAI API key", ("sk-",)),
        ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{32,}\b", "high", "Anthropic API key", ("sk-ant-",)),
        ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "medium", "Google API key", ("AIza",)),
        ("sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "high", "SendGrid API key", ("SG.",)),
        ("twilio_key", r"\bSK[0-9a-fA-F]{32}\b", "medium", "Twilio API key", ("SK",)),
        ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", "critical", "private key",
         ("-----BEGIN ",)),
        ("supabase_service_role", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*cm9sZSI6InNlcnZpY2Vfcm9sZS[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+", "critical", "Supabase service-role key",
         ("eyJ",)),
    )
)
ASSIGNMENT_SOURCE = (
    r"""\b(?P<name>[a-z0-9_]*(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key|client[_-]?secret)[a-z0-9_]*)\b"""
    r"""\s*["']?\s*[:=]\s*(?P<quote>["'`])(?P<value>[^"'`\s]{16,200})(?P=quote)"""
)
ASSIGNMENT = re.compile(ASSIGNMENT_SOURCE, re.IGNORECASE)
# Pre-check for ASSIGNMENT (a superset): the assigned name is a whole word followed by `=`/`:`
# and an opening quote, and contains one of the secret words.
ASSIGNED_WORD = re.compile(r"""\b[a-z0-9_]+\b(?=\s*["']?\s*[:=]\s*["'`])""", re.IGNORECASE)
SECRET_WORD = re.compile(
    r"api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key|client[_-]?secret", re.IGNORECASE)
PLACEHOLDER = re.compile(
    r"(?i)(x{4,}|\*{3,}|\.{3}|your[_-]|example|placeholder|dummy|sample|redacted|changeme|change[_-]me|"
    r"replace[_-]?me|insert[_-]|test[_-]?key|fake|mock|<|>|\$\{|\{\{|process\.env|todo)"
)
NON_SECRET_NAMES = re.compile(r"(?i)(public|publishable|anon|site_?key|client_?id|_url|_uri|_endpoint|_path|_file|_name|_header|_type|_length|_count|_ttl|_expir|_prefix|_id$)")


@dataclass(frozen=True)
class SecretMatch:
    line: int
    column: int
    length: int
    kind: str
    label: str
    severity: Severity
    confidence: str
    masked: str


def mask(value: str) -> str:
    visible = value[:4] if len(value) > 12 else ""
    return f"{visible}…[{len(value)} chars redacted]"


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum(count / len(value) * math.log2(count / len(value)) for count in counts.values())


def _quoted(line: str, column: int) -> bool:
    before = line[:column]
    return any(before.count(quote) % 2 == 1 for quote in ("\"", "'", "`"))


def _candidate_lines(text: str) -> list[int]:
    """0-based indexes of the lines a credential pattern may match (a superset), ascending, so
    the exact per-line rules run only there."""
    spans: list[tuple[int, int]] = []
    for pattern in PATTERNS:
        if not pattern.literals or any(item in text for item in pattern.literals):
            spans.extend((match.start(), match.end()) for match in pattern.regex.finditer(text))
    spans.extend((match.start(), match.end()) for match in ASSIGNED_WORD.finditer(text)
                 if SECRET_WORD.search(match.group(0)))
    if not spans:
        return []
    starts = list(accumulate(map(len, text.splitlines(keepends=True)), initial=0))
    marked: set[int] = set()
    for start, end in spans:
        first = bisect_right(starts, start) - 1
        last = bisect_right(starts, max(start, end - 1)) - 1
        marked.update(range(first, last + 1))
    return sorted(marked)


def scan(text: str, *, max_matches: int = 50) -> Iterator[SecretMatch]:
    """Yield masked credential matches found inside string literals (or key files)."""
    candidates = _candidate_lines(text)
    if not candidates:
        return
    lines = text.splitlines()
    found = 0
    for index in candidates:
        number, line = index + 1, lines[index]
        if len(line) > 4_000:
            continue
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                value = match.group(0)
                if pattern.kind != "private_key" and (not _quoted(line, match.start()) or PLACEHOLDER.search(value)):
                    continue
                yield SecretMatch(number, match.start(), len(value), pattern.kind, pattern.label,
                                  pattern.severity, "high", mask(value))
                found += 1
                if found >= max_matches:
                    return
        for match in ASSIGNMENT.finditer(line):
            name, value = match.group("name"), match.group("value")
            if NON_SECRET_NAMES.search(name) or PLACEHOLDER.search(value) or entropy(value) < 3.5:
                continue
            if any(pattern.regex.search(value) for pattern in PATTERNS):
                continue  # Already reported by a specific pattern.
            if not (re.search(r"[0-9]", value) and re.search(r"[A-Za-z]", value)):
                continue
            yield SecretMatch(number, match.start("value"), len(value), "generic_secret",
                              f"hardcoded value assigned to {name}", "medium", "medium", mask(value))
            found += 1
            if found >= max_matches:
                return


def redact(text: str) -> str:
    """Mask every credential-looking value in arbitrary text (snippets, labels)."""
    def replace(match: re.Match[str]) -> str:
        return mask(match.group(0))

    for pattern in PATTERNS:
        text = pattern.regex.sub(replace, text)

    def assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        if NON_SECRET_NAMES.search(match.group("name")) or entropy(value) < 3.5:
            return match.group(0)
        return match.group(0).replace(value, mask(value))

    return ASSIGNMENT.sub(assignment, text)

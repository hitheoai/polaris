"""A narrow before/after invariant, not general authorization analysis.

Policies arrive over an embedding application's authenticated channel. Repository prose,
comments, route names, and model output never create or relax a guard requirement.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from polaris.jsonio import digest_json, digest_text
from polaris.review.analyzers.base import AnalysisInput, AnalyzerResult, language_for_path
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    CoverageStatus,
    GuardRequirement,
    TrustedGuardPolicy,
    WorkflowFinding,
)

ANALYZER_ID = "polaris-guard-diff"
VERSION = "polaris-guard-diff/0.1.0"
LIMITATIONS = [
    "Only explicit caller-trusted requirements for exact paths and named top-level functions.",
    "Both complete before/after sources and an existing baseline direct guard call are required.",
    "Only direct expression-statement calls count; assignments, decorators, middleware, and wrappers are not analyzed.",
    "Python uses AST; JS/TS uses a conservative balanced-token recognizer, not a general language parser.",
    "JS/TS templates, regex/division, JSX bodies, generators, arrow handlers, and complex signatures are not supported.",
    "JS/TS guard calls must end with a semicolon or be the final expression in the function body.",
    "Preserving a call does not prove correct guard arguments, binding, implementation, ordering, identity, tenancy, or authorization.",
    "Missing policy/baseline or ambiguous syntax is not_checked, not evidence of correctness.",
]


def capability() -> AnalyzerCapability:
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability="available", version=VERSION, expected_version=VERSION,
        rule_pack_version=VERSION, rule_pack_digest=digest_text(Path(__file__).read_text(encoding="utf-8")),
        languages=["python", "javascript", "typescript"], checks=["api_authorization"],
        provenance="Original Polaris explicit-policy guard-call differ",
        license="Apache-2.0", reason="builtin_requires_trusted_policy", limitations=list(LIMITATIONS),
    )


@dataclass(frozen=True)
class _GuardState:
    guarded: bool
    first: int
    last: int


class _UnsupportedSyntax(ValueError):
    pass


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _python_state(text: str, requirement: GuardRequirement) -> _GuardState:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise _UnsupportedSyntax("parse_error") from exc
    functions = [
        item for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == requirement.symbol
    ]
    if len(functions) != 1:
        raise _UnsupportedSyntax("symbol_missing_or_ambiguous")
    function = functions[0]
    guarded = False
    for statement in function.body:
        if not isinstance(statement, ast.Expr):
            continue
        expression = statement.value
        awaited = isinstance(expression, ast.Await)
        if isinstance(expression, ast.Await):
            expression = expression.value
        if (
            isinstance(expression, ast.Call)
            and _call_name(expression.func) == requirement.guard
            and (awaited or not requirement.require_await)
        ):
            guarded = True
    return _GuardState(guarded, function.lineno, function.end_lineno or function.lineno)


@dataclass(frozen=True)
class _Token:
    value: str
    line: int


_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+(?:\.[0-9]+)?")
_PUNCTUATION = frozenset("(){}[].,;:+-*=!?&|<>%")


def _js_tokens(text: str) -> tuple[list[_Token], dict[int, int]]:
    """Discard literals/comments; reject syntax that could hide executable guard lookalikes."""
    tokens: list[_Token] = []
    position, line = 0, 1
    while position < len(text):
        char = text[position]
        if char.isspace():
            line += char == "\n"
            position += 1
            continue
        if text.startswith("//", position):
            end = text.find("\n", position + 2)
            position = len(text) if end < 0 else end
            continue
        if text.startswith("/*", position):
            end = text.find("*/", position + 2)
            if end < 0:
                raise _UnsupportedSyntax("unsupported_guard_syntax")
            line += text[position:end + 2].count("\n")
            position = end + 2
            continue
        if char in "'\"":
            start, first_line = position, line
            position += 1
            closed = False
            while position < len(text):
                if text[position] == "\\":
                    position += 2
                    continue
                if text[position] == char:
                    position += 1
                    closed = True
                    break
                if text[position] in "\r\n":
                    break
                position += 1
            if not closed:
                raise _UnsupportedSyntax("unsupported_guard_syntax")
            line += text[start:position].count("\n")
            tokens.append(_Token("<literal>", first_line))
            continue
        if char in "`/\\":
            # Regex/template interpolation needs a real JS parser. Never count text within
            # those as a guard, and never silently assert the invariant in their presence.
            raise _UnsupportedSyntax("unsupported_guard_syntax")
        match = _WORD.match(text, position)
        if match is not None:
            tokens.append(_Token(match.group(), line))
            position = match.end()
        elif char in _PUNCTUATION:
            tokens.append(_Token(char, line))
            position += 1
        else:
            raise _UnsupportedSyntax("unsupported_guard_syntax")
        if len(tokens) > 100_000:
            raise _UnsupportedSyntax("guard_token_limit")
    stack: list[tuple[str, int]] = []
    pairs: dict[int, int] = {}
    opening = {")": "(", "}": "{", "]": "["}
    for index, token in enumerate(tokens):
        if token.value in ("(", "{", "["):
            stack.append((token.value, index))
        elif token.value in opening:
            if not stack or stack[-1][0] != opening[token.value]:
                raise _UnsupportedSyntax("unsupported_guard_syntax")
            _, start = stack.pop()
            pairs[start], pairs[index] = index, start
    if stack:
        raise _UnsupportedSyntax("unsupported_guard_syntax")
    return tokens, pairs


def _js_state(text: str, requirement: GuardRequirement) -> _GuardState:
    tokens, pairs = _js_tokens(text)
    functions: list[tuple[int, int, int]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.value in ("(", "[", "{"):
            index = pairs[index] + 1
            continue
        if (
            token.value != "function" or index + 2 >= len(tokens)
            or tokens[index + 1].value != requirement.symbol
            or tokens[index + 2].value != "("
        ):
            index += 1
            continue
        prefix = index
        while prefix > 0 and tokens[prefix - 1].value in ("export", "default", "async"):
            prefix -= 1
        if prefix > 0 and tokens[prefix - 1].value not in (";", "}"):
            raise _UnsupportedSyntax("unsupported_guard_signature")
        body = pairs[index + 2] + 1
        if body < len(tokens) and tokens[body].value == ":":
            # Only simple TypeScript return types, not structural/function/conditional types.
            body += 1
            while body < len(tokens) and tokens[body].value != "{":
                value = tokens[body].value
                if _WORD.fullmatch(value) is None and value not in (".", "<", ">", ",", "[", "]", "|", "&", "?"):
                    raise _UnsupportedSyntax("unsupported_guard_signature")
                body += 1
        if body >= len(tokens) or tokens[body].value != "{":
            raise _UnsupportedSyntax("unsupported_guard_signature")
        end = pairs[body]
        # A JSX body needs a real JS parser; conservatively decline '<' rather than
        # accidentally considering guard-shaped markup or a generic arrow expression.
        if any(item.value == "<" for item in tokens[body + 1:end]):
            raise _UnsupportedSyntax("unsupported_guard_syntax")
        functions.append((index, body, end))
        index = end + 1
    if len(functions) != 1:
        raise _UnsupportedSyntax("symbol_missing_or_ambiguous")
    function, body, end = functions[0]
    wanted = requirement.guard.split(".")
    guard_tokens = [part for pair in zip(wanted, ["."] * len(wanted), strict=True) for part in pair][:-1]
    statement = body + 1
    index = statement
    guarded = False
    while index < end:
        if index == statement:
            call = index
            awaited = tokens[call].value == "await"
            if awaited:
                call += 1
            finish = call + len(guard_tokens)
            if (
                finish < end and [item.value for item in tokens[call:finish]] == guard_tokens
                and tokens[finish].value == "(" and (awaited or not requirement.require_await)
            ):
                after_call = pairs[finish] + 1
                if after_call == end or tokens[after_call].value == ";":
                    guarded = True
        value = tokens[index].value
        if value in ("(", "["):
            index = pairs[index] + 1
            continue
        if value == "{":
            index = pairs[index] + 1
            statement = index
            continue
        if value == ";":
            statement = index + 1
        index += 1
    return _GuardState(guarded, tokens[function].line, tokens[end].line)


class GuardAnalyzer:
    analyzer_id = ANALYZER_ID

    def __init__(self, policy: TrustedGuardPolicy | None = None) -> None:
        self.policy = policy

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        findings: list[WorkflowFinding] = []
        coverage: list[CheckCoverage] = []
        required = "api_authorization" in request.checks
        for source in request.sources:
            language = language_for_path(source.path)
            status: CoverageStatus = "not_checked"
            reason = "trusted_policy_missing"
            requirements = [
                item for item in self.policy.requirements
                if item.path == source.path or item.path == source.previous_path
            ] if self.policy else []
            entry_required = required
            if self.policy is not None and not requirements:
                reason = "outside_trusted_policy_scope"
                entry_required = False
            elif self.policy is not None:
                reason = source.skip or source.before_skip or ""
                if any(item.path != source.path for item in requirements):
                    reason = "trusted_policy_path_changed"
                if not reason and language == "unsupported":
                    reason = "unsupported_language"
                if not reason and (source.after is None or source.before is None):
                    reason = "before_and_after_required"
                if not reason and not source.context_complete:
                    reason = "incomplete_source_context"
                if not reason and source.after is not None and source.before is not None:
                    status, reason = "checked", "guard_invariant_completed_no_authorization_proof"
                    try:
                        if max(len(source.after), len(source.before)) > request.config.max_file_bytes:
                            raise _UnsupportedSyntax("file_too_large")
                        if max(len(source.after.encode("utf-8")), len(source.before.encode("utf-8"))) > request.config.max_file_bytes:
                            raise _UnsupportedSyntax("file_too_large")
                        for requirement in requirements:
                            parser = _python_state if language == "python" else _js_state
                            before = parser(source.before, requirement)
                            after = parser(source.after, requirement)
                            if not before.guarded:
                                status, reason = "not_checked", "baseline_guard_not_established"
                            elif not after.guarded:
                                if len(findings) >= request.config.max_findings:
                                    status, reason = "partial", "result_limit"
                                    break
                                digest = digest_text(source.after)
                                policy_digest = digest_json(self.policy.model_dump(mode="json"))
                                findings.append(WorkflowFinding(
                                    finding_id=digest_json([
                                        VERSION, policy_digest, source.path, requirement.symbol,
                                        requirement.guard, digest_text(source.before), digest,
                                    ])[7:27],
                                    path=source.path, start_line=after.first, end_line=after.last,
                                    symbol=requirement.symbol, check_id="api_authorization",
                                    title="Authorization guard regression", result="flagged", engine="rules",
                                    reason="trusted_guard_removed",
                                    message="A direct guard call required by the caller's policy existed before but is absent after.",
                                    guidance="Restore the policy-required guard and have its authorization behavior verified.",
                                    details=[
                                        f"Policy {self.policy.policy_id}@{self.policy.revision}; required call {requirement.guard}.",
                                        "This is a syntactic regression, not proof of correct access control.",
                                    ],
                                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION,
                                    rule_id="polaris.guard.direct-call-removed", evidence_digest=digest,
                                ))
                    except _UnsupportedSyntax as exc:
                        status, reason = "not_checked", str(exc)
                    except (UnicodeError, RecursionError, MemoryError):
                        status, reason = "not_checked", "guard_analysis_error"
            coverage.append(CheckCoverage(
                path=source.path, language=language, check_id="api_authorization",
                analyzer_id=ANALYZER_ID, status=status, reason=reason, required=entry_required,
            ))
        return AnalyzerResult(findings=tuple(findings), coverage=tuple(coverage), capability=capability())

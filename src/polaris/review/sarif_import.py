"""Merge other tools' SARIF 2.1.0 results into a Polaris review as untrusted, labeled data.

Polaris never runs those tools (ESLint, Ruff, CodeQL, Semgrep, Gitleaks or any other SARIF
producer). In CI their SARIF is often produced from the pull request's own code, so a change can
shape every byte of it:

- Size and JSON structure are bounded before anything is materialized. A file that is missing,
  oversized, malformed or not SARIF 2.1.0 is rejected as a whole with a fixed code that never
  echoes its content, and the rejection is recorded in the report. It never stops the Polaris
  review itself, so a change cannot switch off its own review by shaping a SARIF file.
- Only bounded, printable text is kept (tool names, versions, rule ids, messages). Snippets,
  help URIs, fixes and embedded links are never used.
- Locations become repository-relative paths inside the reviewed scope. Results outside the
  repository, with invalid paths or for files that were not reviewed are counted and dropped.
  An absolute path from another machine is mapped only when the whole run agrees on one
  checkout root; nothing is guessed. The files a result names are never read.
- Imported results never change Polaris results, coverage, suppressions, baselines or exit
  codes by themselves. A result at a Polaris finding's location that reports the same weakness
  is attached to it as corroboration ("also reported by"), which never changes the finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from polaris.jsonio import digest_bytes, digest_json
from polaris.review.models import (
    MAX_IMPORTED_RESULTS,
    MAX_SARIF_IMPORTS,
    UNSAFE_TEXT,
    Category,
    ImportedFinding,
    ImportedLevel,
    SarifImport,
    Severity,
    SourceFile,
    WorkflowFinding,
    WorkflowReviewReport,
    valid_source_path,
)

MAX_SARIF_BYTES = 16_000_000
MAX_TOTAL_SARIF_BYTES = 64_000_000
MAX_JSON_NODES = 2_000_000
MAX_RUNS = 256
MAX_RESULTS_PER_FILE = 50_000
# In-scope results considered across all files before the most severe are kept.
MAX_CANDIDATES = 20_000
MAX_URI = 4_096
MAX_BASE_DEPTH = 8
MAX_TAGS = 64
MAX_ARGUMENTS = 16
MAX_FINGERPRINTS = 16
MAX_MESSAGE = 1_000
MAX_RULE_ID = 200
MAX_TOOL = 120
MAX_VERSION = 64
MAX_NAME = 120
LEVELS: tuple[ImportedLevel, ...] = ("error", "warning", "note", "none")
LEVEL_RANK: dict[str, int] = {name: index for index, name in enumerate(LEVELS)}
SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RESULT_KINDS = frozenset({"pass", "open", "informational", "notApplicable", "review", "fail"})
NOT_PROBLEMS = frozenset({"pass", "informational", "notApplicable"})
BASELINE_STATES = frozenset({"new", "unchanged", "updated", "absent"})
SUPPRESSION_KINDS = frozenset({"inSource", "external"})
SUPPRESSION_STATUSES = frozenset({"accepted", "underReview", "rejected"})
# Selected sources whose imported results are out of scope: gone, excluded, or not followed.
OUT_OF_SCOPE = frozenset({
    "deleted", "excluded", "pruned_directory", "symlink", "invalid_path", "duplicate_source_path",
    "unverified_exclusion", "outside_root", "not_regular_file", "unsafe_path",
})
# Results that leave an opted-in imported gate (or comment resolution) unable to decide.
UNEVALUATED = ("result_limit", "imported_limit", "invalid_result")
# Why a SARIF file was rejected as a whole; nothing in a rejected file is imported.
FILE_ERRORS: dict[str, str] = {
    "sarif_unavailable": "The SARIF file is missing, unreadable, a symbolic link or not a regular file.",
    "sarif_too_large": "The SARIF file exceeds the size or structure limits.",
    "sarif_total_limit": "The SARIF files together exceed the total size limit.",
    "invalid_sarif": "The file is not valid SARIF JSON (duplicate keys, NaN or an invalid structure).",
    "unsupported_sarif_version": "Only SARIF 2.1.0 files can be imported.",
}
ERRORS: dict[str, str] = {
    **FILE_ERRORS,
    "too_many_sarif_files": f"At most {MAX_SARIF_IMPORTS} SARIF files can be imported.",
}

_STRING = re.compile(r'"[^"\\]*+(?:\\.[^"\\]*+)*+(?:"|\\?\Z)', re.DOTALL)
# SARIF embedded links, "[text](1)" or "[text](https://...)": only the text is kept. Escaped
# brackets are set aside first, so each match scans only to the next bracket (linear time).
_LINK = re.compile(r"\[([^\[\]]{0,400})\]\([^()\s]{0,400}\)")
_OPEN, _CLOSE = "\ue000", "\ue001"
_PLACEHOLDER = re.compile(r"\{(\d{1,2})\}")
_CWE = re.compile(r"^(?:external/cwe/)?cwe[-_: ]?0*([1-9][0-9]{0,5})(?![0-9])")
_SEVERITY_TEXT = re.compile(r"^\s*([0-9]{1,2}(?:\.[0-9]{1,4})?)\s*$")
_TOOL_KEY = re.compile(r"[^a-z0-9]+")
_RESERVED_TOOLS = ("polaris", "theovex")

# Weaknesses Polaris checks for, by CWE: an imported result with one of these relates to the
# check, so it can corroborate a Polaris finding of that check at the same place.
CWE_CHECKS: dict[str, str] = {
    **dict.fromkeys(("CWE-89", "CWE-564", "CWE-943"), "sql_injection"),
    **dict.fromkeys(("CWE-77", "CWE-78", "CWE-88"), "command_injection"),
    **dict.fromkeys(("CWE-94", "CWE-95", "CWE-502", "CWE-1336"), "code_injection"),
    **dict.fromkeys(("CWE-79", "CWE-80", "CWE-83"), "xss"),
    "CWE-918": "ssrf",
    "CWE-601": "open_redirect",
    **dict.fromkeys(("CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73"), "path_traversal"),
    **dict.fromkeys(("CWE-259", "CWE-321", "CWE-532", "CWE-798"), "secret_exposure"),
    **dict.fromkeys(("CWE-285", "CWE-306", "CWE-639", "CWE-862", "CWE-863"), "missing_authorization"),
    **dict.fromkeys(
        ("CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-331", "CWE-335", "CWE-338", "CWE-347", "CWE-759",
         "CWE-760", "CWE-916"),
        "insecure_auth_crypto",
    ),
    **dict.fromkeys(("CWE-295", "CWE-297", "CWE-346", "CWE-614", "CWE-942", "CWE-1004"),
                    "unsafe_security_configuration"),
}
# Python security rules without CWE tags: Ruff's flake8-bandit codes (S...) mirror Bandit's (B...).
BANDIT_CHECKS: dict[str, str] = {
    "102": "code_injection", "301": "code_injection", "307": "code_injection", "506": "code_injection",
    "105": "secret_exposure", "106": "secret_exposure", "107": "secret_exposure",
    "303": "insecure_auth_crypto", "311": "insecure_auth_crypto", "324": "insecure_auth_crypto",
    "323": "unsafe_security_configuration", "501": "unsafe_security_configuration",
    "602": "command_injection", "603": "command_injection", "604": "command_injection",
    "605": "command_injection", "606": "command_injection", "609": "command_injection",
    "608": "sql_injection", "701": "xss", "704": "xss", "310": "ssrf",
}
ESLINT_CHECKS: dict[str, str] = {
    "no-eval": "code_injection", "no-implied-eval": "code_injection", "no-new-func": "code_injection",
    "react/no-danger": "xss", "no-unsanitized/method": "xss", "no-unsanitized/property": "xss",
    "@microsoft/sdl/no-inner-html": "xss", "@microsoft/sdl/no-document-write": "xss",
    "security/detect-child-process": "command_injection",
    "security/detect-eval-with-expression": "code_injection",
    "security/detect-non-literal-require": "code_injection",
    "security/detect-non-literal-fs-filename": "path_traversal",
    "security/detect-pseudoRandomBytes": "insecure_auth_crypto",
}
ESLINT_SECURITY_PREFIXES = ("security/", "security-node/", "no-unsanitized/", "@microsoft/sdl/", "xss/")
# Secret scanners: every result is a credential found in the code.
SECRET_TOOLS = frozenset({
    "gitleaks", "trufflehog", "detectsecrets", "ggshield", "gitguardian", "secretlint", "noseyparker",
})
# Tools whose every rule is a security rule.
SECURITY_TOOLS = SECRET_TOOLS | frozenset({
    "bandit", "gosec", "brakeman", "trivy", "grype", "osvscanner", "checkov", "tfsec", "kics", "snyk",
    "snykcode", "snykopensource", "dependencycheck", "njsscan", "horusec", "devskim", "securitycodescan",
    "sobelow", "pipaudit", "retirejs",
})
STYLE_TOOLS = frozenset({"stylelint", "markdownlint", "markdownlintcli2", "yamllint", "prettier", "hadolint"})
RUFF_STYLE_KINDS = frozenset({
    "pycodestyle", "pydocstyle", "isort", "pep8-naming", "flake8-quotes", "flake8-commas",
    "flake8-implicit-str-concat", "flake8-annotations", "flake8-copyright", "flake8-todos",
    "eradicate", "flake8-fixme",
})
# CodeQL-style category tags, in the order they decide a result's category.
CATEGORY_TAGS: tuple[tuple[Category, frozenset[str]], ...] = (
    ("correctness", frozenset({"correctness"})),
    ("reliability", frozenset({"reliability", "error-handling", "concurrency", "resource-leak"})),
    ("performance", frozenset({"performance", "efficiency"})),
    ("maintainability", frozenset({
        "maintainability", "readability", "useless-code", "style", "complexity", "duplicate-code",
    })),
)


class SarifProblem(ValueError):
    """A fixed, value-free code: never the file's content or location."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SarifInput:
    """One `--import-sarif` file as the caller read it: its bytes, or why it could not be read."""

    name: str
    data: bytes | None = field(default=None, repr=False)
    error: str | None = None

    def __post_init__(self) -> None:
        if (self.data is None) == (self.error is None) or (self.error is not None and self.error not in FILE_ERRORS):
            raise ValueError("a SARIF input has either content or a known error code")


def text(value: object, limit: int) -> str:
    """Bounded, single-line, printable text. Invisible and control characters become U+FFFD."""
    if not isinstance(value, str):
        return ""
    collapsed = " ".join(value[: limit * 4 + 64].split())
    cleaned = UNSAFE_TEXT.sub("\ufffd", collapsed)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def input_name(path: Path) -> str:
    return text(path.name, MAX_NAME) or "sarif"


def at_least(level: str, threshold: str) -> bool:
    return LEVEL_RANK.get(level, len(LEVELS)) <= LEVEL_RANK[threshold]


def tool_key(name: str) -> str:
    return _TOOL_KEY.sub("", name.casefold())


def reserved_tool(name: str) -> bool:
    """Only Polaris itself reports Polaris results: a run whose tool claims to be it is refused."""
    key = tool_key(name)
    return any(reserved in key for reserved in _RESERVED_TOOLS)


def tool_tag(name: str) -> str:
    """A short, stable tag for the tool that reported a result (namespaces comment keys)."""
    return hashlib.sha256(("polaris-imported-tool/v1\0" + tool_key(name)).encode("utf-8")).hexdigest()[:8]


def imported_key(item: ImportedFinding) -> str:
    """Pull-request comment key of an imported result. Its own grammar, never a Polaris key."""
    return f"sarif-{tool_tag(item.tool)}-{item.fingerprint}"


def scope_paths(sources: Iterable[SourceFile]) -> frozenset[str]:
    """Paths a review selected and kept: imported results elsewhere are out of scope."""
    return frozenset(
        source.path for source in sources
        if source.role == "review" and source.skip not in OUT_OF_SCOPE and valid_source_path(source.path)
        and not source.path.startswith("__polaris")
    )


def unevaluated(report: WorkflowReviewReport) -> bool:
    """Whether some imported input or result was not evaluated: a rejected file, a tool that did
    not finish, or results past a limit."""
    return any(item.status == "rejected" or item.failed_runs or any(reason in UNEVALUATED for reason in item.dropped)
               for item in report.imports)


def corroborations(report: WorkflowReviewReport) -> dict[str, list[ImportedFinding]]:
    """Imported results attached to each Polaris finding id."""
    attached: dict[str, list[ImportedFinding]] = {}
    for item in report.imported:
        if item.corroborates is not None:
            attached.setdefault(item.corroborates, []).append(item)
    return attached


def imported_order(item: ImportedFinding) -> tuple[int, int, str, int, str]:
    return (SEVERITY_RANK[item.severity], LEVEL_RANK[item.level], item.path, item.start_line or 0,
            item.rule_id or "")


def by_tool(items: Iterable[ImportedFinding]) -> list[tuple[str, list[ImportedFinding]]]:
    """Imported results grouped by the tool that reported them, most severe first."""
    groups: dict[str, list[ImportedFinding]] = {}
    for item in items:
        groups.setdefault(item.tool, []).append(item)
    ordered = [(tool, sorted(members, key=imported_order)) for tool, members in groups.items()]
    ordered.sort(key=lambda pair: (imported_order(pair[1][0])[:2], pair[0].casefold(), pair[0]))
    return ordered


# ---- bounded JSON ----------------------------------------------------------------------------


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SarifProblem("invalid_sarif")
        value[key] = item
    return value


def _constant(_: str) -> None:
    raise SarifProblem("invalid_sarif")


def load_document(data: bytes) -> Any:
    """Parse untrusted SARIF JSON within byte and node limits (counted before parsing)."""
    if len(data) > MAX_SARIF_BYTES:
        raise SarifProblem("sarif_too_large")
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SarifProblem("invalid_sarif") from None
    source = source.removeprefix("\ufeff")
    # Every JSON value follows "[", ":" or "," once strings are blanked out (an upper bound).
    skeleton = _STRING.sub('""', source)
    if skeleton.count("[") + skeleton.count(":") + skeleton.count(",") + 1 > MAX_JSON_NODES:
        raise SarifProblem("sarif_too_large")
    del skeleton
    try:
        return json.loads(source, object_pairs_hook=_unique, parse_constant=_constant)
    except SarifProblem:
        raise
    except (ValueError, RecursionError):
        raise SarifProblem("invalid_sarif") from None


# ---- strict structure helpers ----------------------------------------------------------------


def _invalid() -> SarifProblem:
    return SarifProblem("invalid_sarif")


def _object(value: Any, *, optional: bool = True) -> dict[str, Any]:
    if value is None and optional:
        return {}
    if not isinstance(value, dict):
        raise _invalid()
    return value


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _invalid()
    return value


def _string(value: Any) -> str | None:
    if value is not None and not isinstance(value, str):
        raise _invalid()
    return value


def _integer(value: Any) -> int | None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise _invalid()
    return value


def _tags(properties: Mapping[str, Any]) -> tuple[str, ...]:
    tags = _list(properties.get("tags"))
    if not all(isinstance(tag, str) for tag in tags):
        raise _invalid()
    return tuple(text(tag, 200).casefold() for tag in tags[:MAX_TAGS])


def _security_severity(properties: Mapping[str, Any]) -> float | None:
    value = properties.get("security-severity")
    number: float | None = None
    if isinstance(value, str):
        match = _SEVERITY_TEXT.match(value[:32])
        number = float(match.group(1)) if match else None
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
    return round(number, 1) if number is not None and 0 <= number <= 10 else None


def _cwes(tags: Iterable[str], references: Iterable[Any]) -> tuple[str, ...]:
    found: list[str] = []
    for tag in tags:
        match = _CWE.match(tag)
        if match:
            found.append(f"CWE-{match.group(1)}")
    for reference in references:
        if not isinstance(reference, dict):
            raise _invalid()
        component = _object(reference.get("toolComponent"))
        identifier = reference.get("id")
        if text(component.get("name"), 32).casefold() == "cwe" and isinstance(identifier, str):
            match = _CWE.match("cwe-" + identifier.strip().casefold().removeprefix("cwe-")[:16])
            if match:
                found.append(f"CWE-{match.group(1)}")
    return tuple(sorted(set(found), key=lambda item: int(item[4:])))[:8]


@dataclass(frozen=True)
class _Rule:
    level: str | None = None
    tags: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    security_severity: float | None = None
    kind: str | None = None
    messages: Mapping[str, Any] = field(default_factory=dict)


def _rule(descriptor: Any) -> _Rule:
    descriptor = _object(descriptor, optional=False)
    config = _object(descriptor.get("defaultConfiguration"))
    level = _string(config.get("level"))
    if level is not None and level not in LEVEL_RANK:
        raise _invalid()
    properties = _object(descriptor.get("properties"))
    tags = _tags(properties)
    relationships = [_object(item, optional=False).get("target") for item in _list(descriptor.get("relationships"))[:32]]
    kind = properties.get("kind")
    return _Rule(
        level=level, tags=tags, cwe=_cwes(tags, [item for item in relationships if item is not None]),
        security_severity=_security_severity(properties),
        kind=text(kind, 64).casefold() if isinstance(kind, str) else None,
        messages=_object(descriptor.get("messageStrings")),
    )


class _Rules:
    """Rule descriptors of a run's driver and extensions, looked up as results reference them."""

    def __init__(self, tool: Mapping[str, Any], driver: Mapping[str, Any]) -> None:
        extensions = _list(tool.get("extensions"))[:256]
        self.components = [driver, *(_object(item, optional=False) for item in extensions)]
        self.rules = [_list(component.get("rules")) for component in self.components]
        self._by_id: list[dict[str, Any] | None] = [None] * len(self.components)
        self._parsed: dict[int, _Rule] = {}

    def _index(self, component: int) -> dict[str, Any]:
        found = self._by_id[component]
        if found is None:
            found = {}
            for descriptor in self.rules[component]:
                identifier = _string(_object(descriptor, optional=False).get("id"))
                if identifier is not None:
                    found.setdefault(identifier, descriptor)
            self._by_id[component] = found
        return found

    def find(self, result: Mapping[str, Any]) -> tuple[str | None, _Rule]:
        rule_id = _string(result.get("ruleId"))
        index = _integer(result.get("ruleIndex"))
        component = 0
        reference = _object(result.get("rule"))
        if reference:
            rule_id = rule_id or _string(reference.get("id"))
            index = _integer(reference.get("index")) if reference.get("index") is not None else index
            tool_component = _object(reference.get("toolComponent"))
            position = _integer(tool_component.get("index"))
            if position is not None:
                if not 0 <= position < len(self.components) - 1:
                    raise _invalid()
                component = position + 1
        descriptor: Any = None
        if index is not None and 0 <= index < len(self.rules[component]):
            descriptor = self.rules[component][index]
        if descriptor is None and rule_id is not None:
            descriptor = self._index(component).get(rule_id)
            if descriptor is None:
                descriptor = next((self._index(other).get(rule_id) for other in range(len(self.components))
                                   if self._index(other).get(rule_id) is not None), None)
        if descriptor is None:
            return rule_id, _Rule()
        if rule_id is None:
            rule_id = _string(_object(descriptor, optional=False).get("id"))
        parsed = self._parsed.get(id(descriptor))
        if parsed is None:
            parsed = self._parsed[id(descriptor)] = _rule(descriptor)
        return rule_id, parsed


# ---- locations -------------------------------------------------------------------------------


def _decoded(kind: str, value: str) -> tuple[str, str]:
    try:
        value = unquote(value, errors="strict")
    except UnicodeDecodeError:
        return "invalid", ""
    if not value or UNSAFE_TEXT.search(value) or "\\" in value:
        return "invalid", ""
    return kind, value


def _parse_uri(uri: str) -> tuple[str, str]:
    """("relative" | "absolute", decoded path), or ("outside" | "invalid", "")."""
    if not uri or len(uri) > MAX_URI or UNSAFE_TEXT.search(uri) or "\\" in uri:
        return "invalid", ""
    try:
        parts = urlsplit(uri)
    except ValueError:
        return "invalid", ""
    scheme = parts.scheme.lower()
    if len(scheme) == 1:  # a Windows drive letter, not a URI scheme
        return _decoded("absolute", "/" + uri)
    if parts.query or parts.fragment:
        return "invalid", ""
    if scheme == "file":
        if parts.netloc not in ("", "localhost") or not parts.path.startswith("/"):
            return "outside", ""
        return _decoded("absolute", parts.path)
    if scheme or parts.netloc:
        return "outside", ""
    return _decoded("absolute" if parts.path.startswith("/") else "relative", parts.path)


def _segments(path: str) -> list[str] | None:
    """Remove dot segments; None when the path climbs above its start or names a directory."""
    if path.endswith("/"):
        return None
    stack: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return None
            stack.pop()
        else:
            stack.append(part)
    return stack


def _join(base: str, reference: str) -> str:
    if not base or base.endswith("/"):
        return base + reference
    return base[: base.rfind("/") + 1] + reference


def _locate(uri: str, base_id: str | None, bases: Mapping[str, Any]) -> tuple[str, str]:
    """Resolve a result's URI through `originalUriBaseIds`. An undefined base (the usual
    `%SRCROOT%`) is the repository root; a base that is an absolute file URI is kept absolute."""
    relative = ""
    seen: set[str] = set()
    for _ in range(MAX_BASE_DEPTH):
        kind, value = _parse_uri(uri)
        if kind == "absolute":
            parts = _segments(_join(value, relative) if relative else value)
            return ("absolute", "/" + "/".join(parts)) if parts else ("invalid", "")
        if kind != "relative":
            return kind, ""
        relative = _join(value, relative) if relative else value
        if base_id is None or base_id not in bases:
            parts = _segments(relative)
            if parts is None:
                return ("outside" if ".." in relative.split("/") else "invalid"), ""
            return ("relative", "/".join(parts)) if parts else ("invalid", "")
        if base_id in seen:
            return "invalid", ""
        seen.add(base_id)
        base = _object(bases[base_id], optional=False)
        next_uri, base_id = _string(base.get("uri")), _string(base.get("uriBaseId"))
        if next_uri is None:
            base_id = None
            next_uri = "./"
        uri = next_uri
    return "invalid", ""


def _under(path: str, root: str) -> str | None:
    prefix = root.rstrip("/") + "/"
    return path[len(prefix):] if path.startswith(prefix) and len(path) > len(prefix) else None


def _suffix_roots(path: str, scope: frozenset[str]) -> list[str]:
    """Checkout roots under which an absolute path would be an in-scope path of two or more
    segments (a bare file name never identifies a file)."""
    segments = path.split("/")
    return ["/".join(segments[:start]) or "/" for start in range(1, min(len(segments) - 1, 256))
            if "/".join(segments[start:]) in scope]


# ---- results ---------------------------------------------------------------------------------


@dataclass
class _Candidate:
    tool: str
    version: str | None
    rule_id: str | None
    level: ImportedLevel
    severity: Severity
    security_severity: float | None
    category: Category
    cwe: tuple[str, ...]
    related_check: str | None
    message: str
    where: tuple[str, str]
    start_line: int | None
    end_line: int | None
    fingerprints: tuple[tuple[str, str], ...]
    sarif_digest: str
    source: int = 0
    path: str = ""


@dataclass
class _Outcome:
    tools: list[str] = field(default_factory=list)
    runs: int = 0
    failed_runs: int = 0
    results: int = 0
    dropped: Counter[str] = field(default_factory=Counter)
    candidates: list[_Candidate] = field(default_factory=list)


def _severity(level: str, security_severity: float | None) -> Severity:
    """A tool's security-severity rating when it gave one (CVSS-like bands, as code scanning
    uses). Otherwise the level alone, which never rates a result high: error is medium."""
    if security_severity is not None:
        if security_severity >= 9.0:
            return "critical"
        if security_severity >= 7.0:
            return "high"
        if security_severity >= 4.0:
            return "medium"
        return "low" if security_severity > 0 else "info"
    return {"error": "medium", "warning": "low"}.get(level, "info")  # type: ignore[return-value]


def related_check(key: str, rule_id: str | None, cwe: Iterable[str]) -> str | None:
    for item in cwe:
        if item in CWE_CHECKS:
            return CWE_CHECKS[item]
    rule = rule_id or ""
    if key == "ruff" and re.fullmatch(r"S[0-9]{3}", rule):
        return BANDIT_CHECKS.get(rule[1:])
    if key == "bandit" and re.fullmatch(r"B[0-9]{3}", rule):
        return BANDIT_CHECKS.get(rule[1:])
    if key == "eslint":
        return ESLINT_CHECKS.get(rule)
    return "secret_exposure" if key in SECRET_TOOLS else None


def _category(
    key: str, rule_id: str | None, rule: _Rule, tags: Sequence[str], cwe: Sequence[str],
    security_severity: float | None, related: str | None,
) -> Category:
    if "security" in tags or security_severity is not None:
        return "security"
    for category, names in CATEGORY_TAGS:
        if any(tag in names for tag in tags):
            return category
    rule_text = rule_id or ""
    if (cwe or related is not None or key in SECURITY_TOOLS
            or any(tag.startswith(("owasp", "external/owasp")) for tag in tags)
            or (key == "ruff" and rule.kind == "flake8-bandit")
            or (key == "eslint" and rule_text.startswith(ESLINT_SECURITY_PREFIXES))):
        return "security"
    if key in STYLE_TOOLS or (key == "ruff" and rule.kind in RUFF_STYLE_KINDS):
        return "maintainability"
    return "correctness"


def _message(result: Mapping[str, Any], rule: _Rule) -> str:
    message = _object(result.get("message"), optional=False)
    raw = _string(message.get("text"))
    identifier = _string(message.get("id"))
    if raw is None and identifier is not None:
        entry = rule.messages.get(identifier)
        raw = _string(entry.get("text")) if isinstance(entry, dict) else None
    if raw is None:
        raise _invalid()  # SARIF requires message text or a message string the rule defines
    raw = raw[:8_000]
    arguments = _list(message.get("arguments"))
    if arguments:
        if not all(isinstance(item, str) for item in arguments):
            raise _invalid()
        values = [text(item, 200) for item in arguments[:MAX_ARGUMENTS]]
        raw = _PLACEHOLDER.sub(
            lambda match: values[int(match.group(1))] if int(match.group(1)) < len(values) else match.group(0), raw,
        )
    if "](" in raw:
        raw = _LINK.sub(r"\1", raw.replace("\\[", _OPEN).replace("\\]", _CLOSE))
    raw = raw.replace(_OPEN, "[").replace(_CLOSE, "]").replace("\\[", "[").replace("\\]", "]")
    return text(raw, MAX_MESSAGE) or "(no message)"


def _suppressed(result: Mapping[str, Any]) -> bool:
    active = False
    for item in _list(result.get("suppressions")):
        suppression = _object(item, optional=False)
        kind, status = _string(suppression.get("kind")), _string(suppression.get("status"))
        if kind not in SUPPRESSION_KINDS or (status is not None and status not in SUPPRESSION_STATUSES):
            raise _invalid()
        active = active or status in (None, "accepted")
    return active


def _fingerprints(result: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for name in ("partialFingerprints", "fingerprints"):
        values = _object(result.get(name))
        if not all(isinstance(value, str) for value in values.values()):
            raise _invalid()
        pairs.extend((f"{name}:{text(key, 128)}", text(value, 512)) for key, value in values.items())
    return tuple(sorted(pairs)[:MAX_FINGERPRINTS])


def _lines(region: Mapping[str, Any]) -> tuple[int | None, int | None]:
    start, end = _integer(region.get("startLine")), _integer(region.get("endLine"))
    if start is None or not 1 <= start <= 10_000_000:
        return None, None
    return start, end if end is not None and start <= end <= 10_000_000 else start


def _candidate(
    result: Any, *, tool: str, version: str | None, rules: _Rules, artifacts: list[Any],
    bases: Mapping[str, Any], digest: str,
) -> _Candidate | str:
    """A result's normalized fields, or why it is dropped. Structural errors raise."""
    result = _object(result, optional=False)
    rule_id, rule = rules.find(result)
    level = _string(result.get("level"))
    kind = _string(result.get("kind")) or "fail"
    baseline = _string(result.get("baselineState"))
    if (level is not None and level not in LEVEL_RANK) or kind not in RESULT_KINDS or (
            baseline is not None and baseline not in BASELINE_STATES):
        raise _invalid()
    message = _message(result, rule)
    properties = _object(result.get("properties"))
    result_tags = _tags(properties)
    tags = (*rule.tags, *result_tags)
    cwe = tuple(sorted({*rule.cwe, *_cwes(result_tags, _list(result.get("taxa"))[:32])},
                       key=lambda item: int(item[4:])))[:8]
    fingerprints = _fingerprints(result)
    suppressed = _suppressed(result)
    locations = _list(result.get("locations"))
    physical = _object(_object(locations[0], optional=False).get("physicalLocation")) if locations else {}
    artifact = _object(physical.get("artifactLocation"))
    region = _object(physical.get("region"))
    uri, base_id, index = (_string(artifact.get("uri")), _string(artifact.get("uriBaseId")),
                           _integer(artifact.get("index")))
    if uri is None and index is not None and 0 <= index < len(artifacts):
        location = _object(_object(artifacts[index], optional=False).get("location"))
        uri, base_id = _string(location.get("uri")), _string(location.get("uriBaseId"))
    if kind in NOT_PROBLEMS or baseline == "absent":
        return "not_a_problem"
    if suppressed:
        return "suppressed_by_tool"
    if uri is None:
        return "no_location"
    if level is None:
        level = (rule.level or "warning") if kind == "fail" else "none"
    rule_text = text(rule_id, MAX_RULE_ID) or None
    key = tool_key(tool)
    security_severity = _security_severity(properties)
    if security_severity is None:
        security_severity = rule.security_severity
    related = related_check(key, rule_text, cwe)
    start, end = _lines(region)
    return _Candidate(
        tool=tool, version=version, rule_id=rule_text, level=level,  # type: ignore[arg-type]
        severity=_severity(level, security_severity), security_severity=security_severity,
        category=_category(key, rule_text, rule, tags, cwe, security_severity, related), cwe=cwe,
        related_check=related, message=message, where=_locate(uri, base_id, bases), start_line=start,
        end_line=end, fingerprints=fingerprints, sarif_digest=digest,
    )


def _map_paths(candidates: list[_Candidate], *, root: str, scope: frozenset[str]) -> None:
    """Repository paths for a run's results.

    Absolute paths are mapped under the review root. When none is under it (SARIF made in
    another checkout), they are mapped under the producer's root only if that root is
    unanimous: every path that ends with an in-scope path ends with exactly one, and all of
    them imply the same root. A path with several candidates, or any disagreement, is left
    unmapped; nothing is guessed.
    """
    absolute = [item for item in candidates if item.where[0] == "absolute"]
    direct = {id(item): _under(item.where[1], root) for item in absolute}
    local = any(direct.values())
    producer: str | None = None
    ambiguous: set[int] = set()
    if absolute and not local:
        roots: set[str] = set()
        for item in absolute:
            found = _suffix_roots(item.where[1], scope)
            if len(found) > 1:
                ambiguous.add(id(item))
            elif found:
                roots.add(found[0])
        producer = next(iter(roots)) if len(roots) == 1 else None
    for item in candidates:
        kind, value = item.where
        if kind == "relative":
            item.path = value
        elif kind == "absolute":
            mapped = direct[id(item)]
            if mapped is None and producer is not None and id(item) not in ambiguous:
                mapped = _under(value, producer)
            item.path = mapped or ""
            if not mapped:
                item.where = ("outside" if local else "unmapped", "")
        if item.path and not valid_source_path(item.path):
            item.path, item.where = "", ("invalid", "")


def parse_sarif(data: bytes, *, digest: str, root: str, scope: frozenset[str]) -> _Outcome:
    """Every in-scope result of one SARIF file. Raises SarifProblem when the file is rejected."""
    document = load_document(data)
    if not isinstance(document, dict):
        raise _invalid()
    version = document.get("version")
    if version != "2.1.0":
        raise SarifProblem("unsupported_sarif_version" if isinstance(version, str) else "invalid_sarif")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise _invalid()
    if len(runs) > MAX_RUNS:
        raise SarifProblem("sarif_too_large")
    outcome = _Outcome(runs=len(runs))
    budget = MAX_RESULTS_PER_FILE
    for run in runs:
        run = _object(run, optional=False)
        tool = _object(run.get("tool"), optional=False)
        driver = _object(tool.get("driver"), optional=False)
        name = text(_string(driver.get("name")), MAX_TOOL)
        if not name:
            raise _invalid()
        version = text(_string(driver.get("semanticVersion")) or _string(driver.get("version")), MAX_VERSION) or None
        invocations = [_object(item, optional=False) for item in _list(run.get("invocations"))]
        if any(not isinstance(item.get("executionSuccessful", True), bool) for item in invocations):
            raise _invalid()
        if run.get("results") is None or any(item.get("executionSuccessful") is False for item in invocations):
            outcome.failed_runs += 1  # SARIF: null results mean the tool did not produce any
        results = _list(run.get("results"))
        outcome.results += len(results)
        if name not in outcome.tools and len(outcome.tools) < 64:
            outcome.tools.append(name)
        if reserved_tool(name):
            outcome.dropped["reserved_tool_name"] += len(results)
            continue
        rules = _Rules(tool, driver)
        artifacts = _list(run.get("artifacts"))
        bases = _object(run.get("originalUriBaseIds"))
        considered = results[:budget]
        if len(results) > len(considered):
            outcome.dropped["result_limit"] += len(results) - len(considered)
        budget -= len(considered)
        found: list[_Candidate] = []
        for result in considered:
            item = _candidate(result, tool=name, version=version, rules=rules, artifacts=artifacts,
                              bases=bases, digest=digest)
            if isinstance(item, str):
                outcome.dropped[item] += 1
            else:
                found.append(item)
        _map_paths(found, root=root, scope=scope)
        for item in found:
            kind = item.where[0]
            if kind == "invalid":
                outcome.dropped["invalid_path"] += 1
            elif kind == "outside":
                outcome.dropped["outside_repository"] += 1
            elif kind == "unmapped":
                outcome.dropped["unmapped_path"] += 1
            elif item.path not in scope:
                outcome.dropped["outside_review_scope"] += 1
            else:
                outcome.candidates.append(item)
    return outcome


# ---- merging ---------------------------------------------------------------------------------


def _fingerprint(item: _Candidate, line: str | None) -> str:
    material = ["polaris-imported/v1", tool_key(item.tool), item.rule_id or "", item.path]
    if item.fingerprints:
        material.extend(f"{key}={value}" for key, value in item.fingerprints)
    elif line is not None:
        material.extend(("line", " ".join(line.split())[:300], item.message))
    else:
        material.extend(("at", str(item.start_line or 0), item.message))
    return hashlib.sha256("\0".join(material).encode("utf-8")).hexdigest()[:24]


def _dedupe_key(item: _Candidate) -> tuple[str, int, str, str]:
    rule = item.rule_id or "#" + hashlib.sha256(item.message.encode("utf-8")).hexdigest()[:16]
    return item.path, item.start_line or 0, tool_key(item.tool), rule


def _priority(item: _Candidate) -> tuple[int, int, str, int, str, str]:
    return (SEVERITY_RANK[item.severity], LEVEL_RANK[item.level], item.path, item.start_line or 0,
            tool_key(item.tool), item.rule_id or "")


def _corroborated(item: ImportedFinding, findings: Sequence[WorkflowFinding]) -> str | None:
    """The Polaris finding within two lines (of its line or sink) that reports the same CWE or
    check. Corroboration is presentation only; the finding itself never changes."""
    if item.start_line is None:
        return None
    best: tuple[tuple[int, int, str], str] | None = None
    for finding in findings:
        if not ((finding.cwe and finding.cwe in item.cwe) or item.related_check == finding.check_id):
            continue
        lines = {finding.start_line, *(step.line for step in finding.trace
                                       if step.kind == "sink" and step.path in (None, finding.path))}
        distance = min(abs(item.start_line - line) for line in lines)
        if finding.start_line <= item.start_line <= finding.end_line and finding.end_line - finding.start_line <= 20:
            distance = 0
        if distance > 2:
            continue
        rank = (distance, SEVERITY_RANK.get(finding.severity or "medium", 2), finding.finding_id)
        if best is None or rank < best[0]:
            best = (rank, finding.finding_id)
    return best[1] if best else None


def import_sarif(
    report: WorkflowReviewReport, inputs: Sequence[SarifInput], *, root: Path, sources: Iterable[SourceFile],
) -> WorkflowReviewReport:
    """The report with imported results, per-file import records and their digests attached.

    Inputs are processed in content order, so the same files give the same report whatever
    order they were passed in. Polaris findings, coverage and counts are left unchanged.
    """
    if not inputs:
        return report
    if len(inputs) > MAX_SARIF_IMPORTS:
        raise SarifProblem("too_many_sarif_files")
    sources = list(sources)
    scope = scope_paths(sources)
    texts = {source.path: source.after for source in sources if source.after is not None and source.path in scope}
    root_text = root.as_posix()
    entries = sorted(
        ((item, digest_bytes(item.data) if item.data is not None else None) for item in inputs),
        key=lambda pair: (pair[1] or "", pair[0].name),
    )
    parsed: list[_Outcome | None] = []
    errors: list[str | None] = []
    total = 0
    for item, digest in entries:
        outcome: _Outcome | None = None
        error: str | None = None
        if item.data is None or digest is None:
            error = item.error or "sarif_unavailable"
        else:
            total += len(item.data)
            try:
                if total > MAX_TOTAL_SARIF_BYTES:
                    raise SarifProblem("sarif_total_limit")
                outcome = parse_sarif(item.data, digest=digest, root=root_text, scope=scope)
            except SarifProblem as problem:
                error = problem.code if problem.code in FILE_ERRORS else "invalid_sarif"
        parsed.append(outcome)
        errors.append(error)
    seen: set[tuple[str, int, str, str]] = set()
    kept: list[_Candidate] = []
    for position, outcome in enumerate(parsed):
        if outcome is None:
            continue
        for candidate in outcome.candidates:
            key = _dedupe_key(candidate)
            if key in seen:
                outcome.dropped["duplicate"] += 1
            elif len(kept) >= MAX_CANDIDATES:
                outcome.dropped["imported_limit"] += 1
            else:
                seen.add(key)
                candidate.source = position
                kept.append(candidate)
        outcome.candidates = []

    def drop(candidate: _Candidate, reason: str) -> None:
        owner = parsed[candidate.source]
        assert owner is not None
        owner.dropped[reason] += 1

    kept.sort(key=_priority)
    for candidate in kept[MAX_IMPORTED_RESULTS:]:
        drop(candidate, "imported_limit")
    open_findings: dict[str, list[WorkflowFinding]] = {}
    for finding in report.findings:
        if finding.result in ("flagged", "needs_context"):
            open_findings.setdefault(finding.path, []).append(finding)
    lines_by_path: dict[str, list[str]] = {}
    imported: list[ImportedFinding] = []
    counts: Counter[int] = Counter()
    corroborating: Counter[int] = Counter()
    for candidate in kept[:MAX_IMPORTED_RESULTS]:
        line = None
        if candidate.start_line is not None and candidate.path in texts and not candidate.fingerprints:
            if candidate.path not in lines_by_path:
                lines_by_path[candidate.path] = (texts[candidate.path] or "").splitlines()
            numbered = lines_by_path[candidate.path]
            line = numbered[candidate.start_line - 1] if candidate.start_line <= len(numbered) else None
        fingerprint = _fingerprint(candidate, line)
        try:
            result = ImportedFinding(
                import_id=digest_json([candidate.sarif_digest, fingerprint, candidate.path, candidate.start_line,
                                       candidate.rule_id, candidate.message])[7:27],
                tool=candidate.tool, tool_version=candidate.version, rule_id=candidate.rule_id,
                level=candidate.level, severity=candidate.severity, security_severity=candidate.security_severity,
                category=candidate.category, path=candidate.path, start_line=candidate.start_line,
                end_line=candidate.end_line, message=candidate.message, cwe=list(candidate.cwe),
                related_check=candidate.related_check, fingerprint=fingerprint, sarif_digest=candidate.sarif_digest,
            )
        except ValueError:
            drop(candidate, "invalid_result")
            continue
        corroborates = _corroborated(result, open_findings.get(result.path, ()))
        if corroborates is not None:
            result = result.model_copy(update={"corroborates": corroborates})
            corroborating[candidate.source] += 1
        counts[candidate.source] += 1
        imported.append(result)
    imported.sort(key=lambda item: (item.path, item.start_line or 0, tool_key(item.tool), item.rule_id or "",
                                    item.import_id))
    records: list[SarifImport] = []
    for position, ((item, digest), outcome, error) in enumerate(zip(entries, parsed, errors, strict=True)):
        name = text(item.name, MAX_NAME) or "sarif"
        if outcome is None:
            records.append(SarifImport.model_validate(
                {"name": name, "digest": digest, "status": "rejected", "error": error}))
            continue
        records.append(SarifImport.model_validate({
            "name": name, "digest": digest, "status": "imported", "tools": outcome.tools, "runs": outcome.runs,
            "failed_runs": outcome.failed_runs, "results": outcome.results, "imported": counts[position],
            "corroborating": corroborating[position],
            "dropped": {reason: count for reason, count in sorted(outcome.dropped.items()) if count},
        }))
    notices = list(report.notices)
    if imported:
        notices.append(
            f"{len(imported)} result(s) from other tools were imported from SARIF. Polaris did not verify them; "
            "they never change Polaris results, coverage, suppressions or baselines."
        )
    rejected = Counter(record.error for record in records if record.error)
    if rejected:
        reasons = ", ".join(f"{code} ({count})" for code, count in sorted(rejected.items()))
        notices.append(f"{sum(rejected.values())} SARIF file(s) were rejected and nothing was imported from "
                       f"them: {reasons}.")
    digests = [digest for _, digest in entries if digest is not None]
    return report.model_copy(update={
        "imported": imported, "imports": records, "notices": list(dict.fromkeys(notices)),
        "provenance": report.provenance.model_copy(update={"imported_digests": digests}),
    })

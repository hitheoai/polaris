"""Stable data shapes shared by the CLI, REST API, MCP server and GitHub Action."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from polaris.contract import Probability, StrictModel
from polaris.registry import BY_ID

REVIEW_FORMAT: Literal["polaris.review/0.1.0"] = "polaris.review/0.1.0"
Result = Literal["flagged", "ok", "needs_context", "uncertain", "unsupported", "too_large", "error"]
RESULTS: tuple[str, ...] = (
    "flagged", "ok", "needs_context", "uncertain", "unsupported", "too_large", "error",
)
# hybrid: the static rules decide every result and the model adds a second opinion (default).
Engine = Literal["hybrid", "model", "rules"]
# "static" marks decisions made by the no-risky-calls prefilter rather than an engine.
FindingEngine = Literal["model", "rules", "static"]
DEFAULT_CHECKS: tuple[str, ...] = ("sql_injection", "command_injection")
DEFAULT_POLICY: tuple[str, ...] = (
    "Treat function parameters, HTTP request data, command-line arguments, environment "
    "variables, and file or network contents as untrusted unless this policy says otherwise.",
)
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "**/migrations/**",
    "**/*_pb2.py",
    "**/*_pb2_grpc.py",
    "**/vendor/**",
    "**/third_party/**",
)
# Directory names never descended into during scans.
PRUNED_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", ".venv", "venv", ".env", "node_modules", "__pycache__",
        "site-packages", "dist-packages", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".polaris-cache", "build", "dist", ".eggs",
    }
)


def in_sentence(title: str) -> str:
    """A check title inside a sentence: "Command injection" becomes "command injection", while a
    leading acronym keeps its case ("SQL injection", "API authorization")."""
    first = title.split(" ", 1)[0]
    return title if len(first) > 1 and first.isupper() else title[:1].lower() + title[1:]


TITLES: dict[str, str] = {
    "sql_injection": "SQL injection",
    "command_injection": "Command injection",
    "api_authorization": "API authorization",
    "tool_scope": "Tool scope",
    "prompt_injection": "Prompt injection",
    "secret_exposure": "Secret exposure",
    "sensitive_data_exposure": "Sensitive-data exposure",
    "code_injection": "Code injection",
    "xss": "Cross-site scripting (XSS)",
    "ssrf": "Server-side request forgery (SSRF)",
    "open_redirect": "Open redirect",
    "path_traversal": "Path traversal",
    "missing_authorization": "Missing authorization",
    "insecure_auth_crypto": "Insecure auth or crypto",
    "unsafe_security_configuration": "Unsafe security configuration",
    "workflow_injection": "Workflow expression injection",
    "untrusted_checkout": "Untrusted checkout in a privileged workflow",
    "excessive_privileges": "Excessive privileges",
    "unpinned_dependency": "Unpinned dependency",
    "unverified_download": "Download without integrity check",
}
GUIDANCE: dict[str, str] = {
    "sql_injection": (
        "Use parameter placeholders and pass values separately, for example "
        "cursor.execute(\"SELECT ... WHERE id = %s\", (user_id,)). Never build SQL text from "
        "untrusted values; check identifiers such as column names against a fixed allowlist."
    ),
    "command_injection": (
        "Pass the command as a list without shell=True, keep the executable fixed or "
        "allowlisted, and put -- before user-supplied paths. If a shell is unavoidable, quote "
        "every untrusted value with shlex.quote."
    ),
}


class ReviewConfig(StrictModel):
    """Repository or request settings. Policy statements are treated as trusted context."""

    checks: Annotated[list[str], Field(min_length=1, max_length=7)] = Field(
        default_factory=lambda: list(DEFAULT_CHECKS)
    )
    policy: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=2000)]], Field(min_length=1, max_length=16)
    ] = Field(default_factory=lambda: list(DEFAULT_POLICY))
    policy_source: Literal["default", "repository", "request"] = "default"
    flag_threshold: Probability | None = None
    include: Annotated[list[str], Field(min_length=1, max_length=64)] = Field(
        default_factory=lambda: ["**/*.py"]
    )
    exclude: Annotated[list[str], Field(max_length=256)] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDES)
    )
    max_units: Annotated[int, Field(ge=1, le=200_000)] = 50_000
    max_file_bytes: Annotated[int, Field(ge=1_000, le=20_000_000)] = 2_000_000
    report_ok: bool = False

    @model_validator(mode="after")
    def known_checks(self) -> Self:
        if len(set(self.checks)) != len(self.checks) or any(c not in BY_ID for c in self.checks):
            raise ValueError("unknown or duplicate check")
        return self


@dataclass(frozen=True)
class SourceFile:
    """One file to review. `changed_lines` limits review to touched units; None reviews all.

    `skip` records why an input could not be read (for example "binary" or "file_too_large").
    `role="context"` files are read only to resolve calls/imports of reviewed files; they get
    no coverage rows or findings of their own.
    """

    path: str
    after: str | None
    before: str | None = None
    changed_lines: frozenset[int] | None = None
    skip: str | None = None
    previous_path: str | None = None
    context_complete: bool = True
    before_skip: str | None = None
    role: Literal["review", "context"] = "review"


class SecondOpinion(StrictModel):
    """What the model thinks in a hybrid review. It never changes the finding's result."""

    result: Result
    risk: Probability | None = None
    reason: str


class Finding(StrictModel):
    finding_id: str
    path: str
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    symbol: str
    check_id: str
    title: str
    result: Result
    engine: FindingEngine
    risk: Probability | None = None
    threshold: Probability | None = None
    reason: str
    message: str
    guidance: str | None = None
    details: list[str] = Field(default_factory=list)
    request_digest: str | None = None
    second_opinion: SecondOpinion | None = None


class ReviewSummary(StrictModel):
    files_reviewed: int
    files_skipped: dict[str, int]
    units_total: int
    units_assessed: int
    units_prefiltered: int
    results: dict[str, int]
    cache_hits: int = 0
    elapsed_ms: float
    units_per_second: float | None = None
    # Hybrid reviews: results where the model's second opinion clearly disagrees with the rules.
    second_opinion_disagreements: int = 0


class ModelInfo(StrictModel):
    engine: Engine
    model_version: str | None = None
    release_status: str = "not_loaded"
    runtime_variant: str | None = None
    calibration_version: str | None = None


class ReviewReport(StrictModel):
    format: Literal["polaris.review/0.1.0"] = REVIEW_FORMAT
    model: ModelInfo
    checks: list[str]
    policy_source: str
    summary: ReviewSummary
    findings: list[Finding]
    notices: list[str] = Field(default_factory=list)

    def exit_code(self, fail_on: frozenset[str] = frozenset({"flagged"})) -> int:
        """0 when no finding has a result in `fail_on`; 1 otherwise. Errors never pass silently."""
        return 1 if any(finding.result in fail_on for finding in self.findings) else 0


# The broader static workflow is deliberately separate from the assessment/model registry
# and the legacy review contract above. Adding a check here does not train/qualify a model.
WORKFLOW_REVIEW_FORMAT: Literal["polaris.review/0.2.0"] = "polaris.review/0.2.0"
CAPABILITY_FORMAT: Literal["polaris.capabilities/0.2.0"] = "polaris.capabilities/0.2.0"
WORKFLOW_DEFAULT_CHECKS: tuple[str, ...] = (
    "sql_injection", "command_injection", "code_injection", "xss", "ssrf", "open_redirect",
    "path_traversal", "secret_exposure", "missing_authorization", "insecure_auth_crypto",
    "unsafe_security_configuration",
    # CI workflows and container builds (each check applies only to its source-kind domains).
    "workflow_injection", "untrusted_checkout", "excessive_privileges", "unpinned_dependency",
    "unverified_download",
)
WORKFLOW_CHECKS = (*WORKFLOW_DEFAULT_CHECKS, "api_authorization")
# A registered source kind (see polaris.review.analyzers.base.SourceKind): the built-in python,
# javascript, typescript and rust, kinds added by built-in or explicitly loaded analyzers, or
# "unsupported" for files no analyzer reads.
Language = Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_]*$")]
# What a check is about. Security checks are the default merge gate; the others describe bugs,
# reliability, performance and maintainability issues the same way.
Category = Literal["security", "correctness", "reliability", "performance", "maintainability"]
# not_applicable: nothing to analyze for this check (documentation, assets, deleted files).
CoverageStatus = Literal["checked", "not_checked", "partial", "not_applicable"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
AnalyzerAvailability = Literal[
    "available", "not_probed", "unavailable", "disabled", "version_mismatch",
    "sandbox_unavailable", "error",
]


def valid_source_path(value: str) -> bool:
    """A portable relative source identifier, never an absolute path or command argument."""
    return (
        bool(value)
        and len(value) <= 1024
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        and "\\" not in value
        and ":" not in value
        and not PurePosixPath(value).is_absolute()
        and all(part not in ("", ".", "..") for part in value.split("/"))
    )


class GuardRequirement(StrictModel):
    """Caller-designated named-function guard, not a repository-inferred permission policy.

    Only a direct, top-level call statement in a supported named function is considered.
    Arguments, identity/implementation of the callee, and authorization semantics are not proven.
    """

    path: Annotated[str, Field(min_length=1, max_length=1024)]
    symbol: Annotated[str, Field(min_length=1, max_length=128)]
    guard: Annotated[str, Field(min_length=1, max_length=256)]
    require_await: bool = False

    @model_validator(mode="after")
    def narrow_identifiers(self) -> Self:
        identifier = r"[A-Za-z_$][A-Za-z0-9_$]*"
        if (
            not valid_source_path(self.path)
            or re.fullmatch(identifier, self.symbol) is None
            or re.fullmatch(rf"{identifier}(?:\.{identifier})*", self.guard) is None
        ):
            raise ValueError("guard requirements need a relative path and explicit function/call names")
        return self


class TrustedGuardPolicy(StrictModel):
    """The host authenticates this channel; a JSON source label alone establishes no trust."""

    policy_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:/@-]+$")]
    revision: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:/@-]+$")]
    requirements: Annotated[list[GuardRequirement], Field(min_length=1, max_length=128)]
    source: Literal["caller"] = "caller"

    @model_validator(mode="after")
    def unique_requirements(self) -> Self:
        keys = [(item.path, item.symbol, item.guard) for item in self.requirements]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate guard requirement")
        return self


GuardName = Annotated[str, Field(
    min_length=1, max_length=128, pattern=r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$",
)]
RouteGlob = Annotated[str, Field(min_length=1, max_length=256)]


class ProjectSettings(StrictModel):
    """Repository review settings from `.polaris.toml` `[workflow]`.

    These are advisory configuration for local reviews (which guard functions count as
    authentication, which routes are intentionally public, whether inline suppressions apply).
    They never establish a caller-trusted policy; CI gates should read them from the base branch.
    """

    auth_guards: Annotated[list[GuardName], Field(max_length=64)] = Field(default_factory=list)
    public_routes: Annotated[list[RouteGlob], Field(max_length=256)] = Field(default_factory=list)
    honor_suppressions: bool = True
    # Generated, vendored or otherwise out-of-scope paths. Excluded files are listed as
    # excluded (never silently dropped) and don't make a review incomplete.
    exclude: Annotated[list[RouteGlob], Field(max_length=256)] = Field(default_factory=list)


class WorkflowReviewConfig(StrictModel):
    """Static-workflow limits and selection; deliberately contains no executable or trusted policy."""

    checks: Annotated[list[str], Field(min_length=1, max_length=len(WORKFLOW_CHECKS))] = Field(
        default_factory=lambda: list(WORKFLOW_DEFAULT_CHECKS)
    )
    include: Annotated[list[str], Field(min_length=1, max_length=64)] = Field(
        default_factory=lambda: ["**/*"]
    )
    exclude: Annotated[list[str], Field(max_length=256)] = Field(default_factory=list)
    # Shared by MCP, hooks, HTTP and repair approvals (the config is bound into proposals), so
    # sized for real agent sessions; local CLI reviews raise them further for --files scans.
    max_files: Annotated[int, Field(ge=1, le=50_000)] = 2_000
    # Large hand-written modules (feature-flag tables, type guards) are common in real apps.
    max_file_bytes: Annotated[int, Field(ge=1, le=2_000_000)] = 1_000_000
    max_total_bytes: Annotated[int, Field(ge=1, le=512_000_000)] = 64_000_000
    max_units: Annotated[int, Field(ge=1, le=500_000)] = 50_000
    max_findings: Annotated[int, Field(ge=1, le=10_000)] = 1_000
    # "redacted" omits source snippets from findings (hosted/API use); traces keep line numbers.
    evidence: Literal["full", "redacted"] = "full"
    project: ProjectSettings = Field(default_factory=ProjectSettings)

    @model_validator(mode="after")
    def known_workflow_checks(self) -> Self:
        if len(set(self.checks)) != len(self.checks) or any(c not in WORKFLOW_CHECKS for c in self.checks):
            raise ValueError("unknown or duplicate workflow check")
        return self

    @property
    def exclusions(self) -> list[str]:
        """Caller exclude globs plus the project's `.polaris.toml` [workflow].exclude."""
        return [*self.exclude, *self.project.exclude]


class CheckCoverage(StrictModel):
    path: str
    language: Language
    check_id: str
    analyzer_id: str | None = None
    status: CoverageStatus
    reason: str
    # Advisory authorization coverage is visible without making an unrequested check a gate.
    required: bool = True


class CoverageSummary(StrictModel):
    files_total: int
    files_analyzed: int
    files_not_fully_checked: int
    checks_total: int
    checks_completed: int
    complete: bool
    statuses: dict[str, int]
    entries: list[CheckCoverage]
    omissions: list[str] = Field(default_factory=list)


class AnalyzerCapability(StrictModel):
    analyzer_id: str
    availability: AnalyzerAvailability
    version: str | None
    expected_version: str
    distribution_version: str | None = None
    expected_distribution_version: str | None = None
    identity_digest: str | None = None
    upstream_artifact_sha256: str | None = None
    rule_pack_version: str
    rule_pack_digest: str
    languages: list[Language]
    checks: list[str]
    provenance: str
    license: str
    reason: str
    limitations: list[str]


class CheckCapability(StrictModel):
    language: Language
    extensions: list[str]
    # File names and path patterns that also select this language (Dockerfile, CI workflows).
    path_patterns: list[str] = Field(default_factory=list)
    check_id: str
    analyzer_id: str
    availability: AnalyzerAvailability
    requires_trusted_policy: bool = False
    # Supplementary analyzers add findings but never decide coverage completeness.
    supplementary: bool = False
    limitations: list[str]


class CapabilityManifest(StrictModel):
    format: Literal["polaris.capabilities/0.2.0"] = CAPABILITY_FORMAT
    workflow_format: Literal["polaris.review/0.2.0"] = WORKFLOW_REVIEW_FORMAT
    default_checks: list[str]
    analyzers: list[AnalyzerCapability]
    matrix: list[CheckCapability]
    limitations: list[str]


class TraceStep(StrictModel):
    """One hop from an untrusted source to the sink (labels are short code fragments)."""

    kind: Literal["source", "step", "call", "sink"]
    line: Annotated[int, Field(ge=1)]
    label: Annotated[str, Field(min_length=1, max_length=240)]
    path: str | None = None


class SuggestedEdit(StrictModel):
    """A deterministic, rule-generated replacement for one line. Review before applying."""

    line: Annotated[int, Field(ge=1)]
    original: Annotated[str, Field(max_length=2_000)]
    replacement: Annotated[str, Field(max_length=2_000)]
    note: Annotated[str, Field(max_length=500)] = ""


class WorkflowFinding(Finding):
    analyzer_id: str
    analyzer_version: str
    rule_id: str
    evidence_digest: str
    severity: Severity | None = None
    confidence: Confidence | None = None
    cwe: str | None = None
    category: Category | None = None
    # Stable across unrelated edits (path, check, rule, symbol, normalized sink line).
    fingerprint: str | None = None
    snippet: Annotated[str, Field(max_length=4_000)] | None = None
    snippet_start_line: Annotated[int, Field(ge=1)] | None = None
    trace: Annotated[list[TraceStep], Field(max_length=16)] = Field(default_factory=list)
    suggested_edit: SuggestedEdit | None = None
    # needs_context findings: the exact question the agent should answer, and where to look.
    verify: Annotated[str, Field(max_length=1_000)] | None = None
    call_sites: Annotated[list[str], Field(max_length=16)] = Field(default_factory=list)
    # Set when an inline suppression or the review baseline moved this out of the findings.
    suppression: Annotated[str, Field(max_length=500)] | None = None


# Results other tools reported in SARIF files passed with `--import-sarif` (see
# polaris.review.sarif_import). They are untrusted data: Polaris never runs those tools.
MAX_SARIF_IMPORTS = 16
MAX_IMPORTED_RESULTS = 5_000
ImportedLevel = Literal["error", "warning", "note", "none"]
SarifImportError = Literal[
    "sarif_unavailable", "sarif_too_large", "sarif_total_limit", "invalid_sarif", "unsupported_sarif_version",
]
ImportDropReason = Literal[
    "duplicate", "outside_repository", "unmapped_path", "invalid_path", "outside_review_scope", "no_location",
    "suppressed_by_tool", "not_a_problem", "reserved_tool_name", "result_limit", "imported_limit",
    "invalid_result",
]
# Control, invisible and bidirectional formatting characters (including Unicode tag characters
# used to smuggle hidden text), and lone surrogates, never appear in imported text.
UNSAFE_TEXT = re.compile(
    "[\x00-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069"
    "\ud800-\udfff\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]"
)


class ImportedFinding(StrictModel):
    """A result another tool reported in an imported SARIF file. Polaris did not verify it.

    It never changes Polaris results, coverage, suppressions, baselines or exit codes unless the
    caller opts in. Text is bounded and printable; renderers still treat it as untrusted.
    """

    import_id: Annotated[str, Field(pattern=r"^[0-9a-f]{20}$")]
    tool: Annotated[str, Field(min_length=1, max_length=120)]
    tool_version: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    rule_id: Annotated[str, Field(min_length=1, max_length=200)] | None = None
    # The tool's own SARIF level; `severity` uses its security-severity rating when it gave one.
    level: ImportedLevel
    severity: Severity
    security_severity: Annotated[float, Field(ge=0, le=10)] | None = None
    category: Category
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    # None for results the tool reported for a whole file.
    start_line: Annotated[int, Field(ge=1, le=10_000_000)] | None = None
    end_line: Annotated[int, Field(ge=1, le=10_000_000)] | None = None
    message: Annotated[str, Field(min_length=1, max_length=1_000)]
    cwe: Annotated[
        list[Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]{0,5}$")]], Field(max_length=8)
    ] = Field(default_factory=list)
    # The Polaris check this kind of result relates to (from its CWE or a curated rule map).
    related_check: str | None = None
    # From the tool's own fingerprints when it gave some, otherwise from the location.
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{24}$")]
    sarif_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    # The Polaris finding at the same place that reports the same weakness ("also reported by").
    corroborates: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    verified_by_polaris: Literal[False] = False

    @model_validator(mode="after")
    def inert(self) -> Self:
        texts = (self.tool, self.tool_version or "", self.rule_id or "", self.message)
        if any(UNSAFE_TEXT.search(text) for text in texts):
            raise ValueError("imported text must be printable")
        if not valid_source_path(self.path):
            raise ValueError("imported results need a relative repository path")
        if self.end_line is not None and (self.start_line is None or self.end_line < self.start_line):
            raise ValueError("invalid imported line range")
        if self.related_check is not None and self.related_check not in WORKFLOW_CHECKS:
            raise ValueError("unknown related check")
        return self


class SarifImport(StrictModel):
    """One `--import-sarif` input: how many of its results were kept, or why none were."""

    name: Annotated[str, Field(min_length=1, max_length=120)]
    digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None
    status: Literal["imported", "rejected"]
    error: SarifImportError | None = None
    tools: Annotated[list[Annotated[str, Field(min_length=1, max_length=120)]], Field(max_length=64)] = Field(
        default_factory=list
    )
    runs: Annotated[int, Field(ge=0)] = 0
    # Runs without a results array, or whose invocation reports an unsuccessful execution: the
    # tool may not have finished, so its absent results prove nothing.
    failed_runs: Annotated[int, Field(ge=0)] = 0
    results: Annotated[int, Field(ge=0)] = 0
    imported: Annotated[int, Field(ge=0)] = 0
    corroborating: Annotated[int, Field(ge=0)] = 0
    dropped: dict[ImportDropReason, Annotated[int, Field(ge=1)]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (self.status == "rejected") != (self.error is not None):
            raise ValueError("rejected imports carry exactly one error code")
        if any(UNSAFE_TEXT.search(text) for text in (self.name, *self.tools)):
            raise ValueError("import names must be printable")
        if (self.corroborating > self.imported or self.failed_runs > self.runs
                or self.results != self.imported + sum(self.dropped.values())):
            raise ValueError("inconsistent import counts")
        return self


# The attack surface: request handlers, routes and server actions an analyzer recognized in the
# reviewed files (the built-in TypeScript/JavaScript analyzer today), with what each one reaches.
MAX_SURFACE = 2_000
EntryKind = Literal["route_handler", "pages_api", "server_action", "express_handler", "middleware", "page"]
SurfaceLabel = Annotated[str, Field(min_length=1, max_length=200)]


class SurfaceOperation(StrictModel):
    """A data read or write an entry point reaches: its line and a short code label."""

    line: Annotated[int, Field(ge=1)]
    label: SurfaceLabel


class EntryPoint(StrictModel):
    """One request handler, route or server action, its auth guard (or none), and what it reaches.

    Evidence for review, not an access-control model: `guarded` means a recognized auth-guard
    call (or a configured `[workflow].auth_guards` name) was seen in the handler or its route
    middleware, not that authorization is correct. `public` means the file matches the configured
    `[workflow].public_routes`. `findings` are the ids of reported findings inside the handler.
    """

    path: Annotated[str, Field(min_length=1, max_length=1024)]
    line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    kind: EntryKind
    name: SurfaceLabel
    method: Annotated[str, Field(pattern=r"^[A-Z]{1,16}$")] | None = None
    guarded: bool
    guards: Annotated[list[SurfaceLabel], Field(max_length=5)] = Field(default_factory=list)
    public: bool = False
    rate_limited: bool = False
    writes: Annotated[list[SurfaceOperation], Field(max_length=10)] = Field(default_factory=list)
    reads: Annotated[list[SurfaceOperation], Field(max_length=10)] = Field(default_factory=list)
    # Dangerous calls (SQL, process, file, network, HTML...) the handler reaches, tainted or not.
    sinks: Annotated[int, Field(ge=0)] = 0
    findings: Annotated[list[Annotated[str, Field(min_length=1, max_length=128)]], Field(max_length=64)] = Field(
        default_factory=list)
    analyzer_id: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def inert(self) -> Self:
        if not valid_source_path(self.path) or self.end_line < self.line:
            raise ValueError("entry points need a relative path and a line range")
        texts = (self.name, *self.guards, *(item.label for item in (*self.writes, *self.reads)))
        if any(UNSAFE_TEXT.search(text) for text in texts):
            raise ValueError("entry point text must be printable")
        return self


class ReviewProvenance(StrictModel):
    source_digests: dict[str, str | None]
    before_digests: dict[str, str | None]
    checks_digest: str
    guard_policy_digest: str | None
    capability_digest: str
    snapshot_digest: str
    # Related files read only to resolve calls/imports (not reviewed themselves).
    context_digests: dict[str, str] = Field(default_factory=dict)
    # SARIF files imported with --import-sarif (their content, never their location).
    imported_digests: Annotated[
        list[Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]], Field(max_length=MAX_SARIF_IMPORTS)
    ] = Field(default_factory=list)


class WorkflowReviewSummary(StrictModel):
    files_reviewed: int
    files_skipped: dict[str, int]
    findings_total: int
    results: dict[str, int]
    elapsed_ms: float
    files_not_applicable: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    severities: dict[str, int] = Field(default_factory=dict)
    categories: dict[str, int] = Field(default_factory=dict)
    suppressed: int = 0
    suppressions_added: int = 0
    baselined: int = 0


class WorkflowReviewReport(StrictModel):
    format: Literal["polaris.review/0.2.0"] = WORKFLOW_REVIEW_FORMAT
    model: ModelInfo = Field(
        default_factory=lambda: ModelInfo(engine="rules", release_status="not_applicable")
    )
    checks: list[str]
    summary: WorkflowReviewSummary
    findings: list[WorkflowFinding]
    coverage: CoverageSummary
    capabilities: CapabilityManifest
    provenance: ReviewProvenance
    notices: list[str] = Field(default_factory=list)
    # Findings moved out by inline `polaris-ignore` comments or the review baseline. They are
    # reported for transparency and never counted as findings or used for exit codes.
    suppressed: Annotated[list[WorkflowFinding], Field(max_length=500)] = Field(default_factory=list)
    baselined: Annotated[list[WorkflowFinding], Field(max_length=500)] = Field(default_factory=list)
    # Results other tools reported in imported SARIF files, within the reviewed scope. Listed
    # for reviewers; never counted as findings or used for coverage or exit codes by default.
    imported: Annotated[list[ImportedFinding], Field(max_length=MAX_IMPORTED_RESULTS)] = Field(default_factory=list)
    imports: Annotated[list[SarifImport], Field(max_length=MAX_SARIF_IMPORTS)] = Field(default_factory=list)
    # Entry points (routes, handlers, server actions) in reviewed files and what each reaches.
    # Descriptive only: never counted as findings or used for coverage or exit codes.
    surface: Annotated[list[EntryPoint], Field(max_length=MAX_SURFACE)] = Field(default_factory=list)

    def exit_code(
        self, fail_on: frozenset[str] = frozenset({"flagged"}), *, require_complete: bool = True
    ) -> int:
        """1: selected findings, 2: incomplete required coverage, 0: neither (not a safety proof)."""
        if any(finding.result in fail_on for finding in self.findings):
            return 1
        return 2 if require_complete and not self.coverage.complete else 0

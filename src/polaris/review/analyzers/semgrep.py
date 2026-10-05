"""Pinned Semgrep CE, local original rules only; no registry, inference, or project execution."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from polaris.errors import PolarisInputError
from polaris.jsonio import digest_json, digest_text, load_json
from polaris.review.analyzers.base import (
    AnalysisInput,
    AnalysisRuntime,
    AnalyzerResult,
    language_for_path,
)
from polaris.review.analyzers.identity import (
    CONTRACT_SHA256,
    DISTRIBUTION_VERSION,
    installed_identity,
    qualified_platform,
)
from polaris.review.analyzers.process import (
    ProcessResult,
    controlled_environment,
    installed_semgrep,
    run_bounded,
    sandbox_available,
    sandboxed_command,
)
from polaris.review.analyzers.rule_pack import (
    DESCRIPTIONS,
    JS_CHECKS,
    PYTHON_EXTRA_CHECKS,
    RULE_PACK_DIGEST,
    RULE_PACK_VERSION,
    SEMGREP_VERSION,
    rule_pack_bytes,
)
from polaris.review.models import (
    AnalyzerAvailability,
    AnalyzerCapability,
    CheckCoverage,
    CoverageStatus,
    Language,
    SourceFile,
    WorkflowFinding,
    valid_source_path,
)

ANALYZER_ID = "semgrep-ce"
LIMITATIONS = [
    "Original Polaris pattern pack only; no Semgrep Registry, Pro, dependency, or secret-validation rules.",
    "CE analysis is function/file-local, not whole-program data flow or a security proof.",
    "JS/TS injection sources include named/arrow function parameters and selected request/environment reads.",
    "Node process/filesystem imports and selected sink shapes are recognized; wrappers and dynamic imports can be missed.",
    "Secret exposure covers secret-named environment values in selected outputs, not a general credential scanner.",
    "Path checks detect selected untrusted path uses; they do not prove containment or model all sanitizers.",
    "Security configuration covers explicit TLS-verification disabling, not all unsafe configuration.",
    "Complete supplied files are scanned; a match is not necessarily newly introduced by the change.",
    "Private temporary source files are used and removed; cleanup is not secure disk erasure.",
    "OS network denial is required (macOS sandbox-exec or Linux bubblewrap); Windows is unavailable.",
    "The sandbox restricts networking/writes, not all runtime reads, and does not make a hostile analyzer trustworthy.",
    "Only the exact managed macOS ARM64 graph has local compatibility evidence; other platforms need separate qualification.",
    "MCP service, authentication, enabled tracing and arbitrary plugins remain shipped but are outside the supported fixed scan interface.",
    "Metadata identity checks are not a full installed-payload integrity check or a security-risk acceptance.",
]


def supported_checks(language: Language) -> tuple[str, ...]:
    if language == "python":
        return PYTHON_EXTRA_CHECKS
    return JS_CHECKS if language in ("javascript", "typescript") else ()


def _capability(
    availability: AnalyzerAvailability, reason: str, version: str | None = None,
    identity: dict[str, str] | None = None,
) -> AnalyzerCapability:
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability=availability, version=version,
        expected_version=SEMGREP_VERSION, rule_pack_version=RULE_PACK_VERSION,
        distribution_version=identity["distributionVersion"] if identity else None,
        expected_distribution_version=DISTRIBUTION_VERSION,
        identity_digest="sha256:" + CONTRACT_SHA256 if identity else None,
        upstream_artifact_sha256=identity["upstreamWheelSha256"] if identity else None,
        rule_pack_digest=RULE_PACK_DIGEST,
        languages=["python", "javascript", "typescript"], checks=list(JS_CHECKS),
        provenance=(f"https://pypi.org/pypi/semgrep/{SEMGREP_VERSION}/json; "
                    f"metadata-only downstream {DISTRIBUTION_VERSION}; original Polaris rules"),
        license=("Semgrep wheel: LGPL-2.1-or-later; native root: LGPL-2.1-only "
                 "(terms require reconciliation); original Polaris rules: Apache-2.0"),
        reason=reason, limitations=list(LIMITATIONS),
    )


@contextmanager
def _workspace() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="polaris-analysis-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        for name in ("home", "tmp", "source"):
            (root / name).mkdir(mode=0o700)
        yield root


def _private_write(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)


class SemgrepAnalyzer:
    analyzer_id = ANALYZER_ID

    def __init__(self, runtime: AnalysisRuntime | None = None) -> None:
        self.runtime = runtime or AnalysisRuntime()

    def capability(self, *, probe: bool = False) -> AnalyzerCapability:
        runtime = self.runtime
        if not runtime.allow_external_analyzers:
            return _capability("disabled", "external_analyzers_disabled")
        if not runtime.allow_temporary_source_files:
            return _capability("disabled", "temporary_source_files_disabled")
        if runtime.semgrep_executable is None:
            return _capability("disabled", "not_configured")
        executable = installed_semgrep(runtime)
        if executable is None:
            return _capability("unavailable", "semgrep_not_installed")
        if not qualified_platform():
            return _capability("unavailable", "qualified_analyzer_platform_unavailable")
        try:
            identity = installed_identity(executable)
        except (OSError, ValueError, UnicodeError):
            return _capability("version_mismatch", "qualified_analyzer_identity_required")
        if not sandbox_available():
            return _capability("sandbox_unavailable", "network_sandbox_unavailable")
        if not probe:
            return _capability("not_probed", "installed_version_not_probed", identity=identity)
        try:
            with _workspace() as workspace:
                return self._probe(executable, workspace)
        except OSError:
            return _capability("error", "temporary_workspace_unavailable")

    def _run(self, argv: Sequence[str], workspace: Path, timeout: float) -> ProcessResult:
        command = sandboxed_command(argv, workspace=workspace, runtime=self.runtime, timeout=timeout)
        if command is None:
            return ProcessResult("unavailable")
        return run_bounded(
            command, cwd=workspace, env=controlled_environment(workspace, argv[0]),
            timeout=timeout, max_output_bytes=self.runtime.max_output_bytes,
        )

    def _probe(self, executable: str, workspace: Path) -> AnalyzerCapability:
        try:
            identity = installed_identity(executable)
        except (OSError, ValueError, UnicodeError):
            return _capability("version_mismatch", "qualified_analyzer_identity_required")
        done = self._run(
            [executable, "scan", "--version", "--disable-version-check", "--metrics=off", "--no-trace"],
            workspace, self.runtime.version_timeout_seconds,
        )
        if done.status != "ok" or done.returncode != 0:
            return _capability("error", "analyzer_probe_" + (done.status if done.status != "ok" else "failed"))
        try:
            version = done.stdout.decode("ascii").strip()
        except UnicodeDecodeError:
            return _capability("error", "invalid_version_output")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version) is None:
            return _capability("error", "invalid_version_output")
        if version != SEMGREP_VERSION:
            return _capability("version_mismatch", "pinned_version_required", version)
        return _capability("available", "qualified_identity_and_runtime_verified", version, identity)

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        capability = self.capability()
        if capability.availability == "disabled":
            # Opt-in supplementary analyzer that was not requested: nothing to report.
            return AnalyzerResult(capability=capability)
        eligible: list[SourceFile] = []
        coverage: list[CheckCoverage] = []
        omissions: list[str] = []
        total_bytes = 0
        for index, source in enumerate(request.sources):
            checks = self._checks(source, request.checks)
            if not checks:
                continue
            reason = source.skip
            if not valid_source_path(source.path):
                reason = "invalid_path"
            elif source.after is None:
                reason = reason or "missing_source"
            elif "\0" in source.after:
                reason = "binary"
            elif len(source.after) > request.config.max_file_bytes:
                reason = "file_too_large"
            else:
                try:
                    size = len(source.after.encode("utf-8"))
                    total_bytes += size
                    if size > request.config.max_file_bytes:
                        reason = "file_too_large"
                except UnicodeError:
                    reason = "invalid_encoding"
            if index >= request.config.max_files:
                reason = "file_limit"
            if total_bytes > request.config.max_total_bytes:
                reason = "total_source_limit"
            if reason:
                coverage.extend(self._coverage(source, checks, "not_checked", reason))
            else:
                eligible.append(source)
        if not eligible:
            return AnalyzerResult(coverage=tuple(coverage), capability=capability)
        if capability.availability not in ("available", "not_probed"):
            for source in eligible:
                coverage.extend(self._coverage(source, self._checks(source, request.checks),
                                               "not_checked", capability.reason))
            return AnalyzerResult(coverage=tuple(coverage), capability=capability)
        executable = installed_semgrep(self.runtime)
        if executable is None:
            capability = _capability("unavailable", "semgrep_not_installed")
            return self._failed(eligible, request, capability.reason, capability, coverage)
        try:
            with _workspace() as workspace:
                capability = self._probe(executable, workspace)
                if capability.availability != "available":
                    return self._failed(eligible, request, capability.reason, capability, coverage)
                # Never materialize input paths; targets have fixed generated basenames only.
                targets: dict[str, SourceFile] = {}
                for index, source in enumerate(eligible):
                    language = language_for_path(source.path)
                    suffix = PurePosixPath(source.path).suffix.lower()
                    extension = suffix if suffix in (".jsx", ".tsx") else {
                        "python": ".py", "javascript": ".js", "typescript": ".ts",
                    }[language]
                    name = f"source/input-{index:06d}{extension}"
                    assert source.after is not None
                    _private_write(workspace / name, source.after.encode("utf-8"))
                    targets[name] = source
                languages = {language_for_path(source.path) for source in eligible}
                _private_write(
                    workspace / "polaris-rules.yaml",
                    rule_pack_bytes(set(request.checks), languages),
                )
                # An empty local ignore file and generated target names prevent repository
                # ignore/nosem comments or a project's own Semgrep configuration changing scope.
                _private_write(workspace / ".semgrepignore", b"")
                argv = [
                    executable, "scan", "--oss-only", "--config", "polaris-rules.yaml",
                    "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-trace",
                    "--disable-nosem", "--no-git-ignore", "--no-rewrite-rule-ids",
                    "--strict", "--jobs=1",
                    "--max-target-bytes", str(request.config.max_file_bytes),
                    "--max-memory", str(self.runtime.max_memory_mb),
                    "--timeout", str(self.runtime.per_file_timeout_seconds),
                    "--timeout-threshold=1", "--", *targets,
                ]
                done = self._run(argv, workspace, self.runtime.timeout_seconds)
                if done.status != "ok":
                    return self._failed(
                        eligible, request, "analyzer_" + done.status, capability, coverage,
                    )
                findings, run_coverage, result_omissions = self._decode(
                    done, targets, workspace, request,
                )
                coverage.extend(run_coverage)
                omissions.extend(result_omissions)
        except (OSError, UnicodeError):
            return self._failed(eligible, request, "temporary_workspace_error", capability, coverage)
        return AnalyzerResult(
            findings=tuple(findings), coverage=tuple(coverage), capability=capability,
            omissions=tuple(omissions),
            notices=("Semgrep CE analyzed private temporary copies locally with network denied; "
                     "copies were removed (not securely erased). No registry rules or models were used.",),
        )

    @staticmethod
    def _checks(source: SourceFile, checks: Sequence[str]) -> list[str]:
        supported = supported_checks(language_for_path(source.path))
        return [check for check in checks if check in supported]

    @staticmethod
    def _coverage(
        source: SourceFile, checks: Sequence[str], status: CoverageStatus, reason: str,
    ) -> list[CheckCoverage]:
        return [
            CheckCoverage(path=source.path, language=language_for_path(source.path), check_id=check,
                          analyzer_id=ANALYZER_ID, status=status, reason=reason)
            for check in checks
        ]

    def _failed(
        self, sources: Sequence[SourceFile], request: AnalysisInput, reason: str,
        capability: AnalyzerCapability, existing: Sequence[CheckCoverage],
    ) -> AnalyzerResult:
        entries = list(existing)
        for source in sources:
            entries.extend(self._coverage(source, self._checks(source, request.checks), "not_checked", reason))
        return AnalyzerResult(coverage=tuple(entries), capability=capability)

    def _decode(
        self, done: ProcessResult, targets: dict[str, SourceFile], workspace: Path, request: AnalysisInput,
    ) -> tuple[list[WorkflowFinding], list[CheckCoverage], list[str]]:
        def failed(reason: str) -> tuple[list[WorkflowFinding], list[CheckCoverage], list[str]]:
            return [], [
                item for source in targets.values()
                for item in self._coverage(source, self._checks(source, request.checks), "not_checked", reason)
            ], []

        try:
            data = load_json(done.stdout, max_bytes=self.runtime.max_output_bytes)
        except (PolarisInputError, ValueError):
            return failed("invalid_analyzer_json")
        if (
            not isinstance(data, dict) or data.get("version") != SEMGREP_VERSION
            or not isinstance(data.get("results"), list) or not isinstance(data.get("errors"), list)
            or not isinstance(data.get("paths"), dict)
            or not isinstance(data["paths"].get("scanned"), list)
        ):
            return failed("invalid_analyzer_envelope")
        if len(data["results"]) > min(self.runtime.max_results, request.config.max_findings):
            return failed("result_limit")

        def target_name(value: Any) -> str | None:
            if not isinstance(value, str):
                return None
            if value in targets:
                return value
            # Pure string comparison only: do not resolve or open analyzer-returned paths.
            return next((name for name in targets if value == str(workspace / name)), None)

        problems: dict[str, str] = {}
        global_problem: str | None = None
        scanned: set[str] = set()
        for path in data["paths"]["scanned"]:
            name = target_name(path)
            if name is None:
                global_problem = "invalid_scan_manifest"
            else:
                scanned.add(name)
        for error in data["errors"]:
            if not isinstance(error, dict):
                global_problem = "invalid_analyzer_error"
                continue
            error_type = error.get("type")
            # ATD encodes this payload-bearing variant as [tag, locations]. Malformed
            # or unknown variants still make coverage incomplete; never copy payloads.
            if isinstance(error_type, list):
                if (len(error_type) == 2 and error_type[0] == "PartialParsing"
                        and isinstance(error_type[1], list) and error_type[1]
                        and all(isinstance(location, dict) and isinstance(location.get("path"), str)
                                and isinstance(location.get("start"), dict)
                                and isinstance(location.get("end"), dict)
                                for location in error_type[1])):
                    error_type = "PartialParsing"
                else:
                    error_type = None
            reason = {
                "PartialParsing": "partial_parse", "ParseError": "parse_error",
                "SyntaxError": "parse_error", "Timeout": "analyzer_timeout",
                "OutOfMemory": "analyzer_memory_limit",
            }.get(error_type if isinstance(error_type, str) else "", "analyzer_error")
            name = target_name(error.get("path"))
            if name is not None:
                problems[name] = reason
            else:
                global_problem = reason
        if data.get("skipped_rules"):
            global_problem = "analyzer_rules_skipped"
        if done.returncode != 0 and not data["errors"]:
            global_problem = "analyzer_exit_nonzero"
        findings: list[WorkflowFinding] = []
        seen: set[str] = set()
        for record in data["results"]:
            if not isinstance(record, dict):
                global_problem = "invalid_analyzer_result"
                continue
            name = target_name(record.get("path"))
            rule_id = record.get("check_id")
            description = DESCRIPTIONS.get(rule_id) if isinstance(rule_id, str) else None
            if name is None or description is None:
                global_problem = "invalid_analyzer_result"
                continue
            assert isinstance(rule_id, str)
            source = targets[name]
            if (
                description.check_id not in self._checks(source, request.checks)
                or language_for_path(source.path) not in description.languages
            ):
                global_problem = "unexpected_rule_result"
                continue
            start, end = record.get("start"), record.get("end")
            if not isinstance(start, dict) or not isinstance(end, dict):
                problems[name] = "invalid_result_location"
                continue
            first, last = start.get("line"), end.get("line")
            assert source.after is not None
            if (
                type(first) is not int or type(last) is not int
                or not 1 <= first <= last <= max(1, len(source.after.splitlines()))
            ):
                problems[name] = "invalid_result_location"
                continue
            digest = digest_text(source.after)
            finding_id = digest_json([ANALYZER_ID, RULE_PACK_DIGEST, rule_id, source.path, digest, first, last])[7:27]
            if finding_id in seen:
                continue
            seen.add(finding_id)
            findings.append(WorkflowFinding(
                finding_id=finding_id, path=source.path, start_line=first, end_line=last,
                symbol="<file>", check_id=description.check_id, title=description.title,
                result="flagged", engine="rules", reason="original_rule_match",
                message=description.message, guidance=description.guidance,
                details=[f"Original rule {rule_id}; source text and metavariable values omitted."],
                analyzer_id=ANALYZER_ID, analyzer_version=SEMGREP_VERSION,
                rule_id=rule_id, evidence_digest=digest,
            ))
        coverage: list[CheckCoverage] = []
        for name, source in targets.items():
            coverage_reason = problems.get(name) or global_problem
            if name not in scanned:
                coverage_reason = coverage_reason or "target_not_scanned"
            if not source.context_complete:
                coverage_reason = coverage_reason or "incomplete_source_context"
            status: CoverageStatus = (
                "partial" if coverage_reason and name in scanned else "not_checked" if coverage_reason else "checked"
            )
            coverage.extend(self._coverage(
                source, self._checks(source, request.checks), status, coverage_reason or "original_rules_completed",
            ))
        return findings, coverage, []

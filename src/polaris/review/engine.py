"""Review orchestration: files -> units -> static facts -> batched model or rules -> findings."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from polaris.contract import AssessmentRequest, AssessmentResponse, ErrorResponse, RuntimeIdentity
from polaris.engine import Assessor, Backend
from polaris.errors import PolarisRuntimeError
from polaris.jsonio import digest_json, digest_text
from polaris.review import catalog
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.analyzers.base import (
    AnalysisInput,
    AnalyzerResult,
    file_kind,
    generated_reason,
    language_for_path,
    runtime_identity,
)
from polaris.review.analyzers.registry import (
    AnalyzerSpec,
    active_specs,
    implemented_checks,
    load_plugins,
    owned_capability,
)
from polaris.review.cache import ReviewCache
from polaris.review.capabilities import manifest_from_analyzers
from polaris.review.dataflow import (
    CHECK_FOR_KIND,
    FlowFacts,
    analyze,
    describe_sink,
    has_candidate_call,
)
from polaris.review.extract import CodeUnit, hunk_snippets, parse_unified_diff, units_from_source
from polaris.review.format import build_request
from polaris.review.js.tsconfig import is_config
from polaris.review.models import (
    GUIDANCE,
    MAX_SURFACE,
    PRUNED_DIRECTORIES,
    RESULTS,
    TITLES,
    WORKFLOW_DEFAULT_CHECKS,
    CheckCoverage,
    CoverageSummary,
    Engine,
    EntryPoint,
    Finding,
    FindingEngine,
    ModelInfo,
    ReviewConfig,
    ReviewProvenance,
    ReviewReport,
    ReviewSummary,
    SecondOpinion,
    SourceFile,
    TrustedGuardPolicy,
    WorkflowFinding,
    WorkflowReviewConfig,
    WorkflowReviewReport,
    WorkflowReviewSummary,
    in_sentence,
    valid_source_path,
)
from polaris.review.rules import rule_result
from polaris.review.scope import SCOPE_LIMIT_PATH, read_scoped_text, workflow_sources_from_paths

ANALYZABLE = frozenset(CHECK_FOR_KIND.values()) & frozenset({"sql_injection", "command_injection"})
GROUP = 256
Progress = Callable[[int, int], None]
MAX_CONTEXT_FILES = 48
MAX_CONTEXT_BYTES = 1_500_000
# Nothing to analyze: deletions, generated/minified/vendored code and symbolic links (never
# followed; a link's in-repository target is reviewed as its own file).
NOT_APPLICABLE_SKIPS = frozenset({"deleted", "generated_or_minified", "generated_or_vendored", "symlink"})
# For documentation, configuration and assets these are expected, not review failures.
NON_SOURCE_SKIPS = frozenset({"unsupported_language", "binary", "file_too_large", "invalid_encoding"})
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# `// polaris-ignore[xss,ssrf]: reason` (also `#` and `/* */` comments) on or above the line.
SUPPRESSION = re.compile(
    r"(?://|#|/\*|--|<!--)\s*polaris-ignore(?:\[(?P<checks>[a-z_,\s]+)\])?(?:\s*[:\-]\s*(?P<reason>[^*\n]{0,200}))?"
)


def suppression_reason(text: str, line: int, check_id: str) -> str | None:
    """The reason of an inline suppression that applies to this finding line, if any."""
    lines = text.splitlines()
    for number in (line, line - 1):
        if not 1 <= number <= len(lines):
            continue
        match = SUPPRESSION.search(lines[number - 1])
        if match is None:
            continue
        listed = match.group("checks")
        if listed and check_id not in {item.strip() for item in listed.split(",")}:
            continue
        return (match.group("reason") or "").strip() or "suppressed inline without a reason"
    return None


class ThresholdView(Protocol):
    @property
    def evaluation_risk_threshold(self) -> float: ...


class ProfileView(Protocol):
    @property
    def checks(self) -> Mapping[str, ThresholdView]: ...


@runtime_checkable
class RemoteModel(Protocol):
    """A Polaris model that runs elsewhere (the hosted API): requests are sent, not computed here."""

    api_url: str
    identity: RuntimeIdentity
    supported_checks: frozenset[str]

    @property
    def profile(self) -> ProfileView: ...

    def assess_many(self, values: Sequence[AssessmentRequest | dict[str, Any] | str | bytes], *,
                    batch_size: int = 16) -> list[AssessmentResponse | ErrorResponse]: ...

    def assess_envelope(self, value: AssessmentRequest | dict[str, Any] | str | bytes
                        ) -> AssessmentResponse | ErrorResponse: ...


ReviewModel = Backend | RemoteModel

RULE_REASONS = {
    "untrusted_value_in_sql_text": "an untrusted value is built into the SQL text",
    "query_supplied_by_caller": "the whole query comes from the caller",
    "query_origin_not_visible": "the query is built outside this function",
    "query_not_visible": "the query isn't visible in this call",
    "sql_text_fixed_or_parameterized": "the SQL text is fixed or parameterized",
    "untrusted_executable": "an untrusted value chooses the program to run",
    "untrusted_value_in_shell_command": "an untrusted value is built into a shell command",
    "untrusted_command_split": "an untrusted string is split into a command",
    "command_supplied_by_caller": "the whole command comes from the caller",
    "command_origin_not_visible": "the command is built outside this function",
    "executable_not_visible": "the program to run is chosen outside this function",
    "command_not_visible": "the command isn't visible in this call",
    "fixed_executable_argument_list": "the program is fixed and arguments are passed as a list",
    "fixed_shell_command": "the shell command is fixed",
    "no_shell_fixed_program": "no shell is used and the program is fixed",
    "no_candidate_calls": "no SQL or process-execution calls",
}


def _matches(path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
            return True
    return False


def _plugin_scoped(spec: AnalyzerSpec, outcome: AnalyzerResult, reviewed: set[str]) -> AnalyzerResult:
    """A plugin reports only on reviewed files of the languages and checks it declared, so it
    can never mark another analyzer's (or an undeclared) check as complete, nor describe the
    attack surface of files it doesn't own."""
    def owned(path: str, check_id: str) -> bool:
        return path in reviewed and check_id in spec.checks.get(language_for_path(path), ())

    def owned_file(path: str) -> bool:
        return path in reviewed and language_for_path(path) in spec.checks

    return replace(
        outcome,
        findings=tuple(item for item in outcome.findings if owned(item.path, item.check_id)),
        coverage=tuple(item for item in outcome.coverage if owned(item.path, item.check_id)),
        capability=owned_capability(spec, outcome.capability) if outcome.capability is not None else None,
        surface=tuple(item.model_copy(update={"analyzer_id": spec.analyzer_id})
                      for item in outcome.surface if owned_file(item.path)),
    )


def _surface(entries: Iterable[EntryPoint], findings: Sequence[WorkflowFinding], reviewed: set[str]) -> list[EntryPoint]:
    """Entry points of reviewed files, one per handler, each linked to the findings inside it."""
    unique: dict[tuple[str, int, str, str], EntryPoint] = {}
    for entry in entries:
        if entry.path in reviewed:
            unique.setdefault((entry.path, entry.line, entry.kind, entry.name), entry)
    by_path: dict[str, list[WorkflowFinding]] = {}
    for finding in findings:
        if finding.result != "ok":
            by_path.setdefault(finding.path, []).append(finding)
    linked = []
    for entry in sorted(unique.values(), key=lambda item: (item.path, item.line, item.name)):
        inside = [finding.finding_id for finding in by_path.get(entry.path, ())
                  if entry.line <= finding.start_line <= entry.end_line]
        linked.append(entry.model_copy(update={"findings": list(dict.fromkeys(inside))[:64]}))
    return linked


def _finding_id(unit: CodeUnit, check_id: str) -> str:
    material = "\0".join((unit.path, unit.symbol, check_id, unit.source))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def read_text(root: Path, relative: str, limit: int) -> str | None:
    """Read a repository file safely: no absolute paths, traversal, or symlink escapes."""
    return read_scoped_text(root.resolve(), relative, limit)[0]


class Reviewer:
    """Review Python code. Findings describe risk; they never authorize or execute anything."""

    def __init__(
        self,
        backend: ReviewModel | None = None,
        *,
        config: ReviewConfig | None = None,
        engine: Engine = "model",
        allow_experimental: bool = True,
        batch_size: int = 16,
        cache: ReviewCache | None = None,
        notices: list[str] | None = None,
    ) -> None:
        if engine == "model" and backend is None:
            raise PolarisRuntimeError("model_unavailable")
        self.backend = backend
        self.config = config or ReviewConfig()
        self.engine = engine
        self.batch_size = batch_size
        self.cache = cache
        self.extra_notices = list(notices or [])
        # A hosted model assesses on the server; a local one runs through the Assessor here.
        self.assessor: Assessor | RemoteModel = (
            backend if isinstance(backend, RemoteModel)
            else Assessor(backend, allow_experimental=allow_experimental)
        )

    # ---- entry points --------------------------------------------------------------------------

    def review_snippet(self, code: str, *, path: str = "snippet.py") -> ReviewReport:
        return self.review_sources([SourceFile(path, code)])

    def review_diff(self, diff: str, *, root: Path | None = None,
                    read_before: Callable[[str], str | None] | None = None) -> ReviewReport:
        """Review a unified diff. With `root`, whole functions are read from the working tree;
        `read_before(path)` supplies the previous version (for example from `git show`)."""
        sources: list[SourceFile] = []
        partial = False
        for item in parse_unified_diff(diff):
            if item.new_path is None:
                sources.append(SourceFile(item.old_path or "deleted", None, skip="deleted"))
                continue
            if item.binary:
                sources.append(SourceFile(item.new_path, None, skip="binary"))
                continue
            if root is not None:
                after = read_text(root, item.new_path, self.config.max_file_bytes)
                before = read_before(item.old_path) if (read_before and item.old_path) else None
                if after is not None:
                    sources.append(SourceFile(item.new_path, after, before, frozenset(item.changed_lines)))
                    continue
            partial = True
            for start, snippet in hunk_snippets(item):
                # Leading blank lines keep reported line numbers aligned with the real file.
                sources.append(SourceFile(item.new_path, "\n" * (start - 1) + snippet))
        report = self.review_sources(sources)
        if partial:
            notice = ("Some files were reviewed from diff hunks only. Run inside the repository or "
                      "send full files for complete function context.")
            report = report.model_copy(update={"notices": [*report.notices, notice]})
        return report

    def review_paths(self, paths: Iterable[Path], *, root: Path,
                     progress: Progress | None = None) -> ReviewReport:
        return self.review_sources(self.iter_paths(paths, root=root), progress=progress)

    def iter_paths(self, paths: Iterable[Path], *, root: Path) -> Iterator[SourceFile]:
        root = root.resolve()
        for path in paths:
            path = (root / path) if not path.is_absolute() else path
            if path.is_dir() and not path.is_symlink():
                for directory, names, files in os.walk(path):
                    names[:] = sorted(name for name in names if name not in PRUNED_DIRECTORIES
                                      and not name.startswith(".") and not name.endswith(".egg-info"))
                    for name in sorted(files):
                        if name.endswith(".py"):
                            yield self._load(root, Path(directory) / name)
            elif path.is_file():
                yield self._load(root, path)

    def _load(self, root: Path, path: Path) -> SourceFile:
        if path.is_symlink():
            return SourceFile(path.name, None, skip="symlink")
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            return SourceFile(path.name, None, skip="outside_root")
        text = read_text(root, relative, self.config.max_file_bytes)
        if text is not None:
            return SourceFile(relative, text)
        try:
            too_big = path.stat().st_size > self.config.max_file_bytes
        except OSError:
            too_big = False
        return SourceFile(relative, None, skip="file_too_large" if too_big else "unreadable")

    # ---- core ----------------------------------------------------------------------------------

    def _skip(self, source: SourceFile) -> str | None:
        if source.skip is not None:
            return source.skip
        if source.after is None:
            return "deleted"
        if "\0" in source.after:
            return "binary"
        if not source.path.endswith(".py"):
            return "not_python"
        if not _matches(source.path, self.config.include) or _matches(source.path, self.config.exclude):
            return "excluded"
        if len(source.after.encode("utf-8")) > self.config.max_file_bytes:
            return "file_too_large"
        return None

    def review_sources(self, files: Iterable[SourceFile], *, progress: Progress | None = None) -> ReviewReport:
        started = time.perf_counter()
        config = self.config
        checks = [check for check in config.checks if check in ANALYZABLE]
        notices: list[str] = list(self.extra_notices)
        others = [TITLES.get(check, check) for check in config.checks if check not in ANALYZABLE]
        if others:
            notices.append("Not supported by the review engine yet: " + ", ".join(others) + ".")
        skipped: Counter[str] = Counter()
        files_reviewed = 0
        units: list[CodeUnit] = []
        for source in files:
            reason = self._skip(source)
            if reason is not None:
                skipped[reason] += 1
                continue
            assert source.after is not None
            found, reason = units_from_source(
                source.path, source.after, changed_lines=source.changed_lines, before_text=source.before
            )
            if reason is not None:
                skipped[reason] += 1
                continue
            files_reviewed += 1
            room = config.max_units - len(units)
            units.extend(found[:room])
            if len(found) > room:
                notices.append(f"Stopped after {config.max_units} functions; raise max_units to review more.")
                break
        results: Counter[str] = Counter()
        findings: list[Finding] = []
        candidates: list[tuple[CodeUnit, FlowFacts, list[str]]] = []
        prefiltered = 0
        for unit in units:
            facts = analyze(unit.node, unit.imports) if has_candidate_call(unit.node, unit.imports) else None
            relevant = [check for check in checks if facts is not None and facts.sinks_for(check)]
            if not relevant:
                prefiltered += 1
            for check in checks:
                if check not in relevant:
                    results["ok"] += 1
                    if config.report_ok:
                        findings.append(self._finding(unit, check, "ok", "no_candidate_calls",
                                                      "No SQL or process-execution calls here.", engine="static"))
            if relevant and facts is not None:
                candidates.append((unit, facts, relevant))
        cache_hits = 0
        disagreements = 0
        uses_model = self.backend is not None and self.engine in ("model", "hybrid")
        for start in range(0, len(candidates), GROUP):
            group = candidates[start : start + GROUP]
            if not uses_model:
                batch = self._rules(group, results)
            elif self.engine == "hybrid":
                batch, hits, disagreed = self._hybrid(group, results)
                cache_hits += hits
                disagreements += disagreed
            else:
                batch, hits = self._model(group, results)
                cache_hits += hits
            findings.extend(batch)
            if progress is not None:
                progress(min(start + GROUP, len(candidates)), len(candidates))
        if uses_model and self.backend is not None:
            identity = self.backend.identity
            model = ModelInfo(engine=self.engine, model_version=identity.model_version,
                              release_status=identity.release_status,
                              runtime_variant=identity.runtime_variant,
                              calibration_version=identity.calibration_version)
            if self.engine == "hybrid":
                notices.append("Static rules decided each result; the Polaris model added a second opinion "
                               "that never changes it.")
            elif identity.release_status != "qualified":
                notices.append("Experimental model: findings are research diagnostics, not a security qualification.")
            if (identity.model_version or "").startswith("polaris-preview"):
                notices.append("Polaris Preview learned from synthetic examples only; accuracy on real code is unproven.")
            if isinstance(self.backend, RemoteModel):
                notices.append(f"The model ran on the Polaris API ({self.backend.api_url}); only functions with SQL "
                               "or process calls were sent. Everything else stayed on this machine.")
        else:
            model = ModelInfo(engine="rules", release_status="not_applicable")
            if self.engine == "hybrid" and not self.extra_notices:
                notices.append("No Polaris model is installed, so the static rules reviewed this alone. Install "
                               "one (`polaris model install`) to add the model's second opinion.")
            else:
                notices.append("Rule engine: simple static rules only, no model.")
        elapsed = (time.perf_counter() - started) * 1000
        severity = {name: index for index, name in enumerate(("flagged", "error", "too_large", "needs_context", "uncertain", "unsupported", "ok"))}
        findings.sort(key=lambda f: (severity[f.result], f.path, f.start_line, f.check_id))
        return ReviewReport(
            model=model,
            checks=checks,
            policy_source=config.policy_source,
            summary=ReviewSummary(
                files_reviewed=files_reviewed,
                files_skipped=dict(sorted(skipped.items())),
                units_total=len(units),
                units_assessed=len(candidates),
                units_prefiltered=prefiltered,
                results={name: results[name] for name in RESULTS if results[name]},
                cache_hits=cache_hits,
                elapsed_ms=round(elapsed, 3),
                units_per_second=round(len(units) / (elapsed / 1000), 2) if elapsed > 0 and units else None,
                second_opinion_disagreements=disagreements,
            ),
            findings=findings,
            notices=list(dict.fromkeys(notices)),
        )

    # ---- engines -------------------------------------------------------------------------------

    def _finding(self, unit: CodeUnit, check: str, result: str, reason: str, message: str, *,
                 engine: FindingEngine, risk: float | None = None, threshold: float | None = None,
                 facts: FlowFacts | None = None, digest: str | None = None) -> Finding:
        details = [describe_sink(sink) for sink in facts.sinks_for(check)] if facts else []
        return Finding(
            finding_id=_finding_id(unit, check),
            path=unit.path,
            start_line=unit.start_line,
            end_line=unit.end_line,
            symbol=unit.symbol,
            check_id=check,
            title=TITLES.get(check, check),
            result=result,  # type: ignore[arg-type]
            engine=engine,
            risk=risk,
            threshold=threshold,
            reason=reason,
            message=message,
            guidance=GUIDANCE.get(check) if result in ("flagged", "needs_context", "uncertain") else None,
            details=details,
            request_digest=digest,
        )

    def _hybrid(self, group: list[tuple[CodeUnit, FlowFacts, list[str]]],
                results: Counter[str]) -> tuple[list[Finding], int, int]:
        """Rules decide each result; the model's view is attached as a second opinion.

        Rule-OK results are kept only when the model flags them, so people can see where the
        two disagree. The model never changes a result, the exit code or the counts.
        """
        decided = self._rules(group, results, keep_ok=True)
        opinions, hits = self._model(group, Counter(), keep_ok=True)
        by_key = {(f.path, f.symbol, f.start_line, f.check_id): f for f in opinions}
        findings: list[Finding] = []
        disagreements = 0
        for finding in decided:
            opinion = by_key.get((finding.path, finding.symbol, finding.start_line, finding.check_id))
            if opinion is not None:
                finding = finding.model_copy(update={"second_opinion": SecondOpinion(
                    result=opinion.result, risk=opinion.risk, reason=opinion.reason)})
                if {finding.result, opinion.result} == {"flagged", "ok"}:
                    disagreements += 1
            model_flags = finding.second_opinion is not None and finding.second_opinion.result == "flagged"
            if finding.result != "ok" or self.config.report_ok or model_flags:
                findings.append(finding)
        return findings, hits, disagreements

    def _rules(self, group: list[tuple[CodeUnit, FlowFacts, list[str]]], results: Counter[str], *,
               keep_ok: bool = False) -> list[Finding]:
        findings = []
        for unit, facts, relevant in group:
            for check in relevant:
                result, reason, _ = rule_result(check, facts)
                title = in_sentence(TITLES[check])
                phrase = RULE_REASONS.get(reason, reason.replace("_", " "))
                message = {
                    "flagged": f"Likely {title}: {phrase}.",
                    "needs_context": f"Can't judge {title} from this function alone: {phrase}.",
                    "ok": f"No {title} risk found: {phrase}.",
                }[result]
                results[result] += 1
                if result != "ok" or self.config.report_ok or keep_ok:
                    findings.append(self._finding(unit, check, result, reason, message, engine="rules", facts=facts))
        return findings

    def _identity(self) -> dict[str, Any]:
        assert self.backend is not None
        return self.backend.identity.model_dump(mode="json")

    def _model(self, group: list[tuple[CodeUnit, FlowFacts, list[str]]],
               results: Counter[str], *, keep_ok: bool = False) -> tuple[list[Finding], int]:
        assert self.backend is not None
        config = self.config
        findings: list[Finding] = []
        requests: list[dict[str, Any]] = []
        owners: list[tuple[CodeUnit, FlowFacts, list[str]]] = []
        for unit, facts, relevant in group:
            try:
                request = build_request(path=unit.path, symbol=unit.symbol, start_line=unit.start_line,
                                        source=unit.source, before=unit.before, facts=facts, checks=relevant,
                                        policy=config.policy, policy_source=config.policy_source)
            except ValueError:
                for check in relevant:
                    results["too_large"] += 1
                    findings.append(self._finding(unit, check, "too_large", "unit_too_large",
                                                  "This function is too long to assess; review it manually or split it.",
                                                  engine="model", facts=facts))
                continue
            requests.append(request)
            owners.append((unit, facts, relevant))
        responses: list[AssessmentResponse | ErrorResponse | None] = [None] * len(requests)
        identity = self._identity() if self.cache else {}
        keys = [ReviewCache.key(request, identity) for request in requests] if self.cache else []
        hits = 0
        if self.cache:
            for index, key in enumerate(keys):
                cached = self.cache.get(key)
                if cached is not None:
                    try:
                        responses[index] = (
                            ErrorResponse.model_validate_json(cached) if '"kind":"error"' in cached
                            else AssessmentResponse.model_validate_json(cached)
                        )
                        hits += 1
                    except ValueError:
                        responses[index] = None
        todo = [index for index, response in enumerate(responses) if response is None]
        if todo:
            fresh = self.assessor.assess_many([requests[i] for i in todo], batch_size=self.batch_size)
            for index, response in zip(todo, fresh, strict=True):
                responses[index] = response
                cacheable = isinstance(response, AssessmentResponse) or response.code == "context_limit"
                if self.cache and cacheable:
                    self.cache.put(keys[index], response.model_dump_json())
        for (unit, facts, relevant), outcome in zip(owners, responses, strict=True):
            assert outcome is not None
            findings.extend(self._from_response(unit, facts, relevant, outcome, results, keep_ok=keep_ok))
        return findings, hits

    def _from_response(self, unit: CodeUnit, facts: FlowFacts, relevant: list[str],
                       response: AssessmentResponse | ErrorResponse, results: Counter[str], *,
                       keep_ok: bool = False) -> list[Finding]:
        assert self.backend is not None
        findings = []
        if isinstance(response, ErrorResponse):
            result = "too_large" if response.code == "context_limit" else "error"
            message = ("This function is too long for the model's 2,048-token limit; review it manually or split it."
                       if result == "too_large" else f"No assessment: {response.message}")
            for check in relevant:
                results[result] += 1
                findings.append(self._finding(unit, check, result, response.code, message, engine="model", facts=facts))
            return findings
        for check_result in response.results:
            check = check_result.check_id
            title = in_sentence(TITLES.get(check, check))
            reason = check_result.reason_codes[0]
            risk = threshold = None
            if check_result.status == "assessed" and check_result.probabilities is not None:
                risk = check_result.probabilities.risk_present
                threshold = (config_threshold if (config_threshold := self.config.flag_threshold) is not None
                             else self.backend.profile.checks[check].evaluation_risk_threshold)
                result = "flagged" if risk >= threshold else "ok"
                message = (f"Likely {title}: estimated risk {risk:.0%} (flags at {threshold:.0%})."
                           if result == "flagged" else f"No {title} risk found (estimated risk {risk:.0%}).")
            elif check_result.status == "abstain":
                result = "uncertain" if reason == "uncertain" else "needs_context"
                message = (f"Polaris isn't sure about {title} here; take a closer look." if result == "uncertain"
                           else f"Polaris can't judge {title} from this function alone; check where the input comes from.")
            else:
                result = "unsupported"
                message = f"{TITLES.get(check, check)} isn't supported by this model."
            results[result] += 1
            if result != "ok" or self.config.report_ok or keep_ok:
                findings.append(self._finding(unit, check, result, reason, message, engine="model", risk=risk,
                                              threshold=threshold, facts=facts, digest=response.request_digest))
        return findings


class WorkflowReviewer:
    """Broader static review, explicitly separate from legacy Python/model assessments.

    No model is loaded or called. A complete coverage result only describes bounded
    implemented rules on the supplied snapshot, never correctness or authorization.
    """

    def __init__(
        self, *, config: WorkflowReviewConfig | None = None,
        runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
        baseline: frozenset[str] | None = None,
    ) -> None:
        self.config = config or WorkflowReviewConfig()
        self.runtime = runtime or AnalysisRuntime()
        self.guard_policy = guard_policy
        self.baseline = baseline or frozenset()
        # Plugin source kinds must be registered before any path is classified.
        load_plugins(self.runtime.plugins)

    def review_snippet(self, code: str, *, path: str = "snippet.py") -> WorkflowReviewReport:
        return self.review_sources([SourceFile(path, code)])

    def review_paths(
        self, paths: Iterable[Path], *, root: Path, progress: Progress | None = None,
    ) -> WorkflowReviewReport:
        return self.review_sources(
            workflow_sources_from_paths(paths, root=root, config=self.config), progress=progress,
        )

    def review_diff(
        self, diff: str, *, root: Path | None = None,
        read_before: Callable[[str], str | None] | None = None,
    ) -> WorkflowReviewReport:
        if len(diff) > self.config.max_total_bytes:
            return self.review_sources([SourceFile("__polaris_diff__", None, skip="diff_too_large")])
        try:
            if len(diff.encode("utf-8")) > self.config.max_total_bytes:
                raise ValueError("diff limit")
            items = parse_unified_diff(diff)
        except (ValueError, UnicodeError):
            return self.review_sources([SourceFile("__polaris_diff__", None, skip="invalid_diff")])
        if diff.strip() and not items:
            return self.review_sources([SourceFile("__polaris_diff__", None, skip="unrecognized_diff")])
        sources: list[SourceFile] = []
        for item in items[:self.config.max_files]:
            path = item.new_path or item.old_path or "__polaris_diff__"
            if not valid_source_path(path) or (item.old_path is not None and not valid_source_path(item.old_path)):
                sources.append(SourceFile(path, None, skip="invalid_path"))
                continue
            before = read_before(item.old_path) if read_before and item.old_path else None
            previous_path = item.old_path if item.old_path != item.new_path else None
            if item.new_path is None:
                sources.append(SourceFile(path, None, before, skip="deleted", previous_path=previous_path))
                continue
            if item.binary:
                sources.append(SourceFile(path, None, skip="binary", previous_path=previous_path))
                continue
            if language_for_path(path) == "unsupported":
                sources.append(SourceFile(path, None, skip="unsupported_language", previous_path=previous_path))
                continue
            if root is not None:
                after, reason = read_scoped_text(root.resolve(), path, self.config.max_file_bytes)
                if after is not None:
                    sources.append(SourceFile(
                        path, after, before, frozenset(item.changed_lines), previous_path=previous_path,
                    ))
                    continue
                sources.append(SourceFile(path, None, before, skip=reason, previous_path=previous_path))
                continue
            lines: list[str] = []
            for start, snippet in hunk_snippets(item):
                if start > self.config.max_file_bytes or len(lines) + len(snippet) > self.config.max_file_bytes:
                    lines = []
                    break
                lines.extend([""] * max(0, start - 1 - len(lines)))
                lines.extend(snippet.splitlines())
            if not lines:
                sources.append(SourceFile(path, None, before, skip="incomplete_diff", previous_path=previous_path))
            else:
                sources.append(SourceFile(
                    path, "\n".join(lines) + "\n", before, previous_path=previous_path,
                    context_complete=False,
                ))
        if len(items) > self.config.max_files:
            sources.append(SourceFile(SCOPE_LIMIT_PATH, None, skip="file_limit"))
        return self.review_sources(sources)

    def review_sources(
        self, files: Iterable[SourceFile], *, progress: Progress | None = None,
    ) -> WorkflowReviewReport:
        started = time.perf_counter()
        config = self.config
        checks = list(config.checks)
        if self.guard_policy is not None and "api_authorization" not in checks:
            checks.append("api_authorization")
        explicit_checks = list(config.checks) != list(WORKFLOW_DEFAULT_CHECKS)
        sources: list[SourceFile] = []
        context: list[SourceFile] = []
        positions: dict[str, int] = {}
        omissions: list[str] = []
        notices = [
            "Static analysis only: nothing was executed and no model was used. No findings means these "
            "checks found no issues, not that the code is proven safe.",
        ]
        total_bytes = 0
        context_bytes = 0
        index = -1
        for original in files:
            if not isinstance(original, SourceFile):
                raise ValueError("workflow sources must be SourceFile snapshots")
            if original.role == "context":
                text = original.after
                if (text is not None and valid_source_path(original.path) and len(text) <= config.max_file_bytes
                        and "\0" not in text and len(context) < MAX_CONTEXT_FILES
                        and context_bytes + len(text) <= MAX_CONTEXT_BYTES):
                    context_bytes += len(text)
                    context.append(original)
                continue
            index += 1
            if original.path == SCOPE_LIMIT_PATH and original.skip:
                omissions.append(original.skip)
                break
            if index >= config.max_files:
                omissions.append("file_limit")
                break
            source = original
            reason = source.skip
            excluded_by_config = (
                not _matches(source.path, config.include) or _matches(source.path, config.exclusions)
            )
            pruned_by_path = any(
                part in PRUNED_DIRECTORIES or part.endswith(".egg-info")
                for part in source.path.split("/")
            )
            if reason == "excluded" and not excluded_by_config:
                reason = "unverified_exclusion"
            if reason == "pruned_directory" and not pruned_by_path:
                reason = "unverified_exclusion"
            if source.changed_lines is not None and (
                len(source.changed_lines) > config.max_file_bytes
                or any(type(line) is not int or not 1 <= line <= config.max_file_bytes for line in source.changed_lines)
            ):
                source = replace(source, changed_lines=None)
                reason = "invalid_changed_lines"
            if source.previous_path is not None and not valid_source_path(source.previous_path):
                source = replace(source, previous_path=None)
                reason = "invalid_previous_path"
            if not valid_source_path(source.path):
                source = replace(source, path=f"__polaris_invalid_path_{index}__", after=None, before=None)
                reason = "invalid_path"
            if source.path in positions:
                prior = positions[source.path]
                sources[prior] = replace(sources[prior], after=None, before=None, skip="duplicate_source_path")
                omissions.append("duplicate_source_path")
                continue
            if reason is None:
                if excluded_by_config:
                    reason = "excluded"
                elif source.after is None:
                    reason = "deleted"
                elif language_for_path(source.path) == "unsupported":
                    reason = "unsupported_language"
                elif "\0" in source.after:
                    reason = "binary"
                else:
                    reason = generated_reason(source.path, source.after)
            # Do not hash/materialize arbitrarily large caller-provided strings. Unknown
            # digests remain null and their skipped coverage cannot pass a strict gate.
            for field in ("after", "before"):
                text = getattr(source, field)
                if text is None:
                    continue
                size_reason: str | None = None
                if len(text) > config.max_file_bytes:
                    size_reason = "file_too_large"
                else:
                    try:
                        size = len(text.encode("utf-8"))
                        if size > config.max_file_bytes:
                            size_reason = "file_too_large"
                        elif total_bytes + size > config.max_total_bytes:
                            size_reason = "total_source_limit"
                        else:
                            total_bytes += size
                    except UnicodeError:
                        size_reason = "invalid_encoding"
                if size_reason and field == "after":
                    source = replace(source, after=None)
                    reason = reason or size_reason
                elif size_reason:
                    source = replace(source, before=None, before_skip=size_reason)
            if reason is not None:
                source = replace(source, skip=reason)
            positions[source.path] = len(sources)
            sources.append(source)
        required_checks = [check for check in checks if check != "api_authorization"]
        coverage: list[CheckCoverage] = []
        eligible = []
        for source in sources:
            if source.skip is None:
                eligible.append(source)
                continue
            language = language_for_path(source.path)
            applicable = [check for check in required_checks if catalog.applies(check, language)]
            if source.skip in NOT_APPLICABLE_SKIPS or not applicable or (
                file_kind(source.path) == "non_source" and source.skip in NON_SOURCE_SKIPS
            ):
                reason = ("no_applicable_checks" if not applicable and source.skip not in NOT_APPLICABLE_SKIPS
                          else "not_source_code" if source.skip in NON_SOURCE_SKIPS
                          else "symlink_not_followed" if source.skip == "symlink" else source.skip)
                coverage.append(CheckCoverage(path=source.path, language=language, check_id="*",
                                              status="not_applicable", reason=reason, required=False))
            else:
                # Excluded and pruned paths stay visible but are not required.
                optional = source.skip in ("excluded", "pruned_directory")
                coverage.extend(
                    CheckCoverage(path=source.path, language=language, check_id=check, status="not_checked",
                                  reason=source.skip, required=not optional)
                    for check in applicable
                )
        # Changed tsconfig/jsconfig files are not source code, but their path aliases are
        # needed to link imports; analyzers receive them as read-only context.
        context_paths = {item.path for item in context}
        context.extend(
            replace(source, role="context", skip=None) for source in sources
            if is_config(source.path) and source.after is not None and source.path not in context_paths
            and source.skip in (None, "unsupported_language")
        )
        inputs = {
            "analysis": AnalysisInput([*eligible, *context], checks, config, workers=self.runtime.parallel_workers),
            "review": AnalysisInput(eligible, checks, config),
            "all": AnalysisInput(sources, checks, config),
        }
        specs = active_specs(self.runtime)
        outcomes = [spec.create(self.runtime, self.guard_policy).analyze(inputs[spec.inputs]) for spec in specs]
        reviewed_paths = {source.path for source in eligible}
        outcomes = [
            _plugin_scoped(spec, outcome, reviewed_paths) if spec.plugin is not None else outcome
            for spec, outcome in zip(specs, outcomes, strict=True)
        ]
        findings: list[WorkflowFinding] = []
        entry_points: list[EntryPoint] = []
        for position, (spec, outcome) in enumerate(zip(specs, outcomes, strict=True)):
            entry_points.extend(outcome.surface)
            # Supplementary analyzers (Semgrep CE) are opt-in. When the caller explicitly configured
            # one, a failed or partial run leaves requested analysis undone and counts toward completeness.
            supplementary = spec.supplementary and not spec.requested(self.runtime)
            coverage.extend(
                entry.model_copy(update={"required": False}) if supplementary else entry for entry in outcome.coverage
            )
            # Categories come from the Polaris catalog, whichever analyzer (or plugin) reported.
            findings.extend(
                finding if finding.category == catalog.check_category(finding.check_id)
                else finding.model_copy(update={"category": catalog.check_category(finding.check_id)})
                for finding in outcome.findings
            )
            notices.extend(outcome.notices)
            if not supplementary:
                omissions.extend(outcome.omissions)
            if progress is not None:
                progress(position + 1, len(outcomes))
        coverage.extend(self._missing_rows(eligible, required_checks, coverage, explicit_checks))
        findings, suppressed, baselined, added = self._suppress(findings, sources)
        if len(findings) > config.max_findings:
            findings = findings[:config.max_findings]
            omissions.append("result_limit")
        surface = _surface(entry_points, findings, reviewed_paths)
        if len(surface) > MAX_SURFACE:
            # Descriptive only: a shortened attack-surface list never makes coverage incomplete.
            notices.append(f"The attack surface lists the first {MAX_SURFACE} of {len(surface)} entry points.")
            surface = surface[:MAX_SURFACE]
        if added:
            notices.append(f"{added} new polaris-ignore suppression(s) were added in this change; review each one.")
        if any(source.before_skip for source in sources) and self.guard_policy is not None:
            notices.append("Some before versions were unavailable or exceeded limits; their guard regressions cannot be checked.")
        if not sources:
            notices.append("No source files were supplied; this is not a review of an entire repository.")
        coverage.sort(key=lambda entry: (entry.path, entry.check_id, entry.analyzer_id or ""))
        findings.sort(key=lambda finding: (
            finding.result != "flagged", SEVERITY_RANK.get(finding.severity or "medium", 2), finding.path,
            finding.start_line, finding.rule_id,
        ))
        required = [entry for entry in coverage if entry.required]
        checked = [entry for entry in required if entry.status == "checked"]
        analyzed_paths = {entry.path for entry in required if entry.status != "not_checked"}
        incomplete_paths = {entry.path for entry in required if entry.status != "checked"}
        not_applicable = {entry.path for entry in coverage if entry.status == "not_applicable"} - {
            entry.path for entry in coverage if entry.status != "not_applicable" and entry.required
        }
        skipped = Counter({
            reason: len({entry.path for entry in required if entry.status != "checked" and entry.reason == reason})
            for reason in {entry.reason for entry in required if entry.status != "checked"}
        })
        manifest = manifest_from_analyzers([
            outcome.capability for outcome in outcomes if outcome.capability is not None
        ])
        source_digests = {source.path: digest_text(source.after) if source.after is not None else None for source in sources}
        before_digests = {source.path: digest_text(source.before) if source.before is not None else None for source in sources}
        context_digests = {source.path: digest_text(source.after or "") for source in context}
        checks_digest = digest_json(checks)
        policy_digest = digest_json(self.guard_policy.model_dump(mode="json")) if self.guard_policy else None
        capability_digest = digest_json(manifest.model_dump(mode="json"))
        provenance = ReviewProvenance(
            source_digests=source_digests, before_digests=before_digests, checks_digest=checks_digest,
            guard_policy_digest=policy_digest, capability_digest=capability_digest,
            context_digests=context_digests,
            snapshot_digest=digest_json({
                "format": "polaris.review/0.2.0", "after": source_digests, "before": before_digests,
                "context": context_digests,
                "sources": [
                    {"path": source.path, "previous_path": source.previous_path,
                     "changed_lines": sorted(source.changed_lines) if source.changed_lines is not None else None,
                     "skip": source.skip, "before_skip": source.before_skip, "context_complete": source.context_complete}
                    for source in sources
                ],
                "config": config.model_dump(mode="json"), "checks": checks_digest, "policy": policy_digest,
                "capabilities": capability_digest, "runtime": runtime_identity(self.runtime), "omissions": omissions,
                "baseline": sorted(self.baseline),
            }),
        )
        reported = [finding for finding in findings if finding.result != "ok"]
        return WorkflowReviewReport(
            checks=checks,
            summary=WorkflowReviewSummary(
                files_reviewed=len(analyzed_paths), files_skipped=dict(sorted(skipped.items())),
                findings_total=len(findings), results=dict(Counter(finding.result for finding in findings)),
                elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
                files_not_applicable=len(not_applicable),
                languages=dict(Counter(language_for_path(source.path) for source in eligible)),
                severities=dict(Counter(finding.severity or "medium" for finding in reported)),
                categories=dict(Counter(finding.category or "security" for finding in reported)),
                suppressed=len(suppressed), suppressions_added=added, baselined=len(baselined),
            ),
            findings=findings,
            coverage=CoverageSummary(
                files_total=len(sources), files_analyzed=len(analyzed_paths),
                files_not_fully_checked=len(incomplete_paths), checks_total=len(required),
                checks_completed=len(checked), complete=len(required) == len(checked) and not omissions,
                statuses=dict(Counter(entry.status for entry in required)), entries=coverage,
                omissions=list(dict.fromkeys(omissions)),
            ),
            capabilities=manifest, provenance=provenance, notices=list(dict.fromkeys(notices)),
            suppressed=suppressed[:500], baselined=baselined[:500], surface=surface,
        )

    def _missing_rows(
        self, eligible: list[SourceFile], required_checks: list[str], coverage: list[CheckCoverage],
        explicit_checks: bool,
    ) -> list[CheckCoverage]:
        """Never let an unanalyzed applicable (language, check) pair disappear from coverage.

        Checks of another domain (CI workflow checks on TypeScript, code checks on a Dockerfile)
        don't apply at all. A file with no applicable requested check is listed as not
        applicable instead of vanishing from the report.
        """
        covered = {(entry.path, entry.check_id) for entry in coverage if entry.required}
        # Advisory rows (the guard analyzer lists every source) don't account for a file.
        listed = {entry.path for entry in coverage if entry.required or entry.status == "not_applicable"}
        implemented: dict[str, frozenset[str]] = {}
        rows = []
        for source in eligible:
            language = language_for_path(source.path)
            if language not in implemented:
                implemented[language] = implemented_checks(language, self.runtime)
            supported = implemented[language]
            applicable = [check for check in required_checks if catalog.applies(check, language)]
            if not applicable and source.path not in listed:
                rows.append(CheckCoverage(path=source.path, language=language, check_id="*", status="not_applicable",
                                          reason="no_applicable_checks", required=False))
            for check in applicable:
                if (source.path, check) in covered:
                    continue
                if check in supported:
                    rows.append(CheckCoverage(path=source.path, language=language, check_id=check, status="not_checked",
                                              reason="analyzer_produced_no_result", required=True))
                else:
                    rows.append(CheckCoverage(path=source.path, language=language, check_id=check, status="not_checked",
                                              reason="not_implemented_for_language", required=explicit_checks))
        return rows

    def _suppress(
        self, findings: list[WorkflowFinding], sources: list[SourceFile],
    ) -> tuple[list[WorkflowFinding], list[WorkflowFinding], list[WorkflowFinding], int]:
        """Move inline-suppressed and baselined findings out of the counted results."""
        texts = {source.path: source.after or "" for source in sources}
        kept: list[WorkflowFinding] = []
        suppressed: list[WorkflowFinding] = []
        baselined: list[WorkflowFinding] = []
        honor = self.config.project.honor_suppressions
        for finding in findings:
            reason = suppression_reason(texts.get(finding.path, ""), finding.start_line, finding.check_id) if honor else None
            if reason is not None:
                suppressed.append(finding.model_copy(update={"suppression": reason}))
            elif finding.fingerprint is not None and finding.fingerprint in self.baseline:
                baselined.append(finding.model_copy(update={"suppression": "baseline"}))
            else:
                kept.append(finding)
        added = 0
        for source in sources:
            if source.after is not None and source.before is not None:
                added += max(0, len(SUPPRESSION.findall(source.after)) - len(SUPPRESSION.findall(source.before)))
        return kept, suppressed, baselined, added

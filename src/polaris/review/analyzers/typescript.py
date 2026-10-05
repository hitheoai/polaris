"""Built-in TypeScript/JavaScript analyzer: in-process, cross-platform, no external tools.

Parses with tree-sitter (bundled wheels) and never executes, imports or writes the reviewed
code. Coverage rows say exactly which checks ran on which files; a checked row means these
bounded rules completed, not that the file is secure.
"""

from __future__ import annotations

import fnmatch
import math
import os
import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from polaris.jsonio import digest_json
from polaris.review import catalog
from polaris.review.analyzers.base import AnalysisInput, AnalyzerResult, language_for_path
from polaris.review.analyzers.evidence import insert_edit, make_finding, replace_edit, step
from polaris.review.js.tsconfig import AliasConfig, is_config, load_alias_config
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    CoverageStatus,
    EntryPoint,
    SourceFile,
    SurfaceOperation,
    TraceStep,
    WorkflowFinding,
)

ANALYZER_ID = "polaris-ts"
VERSION = "polaris-ts/0.3.0"
CHECKS = (
    "sql_injection", "command_injection", "code_injection", "xss", "ssrf", "open_redirect",
    "path_traversal", "secret_exposure", "missing_authorization", "insecure_auth_crypto",
    "unsafe_security_configuration",
)
LIMITATIONS = [
    "Function-level data flow with summaries across reviewed and related files; not whole-program analysis.",
    "Entry points: Next.js route handlers, pages, middleware and server actions, pages/api, Express/Hono/Fastify registrations, client URL APIs.",
    "Calls into unresolved packages don't carry taint unless they are known string/URL/path helpers.",
    "Validation recognized: allowlist/prefix/equality checks with early exits, known sanitizers, constrained zod/valibot schemas.",
    "missing_authorization recognizes common guard names and configured [workflow].auth_guards; middleware-only auth needs public_routes or auth_guards.",
    "React 19 blocks javascript: URLs; href/src props are not treated as XSS sinks.",
]
VERIFY = {
    "xss": "Is this HTML sanitized (e.g. DOMPurify.sanitize) or built only from trusted, escaped content?",
    "code_injection": "Can this value ever contain user input? If so, replace dynamic evaluation with a fixed dispatch table.",
    "ssrf": "Is the URL's host fixed or checked against an allowlist before this request?",
    "open_redirect": "Is the destination restricted to same-site relative paths or an allowlist?",
    "path_traversal": "Is the path confined to a fixed base folder (resolved and prefix-checked) before use?",
    "sql_injection": "Is every interpolated value a fixed identifier or a bound parameter?",
    "command_injection": "Is every value passed to the program fixed or strictly validated (and separated with \"--\")?",
    "secret_exposure": "Could this value contain a credential?",
    "insecure_auth_crypto": "Is the token or claim verified before it is trusted?",
    "unsafe_security_configuration": "Is this configuration limited to local development?",
}
KIND_LABEL = {
    "request": "request input", "route_param": "route parameter", "url_input": "URL query input",
    "client_input": "browser URL input", "action_input": "server action argument", "argv": "command-line argument",
    "message_data": "postMessage data", "page_prop": "page URL params", "secret_env": "secret environment value",
}
# Reviewed files are parsed and analyzed in batches (syntax trees cost ~25x the source size);
# other files are parsed on demand as context and released with their batch.
BATCH_FILES = 400
BATCH_BYTES = 8_000_000
# Reviews of at least PARALLEL_MIN_FILES files are split into up to PARALLEL_BATCHES batches
# (of at least PARALLEL_MIN_BATCH files), which local CLI/MCP reviews analyze in worker
# processes (AnalysisRuntime.parallel_workers). The split depends only on the review, never on
# the machine, so findings are the same with or without workers.
PARALLEL_MIN_FILES = 80
PARALLEL_MIN_BATCH = 40
PARALLEL_BATCHES = 8


def grammars_available() -> bool:
    """True when the bundled tree-sitter grammars load (they ship as wheels; nothing is built)."""
    try:
        from polaris.review.js.engine import _language

        for name in ("typescript", "tsx", "javascript"):
            _language(name)
        return True
    except (ImportError, OSError, ValueError, AttributeError, TypeError):
        return False


def capability() -> AnalyzerCapability:
    available = grammars_available()
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability="available" if available else "unavailable",
        version=VERSION, expected_version=VERSION, rule_pack_version=VERSION,
        rule_pack_digest=digest_json({"version": VERSION, "rules": sorted(
            rule_id for rule_id in catalog.RULES if rule_id.startswith("polaris.js."))}),
        languages=["javascript", "typescript"], checks=list(CHECKS),
        provenance="Original Polaris tree-sitter rules (tree-sitter, tree-sitter-typescript, tree-sitter-javascript: MIT)",
        license="Apache-2.0", reason="builtin_in_process" if available else "tree_sitter_unavailable",
        limitations=list(LIMITATIONS),
    )


def _batch_size(count: int) -> int:
    if count < PARALLEL_MIN_FILES:
        return BATCH_FILES
    return min(BATCH_FILES, max(PARALLEL_MIN_BATCH, math.ceil(count / PARALLEL_BATCHES)))


def _batches(sources: dict[str, SourceFile], max_files: int | None = None) -> Iterator[list[str]]:
    """Reviewed paths in sorted order (neighbouring files usually call each other), bounded by
    file count and source size."""
    limit = max_files or BATCH_FILES
    batch: list[str] = []
    size = 0
    for path in sorted(sources):
        length = len(sources[path].after or "")
        if batch and (len(batch) >= limit or size + length > BATCH_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(path)
        size += length
    if batch:
        yield batch


@dataclass
class _BatchResult:
    findings: list[WorkflowFinding] = field(default_factory=list)
    statuses: dict[str, tuple[CoverageStatus, str]] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)
    helper_hits: list[Any] = field(default_factory=list)
    call_records: dict[tuple[str, int, int], list[tuple[str, int, str]]] = field(default_factory=dict)
    surface: list[EntryPoint] = field(default_factory=list)


def _entry_points(project: Any, reviewed: dict[str, SourceFile], public: Sequence[str]) -> list[EntryPoint]:
    """The attack surface of this batch's reviewed files, from the auth facts of each handler
    (Next.js route handlers, pages/api, server actions, Express/Hono/Fastify registrations).
    Labels are short code fragments, collapsed and made printable."""
    from polaris.review.sarif_import import text as printable

    def operations(items: Sequence[tuple[int, str]]) -> list[SurfaceOperation]:
        return [SurfaceOperation(line=max(1, line), label=printable(label, 200) or "operation")
                for line, label in items[:10]]

    entries: list[EntryPoint] = []
    for facts in project.auth:
        if facts.path not in reviewed:
            continue
        entry = facts.entry
        method = (entry.method or "").upper()
        try:
            entries.append(EntryPoint(
                path=facts.path, line=facts.line, end_line=max(facts.line, int(entry.node.end_point[0]) + 1),
                kind=entry.kind, name=printable(entry.name, 200) or entry.kind,
                method=method if re.fullmatch(r"[A-Z]{1,16}", method) else None, guarded=facts.guarded,
                guards=[label for label in (printable(name, 200) for name in facts.guard_names) if label][:5],
                public=_public(facts.path, public), rate_limited=facts.rate_limited,
                writes=operations(facts.writes), reads=operations(facts.reads), sinks=max(0, facts.sinks),
                analyzer_id=ANALYZER_ID,
            ))
        except ValueError:  # an entry kind or label outside the model's bounds is left out, never guessed
            continue
    return entries


def _analyze_batch(
    batch: list[str], *, texts: dict[str, str], reviewed: dict[str, SourceFile], context_paths: list[str],
    aliases: dict[str, AliasConfig], checks: list[str], config: Any,
) -> _BatchResult:
    """Parse and analyze one batch of reviewed files; other files are parsed on demand."""
    from polaris.review.js import checks as patterns
    from polaris.review.js.engine import JsFile, Project

    analyzer = TypeScriptAnalyzer()
    evidence = config.evidence
    result = _BatchResult()

    def load_context(path: str) -> JsFile | None:
        text = texts.get(path)
        if text is None:
            return None
        try:
            return JsFile(path, text, role="context")
        except (RecursionError, MemoryError, ValueError, UnicodeError):
            return None

    files: dict[str, JsFile] = {}
    for path in batch:
        try:
            files[path] = JsFile(path, texts[path], role="review")
        except (RecursionError, MemoryError, ValueError, UnicodeError):
            result.failures[path] = "analysis_error"
    project = Project(files, guards=list(config.project.auth_guards), aliases=aliases, loader=load_context)
    for path in batch:
        file = files.get(path)
        if file is None:
            continue
        source = reviewed[path]
        try:
            project.analyze(file)
            pattern_hits = patterns.scan(file)
        except (RecursionError, MemoryError) as exc:
            result.statuses[path] = ("partial", "analysis_limit" if isinstance(exc, RecursionError) else "memory_limit")
            continue
        result.statuses[path] = (
            ("partial", "partial_parse") if file.error_ratio > 0.1 else ("checked", "builtin_rules_completed")
        )
        for item in pattern_hits:
            if item.check not in checks:
                continue
            edit = replace_edit(source, item.line, item.replace_old, item.replace_new,
                                "Re-enables the security control.") if item.replace_old else None
            result.findings.append(make_finding(
                analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=item.check,
                rule_id=item.rule_id, result=item.result, start_line=item.line, symbol=item.symbol,
                message=f"{catalog.RULES[item.rule_id].message} ({item.label})",
                severity=item.severity,  # type: ignore[arg-type]
                confidence=item.confidence,  # type: ignore[arg-type]
                trace=[step("sink", item.line, item.label)], suggested_edit=edit,
                verify=VERIFY.get(item.check) if item.result == "needs_context" else None,
                evidence=evidence, reason="pattern_match",
            ))
    # Importers supplied as context: follow the values they pass into this batch's files.
    for path in context_paths:
        importer = project.load(path)
        if importer is None or not project.imports_reviewed(importer):
            continue
        try:
            project.analyze(importer)
        except (RecursionError, MemoryError):
            continue
    # Hits and auth facts reference this batch's syntax trees: convert them now.
    result.findings.extend(analyzer._hits(project, reviewed, checks, evidence))
    if "missing_authorization" in checks:
        result.findings.extend(analyzer._authorization(project, reviewed, config.project.public_routes, evidence))
    result.surface.extend(_entry_points(project, reviewed, config.project.public_routes))
    result.helper_hits.extend(project.helper_hits)
    for key, records in project.call_records.items():
        result.call_records.setdefault(key, []).extend(records)
    return result


_WORKER_STATE: dict[str, Any] = {}


def _init_worker(shared: dict[str, Any]) -> None:
    # Workers inherit the parent's stdout, which carries the MCP protocol: send any stray
    # output to stderr instead.
    try:
        os.dup2(2, 1)
    except OSError:
        pass
    _WORKER_STATE.clear()
    _WORKER_STATE.update(shared)


def _batch_worker(batch: list[str]) -> _BatchResult:
    return _analyze_batch(batch, **_WORKER_STATE)


def _parallel(batches: list[list[str]], shared: dict[str, Any], workers: int) -> list[_BatchResult] | None:
    """Batches in spawned worker processes (no fork: safe in threaded hosts), in batch order.

    Returns None when worker processes can't be used (frozen executables, process limits, a
    broken pool, unpicklable results); the caller then analyzes the same batches in-process,
    which raises any genuine analysis error itself.
    """
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    if getattr(sys, "frozen", False):
        return None
    try:
        with ProcessPoolExecutor(max_workers=min(workers, len(batches)), mp_context=multiprocessing.get_context("spawn"),
                                 initializer=_init_worker, initargs=(shared,)) as pool:
            return list(pool.map(_batch_worker, batches))
    except Exception:
        return None


def _public(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, pattern.removeprefix("**/"))
               for pattern in patterns)


def _trace(hit: Any, *, secret: bool = False, caller: str | None = None) -> list[TraceStep]:
    """Source-to-sink hops. `caller` labels hops in the calling file when the finding is
    reported at a sink in another (reviewed) file."""
    origins = hit.taint.secrets() if secret else hit.taint.real()
    steps: list[TraceStep] = []
    seen: set[tuple[int, str]] = set()
    for origin in origins[:2]:
        label = f"{origin.label} ({KIND_LABEL.get(origin.kind, origin.kind)})"
        steps.append(step("source", origin.line, label, origin.path or caller))
        seen.add((origin.line, origin.label))
    for line, label, path in hit.taint.steps:
        if (line, label) in seen or any(label == origin.label for origin in origins):
            continue
        seen.add((line, label))
        steps.append(step("call" if label.endswith("(…)") else "step", line, label, path or caller))
    if hit.sink_path or hit.sink_line:
        steps.append(step("sink", hit.sink_line or hit.line, hit.sink, hit.sink_path))
    else:
        steps.append(step("sink", hit.line, hit.sink))
    return steps[-12:]


class TypeScriptAnalyzer:
    analyzer_id = ANALYZER_ID

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        checks = [check for check in request.checks if check in CHECKS]
        config = request.config
        evidence = config.evidence
        findings: list[WorkflowFinding] = []
        coverage: list[CheckCoverage] = []
        if checks and not grammars_available():
            unreviewed = [CheckCoverage(path=source.path, language=language_for_path(source.path), check_id=check,
                                        analyzer_id=ANALYZER_ID, status="not_checked", reason="tree_sitter_unavailable")
                          for source in request.sources
                          if source.role == "review" and source.skip is None and source.after is not None
                          and language_for_path(source.path) in ("javascript", "typescript") for check in checks]
            return AnalyzerResult(coverage=tuple(unreviewed), capability=capability())
        if not checks:
            return AnalyzerResult(capability=capability())
        reviewed: dict[str, SourceFile] = {}
        texts: dict[str, str] = {}
        context_paths: list[str] = []
        failures: dict[str, str] = {}
        configs = {source.path: source.after for source in request.sources
                   if is_config(source.path) and source.after is not None}
        aliases: dict[str, AliasConfig] = {}
        for path in list(configs)[:64]:
            loaded = load_alias_config(path, configs.get)
            if loaded is not None:
                aliases[path] = loaded
        for source in request.sources:
            if language_for_path(source.path) not in ("javascript", "typescript") or source.after is None:
                continue
            if source.skip is not None and source.role == "review":
                continue
            texts[source.path] = source.after
            if source.role == "review":
                reviewed[source.path] = source
            else:
                context_paths.append(source.path)

        shared: dict[str, Any] = {"texts": texts, "reviewed": reviewed, "context_paths": context_paths,
                                  "aliases": aliases, "checks": checks, "config": config}
        batches = list(_batches(reviewed, _batch_size(len(reviewed))))
        results = _parallel(batches, shared, request.workers) if request.workers > 1 and len(batches) > 1 else None
        if results is None:
            results = [_analyze_batch(batch, **shared) for batch in batches]
        statuses: dict[str, tuple[CoverageStatus, str]] = {}
        helper_hits: list[Any] = []
        call_records: dict[tuple[str, int, int], list[tuple[str, int, str]]] = {}
        surface: dict[tuple[str, int, str, str], EntryPoint] = {}
        for result in results:
            findings.extend(result.findings)
            statuses.update(result.statuses)
            failures.update(result.failures)
            helper_hits.extend(result.helper_hits)
            for key, records in result.call_records.items():
                call_records.setdefault(key, []).extend(records)
            for entry in result.surface:
                surface.setdefault((entry.path, entry.line, entry.kind, entry.name), entry)
        # Helper findings depend on every observed caller, so they wait for all batches.
        findings.extend(self._helpers(helper_hits, call_records, reviewed, checks, evidence))
        for path in reviewed:
            if path in failures:
                continue
            row_status, row_reason = statuses.get(path, ("not_checked", "analysis_error"))
            language = language_for_path(path)
            coverage.extend(CheckCoverage(path=path, language=language, check_id=check, analyzer_id=ANALYZER_ID,
                                          status=row_status, reason=row_reason) for check in checks)
        for path, reason in failures.items():
            coverage.extend(CheckCoverage(path=path, language=language_for_path(path), check_id=check,
                                          analyzer_id=ANALYZER_ID, status="not_checked", reason=reason)
                            for check in checks)
        unique: dict[tuple[str, int, str, str], WorkflowFinding] = {}
        for finding in findings:
            unique.setdefault((finding.path, finding.start_line, finding.check_id, finding.rule_id), finding)
        return AnalyzerResult(findings=tuple(unique.values()), coverage=tuple(coverage), capability=capability(),
                              surface=tuple(entry for entry in surface.values() if entry.path not in failures))

    # ---- conversions ------------------------------------------------------------------------

    def _hits(self, project: Any, reviewed: dict[str, SourceFile], checks: list[str], evidence: str) -> list[WorkflowFinding]:
        findings: list[WorkflowFinding] = []
        for hit in project.hits:
            source = reviewed.get(hit.path)
            caller: str | None = None
            if source is None and hit.sink_path in reviewed and not hit.dynamic:
                # A context file (an importer) passes untrusted input into the reviewed file.
                source, caller = reviewed[hit.sink_path], hit.path
            if source is None or hit.check not in checks:
                continue
            rule_info = catalog.RULES[hit.rule_id]
            secret = hit.check == "secret_exposure"
            origins = hit.taint.secrets() if secret else hit.taint.real()
            if caller is not None:
                if not origins:
                    continue
                first = origins[0]
                findings.append(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                    rule_id=hit.rule_id, result="flagged", start_line=hit.sink_line or hit.line,
                    symbol=hit.symbol, confidence="medium",
                    message=(f"{rule_info.message} {first.label} ({KIND_LABEL.get(first.kind, first.kind)}) from "
                             f"{caller}:{first.line} reaches {hit.sink} here."),
                    trace=_trace(hit, secret=secret, caller=caller), evidence=evidence, reason="tainted_flow",
                    details=[f"Caller: {caller}:{hit.line} ({hit.symbol})."],
                ))
                continue
            if hit.dynamic:
                findings.append(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                    rule_id=hit.rule_id, result="needs_context", start_line=hit.line, symbol=hit.symbol,
                    message=f"{rule_info.title}: {hit.sink} receives a dynamic value ({hit.detail}) that isn't "
                            "a constant or visibly sanitized.",
                    confidence="low", trace=[step("sink", hit.line, hit.sink)],
                    verify=VERIFY.get(hit.check), evidence=evidence, reason="dynamic_value",
                ))
                continue
            if not origins:
                continue
            first = origins[0]
            argv_only = all(origin.kind == "argv" for origin in origins)
            severity = "medium" if argv_only and rule_info.severity in ("critical", "high", None) else None
            via = hit.detail.startswith("via ")
            edit = None
            if hit.edit_column >= 0 and hit.edit_text:
                edit = insert_edit(source, hit.line, hit.edit_column, hit.edit_text,
                                   "\"--\" stops the value from being parsed as an option.")
            elif hit.replace_old:
                edit = replace_edit(source, hit.line, hit.replace_old, hit.replace_new,
                                    "The tagged template sends interpolated values as bound parameters.")
            message = (f"{rule_info.message} {first.label} ({KIND_LABEL.get(first.kind, first.kind)}, line {first.line}) "
                       f"reaches {hit.sink}" + (f" {hit.detail}" if via else "") + ".")
            findings.append(make_finding(
                analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                rule_id=hit.rule_id, result="flagged", start_line=hit.line, symbol=hit.symbol, message=message,
                severity=severity,  # type: ignore[arg-type]
                confidence="medium" if via or argv_only else "high", trace=_trace(hit, secret=secret),
                suggested_edit=edit, evidence=evidence, reason="tainted_flow",
                details=[f"Source kinds: {', '.join(sorted({KIND_LABEL.get(o.kind, o.kind) for o in origins}))}."],
            ))
        return findings

    def _helpers(self, helper_hits: list[Any], call_records: dict[tuple[str, int, int], list[tuple[str, int, str]]],
                 reviewed: dict[str, SourceFile], checks: list[str], evidence: str) -> list[WorkflowFinding]:
        findings: list[WorkflowFinding] = []
        seen: set[tuple[str, int, str]] = set()
        for path, name, hit, exported, key in helper_hits:
            source = reviewed.get(hit.path)
            if source is None or not exported or hit.check not in checks or hit.check == "secret_exposure":
                continue
            marker = (hit.path, hit.line, hit.check)
            if marker in seen:
                continue
            indexes = {origin.index for origin in hit.taint.params()}
            records = call_records.get(key, [])
            kinds = [record[2].split(",") for record in records]
            if any(index < len(values) and values[index] == "real" for values in kinds for index in indexes):
                continue  # reported at the call site with the full trace
            if records and all(index >= len(values) or values[index] == "clean" for values in kinds for index in indexes):
                continue  # every observed caller passes a trusted value
            seen.add(marker)
            parameter = ", ".join(sorted({origin.label for origin in hit.taint.params()}))
            rule_info = catalog.RULES[hit.rule_id]
            callers = [f"{caller}:{line}" for caller, line, _ in records if (caller, line) != (path, hit.line)][:8]
            findings.append(make_finding(
                analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                rule_id=hit.rule_id, result="needs_context", start_line=hit.line, symbol=hit.symbol or name,
                message=f"{rule_info.title}: parameter `{parameter}` of exported {name}() reaches {hit.sink}; "
                        "whether that is safe depends on its callers.",
                confidence="low",
                trace=[step("source", origin.line, f"{origin.label} (parameter)") for origin in hit.taint.params()[:1]]
                + [step("sink", hit.line, hit.sink)],
                verify=f"Do all callers of {name}() pass a trusted or validated `{parameter}`? {VERIFY.get(hit.check, '')}".strip(),
                call_sites=callers, evidence=evidence, reason="caller_supplied_value",
            ))
        return findings

    def _authorization(self, project: Any, reviewed: dict[str, SourceFile], public: Sequence[str],
                       evidence: str) -> list[WorkflowFinding]:
        from polaris.review.js.model import MUTATING_METHODS

        findings: list[WorkflowFinding] = []
        seen: set[tuple[str, int]] = set()
        for facts in project.auth:
            source = reviewed.get(facts.path)
            if source is None or facts.guarded or _public(facts.path, public) or (facts.path, facts.line) in seen:
                continue
            seen.add((facts.path, facts.line))
            entry = facts.entry
            method = (entry.method or "").upper()
            label = {"route_handler": f"{method} route handler", "server_action": f"server action {entry.name}()",
                     "pages_api": "API route", "express_handler": f"{entry.name} handler"}.get(entry.kind, entry.name)
            end = int(entry.node.end_point[0]) + 1
            if facts.writes and facts.rate_limited:
                line, operation = facts.writes[0]
                findings.append(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source,
                    check_id="missing_authorization", rule_id="polaris.js.missing_authorization.handler",
                    result="needs_context", start_line=facts.line, end_line=end, symbol=entry.name,
                    message=(f"The {label} changes data ({operation}, line {line}) without calling an auth guard; "
                             "it is rate-limited, which suggests it is public by design."),
                    severity="medium", confidence="low",
                    trace=[step("source", facts.line, label), step("sink", line, operation)],
                    verify="Is this endpoint meant to be public (a public form, a token- or signature-authenticated "
                           "callback)? If not, call your auth guard first; if it is, list it under "
                           "[workflow].public_routes in .polaris.toml.",
                    evidence=evidence, reason="unguarded_write_rate_limited",
                ))
            elif facts.writes:
                line, operation = facts.writes[0]
                findings.append(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source,
                    check_id="missing_authorization", rule_id="polaris.js.missing_authorization.handler",
                    result="flagged", start_line=facts.line, end_line=end, symbol=entry.name,
                    message=f"The {label} changes data ({operation}, line {line}) without calling an auth guard.",
                    severity="high", confidence="medium",
                    trace=[step("source", facts.line, label), step("sink", line, operation)],
                    evidence=evidence, reason="unguarded_write",
                    details=["No guard call (requireUser/getServerSession/auth()/configured auth_guards) was found."],
                ))
            elif facts.reads or (method in MUTATING_METHODS and facts.sinks):
                line, operation = facts.reads[0] if facts.reads else (facts.line, "side effect")
                findings.append(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source,
                    check_id="missing_authorization", rule_id="polaris.js.missing_authorization.handler",
                    result="needs_context", start_line=facts.line, end_line=end, symbol=entry.name,
                    message=f"The {label} reads data ({operation}, line {line}) without calling an auth guard.",
                    severity="medium", confidence="low",
                    trace=[step("source", facts.line, label), step("sink", line, operation)],
                    verify="Is this endpoint intentionally public? If not, call your auth guard first; if it is "
                           "(or middleware protects it), list it under [workflow].public_routes in .polaris.toml.",
                    evidence=evidence, reason="unguarded_read",
                ))
        return findings

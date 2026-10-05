"""Exact static-workflow capability manifest, separate from the experimental model registry."""

from __future__ import annotations

from collections.abc import Sequence

from polaris.review.analyzers.base import AnalysisRuntime, source_kind
from polaris.review.analyzers.registry import analyzer_specs
from polaris.review.analyzers.registry import capabilities as analyzer_capabilities
from polaris.review.analyzers.semgrep import supported_checks
from polaris.review.models import (
    WORKFLOW_DEFAULT_CHECKS,
    AnalyzerCapability,
    CapabilityManifest,
    CheckCapability,
)


def manifest_from_analyzers(analyzers: Sequence[AnalyzerCapability]) -> CapabilityManifest:
    supplementary = {spec.analyzer_id for spec in analyzer_specs() if spec.supplementary}
    matrix: list[CheckCapability] = []
    for analyzer in analyzers:
        for language in analyzer.languages:
            kind = source_kind(language)
            for check in analyzer.checks:
                if analyzer.analyzer_id == "semgrep-ce" and check not in supported_checks(language):
                    continue
                matrix.append(CheckCapability(
                    language=language, extensions=list(kind.extensions) if kind else [],
                    path_patterns=[*kind.filenames, *kind.patterns] if kind else [], check_id=check,
                    analyzer_id=analyzer.analyzer_id, availability=analyzer.availability,
                    requires_trusted_policy=check == "api_authorization",
                    supplementary=analyzer.analyzer_id in supplementary,
                    limitations=list(analyzer.limitations),
                ))
    return CapabilityManifest(
        default_checks=list(WORKFLOW_DEFAULT_CHECKS), analyzers=list(analyzers), matrix=matrix,
        limitations=[
            "Built-in analyzers (Python, JavaScript/TypeScript, Rust) run in-process on every platform; nothing is executed.",
            "Semgrep CE is opt-in (--semgrep/--with-semgrep): it adds supplementary rules, and when requested, "
            "a failed Semgrep run makes the review incomplete.",
            "Only the listed language/check combinations and documented patterns are implemented.",
            "Unsupported source languages, failed and truncated analysis are reported as unreviewed scope, not clean.",
            "A checked coverage row means its bounded rules completed, not that a file is secure.",
            "api_authorization (guard regression) requires a caller-trusted policy; missing_authorization uses repository settings.",
            "The legacy polaris.review/0.1.0 defaults and polaris.assessment/0.1.0 model domain remain unchanged.",
        ],
    )


def capability_manifest(
    *, runtime: AnalysisRuntime | None = None, probe: bool = False,
) -> CapabilityManifest:
    """No install/download or inference. Probe=True may run a sandboxed local version check."""
    return manifest_from_analyzers(analyzer_capabilities(runtime or AnalysisRuntime(), probe=probe))

"""Source kinds, check domains and categories, and the analyzer registry with explicit plugins."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from polaris.cli import main
from polaris.review import catalog, models
from polaris.review.analyzers import base, python, registry
from polaris.review.analyzers.base import (
    AnalysisInput,
    AnalysisRuntime,
    AnalyzerResult,
    SourceKind,
    file_kind,
    language_for_path,
    path_matches,
    register_kind,
    runtime_identity,
    source_kind,
    source_kinds,
)
from polaris.review.analyzers.evidence import make_finding
from polaris.review.analyzers.registry import (
    AnalyzerPlugin,
    AnalyzerSpec,
    PluginProblem,
    load_plugins,
    register_analyzer,
)
from polaris.review.capabilities import capability_manifest
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    SourceFile,
    WorkflowReviewConfig,
)
from polaris.workflow.output import to_codequality, to_sarif
from polaris.workflow.service import review_supplied

CHECK = "pipeline_flaky_step"
RULE = "pipeline.flaky-step"
MEMORY = {"allow_external_analyzers": False, "allow_temporary_source_files": False}
PIPELINE = SourceKind(
    "pipeline", domain="ci", extensions=(".pipeline",), filenames=("Pipelinefile",),
    patterns=(".ci/workflows/*.yml", "**/*.pipeline.yml"),
)
WORKFLOW = ".ci/workflows/build.yml"
BAD_PY = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = " + name)\n'


def capability() -> AnalyzerCapability:
    return AnalyzerCapability(
        analyzer_id="pipeline-test", availability="available", version="1", expected_version="1",
        rule_pack_version="1", rule_pack_digest="sha256:" + "0" * 64, languages=["pipeline"], checks=[CHECK],
        provenance="test fixture", license="Apache-2.0", reason="in_process", limitations=[],
    )


class PipelineAnalyzer:
    """Flags steps marked `flaky`. A greedy instance reports on everything it receives."""

    analyzer_id = "pipeline-test"

    def __init__(self, greedy: bool = False) -> None:
        self.greedy = greedy

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        findings, coverage = [], []
        for source in request.sources:
            if source.role != "review" or source.after is None:
                continue
            if language_for_path(source.path) != "pipeline" and not self.greedy:
                continue
            coverage.extend(
                CheckCoverage(path=source.path, language=language_for_path(source.path), check_id=check,
                              analyzer_id=self.analyzer_id, status="checked", reason="rules_completed")
                for check in request.checks if check == CHECK or self.greedy
            )
            if "flaky" in source.after and CHECK in request.checks:
                finding = make_finding(
                    analyzer_id=self.analyzer_id, analyzer_version="1", source=source, check_id=CHECK, rule_id=RULE,
                    result="flagged", start_line=1, message="This step is retried until it passes.",
                )
                findings.append(finding.model_copy(update={"category": "performance"}))  # mislabeled on purpose
        return AnalyzerResult(findings=tuple(findings), coverage=tuple(coverage), capability=capability())


SPEC = AnalyzerSpec(
    "pipeline-test", lambda runtime, policy: PipelineAnalyzer(), lambda runtime, probe: capability(),
    {"pipeline": (CHECK,)},
)


class EntryPoint:
    def __init__(self, name: str, provided: object) -> None:
        self.name = name
        self.provided = provided
        self.loads = 0

    def load(self) -> object:
        self.loads += 1
        if isinstance(self.provided, Exception):
            raise self.provided
        return self.provided


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """Each test registers into copies of the registries and a catalog with one CI-domain check."""
    monkeypatch.setattr(base, "_KINDS", dict(base._KINDS))
    monkeypatch.setattr(registry, "_SPECS", dict(registry._SPECS))
    monkeypatch.setattr(registry, "_PLUGINS", dict(registry._PLUGINS))
    checks = (*models.WORKFLOW_CHECKS, CHECK)
    monkeypatch.setattr(models, "WORKFLOW_CHECKS", checks)
    monkeypatch.setattr(registry, "WORKFLOW_CHECKS", checks)
    monkeypatch.setitem(catalog.CHECKS, CHECK, catalog.CheckInfo(
        CHECK, "Flaky pipeline step", "CWE-754", "medium", "A pipeline step is retried until it passes.",
        "Retries hide real failures and make releases depend on luck.", "Fix the cause and remove the retry loop.",
        category="reliability", domains=("ci",),
    ))


@pytest.fixture
def installed(monkeypatch):
    entries: list[EntryPoint] = []
    monkeypatch.setattr(registry, "_entry_points", lambda name: [item for item in entries if item.name == name])

    def install(name: str, provided: object) -> EntryPoint:
        entries.append(EntryPoint(name, provided))
        return entries[-1]

    return install


def runtime(*plugins: str) -> AnalysisRuntime:
    return AnalysisRuntime(**MEMORY, plugins=plugins)


def test_source_kinds_match_patterns_then_file_names_then_extensions():
    assert [language_for_path(path) for path in ("a/b.py", "web/app.tsx", "lib.rs", "notes.unknown")] == [
        "python", "typescript", "rust", "unsupported"]
    register_kind(PIPELINE)
    register_kind(SourceKind("yamlish", domain="config", extensions=(".yml",)))
    assert language_for_path(WORKFLOW) == "pipeline"  # the pattern wins over the .yml extension
    assert language_for_path(".ci/workflows/nested/build.yml") == "yamlish"  # `*` stays in one directory
    assert language_for_path("deploy/build.yml") == "yamlish"
    assert language_for_path("deploy/Pipelinefile") == language_for_path("x/y.pipeline") == "pipeline"
    assert language_for_path("release.pipeline.yml") == language_for_path("a/b/release.pipeline.yml") == "pipeline"
    assert file_kind(WORKFLOW) == "supported" and source_kind("pipeline") is PIPELINE and PIPELINE in source_kinds()
    assert path_matches("a/b/Dockerfile.dev", "**/Dockerfile.*") and path_matches("Dockerfile.dev", "**/Dockerfile.*")
    assert not path_matches("a/b/c.yml", "a/*.yml") and path_matches("a/b/c.yml", "a/**")


def test_source_kind_registration_refuses_conflicts_and_malformed_definitions():
    assert register_kind(PIPELINE) is PIPELINE and register_kind(PIPELINE) is PIPELINE  # identical: no-op
    with pytest.raises(ValueError):
        register_kind(replace(PIPELINE, extensions=(".pipe",)))  # same name, different definition
    with pytest.raises(ValueError):
        register_kind(SourceKind("pythonish", extensions=(".py",)))  # python's extension
    with pytest.raises(ValueError):
        register_kind(SourceKind("other", filenames=("Pipelinefile",)))
    for bad in (
        {"name": "Bad", "extensions": (".x",)}, {"name": "unsupported", "extensions": (".x",)}, {"name": "empty"},
        {"name": "nodot", "extensions": ("x",)}, {"name": "nested", "filenames": ("a/b",)},
        {"name": "absolute", "patterns": ("/etc/*",)}, {"name": "escape", "patterns": ("../*.yml",)},
        {"name": "greedy", "patterns": ("**/**/**/x",)}, {"name": "domain", "domain": "Bad Domain", "extensions": (".x",)},
    ):
        with pytest.raises(ValueError):
            SourceKind(**bad)  # type: ignore[arg-type]


def test_analyzer_registration_is_validated():
    register_kind(PIPELINE)
    assert register_analyzer(SPEC) is SPEC and register_analyzer(SPEC) is SPEC
    with pytest.raises(ValueError):
        register_analyzer(replace(SPEC, inputs="review"))  # same id, different analyzer
    for changes in (
        {"analyzer_id": "Bad"}, {"checks": {"cobol": (CHECK,)}}, {"checks": {"pipeline": ("made_up",)}},
        {"checks": {"pipeline": [CHECK]}}, {"inputs": "everything"}, {"create": None},
    ):
        with pytest.raises(ValueError):
            register_analyzer(replace(SPEC, **{"analyzer_id": "pipeline-other", **changes}))
    assert registry.implemented_checks("pipeline") == frozenset({CHECK})


def test_checks_apply_only_to_their_domains(installed):
    installed("pipeline", AnalyzerPlugin((PIPELINE,), SPEC))
    reviewer = WorkflowReviewer(config=WorkflowReviewConfig(checks=[CHECK, "sql_injection"]), runtime=runtime("pipeline"))
    report = reviewer.review_sources([
        SourceFile(WORKFLOW, "steps:\n  - run: make test\n"), SourceFile("app.py", "def ok():\n    return 1\n"),
    ])
    rows = {(entry.path, entry.check_id): entry.status for entry in report.coverage.entries if entry.required}
    # No sql_injection gap on the pipeline and no pipeline gap on the Python file.
    assert rows == {(WORKFLOW, CHECK): "checked", ("app.py", "sql_injection"): "checked"}
    assert report.coverage.complete and report.summary.languages == {"pipeline": 1, "python": 1}

    only_code = WorkflowReviewer(config=WorkflowReviewConfig(checks=["sql_injection"]), runtime=runtime("pipeline"))
    listed = only_code.review_sources([SourceFile(WORKFLOW, "steps: []\n")])
    assert [(entry.check_id, entry.status, entry.reason) for entry in listed.coverage.entries if entry.analyzer_id is None] == [
        ("*", "not_applicable", "no_applicable_checks")]
    assert listed.coverage.complete and listed.summary.files_not_applicable == 1


def test_findings_carry_catalog_categories_into_every_output(installed):
    installed("pipeline", AnalyzerPlugin((PIPELINE,), SPEC))
    envelope = review_supplied(
        [SourceFile(WORKFLOW, "steps:\n  - run: retry flaky make test\n"), SourceFile("db.py", BAD_PY)],
        config=WorkflowReviewConfig(checks=[CHECK, "sql_injection"]), runtime=runtime("pipeline"),
    )
    report = envelope.review
    # The catalog decides the category, not the analyzer that reported (it said "performance").
    assert {finding.check_id: finding.category for finding in report.findings} == {
        CHECK: "reliability", "sql_injection": "security"}
    assert report.summary.categories["reliability"] == 1 and report.summary.categories["security"] >= 1

    sarif = to_sarif(envelope)
    rules = {rule["id"]: rule["properties"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules[RULE]["tags"][0] == "reliability" and "security-severity" not in rules[RULE]
    assert all(props["tags"][0] == "security" and "security-severity" in props
               for rule_id, props in rules.items() if rule_id != RULE)
    results = {result["properties"]["check"]: result["properties"] for result in sarif["runs"][0]["results"]}
    assert results[CHECK]["category"] == "reliability" and "security-severity" not in results[CHECK]
    assert results["sql_injection"]["category"] == "security" and "security-severity" in results["sql_injection"]
    quality = {issue["check_name"]: issue["categories"] for issue in to_codequality(envelope)}
    assert quality[RULE] == ["Bug Risk"]
    assert catalog.explain("sql_injection")["category"] == "security"
    assert catalog.explain(RULE) is None and catalog.explain(CHECK)["category"] == "reliability"


def test_plugins_load_only_when_named_and_are_bound_into_review_identity(installed):
    entry = installed("pipeline", lambda: AnalyzerPlugin((PIPELINE,), SPEC))  # a factory works too
    plain = runtime()
    before = WorkflowReviewer(runtime=plain).review_sources([SourceFile("x.pipeline", "flaky\n")])
    assert entry.loads == 0 and language_for_path("x.pipeline") == "unsupported"
    assert [row.reason for row in before.coverage.entries if row.check_id == "*"] == ["not_source_code"]

    chosen = runtime("pipeline")
    assert load_plugins(chosen.plugins) == ("pipeline",) == load_plugins(chosen.plugins)
    assert entry.loads == 1 and language_for_path("x.pipeline") == "pipeline"
    assert [spec.plugin for spec in registry.active_specs(chosen) if spec.analyzer_id == "pipeline-test"] == ["pipeline"]
    # Loaded in this process, but a runtime that doesn't name it never runs it.
    assert "pipeline-test" not in {spec.analyzer_id for spec in registry.active_specs(plain)}
    assert "plugins" not in runtime_identity(plain) and runtime_identity(chosen)["plugins"] == ("pipeline",)

    sources = [SourceFile("x.pipeline", "flaky\n")]
    with_plugin = WorkflowReviewer(config=WorkflowReviewConfig(checks=[CHECK]), runtime=chosen).review_sources(sources)
    without = WorkflowReviewer(config=WorkflowReviewConfig(checks=[CHECK]), runtime=plain).review_sources(sources)
    assert [finding.rule_id for finding in with_plugin.findings] == [RULE] and with_plugin.coverage.complete
    assert not without.findings and not without.coverage.complete  # the check can't silently pass
    assert with_plugin.provenance.snapshot_digest != without.provenance.snapshot_digest

    rows = [row for row in capability_manifest(runtime=chosen).matrix if row.analyzer_id == "pipeline-test"]
    assert [(row.language, row.check_id, row.extensions, row.supplementary) for row in rows] == [
        ("pipeline", CHECK, [".pipeline"], False)]
    assert rows[0].path_patterns == ["Pipelinefile", ".ci/workflows/*.yml", "**/*.pipeline.yml"]
    assert "pipeline-test" not in {item.analyzer_id for item in capability_manifest(runtime=plain).analyzers}


def test_plugin_results_stay_within_declared_languages_checks_and_files(installed, monkeypatch):
    # secret_exposure also applies to pipelines here, but the plugin never declared it.
    monkeypatch.setitem(catalog.CHECKS, "secret_exposure",
                        replace(catalog.CHECKS["secret_exposure"], domains=("code", "ci")))
    greedy = replace(SPEC, create=lambda runtime, policy: PipelineAnalyzer(greedy=True))
    installed("greedy", AnalyzerPlugin((PIPELINE,), greedy))
    reviewer = WorkflowReviewer(config=WorkflowReviewConfig(checks=[CHECK, "secret_exposure"]), runtime=runtime("greedy"))
    report = reviewer.review_sources([SourceFile(WORKFLOW, "steps: []\n"), SourceFile("app.py", "# flaky\nVALUE = 1\n")])
    assert [(entry.path, entry.check_id) for entry in report.coverage.entries if entry.analyzer_id == "pipeline-test"] == [
        (WORKFLOW, CHECK)]
    assert not [finding for finding in report.findings if finding.analyzer_id == "pipeline-test"]
    gaps = [(entry.path, entry.check_id, entry.reason) for entry in report.coverage.entries
            if entry.required and entry.status != "checked"]
    assert gaps == [(WORKFLOW, "secret_exposure", "not_implemented_for_language")] and not report.coverage.complete


@pytest.mark.parametrize(("name", "provided", "code"), [
    ("absent", None, "analyzer_plugin_unavailable"),
    ("bad name", None, "invalid_plugin_name"),
    ("boom", RuntimeError("token=secret-value"), "analyzer_plugin_failed_to_load"),
    ("junk", object(), "invalid_analyzer_plugin"),
    ("list", AnalyzerPlugin([PIPELINE], SPEC), "invalid_analyzer_plugin"),  # type: ignore[arg-type]
    ("all", AnalyzerPlugin((PIPELINE,), replace(SPEC, inputs="all")), "invalid_analyzer_plugin"),
    ("extra", AnalyzerPlugin((PIPELINE,), replace(SPEC, supplementary=True)), "invalid_analyzer_plugin"),
    ("builtin", AnalyzerPlugin((PIPELINE,), replace(SPEC, analyzer_id=python.ANALYZER_ID)), "invalid_analyzer_plugin"),
    ("kind", AnalyzerPlugin((PIPELINE, SourceKind("pythonish", extensions=(".py",))), SPEC), "analyzer_plugin_conflict"),
    ("check", AnalyzerPlugin((PIPELINE,), replace(SPEC, checks={"pipeline": ("made_up",)})), "analyzer_plugin_conflict"),
])
def test_plugin_problems_have_fixed_codes_and_leave_nothing_behind(installed, name, provided, code):
    if provided is not None:
        installed(name, provided)
    with pytest.raises(PluginProblem) as problem:
        load_plugins((name,))
    assert str(problem.value) == code and code in registry.PLUGIN_ERRORS
    assert source_kind("pipeline") is None and name not in registry._PLUGINS


def test_duplicate_entry_points_are_refused(installed):
    installed("twice", AnalyzerPlugin((PIPELINE,), SPEC))
    installed("twice", AnalyzerPlugin((PIPELINE,), SPEC))
    with pytest.raises(PluginProblem, match="analyzer_plugin_unavailable"):
        load_plugins(("twice",))


def test_cli_loads_named_plugins_and_reports_fixed_codes(installed, capsys):
    installed("pipeline", AnalyzerPlugin((PIPELINE,), SPEC))
    flags = ["--no-external-analyzers", "--analyzer-plugin", "pipeline", "--analyzer-plugin", "pipeline"]
    assert main(["workflow", "capabilities", *flags]) == 0
    assert "pipeline-test" in {item["analyzer_id"] for item in json.loads(capsys.readouterr().out)["analyzers"]}
    assert main(["workflow", "capabilities", "--no-external-analyzers", "--analyzer-plugin", "absent"]) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["code"] == "analyzer_plugin_unavailable" and "absent" not in error["message"]

    from polaris.integrations.forge import cli as forge_cli

    assert forge_cli._error("analyzer_plugin_conflict") == 2
    assert json.loads(capsys.readouterr().out)["message"] == registry.PLUGIN_ERRORS["analyzer_plugin_conflict"]

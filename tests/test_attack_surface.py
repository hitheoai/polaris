"""The attack surface: entry points the TypeScript analyzer recognizes, linked to findings.

Descriptive data only: it never changes findings, coverage or exit codes. A plugin can describe
only reviewed files of the languages it declared.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from polaris.review import catalog, models
from polaris.review.analyzers import base, registry
from polaris.review.analyzers.base import AnalysisInput, AnalysisRuntime, AnalyzerResult, SourceKind
from polaris.review.analyzers.registry import AnalyzerPlugin, AnalyzerSpec
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import (
    MAX_SURFACE,
    AnalyzerCapability,
    CheckCoverage,
    EntryPoint,
    ProjectSettings,
    SourceFile,
    SurfaceOperation,
    WorkflowReviewConfig,
)
from polaris.workflow.models import WorkflowEnvelope
from polaris.workflow.service import review_supplied

MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
ROUTE = """import { db } from "./db";

export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("target");
  const response = await fetch(target!);
  return new Response(await response.text());
}

export async function DELETE(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  await db.project.delete({ where: { id: id! } });
  return new Response(null, { status: 204 });
}
"""
SERVER = """import express from "express";
import { exec } from "node:child_process";
import { requireAdmin } from "./auth";

const app = express();

app.post("/admin/run", requireAdmin, (req, res) => {
  exec("deploy " + req.body.target);
  res.send("ok");
});

app.get("/files", (req, res) => {
  res.sendFile(req.query.name);
});

app.get("/odd\u202eroute", (req, res) => {
  res.send("hi");
});
"""
ACTION = """"use server";
import { db } from "./db";

export async function rename(id: string, name: string) {
  await db.user.update({ where: { id }, data: { name } });
}
"""


def review(*sources: SourceFile, project: ProjectSettings | None = None) -> WorkflowEnvelope:
    config = WorkflowReviewConfig(project=project or ProjectSettings())
    return review_supplied(list(sources), config=config, runtime=MEMORY)


def by_name(envelope: WorkflowEnvelope) -> dict[str, EntryPoint]:
    return {f"{entry.path}:{entry.name}": entry for entry in envelope.review.surface}


def test_route_handlers_server_actions_and_express_routes_with_guards_and_findings():
    envelope = review(SourceFile("app/api/projects/route.ts", ROUTE), SourceFile("server.ts", SERVER),
                      SourceFile("app/actions.ts", ACTION))
    surface = by_name(envelope)
    get = surface["app/api/projects/route.ts:GET"]
    delete = surface["app/api/projects/route.ts:DELETE"]
    assert (get.kind, get.method, get.line, get.guarded, get.analyzer_id) == ("route_handler", "GET", 3, False, "polaris-ts")
    assert get.end_line == 7 and get.sinks >= 1
    assert delete.writes == [SurfaceOperation(line=11, label="db.project.delete")] and not delete.guarded
    titles = {finding.finding_id: finding.check_id for finding in envelope.review.findings}
    assert [titles[item] for item in get.findings] == ["ssrf"]
    assert [titles[item] for item in delete.findings] == ["missing_authorization"]
    admin = surface["server.ts:POST /admin/run"]
    assert admin.kind == "express_handler" and admin.method == "POST" and admin.guarded
    assert any("requireAdmin" in guard for guard in admin.guards)
    assert [titles[item] for item in admin.findings] == ["command_injection"]
    files = surface["server.ts:GET /files"]
    assert not files.guarded and [titles[item] for item in files.findings] == ["path_traversal"]
    action = surface["app/actions.ts:rename"]
    assert action.kind == "server_action" and action.method is None
    assert [item.label for item in action.writes] == ["db.user.update"]
    # Text from the code is made printable before it enters the report.
    odd = [entry for entry in envelope.review.surface if entry.name.startswith("GET /odd")]
    assert odd and "\u202e" not in odd[0].name and "\ufffd" in odd[0].name
    # Descriptive only: findings, coverage and the gate are unchanged by the surface.
    assert envelope.review.coverage.complete
    assert all(entry.path in envelope.review.provenance.source_digests for entry in envelope.review.surface)


def test_public_routes_are_marked_and_the_surface_round_trips():
    envelope = review(SourceFile("app/api/projects/route.ts", ROUTE),
                      project=ProjectSettings(public_routes=["app/api/projects/**"]))
    assert all(entry.public for entry in envelope.review.surface)
    again = WorkflowEnvelope.model_validate_json(json.dumps(envelope.model_dump(mode="json")))
    assert again.review.surface == envelope.review.surface
    # Older reports without the field still load, with an empty surface.
    data = envelope.model_dump(mode="json")
    del data["review"]["surface"]
    assert WorkflowEnvelope.model_validate(data).review.surface == []


def test_only_reviewed_files_appear_never_related_context():
    importer = 'import { handler } from "./lib";\nexport async function GET(request: Request) { return handler(request); }\n'
    context = SourceFile("app/api/other/route.ts", importer, role="context")
    envelope = review(SourceFile("lib.ts", "export function handler(r: Request) { return new Response('x'); }\n"),
                      context)
    assert envelope.review.surface == []


@pytest.mark.parametrize("changes", [
    {"path": "/etc/passwd"}, {"path": "../x.ts"}, {"end_line": 1, "line": 5}, {"name": "GET \u202e/x"},
    {"guards": ["auth\x1b[31m"]}, {"kind": "cron"}, {"method": "get"}, {"guards": ["g"] * 6},
    {"writes": [{"line": 1, "label": "x" * 201}]},
])
def test_entry_points_are_bounded_and_printable(changes):
    valid = {"path": "app/route.ts", "line": 1, "end_line": 3, "kind": "route_handler", "name": "GET",
             "method": "GET", "guarded": False, "analyzer_id": "polaris-ts"}
    EntryPoint.model_validate(valid)
    with pytest.raises(ValidationError):
        EntryPoint.model_validate({**valid, **changes})


# ---- plugins ---------------------------------------------------------------------------------------

CHECK = "pipeline_flaky_step"
PIPELINE = SourceKind("pipeline", domain="ci", extensions=(".pipeline",))


def capability() -> AnalyzerCapability:
    return AnalyzerCapability(
        analyzer_id="pipeline-surface", availability="available", version="1", expected_version="1",
        rule_pack_version="1", rule_pack_digest="sha256:" + "0" * 64, languages=["pipeline"], checks=[CHECK],
        provenance="test fixture", license="Apache-2.0", reason="in_process", limitations=[],
    )


class SurfacePlugin:
    """Claims entry points everywhere: its own pipeline file, a Python file and an unreviewed path."""

    analyzer_id = "pipeline-surface"

    def __init__(self, count: int = 1) -> None:
        self.count = count

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        surface = [EntryPoint(path="build.pipeline", line=line, end_line=line, kind="route_handler",
                              name=f"job {line}", guarded=True, analyzer_id="polaris-ts")
                   for line in range(1, self.count + 1)]
        surface += [EntryPoint(path=path, line=1, end_line=1, kind="route_handler", name="stolen", guarded=False,
                               analyzer_id="pipeline-surface") for path in ("app.py", "not/reviewed.pipeline")]
        coverage = [CheckCoverage(path="build.pipeline", language="pipeline", check_id=CHECK,
                                  analyzer_id=self.analyzer_id, status="checked", reason="rules_completed")]
        return AnalyzerResult(coverage=tuple(coverage), capability=capability(), surface=tuple(surface))


@pytest.fixture
def plugin(monkeypatch):
    monkeypatch.setattr(base, "_KINDS", dict(base._KINDS))
    monkeypatch.setattr(registry, "_SPECS", dict(registry._SPECS))
    monkeypatch.setattr(registry, "_PLUGINS", dict(registry._PLUGINS))
    checks = (*models.WORKFLOW_CHECKS, CHECK)
    monkeypatch.setattr(models, "WORKFLOW_CHECKS", checks)
    monkeypatch.setattr(registry, "WORKFLOW_CHECKS", checks)
    monkeypatch.setitem(catalog.CHECKS, CHECK, catalog.CheckInfo(
        CHECK, "Flaky pipeline step", "CWE-754", "medium", "A step is retried.", "Retries hide failures.",
        "Fix the cause.", category="reliability", domains=("ci",)))

    def install(count: int = 1) -> AnalysisRuntime:
        spec = AnalyzerSpec("pipeline-surface", lambda runtime, policy: SurfacePlugin(count),
                            lambda runtime, probe: capability(), {"pipeline": (CHECK,)})

        class Entry:
            name = "surface"

            def load(self) -> object:
                return AnalyzerPlugin((PIPELINE,), spec)

        monkeypatch.setattr(registry, "_entry_points", lambda name: [Entry()] if name == "surface" else [])
        return AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False,
                               plugins=("surface",))

    return install


def test_a_plugin_describes_only_reviewed_files_of_its_own_languages(plugin):
    runtime = plugin()
    report = WorkflowReviewer(config=WorkflowReviewConfig(checks=[CHECK]), runtime=runtime).review_sources([
        SourceFile("build.pipeline", "steps: []\n"), SourceFile("app.py", "def ok():\n    return 1\n"),
    ])
    assert [(entry.path, entry.name, entry.analyzer_id) for entry in report.surface] == [
        ("build.pipeline", "job 1", "pipeline-surface")]  # renamed to its registered id, never another analyzer's


def test_a_long_surface_is_capped_without_making_coverage_incomplete(plugin):
    runtime = plugin(count=MAX_SURFACE + 25)
    report = WorkflowReviewer(config=WorkflowReviewConfig(checks=[CHECK]), runtime=runtime).review_sources([
        SourceFile("build.pipeline", "steps: []\n")])
    assert len(report.surface) == MAX_SURFACE and report.coverage.complete
    assert any(f"first {MAX_SURFACE} of {MAX_SURFACE + 25}" in notice for notice in report.notices)

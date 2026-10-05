"""Scoped review snapshots, related context, project settings, baseline and actionable output."""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from polaris.cli import main
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.config import load_config
from polaris.review.models import SourceFile, WorkflowReviewConfig
from polaris.review.project import ProjectSettingsError, load_baseline, load_project_settings
from polaris.review.scope import workflow_sources_from_paths
from polaris.workflow.context import collect_related, repository_files
from polaris.workflow.output import to_sarif
from polaris.workflow.service import (
    brief_report,
    expand_paths,
    render_workflow,
    review_scope,
    review_workspace,
)

MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
TSCONFIG = """{
  // A Next.js app inside a monorepo, with a custom alias only tsconfig can resolve.
  "compilerOptions": { "baseUrl": ".", "paths": { "~server/*": ["./server/*"] }, },
}
"""
PREVIEW = """export async function fetchPreview(target: string) {
  const response = await fetch(target);
  return response.text();
}
"""
ROUTE = """import { NextRequest, NextResponse } from "next/server";
import { fetchPreview } from "~server/preview";

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get("url");
  const body = await fetchPreview(url ?? "");
  return NextResponse.json({ body });
}
"""
HELPER = """import { exec } from "child_process";

export function runTool(name: string) {
  exec(`tool ${name}`);
}
"""
CALLER = """import { NextRequest } from "next/server";
import { runTool } from "../../../lib/tools";

export async function POST(request: NextRequest) {
  const { name } = await request.json();
  runTool(name);
  return new Response("ok");
}
"""
BAD_PY = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = " + name)\n'
SECOND_PY = 'def find(db, team):\n    return db.execute("SELECT * FROM teams WHERE name = " + team)\n'


def git(root, *args):
    subprocess.run(
        ["/usr/bin/git", "--no-pager", "-C", str(root), "-c", "user.name=Fixture",
         "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True,
        env={"PATH": os.defpath, "HOME": str(root.parent), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )


def write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def commit(root):
    git(root, "add", "-A")
    git(root, "commit", "-qm", "fixture")


@pytest.fixture
def repo(tmp_path):
    root = (tmp_path / "project").resolve()
    root.mkdir()
    git(root, "init", "-q")
    return root


@pytest.fixture
def monorepo(repo):
    write(repo, "apps/web/tsconfig.json", TSCONFIG)
    write(repo, "apps/web/server/preview.ts", PREVIEW)
    write(repo, "README.md", "# fixture\n")
    commit(repo)
    write(repo, "apps/web/app/api/preview/route.ts", ROUTE)
    return repo


def test_monorepo_alias_import_is_followed_through_related_context(monorepo):
    report = review_workspace(monorepo, runtime=MEMORY)
    assert report.status == "complete", render_workflow(report)
    ssrf = [finding for finding in report.review.findings if finding.check_id == "ssrf"]
    assert ssrf and ssrf[0].result == "flagged" and ssrf[0].path == "apps/web/app/api/preview/route.ts"
    assert any(step.path == "apps/web/server/preview.ts" for step in ssrf[0].trace)
    related = {item.path: item for item in report.context.files}
    assert related["apps/web/server/preview.ts"].reason == "alias_import"
    assert related["apps/web/server/preview.ts"].used_for_analysis
    assert related["apps/web/tsconfig.json"].reason == "tsconfig"
    # Related files are context, not reviewed files.
    assert [change.path for change in report.changes] == ["apps/web/app/api/preview/route.ts"]
    assert "apps/web/server/preview.ts" in report.review.provenance.context_digests


def test_unrelated_edits_keep_a_path_review_fresh_but_context_edits_do_not(monorepo):
    selection = [monorepo / "apps/web/app"]
    first = review_workspace(monorepo, runtime=MEMORY, paths=selection)
    assert first.snapshot.complete and first.snapshot.fresh is True
    write(monorepo, "README.md", "# unrelated change\n")
    write(monorepo, "docs/notes.md", "also unrelated\n")
    again = review_workspace(monorepo, runtime=MEMORY, paths=selection)
    assert again.snapshot.digest == first.snapshot.digest
    write(monorepo, "apps/web/server/preview.ts", PREVIEW + "// edited\n")
    edited = review_workspace(monorepo, runtime=MEMORY, paths=selection)
    assert edited.snapshot.digest != first.snapshot.digest
    write(monorepo, "package.json", '{"name": "changed"}\n')
    assert review_workspace(monorepo, runtime=MEMORY, paths=selection).snapshot.digest != edited.snapshot.digest


def test_importer_input_reaching_a_changed_helper_is_reported_in_the_helper(repo):
    write(repo, "app/api/run/route.ts", CALLER)
    write(repo, "lib/tools.ts", "export function runTool(name: string) {\n  return name;\n}\n")
    commit(repo)
    write(repo, "lib/tools.ts", HELPER)
    report = review_workspace(repo, runtime=MEMORY)
    commands = [finding for finding in report.review.findings if finding.check_id == "command_injection"]
    assert commands and commands[0].result == "flagged" and commands[0].path == "lib/tools.ts"
    assert commands[0].start_line == 4
    assert any(step.path == "app/api/run/route.ts" for step in commands[0].trace)
    assert any(item.path == "app/api/run/route.ts" and item.reason == "importer" for item in report.context.files)


def test_new_untracked_importers_are_found_too(repo):
    write(repo, "lib/tools.ts", "export function runTool(name: string) {\n  return name;\n}\n")
    commit(repo)
    write(repo, "lib/tools.ts", HELPER)
    write(repo, "app/api/run/route.ts", CALLER)  # a brand-new file, not yet tracked
    summary, _ = collect_related(repo, [SourceFile("lib/tools.ts", HELPER)], listing=repository_files(repo))
    assert any(item.path == "app/api/run/route.ts" and item.reason == "importer" for item in summary.files)


def test_test_files_are_listed_but_never_used_as_analysis_context(repo):
    write(repo, "lib/tools.ts", HELPER)
    write(repo, "lib/tools.test.ts", 'import { runTool } from "./tools";\nrunTool("fixed");\n')
    summary, context = collect_related(repo, [SourceFile("lib/tools.ts", HELPER)], listing=repository_files(repo))
    assert context == []
    assert [(item.path, item.reason, item.used_for_analysis) for item in summary.files] == [
        ("lib/tools.test.ts", "test_candidate", False)]


def test_project_settings_are_validated_and_do_not_break_the_legacy_loader(repo):
    write(repo, ".polaris.toml", '[workflow]\nauth_guards = ["requireTeam"]\npublic_routes = ["app/api/health/**"]\n')
    settings = load_project_settings(repo)
    assert settings.auth_guards == ["requireTeam"] and settings.public_routes == ["app/api/health/**"]
    assert load_config(repo)[0] is not None
    write(repo, ".polaris.toml", "[workflow]\nunknown_setting = 1\n")
    with pytest.raises(ProjectSettingsError, match="unknown"):
        load_project_settings(repo)


def test_configured_auth_guard_counts_as_authentication(repo):
    # `teamGate` matches none of the built-in guard name patterns; only configuration makes it one.
    route = ('import { db } from "@/lib/db";\nimport { teamGate } from "@/lib/team";\n\n'
             "export async function POST(request: Request) {\n  await teamGate(request);\n"
             "  await db.project.delete({ where: { id: 1 } });\n  return Response.json({});\n}\n")
    write(repo, "app/api/projects/route.ts", route)
    flagged = review_workspace(repo, runtime=MEMORY)
    assert any(item.check_id == "missing_authorization" and item.result == "flagged"
               for item in flagged.review.findings)
    write(repo, ".polaris.toml", '[workflow]\nauth_guards = ["teamGate"]\n')
    guarded = review_workspace(repo, runtime=MEMORY)
    assert not any(item.check_id == "missing_authorization" for item in guarded.review.findings)


def test_baseline_reports_only_new_findings(repo, capsys):
    write(repo, "app.py", BAD_PY)
    commit(repo)
    assert main(["workflow", "baseline", "--root", str(repo), "--no-external-analyzers", "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["entries"] >= 1 and result["status"] == "complete"
    assert load_baseline(repo)
    write(repo, "app.py", BAD_PY + "\n\n" + SECOND_PY)
    report = review_workspace(repo, runtime=MEMORY)
    assert report.review.summary.baselined == 1
    assert [finding.symbol for finding in report.review.findings if finding.result == "flagged"] == ["find"]
    assert "in .polaris/baseline.json" in render_workflow(report)


def test_range_reviews_read_settings_from_the_base_revision_not_the_change(repo):
    write(repo, "README.md", "# base\n")
    commit(repo)
    git(repo, "branch", "-M", "main")
    git(repo, "checkout", "-q", "-b", "feature")
    route = ('import { db } from "@/lib/db";\n\nexport async function POST(request: Request) {\n'
             "  await db.project.delete({ where: { id: 1 } });\n  return Response.json({});\n}\n")
    write(repo, "app/api/projects/route.ts", route)
    # The change tries to mark its own unguarded endpoint as intentionally public.
    write(repo, ".polaris.toml", '[workflow]\npublic_routes = ["app/api/**"]\n')
    commit(repo)
    local = review_workspace(repo, runtime=MEMORY, paths=[repo / "app"])
    assert not any(item.check_id == "missing_authorization" for item in local.review.findings)
    ci = review_workspace(repo, runtime=MEMORY, revision_range="main...HEAD")
    assert any(item.check_id == "missing_authorization" and item.result == "flagged" for item in ci.review.findings)
    assert any("base revision" in notice for notice in ci.notices)


def test_python_exec_family_sinks_are_analyzed_not_crashed():
    from polaris.review.engine import WorkflowReviewer

    code = ('import os\nfrom flask import request\n\n\ndef run():\n'
            '    tool = request.args["tool"]\n    os.execvp(tool, [tool, "--version"])\n'
            '    os.spawnl(os.P_WAIT, "/bin/ls", "ls", "-l")\n')
    report = WorkflowReviewer(runtime=MEMORY).review_snippet(code, path="app.py")
    assert report.coverage.complete
    assert [(item.check_id, item.result, item.start_line) for item in report.findings
            if item.check_id == "command_injection"] == [("command_injection", "flagged", 7)]


def test_directory_reviews_skip_git_ignored_build_output(repo):
    write(repo, ".gitignore", ".next/\ntarget/\n")
    write(repo, "src/app.ts", "export const answer = 42;\n")
    write(repo, ".next/server/chunk.js", "eval(input)\n")
    write(repo, "target/debug/build/out.rs", "fn main() {}\n")
    names = {path.as_posix() for path in expand_paths(repo, [repo], repository_files(repo))}
    assert "src/app.ts" in names and not any(name.startswith((".next/", "target/")) for name in names)
    report = review_workspace(repo, runtime=MEMORY, paths=[repo])
    assert report.status == "complete", render_workflow(report)
    assert {change.path for change in report.changes} == {".gitignore", "src/app.ts"}


def test_project_excludes_are_listed_and_do_not_make_a_review_incomplete(repo):
    write(repo, "src/app.ts", "export const answer = 42;\n")
    write(repo, "scripts/deploy.sh", "#!/bin/sh\necho deploy\n")
    write(repo, "src/generated/client.ts", "export const client = 1;\n")
    commit(repo)
    unconfigured = review_workspace(repo, runtime=MEMORY, paths=[repo])
    # Shell has no analyzer yet: honest unreviewed scope.
    assert unconfigured.status == "incomplete"
    write(repo, ".polaris.toml", '[workflow]\nexclude = ["**/*.sh"]\n')
    report = review_workspace(repo, runtime=MEMORY, paths=[repo])
    assert report.status == "complete", render_workflow(report)
    rows = [entry for entry in report.review.coverage.entries if entry.path == "scripts/deploy.sh"]
    assert not any(entry.required for entry in rows)
    assert {entry.reason for entry in rows if entry.check_id != "api_authorization"} == {"excluded"}
    assert "1 excluded by configuration" in render_workflow(report)
    assert brief_report(report).coverage["files_excluded"] == 1
    # Generated directories were already not source; a caller exclude still adds to the project's.
    config = WorkflowReviewConfig(exclude=["src/app.ts"])
    both = review_workspace(repo, runtime=MEMORY, paths=[repo], config=config)
    assert {entry.path for entry in both.review.coverage.entries if entry.reason == "excluded"} == {
        "src/app.ts", "scripts/deploy.sh"}


def test_snapshot_binds_source_and_configuration_not_assets():
    sources = [
        SourceFile("src/app.ts", "x"), SourceFile("scripts/deploy.sh", None, skip="unsupported_language"),
        SourceFile("public/intro.mp4", None, skip="unsupported_language"),
        SourceFile("docs/guide.md", None, skip="unsupported_language"),
        SourceFile("apps/web/tsconfig.json", None, skip="unsupported_language"),
        SourceFile("src/new.ts", "x", previous_path="src/old.ts"),
        SourceFile("README.md", "# context", role="context"),
    ]
    assert review_scope(sources) == [
        "README.md", "apps/web/tsconfig.json", "scripts/deploy.sh", "src/app.ts", "src/new.ts", "src/old.ts"]


def test_media_larger_than_the_snapshot_budget_never_makes_a_review_incomplete(repo, monkeypatch):
    import polaris.workflow.service as service
    from polaris.integrations.freshness import SnapshotLimits

    write(repo, "src/app.ts", "export const answer = 42;\n")
    (repo / "public").mkdir()
    (repo / "public" / "intro.mp4").write_bytes(b"\0" * 4096)
    commit(repo)
    monkeypatch.setattr(service, "scoped_limits", lambda size: SnapshotLimits(max_file_bytes=1024))
    report = review_workspace(repo, runtime=MEMORY, paths=[repo])
    assert report.status == "complete" and report.snapshot.complete, render_workflow(report)


def test_oversized_generated_data_is_not_source_but_large_code_stays_unreviewed(repo):
    write(repo, "src/fontData.ts", 'export const FONT = "' + "QUJD" * 8_000 + '";\n')
    write(repo, "src/avatars.generated.ts", "export const A = 1;\n" * 1_000)
    write(repo, "src/bigModule.ts", "export const value = 1;\n" * 2_000)
    config = WorkflowReviewConfig(max_file_bytes=10_000)
    skips = {source.path: source.skip for source in workflow_sources_from_paths([repo / "src"], root=repo, config=config)}
    assert skips == {"src/avatars.generated.ts": "generated_or_vendored", "src/bigModule.ts": "file_too_large",
                     "src/fontData.ts": "generated_or_minified"}


def test_text_and_sarif_reports_carry_the_evidence(monorepo):
    report = review_workspace(monorepo, runtime=MEMORY)
    text = render_workflow(report)
    head = text.splitlines()[0]
    assert head.startswith("Polaris security review \u00b7 1 issue to fix") and head.endswith("review complete")
    assert "apps/web/app/api/preview/route.ts:" in text and "Fix:" in text and "Path:" in text
    assert "> " in text  # the flagged source line is shown
    assert text.rstrip().endswith("not that the code is proven safe.")
    run = to_sarif(report)["runs"][0]
    result = next(item for item in run["results"] if item["properties"]["check"] == "ssrf")
    assert result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert result["partialFingerprints"]["polarisFingerprint/v1"]
    rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
    assert rule["id"] == result["ruleId"] and "Fix:" in rule["help"]["text"]
    assert "external/cwe/cwe-918" in rule["properties"]["tags"]

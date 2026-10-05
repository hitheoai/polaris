"""MCP server tests with the official MCP client. Scripted models exercise software only."""

import subprocess
import sys
from pathlib import Path

import anyio
import pytest
from review_helpers import ScriptedBackend

from polaris import __version__
from polaris.fixtures import sample_request
from polaris.integrations import ReviewService
from polaris.jsonio import digest_text
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import WORKFLOW_CHECKS

pytest.importorskip("mcp")
from mcp import Client, StdioServerParameters  # noqa: E402

from polaris.mcp.server import build_server, usable_folder  # noqa: E402

HEADER = "import os, subprocess\nfrom flask import request\n\n"
BASE_SVC = HEADER + "def run(h):\n    subprocess.run(['ping', h])\n\n\ndef other():\n    return 1\n"
CHANGED_SVC = HEADER + "def run(h):\n    # RISKY\n    os.system('ping ' + h)\n\n\ndef other():\n    return 1\n"
FRESH = HEADER + "def g(db, v):\n    # UNSURE\n    db.execute('SELECT ' + v)\n"
LEGACY_TOOLS = ["review_changes", "review_code", "assess"]
WORKFLOW_TOOLS = ["review_workflow", "review_snippet", "explain_finding", "review_details", "propose_repair",
                  "review_action"]
# Listed by default; the advanced tools are listed with --advanced-tools and callable either way.
DEFAULT_TOOLS = ["polaris_check", "polaris_explain", "polaris_fix"]
ADVANCED_TOOLS = [*DEFAULT_TOOLS, *WORKFLOW_TOOLS, "capabilities"]
ALL_TOOLS = [*ADVANCED_TOOLS, *LEGACY_TOOLS]


def legacy(*args, **kwargs):
    """A server with the older Python-only tools enabled (they are opt-in)."""
    return build_server(*args, legacy_tools=True, **kwargs)


@pytest.fixture(autouse=True)
def isolated_mcp_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("POLARIS_HOME", str(home / ".polaris"))
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
                        "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1",
                        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "svc.py").write_text(BASE_SVC)
    git(root, "add", "svc.py")
    git(root, "commit", "-q", "-m", "base")
    (root / "svc.py").write_text(CHANGED_SVC)
    (root / "fresh.py").write_text(FRESH)
    return root


def call(server, name, arguments=None):
    async def main():
        async with Client(server) as client:
            return await client.call_tool(name, arguments or {})

    return anyio.run(main)


def text(result):
    return result.content[0].text


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file() and ".git" not in path.relative_to(root).parts}


def test_tools_are_listed_read_only_with_schemas_and_instructions():
    async def main(server):
        async with Client(server) as client:
            listing = await client.list_tools()
            return [tool.name for tool in listing.tools], {tool.name: tool for tool in listing.tools}, client.instructions

    names, default, instructions = anyio.run(main, build_server(ReviewService()))
    assert names == DEFAULT_TOOLS
    assert "polaris_check" in instructions and "review_changes" not in instructions
    assert set(default["polaris_check"].input_schema["properties"]) == {"root", "scope", "paths", "limit"}
    assert default["polaris_check"].output_schema["title"] == "CheckResult"
    assert default["polaris_fix"].input_schema["required"] == ["id"]
    names, advanced, instructions = anyio.run(main, build_server(ReviewService(), advanced_tools=True))
    assert names == ADVANCED_TOOLS and "review_details" in instructions
    workflow = advanced["review_workflow"]
    assert set(workflow.input_schema["properties"]) == {"root", "staged", "range", "paths", "checks"}
    assert workflow.input_schema["properties"]["checks"]["anyOf"][0]["maxItems"] == len(WORKFLOW_CHECKS) == 17
    assert advanced["review_snippet"].input_schema["required"] == ["code"]
    names, tools, instructions = anyio.run(main, legacy(ReviewService()))
    assert names == ALL_TOOLS and "review_changes" in instructions
    assert all(tool.annotations.read_only_hint and not tool.annotations.destructive_hint
               for tool in tools.values())
    assert set(tools["review_changes"].input_schema["properties"]) == {"root", "staged", "range", "paths", "engine"}
    assert tools["review_code"].input_schema["required"] == ["code"]
    assert tools["review_code"].output_schema["title"] == "ReviewReport"


def test_editors_on_the_older_handshake_can_connect():
    async def main():
        async with Client(legacy(ReviewService()), mode="legacy") as client:
            names = [tool.name for tool in (await client.list_tools()).tools]
            result = await client.call_tool("review_code", {"code": HEADER + "def f(h):\n    os.system(h)\n",
                                                            "engine": "rules"})
            return names, client.instructions, result

    names, instructions, result = anyio.run(main)
    assert names == ALL_TOOLS
    assert "review_workflow" in instructions and not result.is_error
    assert result.structured_content["findings"][0]["check_id"] == "command_injection"


def test_review_changes_reports_uncommitted_changes_with_rules(repo):
    result = call(legacy(ReviewService(), root=repo), "review_changes", {"engine": "rules"})
    assert not result.is_error
    report = result.structured_content
    assert {(f["path"], f["symbol"], f["result"]) for f in report["findings"]} == {
        ("svc.py", "run", "flagged"), ("fresh.py", "g", "flagged")}
    body = text(result)
    assert "uncommitted changes in project" in body and "[FLAGGED] svc.py:4-6 run" in body
    assert "Fix: " in body and "rule engine" in body and "Next: fix flagged code" in body


def test_hybrid_is_the_default_and_adds_second_opinions(repo):
    result = call(legacy(ReviewService(ScriptedBackend()), root=repo), "review_changes")
    assert not result.is_error
    report = result.structured_content
    assert report["model"]["engine"] == "hybrid"
    assert {f["symbol"]: (f["result"], f["second_opinion"]["result"]) for f in report["findings"]} == {
        "run": ("flagged", "flagged"), "g": ("flagged", "uncertain")}
    assert "Model second opinion: not sure" in text(result) and "rules + second opinion from" in text(result)


def test_review_changes_with_the_model_staged_range_and_paths(repo):
    backend = ScriptedBackend()
    server = legacy(ReviewService(backend), root=repo, default_engine="model")
    uncommitted = call(server, "review_changes")
    assert {f["symbol"]: f["result"] for f in uncommitted.structured_content["findings"]} == {
        "run": "flagged", "g": "uncertain"}
    assert "risk 1.00, flags at 0.50" in text(uncommitted)
    assert "Experimental model" in text(uncommitted)
    git(repo, "add", "svc.py")
    staged = call(server, "review_changes", {"staged": True})
    assert [f["path"] for f in staged.structured_content["findings"]] == ["svc.py"]
    assert "staged changes" in text(staged)
    git(repo, "commit", "-q", "-m", "change")
    ranged = call(server, "review_changes", {"range": "HEAD~1..HEAD"})
    assert [f["symbol"] for f in ranged.structured_content["findings"]] == ["run"]
    whole = call(server, "review_changes", {"paths": ["fresh.py"]})
    assert [f["symbol"] for f in whole.structured_content["findings"]] == ["g"]
    clean = call(server, "review_changes", {"paths": ["svc.py"], "engine": "rules"})
    assert clean.structured_content["model"]["engine"] == "rules"
    git(repo, "add", "fresh.py")
    git(repo, "commit", "-q", "-m", "fresh")
    nothing = call(server, "review_changes")
    assert "no changed Python files" in text(nothing) and nothing.structured_content["findings"] == []


def test_review_code_reviews_a_snippet():
    snippet = HEADER + "def f(db, name):\n    db.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
    rules = call(legacy(ReviewService()), "review_code",
                 {"code": snippet, "path": "app/db.py", "engine": "rules"})
    assert not rules.is_error and "[FLAGGED] app/db.py:4-5 f · SQL injection" in text(rules)
    model = call(legacy(ReviewService(ScriptedBackend())), "review_code",
                 {"code": HEADER + "def f(db, v):\n    # NOCONTEXT\n    db.execute(v)\n"})
    assert model.structured_content["findings"][0]["result"] == "needs_context"
    assert "Guidance: " in text(model)
    quiet = call(legacy(ReviewService()), "review_code",
                 {"code": "def add(a, b):\n    return a + b\n", "engine": "rules"})
    assert "1 function in 1 file" in text(quiet) and "No findings." in text(quiet)
    empty = call(legacy(ReviewService()), "review_code", {"code": "x = 1\n", "engine": "rules"})
    assert "No Python functions to review." in text(empty)


def test_a_missing_model_explains_how_to_install_one_and_offers_rules(repo, tmp_path):
    missing = call(legacy(ReviewService(), root=repo, default_engine="model"), "review_changes")
    assert missing.is_error and "polaris model pull" in text(missing)
    assert 'engine="rules"' in text(missing) and text(missing).count("rules") == 2
    hybrid = call(legacy(ReviewService(), root=repo), "review_changes")
    assert not hybrid.is_error and "No Polaris model is installed" in text(hybrid)
    service = ReviewService.load(str(tmp_path / "no-such-model"), background=True)
    loading = call(legacy(service, root=repo, default_engine="model"), "review_code", {"code": "x = 1\n"})
    assert loading.is_error and "doesn't exist" in text(loading)
    broken = call(legacy(service, root=repo), "review_code", {"code": "x = 1\n"})
    assert not broken.is_error and "doesn't exist" in text(broken) and "rules reviewed this alone" in text(broken)
    rules_only = call(legacy(ReviewService(problem="not_requested"), root=repo, default_engine="rules"),
                      "review_changes")
    assert not rules_only.is_error and rules_only.structured_content["model"]["engine"] == "rules"


def test_bad_arguments_are_explained_not_raised(repo, tmp_path):
    server = legacy(ReviewService(), root=repo)
    cases = [
        ({"root": str(tmp_path / "nowhere")}, "doesn't exist"),
        ({"paths": ["../"], "engine": "rules"}, "isn't a file or folder inside"),
        ({"paths": [], "engine": "rules"}, "at least one"),
        ({"staged": True, "range": "HEAD~1..HEAD"}, "only one of"),
        ({"range": "--output=/tmp/x", "engine": "rules"}, "range must look like"),
        ({"root": str(tmp_path), "engine": "rules"}, "inside the configured workspace"),
    ]
    for arguments, message in cases:
        result = call(server, "review_changes", arguments)
        assert result.is_error and message in text(result), (arguments, text(result))
    home = call(legacy(ReviewService(), root=Path.home()), "review_changes",
                {"paths": ["."], "engine": "rules"})
    assert home.is_error


def test_assess_tool_returns_the_contract(backend):
    assessed = call(legacy(ReviewService(backend)), "assess", {"request": sample_request()})
    assert not assessed.is_error and assessed.structured_content["kind"] == "assessment"
    assert "sql_injection: assessed" in text(assessed)
    missing = call(legacy(ReviewService()), "assess", {"request": sample_request()})
    assert missing.is_error and missing.structured_content["code"] == "model_unavailable"
    assert "polaris model pull" in text(missing)
    invalid = call(legacy(ReviewService(backend)), "assess",
                   {"request": {"contract_version": "polaris.assessment/0.1.0"}})
    assert invalid.is_error and invalid.structured_content["code"] == "invalid_input"


def test_capabilities_describe_checks_engines_and_the_model():
    result = call(legacy(ReviewService(ScriptedBackend())), "capabilities")
    data = result.structured_content
    assert data["checks"] == ["sql_injection", "command_injection"] and data["model"]["loaded"] is True
    assert data["tools"] == ALL_TOOLS
    assert data["review_format"] == "polaris.review/0.1.0"
    assert data["workflow"]["format"] == "polaris.capabilities/0.2.0"
    body = text(result)
    assert body.startswith(f"Polaris {__version__} security review (review_workflow)")
    assert "TypeScript: all 11 checks" in body and "Python: all 11 checks" in body and "Rust: " in body
    assert "Legacy review_changes/review_code: Python only" in body
    default = call(build_server(ReviewService()), "capabilities")  # not listed, but answers by name
    assert default.structured_content["tools"] == DEFAULT_TOOLS and "Legacy" not in text(default)
    assert default.structured_content["callable_tools"] == ADVANCED_TOOLS
    assert "Advanced tools (callable by name; listed with --advanced-tools): review_workflow" in text(default)


def test_snippet_review_and_explanations_need_no_repository():
    code = ('import { NextRequest } from "next/server";\n\nexport async function GET(request: NextRequest) {\n'
            '  const target = request.nextUrl.searchParams.get("url");\n  return fetch(target!);\n}\n')
    server = build_server(ReviewService())
    reviewed = call(server, "review_snippet", {"code": code, "path": "app/api/preview/route.ts"})
    assert not reviewed.is_error
    findings = reviewed.structured_content["findings"]
    assert [(item["check_id"], item["result"], item["start_line"]) for item in findings] == [("ssrf", "flagged", 5)]
    assert findings[0]["trace"] and "route.ts:5" in text(reviewed)
    bad_path = call(server, "review_snippet", {"code": code, "path": "../escape.ts"})
    assert bad_path.is_error and bad_path.structured_content["code"] == "invalid_path"
    explained = call(server, "explain_finding", {"identifier": findings[0]["rule_id"]})
    assert not explained.is_error and explained.structured_content["check_id"] == "ssrf"
    assert "How to fix:" in text(explained) and "CWE-918" in text(explained)
    unknown = call(server, "explain_finding", {"identifier": "no_such_rule"})
    assert unknown.is_error and unknown.structured_content["known"] is False


def test_the_server_never_writes_to_the_repository(repo):
    before = snapshot(repo)
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True).stdout
    server = legacy(ReviewService(ScriptedBackend()), root=repo)
    for name, arguments in [("review_changes", {}), ("review_changes", {"paths": ["."]}),
                            ("review_code", {"code": FRESH}), ("capabilities", {}),
                            ("review_workflow", {}), ("review_workflow", {"paths": ["."]}),
                            ("review_snippet", {"code": FRESH, "path": "fresh.py"}),
                            ("polaris_check", {}), ("polaris_check", {"scope": "all"}),
                            ("polaris_explain", {"id": "command_injection"})]:
        assert not call(server, name, arguments).is_error
    assert snapshot(repo) == before and not (repo / ".polaris-cache").exists()
    assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True,
                          text=True).stdout == status


@pytest.mark.ml
def test_a_real_tiny_bundle_loads_in_the_background(tmp_path, repo):
    pytest.importorskip("torch")
    pytest.importorskip("transformers")
    from ml_helpers import make_tiny_bundle

    service = ReviewService.load(str(make_tiny_bundle(tmp_path / "tiny")), device="cpu", background=True)
    result = call(legacy(service, root=repo), "review_changes")
    assert not result.is_error, text(result)
    assert result.structured_content["model"]["model_version"] == "tiny-random-unit-test"
    assert "second opinion from tiny-random-unit-test (experimental)" in text(result)


def test_unfilled_editor_variables_are_ignored(tmp_path):
    assert usable_folder("${workspaceFolder}") is None and usable_folder("") is None
    assert usable_folder(str(tmp_path / "missing")) is None and usable_folder(tmp_path) == tmp_path.resolve()


def test_stdio_server_works_with_the_official_client(repo, tmp_path):
    def launch(*extra):
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "polaris", "mcp", "--engine", "rules", "--root", str(repo), *extra],
            env={"POLARIS_HOME": str(tmp_path / "polaris-home"), "HF_HUB_OFFLINE": "1",
                 "TRANSFORMERS_OFFLINE": "1"},
        )

    async def main():
        async with Client(launch()) as client:
            listing = await client.list_tools()
            names = [tool.name for tool in listing.tools]
            return names, await client.call_tool("polaris_check", {}), await client.call_tool("review_workflow", {})

    names, checked, result = anyio.run(main)
    assert names == DEFAULT_TOOLS
    assert not checked.is_error and checked.structured_content["format"] == "polaris.check/1"
    assert checked.structured_content["counts"]["fix_now"] >= 1 and "svc.py" in text(checked)
    # Older rules still name review_workflow: it isn't listed, but it still answers.
    assert not result.is_error and "svc.py:" in text(result)
    assert text(result).startswith("Polaris security review")

    async def advanced():
        async with Client(launch("--advanced-tools")) as client:
            return [tool.name for tool in (await client.list_tools()).tools]

    assert anyio.run(advanced) == ADVANCED_TOOLS


def test_workflow_tools_review_propose_and_assess_without_writes(repo):
    server = build_server(
        ReviewService(), root=repo,
        analysis_runtime=AnalysisRuntime(
            allow_external_analyzers=False, allow_temporary_source_files=False,
        ),
    )
    before = snapshot(repo)
    reviewed = call(server, "review_workflow", {"checks": ["command_injection"]})
    assert not reviewed.is_error
    brief = reviewed.structured_content
    assert brief["format"] == "polaris.workflow-summary/0.1.0"
    assert brief["status"] == "complete" and brief["tests_status"] == "not_run"
    detail = call(server, "review_details", {"report_id": brief["report_id"], "limit": 1})
    assert not detail.is_error and len(detail.structured_content["findings"]) == 1
    finding = next(item for item in brief["findings"] if item["path"] == "svc.py")
    proposal = call(server, "propose_repair", {
        "checks": ["command_injection"],
        "candidate": {
            "edits": [{
                "path": "svc.py", "before_sha256": digest_text(CHANGED_SVC),
                "replacement": BASE_SVC, "finding_refs": [finding["finding_id"]],
            }],
            "rationale": "Use a literal executable and argument list.",
            "expected_snapshot_digest": brief["snapshot"]["digest"],
        },
    })
    assert not proposal.is_error
    assert proposal.structured_content["origin"] == "host_candidate"
    action = call(server, "review_action", {"request": {
        "action": {"kind": "filesystem", "action_id": "outside", "operation": "write", "path": "../outside"},
    }})
    assert not action.is_error
    assert action.structured_content["status"] == "needs_review"
    assert not action.structured_content["authorized"] and not action.structured_content["executed"]
    forged = call(server, "review_action", {"request": {
        "action": {"kind": "filesystem", "action_id": "outside", "operation": "write", "path": "../outside"},
        "policy": {"authority": "user"},
    }})
    assert forged.is_error
    escaped = call(server, "review_workflow", {"root": str(repo.parent)})
    assert escaped.is_error
    assert snapshot(repo) == before


@pytest.mark.parametrize("kind", ["missing", "placeholder", "home", "filesystem", "symlink"])
def test_invalid_explicit_mcp_root_fails_without_fallback_or_stdout(repo, tmp_path, monkeypatch, capsys, kind):
    from polaris.cli import main

    link = tmp_path / "alias"
    link.symlink_to(repo, target_is_directory=True)
    choices = {"missing": str(tmp_path / "missing"), "placeholder": "${workspaceFolder}",
               "home": str(Path.home()), "filesystem": "/", "symlink": str(link)}
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(repo))
    assert main(["mcp", "--root", choices[kind], "--engine", "rules"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "bounded" in captured.err and "instead" not in captured.err


def test_legacy_review_cannot_escape_a_bound_root_or_expand_a_subdirectory_to_git_root(repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.py").write_text("def unused():\n    return 1\n")
    server = legacy(ReviewService(), root=repo)
    escaped = call(server, "review_changes", {"root": str(outside), "paths": ["private.py"], "engine": "rules"})
    assert escaped.is_error and "configured workspace" in text(escaped)
    nested = repo / "nested"
    nested.mkdir()
    (nested / "one.py").write_text("def one():\n    return 1\n")
    bounded = legacy(ReviewService(), root=nested)
    expanded = call(bounded, "review_changes", {"engine": "rules"})
    assert expanded.is_error and "outside the selected workspace" in text(expanded)
    selected = call(bounded, "review_changes", {"paths": ["one.py"], "engine": "rules"})
    assert not selected.is_error
    workflow = call(bounded, "review_workflow", {})
    assert workflow.is_error and "not a clean review" in text(workflow)


def test_symlink_root_is_not_usable_or_a_valid_server_binding(repo, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(repo, target_is_directory=True)
    assert usable_folder(alias) is None
    with pytest.raises(ValueError, match="safe project"):
        legacy(ReviewService(), root=alias)

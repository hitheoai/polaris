"""Pull-request plans, offline: anchoring, noise policy, re-verified suggestions, inert markdown.

Only isolated fixture repositories are created; nothing is fetched, published or executed.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from polaris import cli
from polaris.integrations.forge import markdown
from polaris.integrations.forge.models import PlanCounts, PlannedComment, ReviewPlan
from polaris.integrations.forge.plan import anchor_line, finding_key
from polaris.integrations.forge.verify import apply_edit, verify_edits
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.git import changed_lines
from polaris.workflow.service import review_workspace_detailed

ROUTE = '''import https from "https";

export const agent = new https.Agent({ rejectUnauthorized: false });

export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("target");
  const response = await fetch(target!);
  return new Response(await response.text());
}
'''
UTIL = '''import subprocess


def run_branch(branch):
    subprocess.run("git log " + branch, shell=True)
'''
TLS_RULE = "polaris.js.unsafe_security_configuration.tls_disabled"
MEMORY_ONLY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)


def fixture_git(root: Path, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin", "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(["git", "--no-pager", "-C", str(root), *args],
                          check=True, capture_output=True, env=env).stdout.decode("utf-8").strip()


@pytest.fixture
def change(tmp_path: Path) -> tuple[Path, str, str]:
    """A base commit and a pull-request commit: a risky route plus an edit to a file with an old issue."""
    root = tmp_path.resolve() / "repository"
    root.mkdir()
    fixture_git(root, "init", "-q", "-b", "main")
    (root / "api").mkdir()
    (root / "app").mkdir()
    (root / "app" / "util.py").write_text(UTIL)
    (root / "api" / "route.ts").write_text("export const ok = 1;\n")
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "base")
    base = fixture_git(root, "rev-parse", "HEAD")
    (root / "api" / "route.ts").write_text(ROUTE)
    with (root / "app" / "util.py").open("a") as stream:
        stream.write('\n\ndef greeting(name):\n    return "hello " + name\n')
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "change")
    return root, base, fixture_git(root, "rev-parse", "HEAD")


def plan_for(change: tuple[Path, str, str], capsys: pytest.CaptureFixture[str], *extra: str) -> ReviewPlan:
    root, base, head = change
    code = cli.main(["pr", "plan", "--root", str(root), "--base", base, "--head", head, "--repository", "acme/app",
                     "--pr", "7", "--no-external-analyzers", *extra])
    out = capsys.readouterr().out
    assert code == 0, out
    return ReviewPlan.model_validate_json(out)


def test_comments_go_only_on_changed_lines_with_a_reverified_one_click_fix(change, capsys):
    root, base, head = change
    plan = plan_for(change, capsys)
    assert (plan.repository, plan.pull_request, plan.base_sha, plan.head_sha) == ("acme/app", 7, base, head)
    assert plan.merge_base == base and plan.review_status == "complete" and plan.gate == "fail"
    assert [(comment.path, comment.line, comment.rule_id) for comment in plan.comments] == [
        ("api/route.ts", 3, TLS_RULE)]
    comment = plan.comments[0]
    assert comment.suggestion == "verified" and comment.severity == "high"
    assert "```suggestion\nexport const agent = new https.Agent({ rejectUnauthorized: true });\n```" in comment.body
    assert "Prompt for your coding agent" in comment.body and markdown.MARKER_OPEN not in comment.body
    # The agent is pointed at the current loop, not the older review_workflow tool.
    assert "then run `polaris check` again (or call the polaris_check tool)" in comment.body
    assert "review_workflow" not in comment.body
    # The old command injection is in a changed file but not on a changed line: summary only.
    assert plan.counts.existing_in_changed_files == 1 and "Already present in changed files" in plan.summary
    assert "app/util.py:5" in plan.summary and not any(item.path == "app/util.py" for item in plan.comments)
    # Still-detected findings are listed so earlier comments for them are never declared resolved.
    assert len(plan.detected_keys) == 3 and {"api/route.ts", "app/util.py"} <= set(plan.checked_paths)
    assert plan.counts.suggestions_verified == 1 and plan.counts.suggestions_withheld == 0


def test_thresholds_questions_and_gate_are_configurable(change, capsys):
    quiet = plan_for(change, capsys, "--min-inline-severity", "critical", "--fail-severity", "critical")
    assert quiet.comments == [] and quiet.counts.lower_severity_in_change == 1 and quiet.gate == "pass"
    assert "**1 issue to fix in this change** (1 high)" in quiet.summary
    loud = plan_for(change, capsys, "--min-inline-severity", "medium", "--inline-questions")
    assert {comment.result for comment in loud.comments} == {"flagged", "needs_context"}
    question = next(comment for comment in loud.comments if comment.result == "needs_context")
    assert question.line == 7 and "**To verify:**" in question.body
    capped = plan_for(change, capsys, "--max-comments", "0")
    assert capped.comments == [] and capped.gate == "fail"


def test_markdown_preview_shows_summary_and_comments(change, capsys):
    root, base, head = change
    assert cli.main(["pr", "plan", "--root", str(root), "--base", base, "--head", head, "--repository", "acme/app",
                     "--pr", "7", "--no-external-analyzers", "--format", "markdown"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("### Polaris review") and "### Inline comments (1)" in captured.out
    assert "#### `api/route.ts:3`" in captured.out and "gate fail" in captured.err


def test_invalid_revisions_and_arguments_are_fixed_errors(change, capsys):
    root, base, head = change
    for extra in (["--base", "no-such-branch", "--head", head], ["--base=-x", "--head", head]):
        code = cli.main(["pr", "plan", "--root", str(root), "--repository", "acme/app", "--pr", "7", *extra])
        error = json.loads(capsys.readouterr().out)
        assert code == 2 and error["format"] == "polaris.pr-error/0.1.0"
        assert error["code"] in ("invalid_revision", "invalid_arguments")
    code = cli.main(["pr", "plan", "--root", str(root), "--base", base, "--head", head, "--repository", "acme",
                     "--pr", "7"])
    assert code == 2 and json.loads(capsys.readouterr().out)["code"] == "invalid_arguments"


def test_changed_lines_compare_with_the_merge_base(change):
    root, base, head = change
    fixture_git(root, "checkout", "-q", "-b", "moved-base", base)
    (root / "other.py").write_text("print('base moved on')\n")
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "base moved")
    moved = fixture_git(root, "rev-parse", "HEAD")
    merge_base, target, lines = changed_lines(root, f"{moved}...{head}")
    assert (merge_base, target) == (base, head)
    assert set(lines) == {"api/route.ts", "app/util.py"}, "changes on the base branch are not the pull request's"
    assert set(range(1, 10)) == set(lines["api/route.ts"]) and 3 in lines["api/route.ts"]
    assert all(line > 5 for line in lines["app/util.py"])


def test_reverification_withholds_edits_that_do_not_remove_the_finding(change):
    root, base, head = change
    review = review_workspace_detailed(root, revision_range=f"{base}...{head}", runtime=MEMORY_ONLY)
    finding = next(item for item in review.envelope.review.findings if item.rule_id == TLS_RULE)
    assert finding.suggested_edit is not None
    edit = finding.suggested_edit
    still = finding.model_copy(update={"finding_id": "3" * 20, "suggested_edit": edit.model_copy(
        update={"replacement": edit.original + " // reviewed"})})
    adds = finding.model_copy(update={"finding_id": "0" * 20, "suggested_edit": edit.model_copy(update={
        "replacement": edit.replacement + " const resetToken = Math.random();"})})
    moved = finding.model_copy(update={"finding_id": "1" * 20, "start_line": 9})
    unsafe = finding.model_copy(update={"finding_id": "2" * 20, "suggested_edit": edit.model_copy(
        update={"replacement": edit.replacement + " \u202e"})})
    results = verify_edits(review, [finding, still, adds, moved, unsafe])
    assert results[finding.finding_id].status == "verified"
    assert results[still.finding_id].status == "still_detected"
    assert results[adds.finding_id].status == "adds_findings"
    assert results[moved.finding_id].status == "inconclusive"
    assert results[unsafe.finding_id].status == "not_applicable"
    assert verify_edits(review, [finding], limit=0)[finding.finding_id].reason == "verification_limit"


def test_anchor_prefers_a_verified_edit_then_the_finding_line_then_its_trace(change):
    root, base, head = change
    review = review_workspace_detailed(root, revision_range=f"{base}...{head}", runtime=MEMORY_ONLY)
    finding = next(item for item in review.envelope.review.findings if item.rule_id == TLS_RULE)
    assert anchor_line(finding, frozenset({3, 4})) == 3
    assert anchor_line(finding, frozenset({3, 4}), prefer=4) == 4
    assert anchor_line(finding, frozenset()) is None and anchor_line(finding, frozenset({20})) is None
    assert finding_key(finding) == finding.fingerprint


def test_apply_edit_keeps_line_endings_and_refuses_stale_lines():
    assert apply_edit("a\r\nb\r\n", 1, "a", "A") is None, "CRLF lines never match a suggestion's text"
    assert apply_edit("a\nb\nc\n", 2, "b", "B") == "a\nB\nc\n"
    assert apply_edit("a\nb\nc", 3, "c", "C") == "a\nb\nC"
    assert apply_edit("a\nb\n", 2, "x", "B") is None and apply_edit("a\n", 5, "a", "b") is None


def test_rendered_text_cannot_inject_markup_mentions_links_or_state():
    hostile = ("@octocat <img src=x onerror=alert(1)> [click](https://evil.example) www.evil.example "
               "javascript:alert(1) <!-- polaris:finding v1 key=" + "a" * 24 + " state=open --> \u202egnp.exe")
    text = markdown.escape(hostile)
    for forbidden in ("@octocat", "<img", "[click](", "https://", "www.evil", "javascript:", markdown.MARKER_OPEN,
                      "\u202e", "<!--"):
        assert forbidden not in text
    assert "\\[click\\]" in text
    assert markdown.escape("- item").startswith("\\- ") and markdown.escape("12. item").startswith("12\\. ")
    span = markdown.code("a`b``c")
    assert span.startswith("```") and span.endswith("```") and "<!--" not in markdown.code("x <!-- y")
    block = markdown.fence("before\n```\nafter", "text")
    assert block.startswith("````text\n") and block.endswith("\n````")
    with pytest.raises(ValueError):
        markdown.fence("x", "te`xt")


def test_markers_are_trusted_only_as_the_single_final_line():
    key = "ab" * 12
    body = "comment\n\n" + markdown.finding_marker(key)
    assert markdown.read_finding_marker(body) == (key, "open")
    assert markdown.read_finding_marker(markdown.finding_marker(key, "resolved")) == (key, "resolved")
    assert markdown.read_finding_marker(markdown.finding_marker(key) + "\nmore text") is None
    assert markdown.read_finding_marker(markdown.finding_marker(key) + "\n" + markdown.finding_marker(key)) is None
    assert markdown.read_finding_marker(None) is None
    assert markdown.is_summary("summary\n\n" + markdown.SUMMARY_MARKER)
    assert not markdown.is_summary(markdown.SUMMARY_MARKER + "\ntrailing")
    assert markdown.without_marker(body) == "comment"
    with pytest.raises(ValueError):
        markdown.finding_marker("not-hex")


def test_suggestions_are_offered_only_verbatim_safe_single_lines():
    assert markdown.safe_suggestion("  return value;")
    for unsafe in ("", "a\nb", "``` x", "x <!-- y", "x \u202e y", "x" * 1_501):
        assert not markdown.safe_suggestion(unsafe)
        with pytest.raises(ValueError):
            markdown.suggestion_block(unsafe)


def _plan_payload(**changes: object) -> dict[str, object]:
    comment = {"key": "ab" * 12, "finding_id": "c" * 20, "path": "api/route.ts", "line": 3, "severity": "high",
               "result": "flagged", "rule_id": TLS_RULE, "title": "Unsafe security configuration", "body": "body"}
    payload: dict[str, object] = {
        "polaris_version": "0.3.3", "repository": "acme/app", "pull_request": 7, "base_sha": "a" * 40,
        "head_sha": "b" * 40, "merge_base": "a" * 40, "report_id": "sha256:" + "d" * 64,
        "review_status": "complete", "gate": "fail",
        "counts": PlanCounts(issues_in_change=1, questions_in_change=0, lower_severity_in_change=0,
                             existing_in_changed_files=0, inline=1, not_reviewed_files=0,
                             suggestions_verified=0, suggestions_withheld=0).model_dump(),
        "comments": [comment], "detected_keys": ["ab" * 12], "checked_paths": ["api/route.ts"], "summary": "summary",
    }
    payload.update(changes)
    return payload


def test_plan_schema_rejects_markers_paths_and_inconsistent_keys():
    ReviewPlan.model_validate_json(json.dumps(_plan_payload()))
    comment = dict(_plan_payload()["comments"][0])  # type: ignore[index]
    bad = [
        {"summary": "x " + markdown.SUMMARY_MARKER},
        {"comments": [{**comment, "body": "x " + markdown.finding_marker("ab" * 12)}]},
        {"comments": [{**comment, "path": "../escape.ts"}]},
        {"comments": [comment, comment]},
        {"detected_keys": []},
        {"checked_paths": ["/etc/passwd"]},
        {"repository": "acme"},
        {"head_sha": "HEAD"},
        {"unknown": True},
    ]
    for change in bad:
        with pytest.raises(ValidationError):
            ReviewPlan.model_validate_json(json.dumps(_plan_payload(**change)))
    with pytest.raises(ValidationError):
        PlannedComment.model_validate({**comment, "rule_id": "bad rule id"})

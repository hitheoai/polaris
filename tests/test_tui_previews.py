"""`polaris tui` milestone 5 without Textual: the PR preview (same plan as `pr plan`, verifications
cached across option changes), the fix preview and its budget, other tools' results and the
attack surface views."""

from __future__ import annotations

import json
import re
from dataclasses import replace

import pytest
from tui_fixtures import live_data, sample_repository, sarif_file, saved_copy

from polaris import cli
from polaris.integrations.forge import plan as plan_module
from polaris.integrations.forge import verify as verify_module
from polaris.integrations.forge.plan import (
    PlanOptions,
    build_plan,
    edit_candidates,
    plan_verifications,
)
from polaris.integrations.forge.verify import Verification
from polaris.tui import panels, view
from polaris.tui.prpreview import PLACEHOLDER_REPOSITORY, PlanState, Verifier
from polaris.tui.source import SourceIndex

ELAPSED = re.compile(r"\(\d+\.\ds\)")


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> dict:
    base = tmp_path_factory.mktemp("tui-previews")
    root = sample_repository(base)
    sarif = sarif_file(base)
    pull_request = live_data(root, "--base", "main", "--import-sarif", str(sarif))
    return {"root": root, "sarif": sarif, "pr": pull_request, "base": base}


@pytest.fixture
def counted(monkeypatch):
    """Count verify_edits calls (and the candidates each one re-reviews), from plans and fix previews."""
    calls: list[list[str]] = []
    original = verify_module.verify_edits

    def spy(review, findings, *, limit=20):
        calls.append([finding.finding_id for finding in findings])
        return original(review, findings, limit=limit)

    monkeypatch.setattr(plan_module, "verify_edits", spy)
    monkeypatch.setattr(verify_module, "verify_edits", spy)
    return calls


def test_the_first_preview_is_exactly_the_plan_pr_plan_writes(sample, capsys):
    data = sample["pr"]
    preview = Verifier(data).plan(PlanState())
    pull_request = data.pull_request
    code = cli.main(["pr", "plan", "--root", str(sample["root"]), "--base", "main", "--head", "HEAD",
                     "--repository", "acme/app", "--pr", "7", "--no-external-analyzers",
                     "--import-sarif", str(sample["sarif"])])
    published = json.loads(capsys.readouterr().out)
    assert code == 0 and preview.repository == PLACEHOLDER_REPOSITORY and preview.pull_request == 1
    assert (preview.base_sha, preview.head_sha, preview.merge_base) == (
        published["base_sha"], published["head_sha"], published["merge_base"]) == (
        pull_request.base_sha, pull_request.head_sha, pull_request.merge_base)
    mine = preview.model_dump(mode="json")
    for field in ("comments", "gate", "counts", "detected_keys", "checked_paths", "imported_tools", "imported_paths"):
        assert mine[field] == published[field], field
    # The summary differs only in how long each review took.
    assert ELAPSED.sub("(…)", preview.summary) == ELAPSED.sub("(…)", published["summary"])
    assert PLACEHOLDER_REPOSITORY not in preview.summary + "".join(comment.body for comment in preview.comments)


def test_option_changes_reuse_verifications_and_respect_the_budget(sample, counted):
    data = sample["pr"]
    verifier = Verifier(data)
    high = verifier.plan(PlanState())
    assert counted == [] and high.counts.suggestions_verified == 0  # no edit is eligible at high+
    medium_state = PlanState().toggled("inline")
    assert medium_state.min_inline_severity == "medium"
    medium = verifier.plan(medium_state)
    assert len(counted) == 1 and len(counted[0]) == 2 and medium.counts.suggestions_verified == 2
    assert {comment.suggestion for comment in medium.comments if comment.severity == "medium"} == {"verified"}
    verifier.plan(PlanState())
    again = verifier.plan(medium_state.toggled("gate").toggled("questions"))
    assert len(counted) == 1, "toggling options never re-runs a verification it already has"
    assert again.counts.suggestions_verified == 2
    # A plan built from known results is the same plan as one that verifies from scratch.
    fresh = build_plan(data.workspace, repository=PLACEHOLDER_REPOSITORY, pull_request=1,
                       base_sha=data.pull_request.base_sha, head_sha=data.pull_request.head_sha,
                       merge_base=data.pull_request.merge_base, changed=data.pull_request.changed,
                       options=medium_state.options())
    assert fresh == medium
    off = verifier.plan(medium_state.toggled("verify"))
    assert off.counts.suggestions_verified == 0 and {comment.suggestion for comment in off.comments} <= {"withheld", "none"}


def test_plan_verifications_spend_only_the_remaining_budget(sample, counted):
    data = sample["pr"]
    changed = data.pull_request.changed
    options = PlanOptions(min_inline_severity="medium", max_verifications=1)
    candidates = edit_candidates(data.workspace, changed, options)
    assert len(candidates) == 2
    first = plan_verifications(data.workspace, changed, options)
    limited = [item for item in first.values() if item.reason == "verification_limit"]
    assert len(limited) == 1 and len(counted) == 1
    # Known results are reused; limit-capped ones are verified again only within what's left.
    known = {key: value for key, value in first.items() if value.reason != "verification_limit"}
    again = plan_verifications(data.workspace, changed, options, known=known)
    assert len(counted) == 2 and len(counted[1]) == 1
    assert [item.reason for item in again.values()].count("verification_limit") == 1
    assert plan_verifications(data.workspace, changed, replace(options, verify_fixes=False)) == {}


def test_fix_preview_verifies_on_demand_with_a_cap(sample, counted):
    data = sample["pr"]
    verifier = Verifier(data)
    edits = [finding for finding in data.envelope.review.findings if finding.suggested_edit is not None]
    python = next(finding for finding in edits if finding.path == "scripts/deploy.py")
    result = verifier.verify(python)
    assert (result.status, result.reason) == ("verified", "no_longer_detected")
    assert verifier.left == verifier.limit - 1 and verifier.verify(python) is result
    assert counted == [[python.finding_id]], "one finding per on-demand verification, cached afterwards"
    # The PR preview reuses it rather than verifying it again.
    verifier.plan(PlanState().toggled("inline"))
    assert len(counted) == 2 and python.finding_id not in counted[1]
    spent = Verifier(data)
    spent.on_demand = spent.limit
    capped = spent.verify(python)
    assert (capped.status, capped.reason) == ("inconclusive", "verification_limit") and len(counted) == 2
    assert spent.known(python) is None, "a capped result is never cached"
    with pytest.raises(ValueError):
        Verifier(saved_copy(data)).verify(python)
    sources = SourceIndex(data)
    shown = view.plain_lines(panels.fix_lines(python, data, sources, result, left=19))
    assert '- 6 │     subprocess.run(["git", "checkout", branch])' in shown
    assert '+ 6 │     subprocess.run(["git", "checkout", "--", branch])' in shown
    assert "  5 │ def deploy(branch):" in shown
    assert "✓ verified" in shown and "no longer detects the finding" in shown and "Tests were not run" in shown
    assert "◌ verifying" in view.plain_lines(panels.fix_lines(python, data, sources, "pending", left=19))
    assert "19 verification(s) left" in view.plain_lines(panels.fix_lines(python, data, sources, None, left=19))
    saved = saved_copy(data)
    assert "needs a live review" in view.plain_lines(panels.fix_lines(python, saved, SourceIndex(saved), None, left=0))
    limited = view.plain_lines(panels.fix_lines(python, data, sources, Verification("inconclusive",
                                                                                     "verification_limit"), left=0))
    assert "? inconclusive" in limited and "20 per review" in limited


def test_plan_header_rows_and_markdown_are_labelled_and_inert(sample):
    data = sample["pr"]
    plan = Verifier(data).plan(PlanState())
    header = view.plain_lines(panels.plan_header(plan, PlanState(), data))
    assert "placeholder repository local-preview/unpublished, PR #1 · nothing is published" in header
    assert "Gate ✖ FAIL · 5 inline" in header and "i inline ▲ HIGH+" in header and "u verify fixes: on" in header
    rows = panels.plan_rows(plan)
    assert [key for key, _ in rows] == ["summary", *(f"comment-{index}" for index in range(5))]
    assert view.plain(rows[1][1][0]) == "◆ CRIT"
    body = panels.plan_body(plan, "comment-0")
    assert view.plain(body[0]).startswith("Inline comment at .github/workflows/triage.yml:9")
    markdown = panels.markdown_lines("### Title\n```text\n  code [red]\n```\n<sub>note</sub>\n\x1b[2Jtext")
    assert [role for line in markdown for _, role in line] == ["heading", "code.number", "code", "code.number", "muted",
                                                               "text"]
    assert view.plain(markdown[2]) == "  code [red]" and "\x1b" not in view.plain_lines(markdown)
    unavailable = view.plain_lines(panels.plan_unavailable(saved_copy(data)))
    assert "saved report can't be turned into a PR preview" in unavailable and "polaris tui --base main" in unavailable
    # Options wrap between options, never inside one, and come before the informational lines
    # (a small terminal shows only the top of the header). Narrow terminals get a one-row label.
    for width in (60, 78, 118):
        texts = [view.plain(item) for item in panels.plan_header(plan, PlanState(), data, width=width)]
        options = [index for index, text in enumerate(texts) if text.startswith(("i ", "k ", "g ", "m ", "e ", "u "))]
        assert any("u verify fixes: on" in texts[index] for index in options)
        assert all(len(texts[index].rstrip()) <= width for index in options)
        assert texts[1].startswith("Gate ") and max(options) < texts.index(next(t for t in texts if t.startswith("Reviewed")))
    narrow = view.plain(panels.plan_header(plan, PlanState(), data, width=78)[0])
    assert narrow == "Local preview, nothing is published (placeholder local-preview/unpublished #1)"


@pytest.mark.parametrize("width", [80, 100, 120, 200])
def test_preview_tables_fit_the_terminal(width):
    for columns, count in ((panels.plan_columns(width), 4), (panels.surface_columns(width), 5)):
        # Each column has one cell of padding on each side, and the table keeps one for its scrollbar.
        assert sum(size for _, size in columns) + 2 * count + 1 <= width
        assert dict(columns)["Where"] >= 12
    assert dict(panels.surface_columns(width))["Guard"] >= len("✗ no auth guard")
    assert dict(panels.surface_columns(width))["Findings"] == len("Findings")


def test_other_tools_groups(sample):
    data = sample["pr"]
    text = view.plain_lines(panels.tools_lines(data))
    assert "⇄ corroborated (2)" in text and "react.dangerously-set-inner-html" in text
    assert "js.child-process · lib/run.ts:4" in text  # the shell finding matches the imported result
    assert "↗ tool only (1)" in text
    assert "[red]markup[/red] \ufffdevil" in text  # imported text is shown, never interpreted
    assert "\u2736 Polaris only (9)" in text and "⊘ left out (1)" in text and "1 outside review scope" in text
    assert "✗ rejected (0)" in text
    review = data.envelope.review
    nothing = replace(data, envelope=data.envelope.model_copy(update={"review": review.model_copy(update={
        "imports": [], "imported": []})}))
    assert "No SARIF was imported" in view.plain_lines(panels.tools_lines(nothing))


def test_attack_surface_rows_and_details(sample):
    data = sample["pr"]
    rows = panels.surface_rows(data)
    assert [view.plain(cells[1]) for _, cells in rows] == ["GET", "DELETE", "POST"]
    assert [view.plain(cells[0]) for _, cells in rows] == ["✗ no auth guard"] * 3
    assert view.plain(rows[1][1][3]).startswith("1 write") and view.plain(rows[2][1][4]) == "1◆"
    delete = data.envelope.review.surface[1]
    detail = view.plain_lines(panels.surface_detail(delete, data))
    assert "Writes: db.user.delete (line 15)" in detail and "Missing authorization · line 13" in detail
    assert "Evidence for review, not an access-control model" in detail
    summary = view.plain(panels.surface_summary(data.envelope.review.surface))
    assert summary == "3 entry points · ✗ 3 without an auth guard (1 of them write data)"
    guarded = delete.model_copy(update={"guarded": True, "guards": ["requireUser"]})
    assert view.plain(panels.surface_rows(replace(data, envelope=data.envelope.model_copy(update={
        "review": data.envelope.review.model_copy(update={"surface": [guarded]})})))[0][1][0]) == "✓ guarded"
    public = delete.model_copy(update={"public": True})
    assert panels.guard_state(public).word == "public route"

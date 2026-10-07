"""`polaris tui` without Textual: the view model, code context, saved reports, editor commands,
themes, and the command's guards. Uses real reviews of a sample repository (TypeScript, Python,
a GitHub Actions workflow, a Dockerfile, an unsupported Go file, docs and imported SARIF)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from tui_fixtures import fixed, live_data, sample_repository, sarif_file, saved_copy

from polaris import cli
from polaris.tui import theme, view
from polaris.tui.editor import EditorProblem, build_command, editor_words
from polaris.tui.session import (
    MAX_REPORT_BYTES,
    SessionProblem,
    load_report,
    parse_report,
    report_json,
)
from polaris.tui.source import SourceIndex, split_lines, unusual_breaks
from polaris.tui.text import clean, clean_code_line

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> dict:
    base = tmp_path_factory.mktemp("tui-view")
    root = sample_repository(base)
    sarif = sarif_file(base)
    data = live_data(root, "--diff", "main...feature", "--import-sarif", str(sarif))
    return {"root": root, "sarif": sarif, "data": data, "base": base}


def rows(data, **filters) -> list[view.FindingRow]:
    return list(view.finding_view(data, view.Filters(**filters)).rows)


def titles(data, **filters) -> list[tuple[str, str]]:
    return [(row.finding.title, row.finding.path) for row in rows(data, **filters)]


def find(data, rule_part: str, path: str | None = None):
    for finding in data.envelope.review.findings:
        if rule_part in finding.rule_id and (path is None or finding.path == path):
            return finding
    raise AssertionError(rule_part)


# ---- inert text --------------------------------------------------------------------------------


@pytest.mark.parametrize("hostile", [
    "\x1b[31mred\x1b[0m", "\x1b]8;;https://evil.example\x07link\x1b]8;;\x07", "abc\u202edcba", "zero\u200bwidth",
    "bell\x07", "tag\U000e0041", "nul\x00", "c1\x9bcsi",
])
def test_control_bidi_and_escape_characters_are_shown_never_interpreted(hostile):
    for cleaned in (clean(hostile), clean_code_line(hostile)):
        assert "\x1b" not in cleaned and "\x07" not in cleaned and "\x00" not in cleaned and "\x9b" not in cleaned
        assert "\u202e" not in cleaned and "\u200b" not in cleaned and "\U000e0041" not in cleaned
        assert "\ufffd" in cleaned


def test_markup_stays_literal_and_long_lines_are_capped():
    assert clean("[red]boom[/red] :smile:") == "[red]boom[/red] :smile:"
    long = clean_code_line("x" * 100_000)
    assert len(long) <= 1_000 and long.endswith("…")
    assert clean_code_line("\tindent") == "    indent"


def test_lines_are_numbered_like_the_analyzers_and_unusual_breaks_are_flagged():
    assert split_lines("a\r\nb\nc\n") == ["a", "b", "c"]
    assert split_lines("a\u2028b\nc") == ["a\u2028b", "c"]  # one line, as tree-sitter counts it
    assert unusual_breaks("a\u2028b") and unusual_breaks("a\rb") and not unusual_breaks("a\r\nb\n")


# ---- themes: a glyph and a word for every state ---------------------------------------------------


def test_every_state_has_a_glyph_a_word_and_a_style_in_every_palette():
    tables = (theme.SEVERITY, theme.RESULT, theme.COVERAGE, theme.FRESHNESS, theme.COMPLETENESS,
              theme.VERIFICATION, theme.GATE, theme.STEP, theme.IMPORT_GROUP, theme.SURFACE, theme.MARKS)
    for table in tables:
        for state in table.values():
            assert state.glyph.strip() and state.word.strip()
            for palette in theme.PALETTES.values():
                assert state.role in palette
    words = [state.word for state in theme.SEVERITY.values()]
    assert len(set(words)) == len(words), "severities differ by word, not only by colour"
    assert all(not any(c in style for c in "#") for style in theme.PALETTES["ansi"].values())
    assert all(" on " not in style and "#" not in style and not any(
        name in style for name in ("red", "green", "yellow", "blue", "magenta", "cyan"))
        for style in theme.PALETTES["none"].values()), "NO_COLOR palette uses attributes only"
    assert theme.palette_for(ansi=False, dark=True, no_color=True) == "none"
    assert theme.palette_for(ansi=True, dark=True, no_color=False) == "ansi"


# ---- the cockpit ---------------------------------------------------------------------------------


def test_default_floor_hides_low_issues_but_keeps_questions_with_their_own_count(sample):
    data = sample["data"]
    findings = view.finding_view(data, view.Filters())
    assert [row.group for row in findings.rows] == ["issue"] * 5 + ["question"]
    assert all(theme.at_least(row.severity, "high") for row in findings.rows if row.group == "issue")
    assert findings.issues_below_floor == 5 and findings.questions_shown == 1
    status = view.plain(findings.status(view.Filters()))
    assert "5 issues, 5 below ▲ HIGH+ (s)" in status and "1 question" in status
    # The floor never hides medium questions, even at its highest.
    assert any(row.group == "question" for row in rows(data, floor="critical"))
    assert not any(row.group == "question" for row in rows(data, questions=False))
    assert "1 question hidden" in view.plain(view.finding_view(data, view.Filters(questions=False)).status(
        view.Filters(questions=False)))
    everything = rows(data, floor="info")
    assert len([row for row in everything if row.group == "issue"]) == 10


def test_floor_cycles_from_high_through_info_and_critical():
    seen = ["high"]
    for _ in range(5):
        seen.append(view.next_floor(seen[-1]))
    assert seen == ["high", "medium", "low", "info", "critical", "high"]


def test_text_and_file_filters(sample):
    data = sample["data"]
    assert {path for _, path in titles(data, floor="info", query="route.ts")} == {"app/api/users/route.ts"}
    assert titles(data, floor="info", path="scripts/") == [("Command injection", "scripts/deploy.py")]
    assert titles(data, floor="info", path="scripts/deploy.py") == [("Command injection", "scripts/deploy.py")]
    filtered = view.finding_view(data, view.Filters(query="ssrf"))
    assert [row.finding.check_id for row in filtered.rows] == ["ssrf"]
    assert "matching “ssrf”" in view.plain(filtered.status(view.Filters(query="ssrf")))


def test_rows_mark_corroborated_findings_and_suggested_edits(sample):
    data = sample["data"]
    cells = {row.finding.path: [view.plain(cell) for cell in row.cells()] for row in rows(data, floor="info")}
    assert cells["app/components/Comment.tsx"][1] == "? verify"
    assert cells["scripts/deploy.py"][1] == "✖ issue", "the Kind column says what it is, not what to do"
    assert "⇄1" in cells["app/components/Comment.tsx"][2]
    assert "✎" in cells["scripts/deploy.py"][2]
    legend = view.plain_lines(view.help_lines(view.UiState()))
    assert "✖ issue   ? verify   ! error" in legend
    assert "✎ has a suggested edit (f previews it)" in legend and "⇄N also reported by N imported results" in legend
    assert view.tail("app/api/users/route.ts:21", 12) == "…route.ts:21"


def test_file_tree_shows_coverage_states_and_visible_counts(sample):
    data = sample["data"]
    findings = view.finding_view(data, view.Filters())
    tree = view.file_tree(data, findings)
    labels = {}

    def walk(node):
        for child in node.sorted_children():
            labels[child.path] = view.plain(child.label())
            walk(child)

    walk(tree)
    assert labels["cmd/"].startswith("✗ cmd/") and labels["cmd/tool/main.go"].startswith("✗ main.go")
    assert labels["docs/notes.md"].startswith("· notes.md")
    assert labels["app/api/users/route.ts"] == "✓ route.ts  3◆"
    assert labels["app/components/Comment.tsx"] == "✓ Comment.tsx  1?"
    assert labels["scripts/deploy.py"] == "✓ deploy.py", "a medium issue below the floor isn't counted"
    assert tree.issues == 5 and tree.questions == 1 and tree.state == "partial"


def test_detail_pane_has_exact_code_the_path_the_fix_and_the_explanation(sample):
    data = sample["data"]
    sources = SourceIndex(data)
    row = next(row for row in rows(data) if row.finding.path == "app/api/users/route.ts"
               and row.finding.check_id == "command_injection")
    text = view.plain_lines(view.detail_lines(row, data, sources))
    assert "Code — the exact text that was analyzed" in text
    assert "> 21 │   return runReport(body.name);" in text
    assert "Path (4 steps, press t to walk it)" in text and "exec(…) (lib/run.ts:4)" in text
    assert "About this check · Command injection" in text and "Why it matters:" in text
    assert "polaris.js.command_injection.shell · CWE-78" in text
    edit_row = next(row for row in rows(data, floor="info") if row.finding.path == "scripts/deploy.py")
    edited = view.plain_lines(view.detail_lines(edit_row, data, sources))
    assert '+ subprocess.run(["git", "checkout", "--", branch])' in edited
    assert "○ not verified yet — press f" in edited
    question = next(row for row in rows(data) if row.group == "question")
    asked = view.plain_lines(view.detail_lines(question, data, sources))
    assert "To verify: Do all callers of Comment()" in asked
    assert "Also reported by: Semgrep OSS react.dangerously-set-inner-html (line 2)" in asked


def test_taint_walk_steps_cross_files_with_the_analyzed_code(sample):
    data = sample["data"]
    finding = find(data, "command_injection.shell")
    steps = view.walk_steps(finding, SourceIndex(data))
    assert [(step.kind, step.path, step.line) for step in steps] == [
        ("source", "app/api/users/route.ts", 20), ("step", "app/api/users/route.ts", 20),
        ("call", "app/api/users/route.ts", 21), ("sink", "lib/run.ts", 4)]
    sink = view.plain_lines(view.code_block(steps[-1].context))
    assert '> 4 │   exec("report --name " + name);' in sink
    assert view.plain(steps[0].header(4)).startswith("1/4 ◉ source  app/api/users/route.ts:20")
    listing = view.plain_lines(view.walk_lines(steps, 3))
    assert "▶ ◎ sink  lib/run.ts:4" in listing


def test_saved_reports_use_worktree_code_only_when_it_is_exactly_what_was_reviewed(sample, tmp_path):
    data = sample["data"]
    finding = find(data, "command_injection.shell")
    saved = saved_copy(data)
    sources = SourceIndex(saved)
    assert sources.context(finding.path, finding.start_line, finding=finding).origin == "worktree"
    assert sources.worktree_summary() == (7, 7)
    # Same report, but the worktree file changed since the review: the stored snippet is shown.
    copy = tmp_path.resolve() / "copy"
    subprocess.run(["cp", "-R", str(sample["root"]), str(copy)], check=True)
    (copy / "app/api/users/route.ts").write_text("// edited\n" * 30)
    changed = SourceIndex(saved_copy(data, root=copy))
    context = changed.context(finding.path, finding.start_line, finding=finding)
    assert context.origin == "snippet" and "Changed since the review" in (context.note or "")
    assert any(line.flagged and "runReport(body.name)" in line.text for line in context.lines)
    step = changed.context("app/api/users/route.ts", 20)
    assert step.origin == "none" and not step.lines
    unrecorded = changed.context("not/reviewed.ts", 1)
    assert unrecorded.origin == "none" and "recorded inputs" in (unrecorded.note or "")
    assert changed.worktree_summary() == (6, 7)
    no_root = SourceIndex(replace(saved, root=None))
    assert no_root.context(finding.path, finding.start_line, finding=finding).origin == "snippet"


def test_coverage_matrix_states_reasons_and_filters(sample):
    data = sample["data"]
    columns = view.coverage_columns(data)
    assert columns == data.envelope.review.checks and "api_authorization" not in columns
    matrix = {row.path: row for row in view.coverage_rows(data)}
    go = matrix["cmd/tool/main.go"]
    assert go.state == "not_checked" and go.gap == "unsupported_language"
    assert go.cells["sql_injection"].state == "not_checked"
    assert go.cells["workflow_injection"].state == "not_applicable"
    assert matrix["docs/notes.md"].state == "not_applicable" and matrix["docs/notes.md"].gap == "not_source_code"
    workflow = matrix[".github/workflows/triage.yml"]
    assert workflow.cells["workflow_injection"].state == "checked" and workflow.cells["xss"].state == "not_applicable"
    explained = view.plain(view.cell_explanation(go, "sql_injection"))
    assert explained == "SQ SQL injection on cmd/tool/main.go: ✗ not checked — no analyzer for this language yet"
    # The file's overall state leads its name in the first column, never in an unlabeled one.
    assert view.plain(view.coverage_file(go)) == "✗ cmd/tool/main.go"
    assert view.plain(view.coverage_file(workflow, 14)) == "✓ …/triage.yml"
    assert [row.path for row in view.coverage_rows(data, only="unreviewed")] == ["cmd/tool/main.go"]
    assert view.coverage_rows(data, only="excluded") == []
    assert {row.path for row in view.coverage_rows(data, language="python")} == {"scripts/deploy.py"}
    assert "python" in view.coverage_languages(data) and "dockerfile" in view.coverage_languages(data)
    summary = view.plain(view.coverage_summary(data, view.coverage_rows(data)))
    assert "✓ 7 checked" in summary and "✗ 1 not checked" in summary and "· 1 not applicable" in summary


def test_what_ran_names_analyzers_scope_gaps_and_imports(sample):
    data = sample["data"]
    text = view.plain_lines(view.what_ran(data, SourceIndex(data)))
    assert "\u2713 polaris-ts 0.3.1 \u00b7 javascript, typescript" in text
    assert "– semgrep-ce" in text and "disabled" in text
    assert "Checks (16):" in text and "not run (needs a trusted --guard-policy)" in text
    assert "7 files analyzed, 1 not source code, 1 not reviewed" in text
    assert "✗ cmd/tool/main.go — no analyzer for this language yet" in text
    assert "↗ SARIF semgrep.sarif: 3 of 4 results imported; left out: 1 outside review scope." in text
    assert "nothing was executed and no model was used. Tests: not run." in text


def test_trust_bar_keeps_freshness_and_completeness_at_any_width(sample):
    data = fixed(sample["data"])
    wide = view.plain(view.trust_bar(data, view.Activity(), 200))
    assert wide.startswith("\u2736 POLARIS · range main...feature · HEAD ")
    assert wide.endswith("offline · no model · 123 ms") and "● FRESH" in wide and "◐ INCOMPLETE" in wide
    # The brand mark stays at 80 columns: the review label, HEAD and elapsed time give way first.
    assert view.plain(view.trust_bar(data, view.Activity(), 78)) == (
        "\u2736 POLARIS · range main...… · ● FRESH · ◐ INCOMPLETE · offline · no model")
    for width in (78, 60, 40, 20):
        narrow = view.plain(view.trust_bar(data, view.Activity(), width))
        assert narrow.startswith("\u2736") and "● FRESH" in narrow and "◐ INCOMPLETE" in narrow
        assert len(narrow) <= max(width, len("\u2736 · ● FRESH · ◐ INCOMPLETE"))  # at worst, only the star
    stale = replace(data, envelope=data.envelope.model_copy(update={"status": "stale"}))
    assert "✖ STALE" in view.plain(view.trust_bar(stale, view.Activity(), 120))
    assert "✖ STALE" in view.plain(view.trust_bar(replace(data, settings_changed=True), view.Activity(), 120))
    saved = view.plain(view.trust_bar(saved_copy(data), view.Activity(), 120))
    assert "○ SAVED" in saved and "report sample.json" in saved
    running = view.plain(view.trust_bar(None, view.Activity(running=True, elapsed=2.25), 80))
    assert running == "\u2736 POLARIS · ◌ REVIEWING · offline · no model · 2.2s"


def test_unavailable_keys_say_why(sample):
    data = sample["data"]
    plain_finding = find(data, "ssrf")
    state = view.UiState(mode="saved", finding=plain_finding, editor=False, root=True)
    hints = {hint.key: hint for hint in view.key_hints("findings", state)}
    assert hints["f"].reason == "no deterministic fix for this rule"
    assert hints["o"].reason == "set $VISUAL or $EDITOR"
    assert hints["r"].reason.startswith("saved report")
    assert hints["t"].available and hints["y"].available
    bar = view.plain(view.key_bar(view.key_hints("findings", state), 200))
    assert "⊘ f fix: no deterministic fix for this rule" in bar and bar.endswith("q quit  ")
    narrow = view.plain(view.key_bar(view.key_hints("findings", state), 78))
    assert "⊘ f fix: no fix" in narrow and "? help" in narrow and len(narrow) <= 78
    nothing = {hint.key: hint.reason for hint in view.key_hints("findings", view.UiState(mode="live"))}
    assert nothing["t"] == "select a finding first"
    help_text = view.plain_lines(view.help_lines(state))
    assert "Unavailable right now" in help_text and "⊘ f" in help_text and "Glyphs" in help_text
    # Without an editor, help (and pressing o) says how to set one.
    assert "Opening files" in help_text
    assert 'export EDITOR="code --wait"' in help_text and "export EDITOR=nvim" in help_text
    assert "Opening files" not in view.plain_lines(view.help_lines(replace(state, editor=True)))
    assert "export EDITOR=nvim" in view.notice(hints["o"].reason)
    assert view.notice(hints["f"].reason) == "No deterministic fix for this rule."


# ---- saved reports -------------------------------------------------------------------------------


def test_saved_report_round_trip_and_bounds(sample, tmp_path):
    data = sample["data"]
    path = tmp_path.resolve() / "report.json"
    path.write_text(json.dumps(report_json(data)))
    loaded = load_report(path, root=sample["root"])
    assert loaded.envelope == data.envelope and loaded.mode == "saved" and loaded.report_name == "report.json"
    assert not loaded.live
    with pytest.raises(SessionProblem) as problem:
        parse_report(b'{"format": "polaris.workflow/0.1.0", "format": "x"}')
    assert problem.value.code == "invalid_report"
    for payload, code in ((b"[1, 2]", "unsupported_report"), (b"{\"format\": \"polaris.review/0.2.0\"}", "unsupported_report"),
                          (b"{\"format\": \"polaris.workflow/0.1.0\"}", "invalid_report"), (b"\xff", "invalid_report"),
                          (b"{\"a\": NaN}", "invalid_report"), (b"[" * 5_000 + b"]" * 5_000, "invalid_report")):
        with pytest.raises(SessionProblem) as problem:
            parse_report(payload)
        assert problem.value.code == code, payload[:40]
    with pytest.raises(SessionProblem) as problem:
        parse_report(b" " * (MAX_REPORT_BYTES + 1))
    assert problem.value.code == "report_too_large"
    link = tmp_path.resolve() / "link.json"
    link.symlink_to(path)
    with pytest.raises(SessionProblem) as problem:
        load_report(link, root=None)
    assert problem.value.code == "report_unavailable"
    with pytest.raises(SessionProblem):
        load_report(tmp_path.resolve() / "missing.json", root=None)


def test_problem_messages_are_fixed_text():
    for code in ("not_a_terminal", "ci_environment", "textual_missing", "invalid_report", "too_many_sarif_files",
                 "unknown"):
        message = SessionProblem(code).message
        assert message and "{" not in message


# ---- the editor ----------------------------------------------------------------------------------


def test_editor_commands_use_shlex_and_the_right_line_argument(sample):
    root = sample["root"]
    target = str(root / "scripts/deploy.py")
    cases = {
        "nvim": ["nvim", "+6", target], "vim -u NONE": ["vim", "-u", "NONE", "+6", target],
        "/opt/homebrew/bin/hx": ["/opt/homebrew/bin/hx", "+6", target],
        "emacsclient -t": ["emacsclient", "-t", "+6", target], "nano": ["nano", "+6", target],
        "micro": ["micro", "+6", target], "code --wait": ["code", "--wait", "--goto", f"{target}:6"],
        "cursor": ["cursor", "--goto", f"{target}:6"], "subl": ["subl", target],
        "'/Applications/My Editor.app/bin/edit' --flag 'two words'":
            ["/Applications/My Editor.app/bin/edit", "--flag", "two words", target],
    }
    for value, expected in cases.items():
        command = build_command(root, "scripts/deploy.py", 6, {"EDITOR": value})
        assert list(command.argv) == expected, value
    assert build_command(root, "scripts/deploy.py", 6, {"VISUAL": "nvim", "EDITOR": "nano"}).argv[0] == "nvim"


@pytest.mark.parametrize(("environ", "path", "code"), [
    ({}, "scripts/deploy.py", "editor_not_set"),
    ({"EDITOR": "vim 'unbalanced"}, "scripts/deploy.py", "editor_unparsable"),
    ({"EDITOR": "vim"}, "../outside.py", "invalid_path"),
    ({"EDITOR": "vim"}, "/etc/passwd", "invalid_path"),
    ({"EDITOR": "vim"}, "missing.py", "file_missing"),
    ({"EDITOR": "vim"}, "escape.py", "outside_root"),
])
def test_editor_refuses_paths_outside_the_root_and_bad_settings(sample, tmp_path, environ, path, code):
    root = sample["root"]
    escape = root / "escape.py"
    if not escape.exists():
        escape.symlink_to(tmp_path.resolve())
    with pytest.raises(EditorProblem) as problem:
        build_command(root, path, 1, environ)
    assert problem.value.code == code
    with pytest.raises(EditorProblem):
        build_command(None, "scripts/deploy.py", 1, {"EDITOR": "vim"})
    with pytest.raises(EditorProblem):
        editor_words({"EDITOR": "   "})


# ---- the command -------------------------------------------------------------------------------


def test_tui_is_registered_and_help_never_imports_textual():
    args = cli.parser().parse_args(["tui", "--report", "x.json", "--theme", "ansi-dark", "--no-mouse"])
    assert (args.command, args.theme, args.no_mouse) == ("tui", "ansi-dark", True)
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["tui", "--staged", "--report", "x.json"])
    script = ("import sys; from polaris import cli\n"
              "try:\n    cli.main(['tui', '--help'])\nexcept SystemExit:\n    pass\n"
              "cli.parser()\nassert 'textual' not in sys.modules and 'rich' not in sys.modules, sorted(sys.modules)\n")
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    assert "--plain" in done.stdout and "--report" in done.stdout


def test_interface_refuses_without_a_terminal_or_in_ci(monkeypatch, capsys):
    monkeypatch.delenv("CI", raising=False)
    assert cli.main(["tui", "--report", "x.json"]) == 2  # pytest's stdin is not a terminal
    assert "[not_a_terminal]" in capsys.readouterr().err
    monkeypatch.setenv("CI", "true")
    assert cli.main(["tui", "--report", "x.json"]) == 2
    error = capsys.readouterr().err
    assert "[ci_environment]" in error and "--format text|json|sarif" in error
    monkeypatch.delenv("CI")
    assert cli.main(["tui", "--head", "HEAD"]) == 2
    assert "[invalid_arguments]" in capsys.readouterr().err
    assert cli.main(["tui", "--base=--upload-pack=x"]) == 2
    assert "[invalid_arguments]" in capsys.readouterr().err


def test_missing_textual_prints_the_install_hint(monkeypatch, capsys):
    from polaris.tui import cli as tui_cli

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(tui_cli, "textual_available", lambda: False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert cli.main(["tui", "--report", "x.json"]) == 2
    error = capsys.readouterr().err
    assert "theovex-polaris[tui]" in error and "[textual_missing]" in error


def test_plain_prints_the_workflow_text_report_with_its_exit_code(sample, capsys, monkeypatch):
    from polaris.workflow.service import render_workflow

    monkeypatch.setenv("CI", "true")  # --plain is meant for CI and screen readers
    root = sample["root"]
    code = cli.main(["tui", "--plain", "--root", str(root), "--diff", "main...feature", "--no-external-analyzers"])
    out = capsys.readouterr().out
    assert code == 1 and out.startswith("Polaris security review · 10 issues to fix")
    path = sample["base"] / "plain-report.json"
    if not path.exists():
        path.write_text(json.dumps(report_json(sample["data"])))
    assert cli.main(["tui", "--plain", "--report", str(path)]) == 1
    assert capsys.readouterr().out.rstrip("\n") == render_workflow(sample["data"].envelope)
    assert cli.main(["tui", "--plain", "--report", str(path), "--fail-on-imported", "error"]) == 1
    assert cli.main(["tui", "--plain", "--report", str(sample["base"] / "nope.json")]) == 2
    assert "[report_unavailable]" in capsys.readouterr().err


def test_live_review_errors_have_fixed_codes(sample, capsys):
    root = sample["root"]
    assert cli.main(["tui", "--plain", "--root", str(root), "--base", "no-such-branch",
                     "--no-external-analyzers"]) == 2
    assert "[invalid_revision]" in capsys.readouterr().err
    outside = sample["base"] / "not-a-repository"
    outside.mkdir(exist_ok=True)
    assert cli.main(["tui", "--plain", "--root", str(outside), "--no-external-analyzers"]) == 2
    assert "[not_a_repository]" in capsys.readouterr().err


def test_pr_preview_selection_reviews_the_merge_base_range(sample):
    data = live_data(sample["root"], "--base", "main")
    assert data.pull_request is not None and data.envelope.snapshot.kind == "git_revision"
    assert data.label == "PR preview main...HEAD"
    assert "app/api/users/route.ts" in data.pull_request.changed
    assert data.envelope.finding_count == 10


def test_environment_is_not_mutated_by_the_view_model(sample):
    before = dict(os.environ)
    view.what_ran(sample["data"])
    assert dict(os.environ) == before

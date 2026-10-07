"""The simple view's words and the Polaris brand, without a terminal: the website's lockup, its
gradients and the star's light, the palettes (NO_COLOR keeps attributes only, every text colour
reads at 4.5:1), headers, rows, key bars and every part of a problem, built from a real check of
the deterministic sample repository."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("textual")

from rich.cells import cell_len  # noqa: E402
from tui_fixtures import sample_repository  # noqa: E402

from polaris.check import brand_site as site  # noqa: E402
from polaris.check.brand import (  # noqa: E402
    PALETTES,
    STAR_GLOWS,
    STATUS_MARKS,
    WORDMARK_GRADIENTS,
    contrast,
)
from polaris.check.model import CheckResult, NotChecked, SinceLastCheck, SuggestedFix  # noqa: E402
from polaris.check.runner import CheckRequest, CheckRun, run_check  # noqa: E402
from polaris.tui import brand  # noqa: E402
from polaris.tui.simple import view  # noqa: E402

DELETE = "Anyone can use DELETE /api/users without logging in"
ATTRIBUTES = {"bold", "reverse", "underline", "not"}
TEXT_ROLES = ("text", "label", "heading", "star", "fix_now", "check_this", "worth_a_look", "clear", "muted", "key",
              "row", "row.file", "code", "code.number", "before", "after", "warning")


def colour(style: str) -> str:
    """The foreground colour in a style string such as "bold #aabbcc on #112233"."""
    return next(word for word in style.split(" on ")[0].split() if word.startswith("#")).lower()


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> CheckRun:
    root = sample_repository(tmp_path_factory.mktemp("tui-simple-view"))
    return run_check(CheckRequest(root=root, mode="range", revision_range="main...feature", remember=False))


def item(result: CheckResult, title: str) -> Any:
    return next(entry for entry in result.items if entry.title == title)


# ---- the brand ----------------------------------------------------------------------------------


def test_lockups_are_the_site_logo_side_by_side() -> None:
    large, small = brand.LOCKUPS["large"], brand.LOCKUPS["small"]
    assert (large.width, large.height, large.offset) == (59, 10, 2)
    assert (small.width, small.height, small.offset) == (40, 7, 1)
    for mark, star, wordmark in ((large, site.STAR_LARGE, site.WORDMARK_LARGE),
                                 (small, site.STAR_SMALL, site.WORDMARK_SMALL)):
        rows = mark.plain()
        assert len(rows) == mark.height and all(cell_len(row) == mark.width for row in rows)
        # The star on the left; the wordmark beside its middle, after the gap.
        assert [row[:mark.star_width].rstrip() for row in rows] == list(star)
        words = [row[mark.star_width + mark.gap:].rstrip() for row in rows]
        assert words[mark.offset:mark.offset + len(wordmark)] == list(wordmark)
        assert not any(words[:mark.offset]) and not any(words[mark.offset + len(wordmark):])


def test_the_largest_lockup_that_fits_is_chosen() -> None:
    assert brand.lockup_size(120, 40) == brand.lockup_size(80, 24) == "large"  # 80x24 fits it with every line
    assert brand.lockup_size(62, 24) == brand.lockup_size(80, 18) == brand.lockup_size(50, 16) == "small"
    assert brand.lockup_size(43, 24) is None and brand.lockup_size(80, 15) is None


def test_wordmark_runs_through_the_site_gradient_column_by_column() -> None:
    for palette in ("dark", "light"):
        mark = brand.LOCKUPS["large"]
        stops = WORDMARK_GRADIENTS[palette]
        colours = brand.gradient(stops, mark.wordmark_width)
        assert colours[0].lower() == stops[0] and colours[-1].lower() == stops[-1]
        start = mark.star_width + mark.gap
        for line in mark.render(palette):
            for span in line.spans:
                if span.start >= start:  # the same column has the same colour on every row
                    assert str(span.style) == f"bold {colours[span.start - start]}"
    assert brand.gradient(stops, 1) == [stops[0].upper()] and brand.gradient(stops, 0) == []


def test_the_star_is_gold_with_a_warm_middle_and_a_twinkle_that_sweeps_out() -> None:
    gold, glow, flash = STAR_GLOWS["dark"]
    assert colour(brand.star_style("dark", 1.0, None)) == gold  # the tips
    assert colour(brand.star_style("dark", 0.0, None)) == glow  # where the rays meet
    # A band of light runs from the middle out to the tips, briefly reaching the flash, then rests.
    fronts = [max(range(11), key=lambda tenth, frame=frame: brand.twinkle(tenth / 10, frame))
              for frame in range(1, brand.SWEEP_FRAMES - 1)]
    assert fronts == sorted(fronts) and fronts[0] < 3 and fronts[-1] > 7
    assert max(brand.twinkle(tenth / 10, frame) for tenth in range(11) for frame in range(brand.SWEEP_FRAMES)) > 0.95
    assert colour(brand.star_style("dark", 0.5, None)) != colour(brand.star_style("dark", 0.5, 6))
    resting = [brand.twinkle(0.5, frame) for frame in range(brand.SWEEP_FRAMES, brand.TWINKLE_FRAMES)]
    assert resting and not any(resting)
    # Every drawn cell of the star is lit by the glow; spaces stay unstyled.
    large = brand.LOCKUPS["large"]
    assert set(large.distances) == {(row, column) for row, line in enumerate(site.STAR_LARGE)
                                    for column, character in enumerate(line) if character != " "}
    assert min(large.distances.values()) < 0.3 and max(large.distances.values()) == 1.0  # the middle is a gap
    assert brand.star_style("ansi", 0.5, None) == "bold yellow" and brand.star_style("none", 0.5, 6) == "bold"


def test_compact_mark_is_a_gold_star_and_gradient_letters() -> None:
    mark = brand.compact("dark")
    assert mark.plain == "\u2736 POLARIS" and brand.compact("none").plain == "\u2736 POLARIS"
    assert colour(str(mark.spans[0].style)) == PALETTES["dark"]["star"]
    letters = [colour(str(span.style)) for span in mark.spans[1:]]
    assert letters[0] == WORDMARK_GRADIENTS["dark"][0] and letters[-1] == WORDMARK_GRADIENTS["dark"][-1]
    assert str(brand.compact("ansi").spans[0].style) == "bold yellow"
    assert {str(span.style) for span in brand.compact("none").spans} == {"bold"}


def test_no_color_and_ansi_palettes_never_use_24_bit_colour() -> None:
    for style in brand.STYLES["none"].values():
        assert set(style.split()) <= ATTRIBUTES, style
    for line in brand.LOCKUPS["large"].render("none"):
        assert {str(span.style) for span in line.spans} <= {"bold"}
    for style in brand.STYLES["ansi"].values():
        assert "#" not in style, style
    assert "dim" not in " ".join(style for styles in brand.STYLES.values() for style in styles.values())


@pytest.mark.parametrize("palette", ["dark", "light"])
def test_site_colours_stay_readable(palette: str) -> None:
    colours = PALETTES[palette]
    styles = brand.STYLES[palette]
    for role in TEXT_ROLES:
        assert contrast(colour(styles[role]), colours["background"]) >= 4.5, role
    for role in ("row.selected", "row.marker.selected", "row.file.selected"):
        assert styles[role].endswith(f" on {colours['selected']}")
        assert contrast(colour(styles[role]), colours["selected"]) >= 4.5, role
    theme = brand.CUSTOM_THEMES[0 if palette == "dark" else 1]
    assert theme.background == colours["background"] and theme.variables["text-muted"] == colours["muted"]


def test_the_expert_view_draws_the_same_brand_mark() -> None:
    from polaris.tui import view as expert
    from polaris.tui.widgets.render import to_text

    dark = to_text(expert.BRAND_MARK, "dark")
    assert dark.plain == "\u2736 POLARIS" and colour(str(dark.spans[0].style)) == PALETTES["dark"]["star"]
    assert [colour(str(span.style)) for span in dark.spans[1:]] == [
        value.lower() for value in brand.gradient(WORDMARK_GRADIENTS["dark"], 7)]
    assert [str(span.style) for span in to_text(expert.BRAND_MARK, "ansi").spans] == ["bold yellow", "bold"]
    assert {str(span.style) for span in to_text(expert.BRAND_MARK, "none").spans} == {"bold"}


def test_text_is_built_from_spans_never_markup() -> None:
    text = brand.to_text((("[red]x[/red] :smile: [link=https://e.example]y[/link]", "text"),), "dark")
    assert text.plain == "[red]x[/red] :smile: [link=https://e.example]y[/link]"


# ---- wording ------------------------------------------------------------------------------------


def test_header_fits_and_drops_the_time_first() -> None:
    wide = view.header("sample", "the changes in main...feature", "checked just now", 78)
    assert view.plain(wide) == "\u2736 POLARIS   sample \u00b7 the changes in main...feature \u00b7 checked just now"
    narrow = view.plain(view.header("sample", "the changes in main...feature", "checked just now", 50))
    assert narrow == "\u2736 POLARIS   sample \u00b7 the changes in main...feature"
    tiny = view.plain(view.header("sample", "the changes in main...feature", "checked just now", 30))
    assert cell_len(tiny) <= 30 and tiny.endswith(view.ELLIPSIS)


def test_when_the_check_ran_in_words() -> None:
    assert [view.ago(seconds) for seconds in (0, 59, 60, 150, 3_600, 7_300, 200_000)] == [
        "checked just now", "checked just now", "checked 1 minute ago", "checked 2 minutes ago",
        "checked 1 hour ago", "checked 2 hours ago", "checked 2 days ago"]


def test_rows_fill_the_width_and_keep_the_file_name(run: CheckRun) -> None:
    result = run.result
    file_width = view.file_column(result.items)
    for width in (30, 60, 76, 116):
        for entry in result.items:
            for chosen in (False, True):
                assert cell_len(view.plain(view.row(entry, chosen=chosen, width=width, file_width=file_width))) == width
    ssrf = next(entry for entry in result.items if entry.technical.check == "ssrf")
    narrow = view.plain(view.row(ssrf, chosen=True, width=76, file_width=file_width))
    assert narrow.startswith("\u25b6 Users of GET /api/users could make your server visit other") and "\u2026" in narrow
    assert narrow.rstrip().endswith("route.ts")
    question = next(entry for entry in result.items if entry.priority == "check_this")
    assert view.row_label(question) == "Could a user put their own HTML or script on this page?"


def test_key_bars_fit_and_always_keep_help_and_quit(run: CheckRun) -> None:
    keys = view.results_keys(run.result, expanded=False, expert=True)
    assert view.plain(view.key_bar(keys, 76)) == (
        "\u2191\u2193 choose  Enter details  a copy all fixes  r check again  ? help  q quit")
    assert view.plain(view.key_bar(keys, 116)) == (
        "\u2191\u2193 choose  Enter details  a copy all fixes  r check again  c copy fix  w show more  "
        "x expert view  ? help  q quit")
    assert view.plain(view.key_bar(keys, 20)) == "? help   q quit"  # only the essential keys are left
    problem = view.problem_keys(run.result, technical=False, expert=True)
    # 80 columns: the plan's footer, plus help; q still works everywhere.
    assert view.plain(view.key_bar(problem, 76)) == (
        "c copy fix for your AI  o open file  t technical details  Esc back  ? help")
    assert view.plain(view.key_bar(problem, 116)) == (
        "c copy fix for your AI  o open file  t technical details  a copy all fixes  r check again  Esc back  "
        "? help  q quit")
    for width in (40, 60, 76, 116, 200):
        assert cell_len(view.plain(view.key_bar(keys, width))) <= width
        assert cell_len(view.plain(view.key_bar(problem, width))) <= width


def test_the_answer_comes_first(run: CheckRun) -> None:
    result = run.result
    assert view.plain_lines(view.status_lines(result)) == "Safe to ship?  \u2716 Not yet \u2014 5 things to fix."
    incomplete = result.model_copy(update={
        "status": "incomplete", "counts": result.counts.model_copy(update={"fix_now": 0}),
        "summary": "No problems to fix now in what Polaris could check, but 1 file couldn't be checked."})
    assert view.plain_lines(view.status_lines(incomplete)) == (
        "Safe to ship?  \u25d0 Not fully checked. No problems to fix now in what Polaris could check, but 1 file "
        "couldn't be checked.")
    counts = result.counts.model_copy(update={"fix_now": 0, "check_this": 0, "worth_a_look": 0})
    clear = result.model_copy(update={"status": "clear", "counts": counts, "items": [], "scope_label": "your changes"})
    assert view.plain_lines(view.status_lines(clear)) == (
        f"{STATUS_MARKS['clear']} Safe to ship \u2014 no problems found in your changes.\n\n"
        "Polaris checked 7 files for 16 kinds of problems. That means these checks found nothing, not that the "
        "code is perfect.")
    questions = clear.model_copy(update={"counts": counts.model_copy(update={"check_this": 1})})
    assert "nothing to fix now in your changes" in view.plain_lines(view.status_lines(questions))
    assert "found nothing to fix now, not that" in view.plain(view.honest_line(questions))
    empty = clear.model_copy(update={"counts": counts.model_copy(update={"files_checked": 0})})
    assert "there was no code to check in your changes" in view.plain_lines(view.status_lines(empty))


def test_what_was_checked_in_plain_words(run: CheckRun) -> None:
    result = run.result
    assert view.plain_lines(view.checked_lines(result)) == (
        "Checked 7 files. 1 couldn't be checked (Polaris can't check Go files yet).")
    complete = result.model_copy(update={"not_checked": [], "counts": result.counts.model_copy(
        update={"files_not_checked": 0})})
    assert view.plain_lines(view.checked_lines(complete)) == "Checked 7 files for 16 kinds of problems."
    mixed = result.model_copy(update={
        "not_checked": [NotChecked(file="cmd/tool/main.go", reason="Polaris can't check Go files yet"),
                        NotChecked(file="big.ts", reason="it's too big to check")],
        "counts": result.counts.model_copy(update={"files_not_checked": 5}),
        "notes": ["You have no changes since your last commit, so Polaris checked your whole project."],
        "since_last_check": SinceLastCheck(fixed=["a" * 12], new=[], still_open=["b" * 12, "c" * 12]),
    })
    assert view.plain_lines(view.checked_lines(mixed)) == "\n".join([
        "Checked 7 files. 5 couldn't be checked:",
        "  cmd/tool/main.go \u2014 Polaris can't check Go files yet",
        "  big.ts \u2014 it's too big to check",
        "  \u2026 and 3 more.",
        "You have no changes since your last commit, so Polaris checked your whole project.",
    ])
    assert view.plain(view.since_line(mixed)) == "Since your last check: 1 fixed, 0 new, 2 still open."
    assert view.since_line(result) == ()


def test_sections_and_more(run: CheckRun) -> None:
    assert view.plain(view.section_title("fix_now", 4)) == "\u25cf Fix now"
    assert view.plain(view.section_title("check_this", 1)) == "? Check this (1)"
    assert view.plain(view.section_title("worth_a_look", 5, expanded=False)) == (
        "\u25cb Worth a look (5) \u2014 press w to show")
    more = run.result.model_copy(update={"more": {"fix_now": 3}})
    assert view.plain(view.more_line(more, "fix_now")) == "\u2026 and 3 more. Fix these first, then check again."
    assert view.more_line(run.result, "fix_now") == ()


def test_a_problem_has_the_same_parts_every_time(run: CheckRun) -> None:
    result = run.result
    delete = item(result, DELETE)
    assert view.key_lines(delete) == [13, 15]  # the handler and the line that deletes, as in the plan
    sections = view.problem_sections(delete)
    assert [section.label for section in sections] == ["What's wrong", "Why it matters", "Where", "How to fix"]
    assert view.plain_lines(sections[2].lines) == "app/api/users/route.ts, line 13"
    question = next(entry for entry in result.items if entry.priority == "check_this")
    labels = [section.label for section in view.problem_sections(question)]
    assert labels == ["What's wrong", "Question", "Why it matters", "Where", "How to fix"]
    tested = next(entry for entry in result.items if entry.fix.edit is not None and entry.fix.edit.status == "verified")
    fixed = view.problem_sections(tested)[-1]
    assert fixed.label == "Tested fix" and "the problem was gone and nothing new appeared" in view.plain(fixed.lines[0])
    assert view.plain(fixed.lines[1]).startswith("  before  7 \u2502") and '"--", branch' in view.plain(fixed.lines[2])
    assert fixed.lines[0] and fixed.lines[1][2][1] == "code"
    withheld = tested.model_copy(update={"fix": tested.fix.model_copy(update={
        "edit": tested.fix.edit.model_copy(update={"status": "withheld"})})})
    assert "Tested fix" not in [section.label for section in view.problem_sections(withheld)]


def test_technical_details_hold_the_jargon(run: CheckRun) -> None:
    delete = item(run.result, DELETE)
    technical = {section.label: view.plain_lines(section.lines) for section in view.technical_sections(delete)}
    assert technical["CWE"] == "CWE-862" and technical["Rule"] == "polaris.js.missing_authorization.handler"
    assert technical["Severity"] == "high \u00b7 confidence medium"
    assert technical["Evidence trail"] == ("source app/api/users/route.ts:13  DELETE route handler\n"
                                           "sink   app/api/users/route.ts:15  db.user.delete")


def test_code_and_edits_are_shown_as_inert_text() -> None:
    edit = SuggestedFix(line=3, before="\x1b[31mred\u202e [b]x[/b]", after="\tok()", status="verified")
    lines = view.tested_fix_lines(edit)
    before, after = view.plain(lines[1]), view.plain(lines[2])
    assert "\x1b" not in before and "\u202e" not in before and "\ufffd[31mred\ufffd [b]x[/b]" in before
    assert after.endswith("    ok()")  # tabs expanded, as in the code view
    assert view.file_name("app/\u009b31mred\u202e.ts") == "\ufffd31mred\ufffd.ts"


def test_help_names_every_key_and_mark() -> None:
    text = view.plain_lines(view.help_lines())
    for words in ("check again", "copy all the fixes for your AI", "open the expert view", "Your code stays private",
                  "\u25cf Fix now", "\u25d0 Not fully checked"):
        assert words in text

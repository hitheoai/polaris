"""The simple view (`polaris check` in a terminal), driven with Textual's Pilot: the branded
checking screen, the results, a problem's page and the all clear; the keys and their only side
effects (copying a prompt, opening the editor); checking again; the hand-over to the expert view;
problems that stop a check; NO_COLOR and the star's animation; plain words; inert text.

Real checks of deterministic repositories back the screens; a stand-in for `run_check` decides
when a check finishes. Skipped when the optional `tui` extra (Textual) is not installed."""

from __future__ import annotations

import asyncio
import contextlib
import re
import subprocess
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("textual")

from tui_fixtures import FILES_FEATURE, sample_repository, screen_text, write  # noqa: E402
from tui_simple_fixtures import (  # noqa: E402
    PROGRESS,
    FakeRunner,
    clean_repository,
    scenario,
    settle,
    until,
)

from polaris.check import brand_site as site  # noqa: E402
from polaris.check.build import combined_prompt  # noqa: E402
from polaris.check.runner import CheckProblem, CheckRequest, CheckRun, run_check  # noqa: E402
from polaris.tui.simple import view  # noqa: E402
from polaris.tui.simple.app import EDITOR_MESSAGES, SimpleApp, Stopped  # noqa: E402
from polaris.tui.simple.screens import (  # noqa: E402
    CheckingScreen,
    CopyScreen,
    ErrorScreen,
    HelpScreen,
    ProblemScreen,
    ResultsScreen,
)
from polaris.tui.simple.widgets import Bar, ItemRow  # noqa: E402

DELETE = "Anyone can use DELETE /api/users without logging in"
WORKFLOW = "A pull request or issue could take over your GitHub workflow"
# Words a beginner shouldn't meet outside "Technical details" (whole words; "last" is fine).
JARGON = re.compile(r"\b(taint\w*|sinks?|cwe|coverage|provenance|fingerprints?|snapshots?|sarif|payloads?|"
                    r"deserializ\w*|ast|severity|confidence)\b", re.IGNORECASE)


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    base = tmp_path_factory.mktemp("tui-simple")
    root = sample_repository(base)
    clean = clean_repository(base)
    request = CheckRequest(root=root, mode="range", revision_range="main...feature", remember=False)
    return {"root": root, "request": request, "run": run_check(request),
            "clean": run_check(CheckRequest(root=clean, remember=False))}


@pytest.fixture(autouse=True)
def plain_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("VISUAL", "EDITOR", "NO_COLOR", "TEXTUAL", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)


def make(sample: dict[str, Any], outcome: Any = None, *, hold: bool = False, **options: Any) -> tuple[SimpleApp,
                                                                                                    FakeRunner]:
    runner = FakeRunner(sample["run"] if outcome is None else outcome, hold=hold)
    app = SimpleApp(sample["request"], runner=runner, clock=lambda: 0.0, **{"animation": False, **options})
    return app, runner


def results(app: SimpleApp) -> ResultsScreen:
    screen = app.screen
    assert isinstance(screen, ResultsScreen), type(screen).__name__
    return screen


def chosen(app: SimpleApp) -> str | None:
    current = results(app).current
    return current.item.title if current is not None else None


def shown(app: SimpleApp) -> list[str]:
    return [row.item.title for row in results(app).rows if row.display]


def words(text: str) -> str:
    """Screen text with its line breaks and padding folded away (prose wraps)."""
    return " ".join(text.split())


async def checking(pilot: Any, app: SimpleApp) -> None:
    await until(pilot, lambda: isinstance(app.screen, CheckingScreen) and app.progress == PROGRESS)
    await pilot.pause()


# ---- the flow -----------------------------------------------------------------------------------


@scenario
async def test_checking_then_results_then_a_problem_and_back(sample):
    app, runner = make(sample, hold=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await checking(pilot, app)
        text = screen_text(app)
        # The website's lockup: the star, and beside its middle the drawn wordmark.
        for expected in (site.STAR_LARGE[0].strip(), site.WORDMARK_LARGE[0], site.WORDMARK_LARGE[-1],
                         "a security check for your code", "\u2736 Looking at your changes\u2026",
                         "Polaris looks for 16 kinds of problems.", "Nothing leaves your computer.", "q quit"):
            assert expected in text, expected
        assert app.checking and app.exit_code == 2
        runner.release()
        await settle(pilot, app)
        text = screen_text(app)
        assert "\u2736 POLARIS   sample \u00b7 the changes in main...feature \u00b7 checked just now" in text
        assert "Safe to ship?  \u2716 Not yet \u2014 5 things to fix." in text
        assert "\u25cf Fix now" in text and "? Check this (1)" in text
        assert "\u25cb Worth a look (5) \u2014 press w to show" in text
        assert "Checked 7 files. 1 couldn't be checked (Polaris can't check Go files yet)." in text
        assert f"\u25b6 {WORKFLOW}" in text and "triage.yml" in text
        assert app.exit_code == 1 and chosen(app) == WORKFLOW
        await pilot.press("down", "down", "down", "down")
        assert chosen(app) == DELETE
        await pilot.press("enter")
        assert isinstance(app.screen, ProblemScreen) and app.screen.item.title == DELETE
        text = screen_text(app)
        assert f"\u2736 POLARIS  \u203a  {DELETE}   \u25cf Fix now" in text
        for expected in ("What's wrong", "Why it matters", "How to fix", "app/api/users/route.ts, line 13",
                         "13 \u2502 export async function DELETE(request: Request) {",
                         "15 \u2502   await db.user.delete({ where: { id: id! } });",
                         "c copy fix for your AI", "Esc back"):
            assert expected in text, expected
        assert "Technical details" not in text
        await pilot.press("escape")
        assert chosen(app) == DELETE
        await pilot.press("up", "up", "up", "up", "up")
        assert chosen(app) == WORKFLOW  # the list stops at the top


@scenario
async def test_clicking_a_problem_opens_it(sample):
    app, _ = make(sample)
    async with app.run_test(size=(120, 40)) as pilot:
        await settle(pilot, app)
        row = next(row for row in results(app).rows if row.item.title == DELETE)
        assert isinstance(row, ItemRow) and not row.chosen
        await pilot.click(row, offset=(5, 0))
        await pilot.pause()
        assert isinstance(app.screen, ProblemScreen) and app.screen.item.title == DELETE


@scenario
async def test_worth_a_look_is_folded_until_w(sample):
    app, _ = make(sample)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        assert len(shown(app)) == 6 and "Something runs with more power than it needs" not in screen_text(app)
        await pilot.press("w")
        text = screen_text(app)
        assert "\u25cb Worth a look (5) \u2014 press w to hide" in text
        assert "Something runs with more power than it needs" in text and len(shown(app)) == 11
        await pilot.press("end")
        assert chosen(app) == "You download and run a script without checking it"
        await pilot.press("w")
        assert len(shown(app)) == 6 and chosen(app) == "Attackers could run scripts in your users' browsers"
        assert "press w to show" in screen_text(app)


@scenario
async def test_copying_one_fix_or_all_of_them_shows_the_text(sample):
    app, _ = make(sample)
    result = sample["run"].result
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        await pilot.press("c")
        assert isinstance(app.screen, CopyScreen) and app.clipboard == result.items[0].prompt
        text = screen_text(app)
        assert "\u2714 Copied the fix for your AI" in text and "Fix a security problem that Polaris found" in text
        assert "hold Shift" in words(text) and "Esc close" in text
        await pilot.press("escape")
        await pilot.press("a")
        assert isinstance(app.screen, CopyScreen) and app.clipboard == combined_prompt(result)
        assert "Copied all the fixes for your AI" in screen_text(app)
        await pilot.press("escape", "down", "down", "down", "down", "enter", "c")
        assert isinstance(app.screen, CopyScreen)
        assert app.clipboard == next(item for item in result.items if item.title == DELETE).prompt


@scenario
async def test_technical_details_only_after_t(sample):
    app, _ = make(sample)
    async with app.run_test(size=(120, 40)) as pilot:
        await settle(pilot, app)
        await pilot.press("down", "down", "down", "down", "enter")
        assert "CWE-862" not in screen_text(app) and "t technical details" in view.plain(
            app.screen.query_one("#keys", Bar).value)
        await pilot.press("t")
        text = screen_text(app)
        assert "Technical details" in text and "CWE-862" in text and "polaris.js.missing_authorization.handler" in text
        assert "source app/api/users/route.ts:13  DELETE route handler" in text
        assert "sink   app/api/users/route.ts:15  db.user.delete" in text
        await pilot.press("t")
        assert "CWE-862" not in screen_text(app)


@scenario
async def test_check_again_runs_a_new_check_and_keeps_the_choice(sample):
    app, runner = make(sample)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        await pilot.press("down", "down", "down", "down")
        runner.hold = True
        await pilot.press("r")
        await checking(pilot, app)
        assert app.checking and app.exit_code == 2
        await pilot.press("r")  # one check at a time
        assert runner.calls == 2
        runner.release()
        await settle(pilot, app)
        assert runner.calls == 2 and chosen(app) == DELETE and app.exit_code == 1
        runner.hold = False
        await pilot.press("enter", "r")  # from a problem's page too
        await settle(pilot, app)
        assert runner.calls == 3 and isinstance(app.screen, ResultsScreen) and chosen(app) == DELETE


@scenario
async def test_x_hands_the_same_review_to_the_expert_view(sample):
    app, runner = make(sample, hold=True)
    notes: list[str] = []
    async with app.run_test(size=(80, 24)) as pilot:
        await checking(pilot, app)
        app.notify = lambda message, **_: notes.append(str(message))  # type: ignore[method-assign]
        await pilot.press("x")
        assert notes == ["The expert view opens once a check has finished."] and app.expert is None
        runner.release()
        await settle(pilot, app)
        await pilot.press("down", "enter", "x")
        await pilot.pause()
    run = sample["run"]
    data = app.expert
    assert data is not None and data.live and data.mode == "live" and data.label == "the changes in main...feature"
    assert data.envelope is run.envelope and data.workspace is run.workspace and data.root == run.root
    assert app.exit_code == 1


def test_run_opens_the_expert_view_after_x_and_returns_the_last_exit_code(sample, monkeypatch):
    from polaris.tui import app as expert
    from polaris.tui import simple
    from polaris.tui.session import ReviewData
    from polaris.tui.simple import app as simple_app

    run = sample["run"]
    data = ReviewData(envelope=run.envelope, mode="live", label="your changes", root=run.root,
                      workspace=run.workspace)
    opened: list[tuple[Any, str]] = []
    seen: dict[str, Any] = {}

    def check_then_x(self: SimpleApp, *args: Any, **kwargs: Any) -> None:
        seen.update(request=self.request, animation=self.animation, theme=self.theme_choice)
        self.exit_code, self.expert = 1, data

    monkeypatch.setattr(simple_app.SimpleApp, "run", check_then_x)
    monkeypatch.setattr(expert.PolarisApp, "run", lambda self, *a, **k: opened.append((self.data, self.options.theme)))
    request = CheckRequest(root=sample["root"])
    assert simple.run(request, animation=False, theme="light") == 1
    assert opened == [(data, "light")] and seen == {"request": request, "animation": False, "theme": "light"}

    def quit_while_checking(self: SimpleApp, *args: Any, **kwargs: Any) -> None:
        self.exit_code = 2

    monkeypatch.setattr(simple_app.SimpleApp, "run", quit_while_checking)
    assert simple.run(request) == 2 and len(opened) == 1

    def crashed(self: SimpleApp, *args: Any, **kwargs: Any) -> None:
        self.exit_code, self._return_code = 0, 1

    monkeypatch.setattr(simple_app.SimpleApp, "run", crashed)
    assert simple.run(request) == 2


def test_polaris_check_in_a_terminal_opens_the_simple_view(monkeypatch):
    from polaris import cli
    from polaris.check import cli as check_cli
    from polaris.tui import simple

    calls: list[tuple[Any, bool, str]] = []

    def fake(request: CheckRequest, *, animation: bool = True, theme: str = "dark") -> int:
        calls.append((request, animation, theme))
        return 1

    monkeypatch.setattr(check_cli, "_terminal", lambda: True)
    monkeypatch.setattr(simple, "run", fake)
    assert cli.main(["check", "--all", "--no-animation", "--theme", "ansi-light"]) == 1
    assert calls[0][0].mode == "all" and calls[0][1:] == (False, "ansi-light")


# ---- problems that stop a check -----------------------------------------------------------------


@scenario
async def test_problems_that_stop_the_check_are_plain_and_can_be_retried(sample):
    app, runner = make(sample, CheckProblem("invalid_revision"))
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        assert isinstance(app.screen, ErrorScreen) and app.exit_code == 2
        text = screen_text(app)
        assert "\u2716 Polaris couldn't check your code" in text
        assert CheckProblem("invalid_revision").message in words(text)
        assert "r try again" in text and "q quit" in text
        runner.outcome = sample["run"]
        await pilot.press("r")
        await settle(pilot, app)
        assert isinstance(app.screen, ResultsScreen) and runner.calls == 2 and app.exit_code == 1


@scenario
async def test_a_failed_check_again_forgets_the_previous_review(sample):
    app, runner = make(sample)
    notes: list[str] = []
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        runner.outcome = CheckProblem("check_failed")
        await pilot.press("r")
        await settle(pilot, app)
        assert isinstance(app.screen, ErrorScreen) and app.exit_code == 2 and app.data is None
        app.notify = lambda message, **_: notes.append(str(message))  # type: ignore[method-assign]
        await pilot.press("x")
        assert notes == ["The expert view opens once a check has finished."] and app.expert is None


@scenario
async def test_a_real_failed_check_shows_its_plain_message(sample):
    request = CheckRequest(root=sample["root"], mode="range", revision_range="nope...missing", remember=False)
    app = SimpleApp(request, animation=False, clock=lambda: 0.0)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        assert isinstance(app.screen, ErrorScreen) and app.exit_code == 2
        assert CheckProblem("invalid_revision").message in words(screen_text(app))


@scenario
async def test_unexpected_failures_never_show_their_text(sample):
    app, _ = make(sample, RuntimeError("token=hunter2 at /Users/someone/secret.py line 3"))
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        text = screen_text(app)
        assert isinstance(app.screen, ErrorScreen) and "hunter2" not in text and "secret.py" not in text
        assert CheckProblem("check_failed").message in words(text)


@scenario
async def test_quitting_while_checking_stops_it_at_its_next_step(sample):
    stopped = threading.Event()
    release = threading.Event()

    def runner(request: CheckRequest, *, progress: Any = None) -> CheckRun:
        progress(PROGRESS)
        release.wait(30)
        try:
            progress("Testing the suggested fixes\u2026")
        except Stopped:
            stopped.set()
            raise
        return sample["run"]

    app = SimpleApp(sample["request"], animation=False, runner=runner, clock=lambda: 0.0)
    async with app.run_test(size=(80, 24)) as pilot:
        await checking(pilot, app)
        await pilot.press("q")
        release.set()
    assert stopped.wait(10) and app.exit_code == 2 and app.expert is None


# ---- colour, motion and size --------------------------------------------------------------------


@scenario
async def test_no_color_means_no_animation_and_every_state_keeps_its_mark(sample, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    app, runner = make(sample, hold=True, animation=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await checking(pilot, app)
        await asyncio.sleep(0.4)
        await pilot.pause()
        assert app.no_color and app.palette == "none" and not app.animated and app.frame == 0
        runner.release()
        await settle(pilot, app)
        text = screen_text(app)
        for expected in ("\u2716 Not yet", "\u25cf Fix now", "? Check this (1)", "\u25cb Worth a look (5)",
                         f"\u25b6 {WORKFLOW}"):
            assert expected in text, expected


@scenario
async def test_the_star_twinkles_only_while_a_check_runs(sample):
    app, runner = make(sample, hold=True, animation=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await checking(pilot, app)
        assert app.animated
        await until(pilot, lambda: app.frame >= 3)
        runner.release()
        await settle(pilot, app)
        frame = app.frame
        await asyncio.sleep(0.4)
        await pilot.pause()
        assert app.frame == frame  # stopped with the check: no added delay, no idle motion
    still, runner = make(sample, hold=True, animation=False)
    async with still.run_test(size=(80, 24)) as pilot:
        await checking(pilot, still)
        await asyncio.sleep(0.4)
        await pilot.pause()
        assert still.frame == 0 and not still.animated
        runner.release()
        await settle(pilot, still)


@pytest.mark.parametrize(("choice", "textual_theme", "palette"), [
    ("dark", "polaris-dark", "dark"), ("light", "polaris-light", "light"), ("ansi-dark", "ansi-dark", "ansi"),
    ("ansi-light", "ansi-light", "ansi"), ("unknown", "polaris-dark", "dark")])
@scenario
async def test_themes_choose_matching_palettes(sample, choice, textual_theme, palette):
    app, _ = make(sample, theme=choice)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        assert app.theme == textual_theme and app.palette == palette
        assert "\u25cf Fix now" in screen_text(app)


@scenario
async def test_every_screen_fits_80x24(sample):
    app, runner = make(sample, hold=True)
    screens: list[str] = []
    async with app.run_test(size=(80, 24)) as pilot:
        await checking(pilot, app)
        screens.append(screen_text(app))
        runner.release()
        await settle(pilot, app)
        for keys in ((), ("w",), ("down", "enter"), ("t",), ("c",), ("escape", "escape", "question_mark")):
            await pilot.press(*keys)
            await pilot.pause()
            screens.append(screen_text(app))
    for text in screens:
        lines = text.splitlines()
        assert len(lines) == 24 and all(len(line) <= 80 for line in lines)


@scenario
async def test_smaller_terminals_get_smaller_marks_and_still_work(sample):
    for size, shown_mark, hidden_mark in (((50, 16), site.WORDMARK_SMALL[0], site.WORDMARK_LARGE[0]),
                                          ((40, 12), "\u2736 POLARIS", site.WORDMARK_SMALL[0])):
        app, runner = make(sample, hold=True)
        async with app.run_test(size=size) as pilot:
            await checking(pilot, app)
            text = screen_text(app)
            assert shown_mark in text and hidden_mark not in text and "Nothing leaves your computer." in text
            runner.release()
            await settle(pilot, app)
    tiny, _ = make(sample)
    async with tiny.run_test(size=(40, 12)) as pilot:
        await settle(pilot, tiny)
        await pilot.press("down", "w", "end", "enter", "t", "escape", "question_mark", "escape", "c", "escape")
        assert isinstance(tiny.screen, ResultsScreen)


# ---- words and safety --------------------------------------------------------------------------


@scenario
async def test_simple_screens_use_plain_words(sample):
    texts: list[str] = []
    app, runner = make(sample, hold=True)
    async with app.run_test(size=(120, 40)) as pilot:
        await checking(pilot, app)
        texts.append(screen_text(app))
        runner.release()
        await settle(pilot, app)
        await pilot.press("w")
        texts.append(screen_text(app))
        for _ in results(app).rows:  # every problem's page, without the technical details
            await pilot.press("enter")
            assert isinstance(app.screen, ProblemScreen)
            texts.append(screen_text(app))
            await pilot.press("escape", "down")
        await pilot.press("question_mark")
        texts.append(screen_text(app))
    for outcome in (sample["clean"], CheckProblem("not_a_git_project")):
        other, _ = make(sample, outcome)
        async with other.run_test(size=(120, 40)) as pilot:
            await settle(pilot, other)
            texts.append(screen_text(other))
    assert len(texts) == 16  # checking, results, 11 problems, help, all clear, a problem that stopped the check
    for text in texts:
        assert not JARGON.findall(text), JARGON.findall(text)


@scenario
async def test_a_folder_without_git_is_checked_and_explained(tmp_path):
    folder = tmp_path.resolve() / "notes-app"
    write(folder, {name: FILES_FEATURE[name] for name in ("app/api/users/route.ts", "lib/db.ts", "lib/run.ts")})
    write(folder, {"node_modules/left-pad/index.js": "module.exports = (s) => s;\n"})
    app = SimpleApp(CheckRequest(root=folder, remember=False), animation=False, clock=lambda: 0.0)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        text = screen_text(app)
        assert "\u2736 POLARIS   notes-app \u00b7 this folder \u00b7 checked just now" in text
        assert "\u25b6 Users of POST /api/users could run commands on your server" in text
        assert ("This folder doesn't use Git, so Polaris checked all of its files (it skipped dependency and build "
                "folders: node_modules).") in words(text)
        assert app.outcome is not None and app.outcome.result.since_last_check is None
        await pilot.press("down", "down", "down", "enter")
        assert "15 \u2502   await db.user.delete({ where: { id: id! } });" in screen_text(app)


@scenario
async def test_checking_again_says_what_changed_since_the_last_check(tmp_path):
    root = sample_repository(tmp_path)
    request = CheckRequest(root=root, mode="range", revision_range="main...feature", verify_fixes=False)
    app = SimpleApp(request, animation=False, clock=lambda: 0.0)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        assert "Since your last check" not in screen_text(app)
        await pilot.press("r")
        await settle(pilot, app)
        assert "Since your last check: 0 fixed, 0 new, 11 still open." in screen_text(app)


@scenario
async def test_all_clear_says_what_it_means(sample):
    app, _ = make(sample, sample["clean"])
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        text = screen_text(app)
        assert "\u2736 POLARIS   clean-app \u00b7 your changes \u00b7 checked just now" in text
        assert site.WORDMARK_SMALL[0] in text  # the lockup celebrates the all clear, when there's room
        assert "\u2714 Safe to ship \u2014 no problems found in your changes." in text
        assert ("Polaris checked 2 files for 16 kinds of problems. That means these checks found nothing, not that "
                "the code is perfect.") in words(text)
        assert app.exit_code == 0 and not results(app).rows
        notes: list[str] = []
        app.notify = lambda message, **_: notes.append(str(message))  # type: ignore[method-assign]
        await pilot.press("c", "a", "enter", "w")
        assert notes == ["Polaris found nothing to fix, so there's nothing to choose.",
                         "Nothing needs fixing now, so there's nothing to copy.",
                         "Polaris found nothing to fix, so there's nothing to choose.",
                         "Nothing is marked \"worth a look\"."]


@scenario
async def test_repository_text_is_shown_inert(sample):
    run = sample["run"]
    first = run.result.items[0]
    hostile_path = "app/\u202eevil[red]x\u009b31m.ts"
    hostile = first.model_copy(update={
        "where": first.where.model_copy(update={"file": hostile_path}),
        "evidence": [step.model_copy(update={"label": "[blink]label[/blink]\x1b[5m"}) for step in first.evidence],
    })
    result = run.result.model_copy(update={"items": [hostile, *run.result.items[1:]],
                                           "notes": ["[bold]note[/bold] \x1b]0;pwned\x07"]})
    app, _ = make(sample, replace(run, result=result))
    async with app.run_test(size=(120, 40)) as pilot:
        await settle(pilot, app)
        text = screen_text(app)
        assert "\ufffdevil[red]x\ufffd31m.ts" in text  # the file name, in its column
        assert "[bold]note[/bold] \ufffd]0;pwned\ufffd" in text
        await pilot.press("enter", "t")
        text = screen_text(app)
        assert "app/\ufffdevil[red]x\ufffd31m.ts, line 9" in text and "[blink]label[/blink]\ufffd[5m" in text
        for unsafe in ("\x1b", "\u202e", "\u009b", "\x07"):
            assert unsafe not in text


@scenario
async def test_o_opens_the_editor_only_after_the_key_and_inside_the_project(sample, monkeypatch):
    calls: list[tuple[list[str], Path]] = []
    monkeypatch.setenv("VISUAL", "nvim -u NONE")

    def no_process(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("no process may start before a key press")

    app, _ = make(sample)
    app.editor_runner = lambda argv, cwd, check: calls.append((argv, cwd))
    monkeypatch.setattr(app, "suspend", contextlib.nullcontext)
    with monkeypatch.context() as patched:
        patched.setattr(subprocess, "Popen", no_process)
        async with app.run_test(size=(80, 24)) as pilot:
            await settle(pilot, app)
            await pilot.press("down", "up", "w", "w", "question_mark", "escape", "c", "escape")
            assert calls == []
            await pilot.press("o")
            await pilot.press("down", "down", "down", "down", "enter", "o")
    root = sample["root"]
    assert calls == [
        (["nvim", "-u", "NONE", "+9", str(root / ".github/workflows/triage.yml")], root),
        (["nvim", "-u", "NONE", "+13", str(root / "app/api/users/route.ts")], root),
    ]


@scenario
async def test_o_without_an_editor_says_how_to_set_one(sample):
    app, _ = make(sample)
    notes: list[str] = []
    calls: list[Any] = []
    app.editor_runner = lambda *args, **kwargs: calls.append(args)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot, app)
        app.notify = lambda message, **_: notes.append(str(message))  # type: ignore[method-assign]
        await pilot.press("o")
    assert notes == [EDITOR_MESSAGES["editor_not_set"]] and calls == []
    assert "polaris check" in notes[0] and "polaris tui" not in notes[0]


@scenario
async def test_help_explains_every_key_and_mark(sample):
    app, _ = make(sample)
    async with app.run_test(size=(120, 40)) as pilot:
        await settle(pilot, app)
        await pilot.press("question_mark")
        assert isinstance(app.screen, HelpScreen)
        text = screen_text(app)
        for expected in ("check again", "open the expert view", "\u25cf Fix now", "? Check this",
                         "Your code stays private", "Esc close"):
            assert expected in text, expected
        await pilot.press("escape")
        assert isinstance(app.screen, ResultsScreen)

"""The simple view's app: runs one check at a time in a thread worker and shows it.

Read-only. The only side effects come after a key press: copying a prompt (OSC 52, always shown
on screen too) and opening the user's editor inside `App.suspend()` (`polaris.tui.editor` checks
the path and builds the command without a shell). `x` exits with the review in `expert`, so
`polaris.tui.simple.run` can open the expert view on it. `run_check` holds the process-wide
analysis lock, so a check never overlaps a review or a fix re-check.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from functools import partial
from typing import Any, ClassVar, Protocol

from textual import on
from textual.app import App
from textual.binding import Binding, BindingType
from textual.message import Message
from textual.screen import Screen
from textual.timer import Timer
from textual.worker import Worker, WorkerState

from polaris.check.build import combined_prompt
from polaris.check.model import CheckItem
from polaris.check.runner import CheckProblem, CheckRequest, CheckRun, Progress, run_check
from polaris.review.sarif_import import text as printable
from polaris.tui import brand
from polaris.tui.session import ReviewData
from polaris.tui.simple.screens import (
    CheckingScreen,
    CopyScreen,
    ErrorScreen,
    HelpScreen,
    ProblemScreen,
    ResultsScreen,
)
from polaris.tui.simple.widgets import palette_of
from polaris.tui.source import SourceIndex
from polaris.tui.text import clean_block
from polaris.tui.theme import THEMES, PaletteName

TWINKLE_SECONDS = 0.08  # one sweep of light out along the star's rays takes about a second
STARTING = "Getting ready\u2026"
# The editor helpers' messages mention `polaris tui`; the simple view is started by `polaris check`.
EDITOR_MESSAGES = {
    "editor_not_set": ("No editor is set, so Polaris can't open the file. Quit, set one in your shell (for example "
                       "export EDITOR=\"code --wait\" or export EDITOR=nvim), then run polaris check again."),
    "no_repository": "Polaris doesn't know your project folder, so it can't open the file.",
}


class Runner(Protocol):
    def __call__(self, request: CheckRequest, *, progress: Progress | None = None) -> CheckRun: ...


class CheckProgress(Message):
    """A progress line from the running check, posted from its worker thread."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class Stopped(Exception):
    """Raised inside the check's thread at its next step after the user quits (never shown)."""


class SimpleApp(App[None]):
    """Checking, then the results; `r` checks again. `runner` and `clock` are for tests."""

    TITLE = "Polaris"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "quit"), Binding("question_mark", "help", "help"),
        Binding("r", "check_again", show=False), Binding("x", "expert", show=False),
    ]

    def __init__(self, request: CheckRequest, *, animation: bool = True, theme: str = "dark",
                 runner: Runner | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__()
        self.request = request
        self.animation = animation
        self.theme_choice = theme if theme in THEMES else "dark"
        self.runner: Runner = runner or run_check
        self.clock = clock
        self.editor_runner: Any = None  # tests replace the editor runner; None runs the real editor
        self.outcome: CheckRun | None = None
        self.data: ReviewData | None = None
        self.sources: SourceIndex | None = None
        self.checked_at: float | None = None
        self.exit_code = 2
        self.expert: ReviewData | None = None
        self.checking = False
        self.progress = STARTING
        self.animated = False
        self.frame = 0
        self.expanded = False
        self.technical = False
        self.selected_id: str | None = None
        self._stopping = False
        self._worker: Worker[CheckRun] | None = None
        self._twinkle: Timer | None = None

    @property
    def palette(self) -> PaletteName:
        return palette_of(self)

    def on_mount(self) -> None:
        for custom in brand.CUSTOM_THEMES:
            self.register_theme(custom)
        self.theme = THEMES[self.theme_choice]
        self.animated = self.animation and not self.no_color
        self._twinkle = self.set_interval(TWINKLE_SECONDS, self._twinkle_tick, pause=True)
        self.set_interval(30, self._tick_clock)
        self.start_check()

    # ---- the check --------------------------------------------------------------------------------

    def start_check(self) -> None:
        if self.checking:
            return
        self.checking = True
        self.exit_code = 2  # quitting before this check finishes leaves it unfinished
        # Only the check on screen can be copied or opened in the expert view.
        self.outcome = self.data = self.sources = self.checked_at = None
        self.progress = STARTING
        self.frame = 0
        self._show(CheckingScreen())
        if self.animated and self._twinkle is not None:
            self._twinkle.resume()
        self._worker = self.run_worker(partial(self._check, self.request), thread=True, exclusive=True,
                                       group="check", name="check", exit_on_error=False)

    def _check(self, request: CheckRequest) -> CheckRun:
        return self.runner(request, progress=self._progress)

    def _progress(self, message: str) -> None:
        """Called from the worker thread: post the line to the interface (thread-safe)."""
        if self._stopping:
            raise Stopped
        try:
            self.post_message(CheckProgress(message))
        except RuntimeError:  # the interface is shutting down
            pass

    def on_check_progress(self, message: CheckProgress) -> None:
        self.progress = printable(message.text, 200) or self.progress
        screen = self._find(CheckingScreen)
        if screen is not None:
            screen.show_words()

    def _twinkle_tick(self) -> None:
        if not self.checking:
            return
        self.frame += 1
        screen = self._find(CheckingScreen)
        if screen is not None:
            screen.show_star()

    def _tick_clock(self) -> None:
        screen = self._find(ResultsScreen)
        if screen is not None:
            screen.refresh_bars()

    @on(Worker.StateChanged)
    def _worker_changed(self, event: Worker.StateChanged) -> None:
        worker = event.worker
        if worker is not self._worker or event.state not in (WorkerState.SUCCESS, WorkerState.ERROR,
                                                             WorkerState.CANCELLED):
            return
        self.checking = False
        if self._twinkle is not None:
            self._twinkle.pause()
        if self._stopping:
            return
        if event.state == WorkerState.SUCCESS and isinstance(worker.result, CheckRun):
            self._finished(worker.result)
            return
        error = worker.error
        # Fixed, plain messages only: exception text can quote source, paths or credentials.
        self._failed(error.message if isinstance(error, CheckProblem) else CheckProblem("check_failed").message)

    def _finished(self, outcome: CheckRun) -> None:
        self.outcome = outcome
        self.data = ReviewData(envelope=outcome.envelope, mode="live", label=outcome.result.scope_label,
                               root=outcome.root, workspace=outcome.workspace, elapsed_s=outcome.elapsed_s)
        self.sources = SourceIndex(self.data)
        self.exit_code = outcome.result.exit_code()
        self.checked_at = self.clock()
        self._show(ResultsScreen(outcome))

    def _failed(self, message: str) -> None:
        self.exit_code = 2
        self._show(ErrorScreen(message))

    # ---- screens ----------------------------------------------------------------------------------

    def _show(self, screen: Screen[Any]) -> None:
        """Make `screen` the base screen (checking, results or a problem), closing anything above."""
        while len(self.screen_stack) > 2:
            self.pop_screen()
        if len(self.screen_stack) == 2:
            self.switch_screen(screen)
        else:
            self.push_screen(screen)

    def _find(self, kind: type[Any]) -> Any:
        return next((screen for screen in self.screen_stack if isinstance(screen, kind)), None)

    def show_problem(self, item: CheckItem) -> None:
        if self.outcome is not None:
            self.push_screen(ProblemScreen(item, self.outcome.result))

    def action_help(self) -> None:
        if not isinstance(self.screen, HelpScreen):
            self.push_screen(HelpScreen())

    def action_check_again(self) -> None:
        self.start_check()

    async def action_quit(self) -> None:
        self._stopping = True
        self.exit()

    def action_expert(self) -> None:
        """Hand the same review to the expert view (opened by `polaris.tui.simple.run`)."""
        if self.checking or self.data is None:
            self.notify("The expert view opens once a check has finished.", markup=False, timeout=4)
            return
        self.expert = self.data
        self.exit()

    # ---- side effects (each one only after a key press) ------------------------------------------

    def copy_text(self, text: str, title: str) -> None:
        """Copy with OSC 52 and always show the text: copying can't be confirmed in a terminal."""
        lines = clean_block(text, 60_000, lines=400)
        self.copy_to_clipboard("\n".join(lines))
        self.push_screen(CopyScreen(title, lines))

    def copy_prompt(self, item: CheckItem) -> None:
        self.copy_text(item.prompt, "Copied the fix for your AI")

    def action_copy_all(self) -> None:
        if self.outcome is None:
            return
        result = self.outcome.result
        if not any(item.priority == "fix_now" for item in result.items):
            self.notify("Nothing needs fixing now, so there's nothing to copy.", markup=False, timeout=4)
            return
        self.copy_text(combined_prompt(result), "Copied all the fixes for your AI")

    def open_file(self, item: CheckItem) -> None:
        from textual.app import SuspendNotSupported

        from polaris.tui.editor import EditorProblem, build_command, run_editor

        root = self.outcome.root if self.outcome is not None else None
        try:
            command = build_command(root, item.where.file, item.where.line)
        except EditorProblem as problem:
            self.notify(EDITOR_MESSAGES.get(problem.code, problem.message), severity="warning", markup=False)
            return
        try:
            with self.suspend():
                if self.editor_runner is not None:
                    run_editor(command, runner=self.editor_runner)
                else:
                    run_editor(command)
        except SuspendNotSupported:
            self.notify("This terminal can't hand control to an editor.", severity="warning", markup=False)
        except EditorProblem as problem:
            self.notify(EDITOR_MESSAGES.get(problem.code, problem.message), severity="warning", markup=False)

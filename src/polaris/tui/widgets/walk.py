"""The taint walk: one finding's trace, step by step, from the untrusted source to the sink."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static

from polaris.tui import theme, view
from polaris.tui.text import clean
from polaris.tui.widgets.bars import LineBar
from polaris.tui.widgets.render import to_block

if TYPE_CHECKING:
    from polaris.tui.app import PolarisApp


class WalkScreen(Screen[None]):
    DEFAULT_CSS = """
    WalkScreen {
        layout: vertical;
    }
    #walk-header {
        height: auto;
        max-height: 3;
        padding: 0 1;
        background: $boost;
    }
    #walk-steps {
        height: auto;
        max-height: 40%;
        padding: 0 1;
    }
    #walk-code-scroll {
        height: 1fr;
        border-top: solid $accent;
        padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("n", "step(1)", "next"), Binding("down", "step(1)", show=False),
        Binding("p", "step(-1)", "previous"), Binding("up", "step(-1)", show=False),
        Binding("g", "jump('first')", "source"), Binding("G", "jump('last')", "sink"),
        Binding("enter", "open", "open"), Binding("o", "open", show=False),
        Binding("y", "prompt", "prompt"), Binding("escape", "back", "back"), Binding("t", "back", show=False),
    ]

    def __init__(self, row: view.FindingRow, steps: list[view.WalkStep]) -> None:
        super().__init__()
        self.row = row
        self.steps = steps
        self.current = 0

    @property
    def polaris(self) -> PolarisApp:
        from polaris.tui.app import PolarisApp

        assert isinstance(self.app, PolarisApp)
        return self.app

    def compose(self) -> ComposeResult:
        yield LineBar(id="walk-trust")
        yield Static("", id="walk-header")
        yield Static("", id="walk-steps")
        with VerticalScroll(id="walk-code-scroll"):
            yield Static("", id="walk-code")
        yield LineBar(id="walk-keys")

    def on_mount(self) -> None:
        self.refresh_walk()
        self.query_one("#walk-code-scroll").focus()

    def refresh_walk(self) -> None:
        app = self.polaris
        palette = app.palette
        finding = self.row.finding
        self.query_one("#walk-trust", LineBar).show_fitted(app.trust_line, palette)
        header = [
            view.line(view.severity_span(finding.severity), (" ", ""),
                      view.state_span(theme.RESULT.get(finding.result, theme.RESULT["error"])),
                      ("  ", ""), (clean(finding.title, 120), "heading"), ("  ", ""),
                      (view.where(finding.path, finding.start_line, finding.symbol), "muted")),
        ]
        self.query_one("#walk-header", Static).update(to_block(header, palette))
        self.query_one("#walk-steps", Static).update(to_block(view.walk_lines(self.steps, self.current), palette))
        if self.steps:
            step = self.steps[self.current]
            lines = [step.header(len(self.steps)), ()]
            lines.extend(view.code_block(step.context))
            lines.append(())
            lines.append(view.line((f"Code: {view.origin_note(step.context)}.", "muted")))
        else:
            lines = [view.line(("This finding has no data-flow trace.", "muted"))]
        self.query_one("#walk-code", Static).update(to_block(lines, palette))
        hints = view.key_hints("walk", app.ui_state(self.row.finding), include_global=False)
        self.query_one("#walk-keys", LineBar).show_fitted(lambda width: view.key_bar(hints, width), palette)

    def action_step(self, delta: int) -> None:
        if self.steps:
            self.current = max(0, min(len(self.steps) - 1, self.current + delta))
            self.refresh_walk()

    def action_jump(self, where: str) -> None:
        if self.steps:
            self.current = 0 if where == "first" else len(self.steps) - 1
            self.refresh_walk()

    def action_open(self) -> None:
        if self.steps:
            step = self.steps[self.current]
            self.polaris.open_in_editor(step.path, step.line)

    def action_prompt(self) -> None:
        self.polaris.copy_prompt(self.row.finding)

    def action_back(self) -> None:
        self.dismiss(None)

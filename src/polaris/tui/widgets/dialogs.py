"""Modal screens. None of them runs anything: saving goes through the app's new-file writer."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from polaris.tui import theme
from polaris.tui.view import Line
from polaris.tui.widgets.render import to_block, to_text

DIALOG_CSS = """
ModalScreen {
    align: center middle;
}
.dialog {
    width: 90%;
    max-width: 110;
    height: auto;
    max-height: 90%;
    border: round $accent;
    background: $surface;
    padding: 0 1;
}
.dialog-title {
    height: 1;
    text-style: bold;
}
.dialog-hint {
    height: auto;
    color: $text-muted;
}
.dialog-body {
    height: auto;
    max-height: 30;
}
"""


class TextScreen(ModalScreen[None]):
    """A scrollable block of view-model lines (help, the agent prompt)."""

    DEFAULT_CSS = DIALOG_CSS
    BINDINGS = [
        Binding("escape", "close", "close"), Binding("enter", "close", show=False),
        Binding("question_mark", "close", show=False), Binding("q", "close", show=False),
    ]

    def __init__(self, title: str, lines: Sequence[Line], palette: theme.PaletteName, *, hint: str = "",
                 name: str | None = None) -> None:
        super().__init__(name=name)
        self.title_text = title
        self.lines = list(lines)
        self.palette = palette
        self.hint = hint

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(Text(self.title_text), classes="dialog-title")
            with VerticalScroll(classes="dialog-body", id="dialog-scroll"):
                yield Static(to_block(self.lines, self.palette), id="dialog-text")
            if self.hint:
                yield Static(Text(self.hint), classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one("#dialog-scroll").focus()

    def action_close(self) -> None:
        self.dismiss(None)


class PromptScreen(TextScreen):
    """The agent prompt, on screen: OSC 52 copying can't be confirmed, so the text is always shown."""

    def __init__(self, prompt_lines: Sequence[str], palette: theme.PaletteName) -> None:
        super().__init__(
            "Prompt for your coding agent", [((text, "text"),) for text in prompt_lines], palette,
            hint="Copied to the clipboard if your terminal allows OSC 52 copying. If not, select the text above "
                 "(run with --no-mouse, or hold Shift/Option while selecting). esc closes.",
        )


class FixScreen(ModalScreen[None]):
    """The one-line edit and its re-verification. The app refreshes it when a result arrives."""

    DEFAULT_CSS = DIALOG_CSS
    BINDINGS = [
        Binding("escape", "close", "close"), Binding("f", "close", show=False), Binding("q", "close", show=False),
        Binding("o", "open", "open at the edit"),
    ]

    def __init__(self, finding_id: str, render: Callable[[], Sequence[Line]], open_edit: Callable[[], None],
                 palette: theme.PaletteName) -> None:
        super().__init__()
        self.finding_id = finding_id
        self.lines_source = render
        self.open_edit = open_edit
        self.palette = palette

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(Text("Fix preview"), classes="dialog-title")
            with VerticalScroll(classes="dialog-body", id="fix-scroll"):
                yield Static("", id="fix-text")
            yield Static(Text("o opens your editor at the edit · esc closes"), classes="dialog-hint")

    def on_mount(self) -> None:
        self.refresh_fix()
        self.query_one("#fix-scroll").focus()

    def refresh_fix(self) -> None:
        # The app may ask before the screen has composed; on_mount renders it then.
        for body in self.query("#fix-text").results(Static):
            body.update(to_block(self.lines_source(), self.palette))

    def action_open(self) -> None:
        self.open_edit()

    def action_close(self) -> None:
        self.dismiss(None)


class SaveScreen(ModalScreen[str | None]):
    """Ask for a new file name; the app writes it and refuses existing files and links."""

    DEFAULT_CSS = DIALOG_CSS
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, suggestion: str, save: Callable[[str], str | None], palette: theme.PaletteName) -> None:
        super().__init__()
        self.suggestion = suggestion
        self.save = save
        self.palette = palette

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(Text("Save the report as JSON"), classes="dialog-title")
            yield Static(Text("A new file is always created; existing files and symbolic links are never "
                              "overwritten. Open it later with polaris tui --report FILE."), classes="dialog-hint")
            yield Input(value=self.suggestion, id="save-path")
            yield Static(Text(""), id="save-error", classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        problem = self.save(event.value.strip())
        if problem is None:
            self.dismiss(event.value.strip())
        else:
            self.query_one("#save-error", Static).update(to_text(((problem, "warning"),), self.palette))

    def action_cancel(self) -> None:
        self.dismiss(None)

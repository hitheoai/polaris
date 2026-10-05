"""The simple view's building blocks. Each one renders Rich `Text` built from view spans, at the
width it is given, so headers, rows and key bars refit on resize without markup anywhere."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

from rich.console import Group
from rich.table import Table
from textual.app import App, RenderResult
from textual.containers import VerticalScroll
from textual.events import Click
from textual.message import Message
from textual.widget import Widget

from polaris.check.model import CheckItem
from polaris.tui import brand
from polaris.tui.simple import view
from polaris.tui.theme import PaletteName, palette_for

RULE = "\u2500"  # ─
LABEL_WIDTH = 14


def palette_of(app: App[Any]) -> PaletteName:
    return palette_for(ansi=app.native_ansi_color, dark=app.current_theme.dark, no_color=app.no_color)


def block(lines: Iterable[view.Line], palette: PaletteName) -> Group:
    """Many lines: prose wraps, code keeps its columns (cropped, never wrapped)."""
    return Group(*(brand.to_text(value, palette, no_wrap=view.is_code(value), end="\n") for value in lines))


def sections_table(sections: Sequence[view.Section], palette: PaletteName) -> Table:
    """Labelled parts of a problem: the label column on the left, the words wrapping beside it."""
    table = Table.grid(expand=True, padding=(0, 2))
    table.add_column(width=LABEL_WIDTH, no_wrap=True)
    table.add_column(ratio=1)
    for section in sections:
        label = brand.to_text(((section.label, "label"),), palette, no_wrap=True)
        table.add_row(label, block(section.lines, palette))
    return table


class Bar(Widget):
    """One line of spans computed from the width it gets: headers and key bars."""

    DEFAULT_CSS = """
    Bar {
        height: 1;
        width: 1fr;
    }
    """

    def __init__(self, source: Callable[[int], view.Line], *, id: str | None = None,
                 classes: str | None = None) -> None:
        super().__init__(id=id, classes=classes)
        self.source = source

    @property
    def value(self) -> view.Line:
        return self.source(self.size.width or self.app.size.width)

    def render(self) -> RenderResult:
        return brand.to_text(self.value, palette_of(self.app), no_wrap=True)


class Divider(Widget):
    """A thin line in the brand's night blue between the header, the body and the keys."""

    DEFAULT_CSS = """
    Divider {
        height: 1;
        width: 1fr;
    }
    """

    def render(self) -> RenderResult:
        return brand.to_text(((RULE * max(1, self.size.width), "rule"),), palette_of(self.app), no_wrap=True)


class ItemRow(Widget):
    """One problem in the list. A click opens it (keys do the same: arrows, then Enter)."""

    DEFAULT_CSS = """
    ItemRow {
        height: 1;
        width: 1fr;
    }
    """

    class Picked(Message):
        def __init__(self, row: ItemRow) -> None:
            super().__init__()
            self.row = row

    def __init__(self, item: CheckItem, file_width: int, *, classes: str | None = None) -> None:
        super().__init__(classes=classes)
        self.item = item
        self.file_width = file_width
        self.chosen = False

    @property
    def value(self) -> view.Line:
        return view.row(self.item, chosen=self.chosen, width=self.size.width or 80, file_width=self.file_width)

    def render(self) -> RenderResult:
        return brand.to_text(self.value, palette_of(self.app), no_wrap=True)

    def choose(self, chosen: bool) -> None:
        if chosen != self.chosen:
            self.chosen = chosen
            self.refresh()

    def on_click(self, event: Click) -> None:
        event.stop()
        self.post_message(self.Picked(self))


class Body(VerticalScroll, can_focus=False):
    """The scrolling middle of a screen. Not focusable, so the arrow keys choose a problem
    instead of scrolling; the chosen row is always scrolled into view."""

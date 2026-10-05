"""One-line bars: the trust bar (always visible), the status line and the key bar."""

from __future__ import annotations

from collections.abc import Callable

from textual.events import Resize
from textual.widgets import Static

from polaris.tui import theme
from polaris.tui.view import Line
from polaris.tui.widgets.render import to_text


class LineBar(Static):
    """A single line of view-model spans, cropped (never wrapped) to the terminal width."""

    DEFAULT_CSS = """
    LineBar {
        height: 1;
        width: 1fr;
        padding: 0 1;
    }
    """

    def __init__(self, *, id: str | None = None, classes: str | None = None) -> None:
        super().__init__("", id=id, classes=classes)
        self.value: Line = ()
        self._source: Callable[[int], Line] | None = None
        self._palette: theme.PaletteName = "dark"

    def show(self, value: Line, palette: theme.PaletteName) -> None:
        self.value = value
        self._palette = palette
        self.update(to_text(value, palette, no_wrap=True))

    def show_fitted(self, source: Callable[[int], Line], palette: theme.PaletteName) -> None:
        """Render with a function of the available width (re-run on resize)."""
        self._source = source
        self.show(source(self.available()), palette)

    def available(self) -> int:
        # `size` is the content area (padding excluded); before layout, assume the full screen width.
        return max(20, self.size.width or self.app.size.width - 2)

    def on_resize(self, event: Resize) -> None:
        if self._source is not None:
            self.show(self._source(self.available()), self._palette)

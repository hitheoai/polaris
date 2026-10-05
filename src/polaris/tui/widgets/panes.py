"""The tab panes. They hold widgets only; the app owns the review and the view state."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Static, Tree


class FileTree(Tree[str]):
    """Directories and files with coverage glyphs and visible finding counts; enter filters."""

    DEFAULT_CSS = """
    FileTree {
        width: 26;
        height: 1fr;
        padding: 0;
        scrollbar-size-vertical: 1;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(Text("All files"), data="", id=id)
        self.show_root = True
        self.guide_depth = 2


class FindingsTable(DataTable[Text]):
    DEFAULT_CSS = """
    FindingsTable {
        height: 40%;
        min-height: 4;
        scrollbar-size-vertical: 1;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=False, show_cursor=True)


class FindingsPane(Horizontal):
    DEFAULT_CSS = """
    FindingsPane {
        height: 1fr;
    }
    #findings-right {
        width: 1fr;
        height: 1fr;
    }
    #detail {
        height: 1fr;
        padding: 0 1;
        border-top: solid $panel-lighten-2;
        scrollbar-size-vertical: 1;
    }
    #detail:focus {
        border-top: solid $accent;
    }
    """

    def compose(self) -> ComposeResult:
        yield FileTree(id="tree")
        with Vertical(id="findings-right"):
            yield FindingsTable(id="table")
            with VerticalScroll(id="detail"):
                yield Static("", id="detail-body")


class CoverageTable(DataTable[Text]):
    """Files × checks. Cell cursor: the line below explains the selected cell."""

    DEFAULT_CSS = """
    CoverageTable {
        height: 1fr;
        scrollbar-size-vertical: 1;
    }
    """
    BINDINGS = [
        Binding("u", "app.coverage('unreviewed')", "unreviewed"),
        Binding("l", "app.coverage('language')", "language"),
        Binding("x", "app.coverage('excluded')", "excluded"),
        Binding("a", "app.coverage('all')", "all"),
    ]

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="cell", zebra_stripes=False, cell_padding=0)


class CoveragePane(Vertical):
    DEFAULT_CSS = """
    CoveragePane {
        height: 1fr;
    }
    #coverage-body {
        height: 1fr;
        layout: vertical;
    }
    #matrix-box {
        height: 3fr;
    }
    #what-ran {
        height: 2fr;
        padding: 0 1;
        border-top: solid $panel-lighten-2;
        scrollbar-size-vertical: 1;
    }
    #what-ran:focus {
        border-top: solid $accent;
    }
    #coverage-reason {
        height: auto;
        max-height: 2;
        padding: 0 1;
        background: $boost;
    }
    #coverage-legend {
        display: none;
        height: auto;
        max-height: 2;
        padding: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="coverage-body"):
            with Vertical(id="matrix-box"):
                yield CoverageTable(id="matrix")
                yield Static("", id="coverage-reason")
                yield Static("", id="coverage-legend")
            with VerticalScroll(id="what-ran"):
                yield Static("", id="what-ran-body")


class NoticePane(VerticalScroll):
    """A pane that shows a scrollable block of text (other tools' results, empty states)."""

    DEFAULT_CSS = """
    NoticePane {
        height: 1fr;
        padding: 0 1;
        scrollbar-size-vertical: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("", classes="notice-body")


class SurfaceTable(DataTable[Text]):
    DEFAULT_CSS = """
    SurfaceTable {
        height: 45%;
        min-height: 4;
        scrollbar-size-vertical: 1;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=False)


class SurfacePane(Vertical):
    """Each route or handler, its auth guard (or none), what it reaches, and its findings."""

    DEFAULT_CSS = """
    SurfacePane {
        height: 1fr;
    }
    #surface-summary {
        height: 1;
        padding: 0 1;
    }
    #surface-detail {
        height: 1fr;
        padding: 0 1;
        border-top: solid $panel-lighten-2;
        scrollbar-size-vertical: 1;
    }
    """
    BINDINGS = [Binding("o", "app.surface_open", "open", show=False)]

    def compose(self) -> ComposeResult:
        yield Static("", id="surface-summary")
        yield SurfaceTable(id="surface-table")
        with VerticalScroll(id="surface-detail"):
            yield Static("", id="surface-detail-body")


class PlanTable(DataTable[Text]):
    DEFAULT_CSS = """
    PlanTable {
        height: 35%;
        min-height: 4;
        scrollbar-size-vertical: 1;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=False)


class PlanPane(Vertical):
    """What the PR bot would post: gate, summary and inline comments, recomputed offline."""

    DEFAULT_CSS = """
    PlanPane {
        height: 1fr;
    }
    #plan-header {
        height: auto;
        max-height: 8;
        padding: 0 1;
        background: $boost;
    }
    #plan-body {
        height: 1fr;
        padding: 0 1;
        border-top: solid $panel-lighten-2;
        scrollbar-size-vertical: 1;
    }
    """
    BINDINGS = [
        Binding("i", "app.plan_option('inline')", "inline floor"),
        Binding("k", "app.plan_option('questions')", "questions inline"),
        Binding("g", "app.plan_option('gate')", "gate floor"),
        Binding("m", "app.plan_option('imported')", "imported inline"),
        Binding("e", "app.plan_option('fail_imported')", "fail on imported"),
        Binding("u", "app.plan_option('verify')", "verify fixes"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="plan-header")
        yield PlanTable(id="plan-table")
        with VerticalScroll(id="plan-body"):
            yield Static("", id="plan-body-text")

"""The simple view's screens: checking, results (including all clear), one problem, a problem
that stopped the check, and the help and copy panels. Screens only show things; the app owns
the check, the side effects (copying, opening the editor) and the switch to the expert view."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from rich.align import Align
from rich.console import Group
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.events import Resize
from textual.screen import ModalScreen, Screen
from textual.widgets import Static

from polaris.check.brand import STATUS_MARKS, TAGLINE
from polaris.check.model import PRIORITIES, CheckItem, CheckResult
from polaris.review.sarif_import import text as printable
from polaris.tui import brand
from polaris.tui.simple import view
from polaris.tui.simple.widgets import Bar, Body, Divider, ItemRow, block, sections_table

if TYPE_CHECKING:
    from polaris.check.runner import CheckRun
    from polaris.tui.simple.app import SimpleApp

PAGE_CSS = """
{name} {{
    layout: vertical;
}}
{name} #header {{
    padding: 0 1;
}}
{name} Divider {{
    padding: 0 1;
}}
{name} #body {{
    height: 1fr;
    padding: 0 1 0 2;
    scrollbar-size-vertical: 1;
}}
{name} #keys {{
    padding: 0 2;
}}
{name} .gap {{
    margin-top: 1;
}}
{name} #mark {{
    margin-top: 1;
}}
"""
DIALOG_CSS = """
{name} {{
    align: center middle;
}}
{name} .dialog {{
    width: 90%;
    max-width: 100;
    height: auto;
    max-height: 90%;
    border: round $primary;
    background: $surface;
    padding: 0 1;
}}
{name} .dialog-body {{
    height: auto;
    max-height: {body};
}}
{name} .dialog-hint {{
    height: auto;
    margin-top: 1;
}}
"""


class SimpleScreen(Screen[None]):
    @property
    def polaris(self) -> SimpleApp:
        from polaris.tui.simple.app import SimpleApp

        assert isinstance(self.app, SimpleApp)
        return self.app


def heading(value: str, role: str, app: SimpleApp) -> Text:
    return brand.to_text(((value, role),), app.palette, end="\n")


# ---- checking -------------------------------------------------------------------------------------


class CheckingScreen(SimpleScreen):
    """The brand moment while a check runs: the website's lockup (its star twinkling only while
    the check really runs), the tagline, and the check's own progress lines. No added delays."""

    DEFAULT_CSS = """
    CheckingScreen {
        align: center middle;
    }
    CheckingScreen > Static {
        width: 100%;
        height: auto;
    }
    CheckingScreen #brand-words {
        margin-top: 1;
        text-align: center;
    }
    CheckingScreen #keys {
        dock: bottom;
        padding: 0 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(Text(""), id="brand-mark")
        yield Static(Text(""), id="brand-words")
        yield Bar(lambda width: view.key_bar([view.HELP, view.QUIT], width), id="keys")

    def on_mount(self) -> None:
        self.refresh_all()

    def on_resize(self, event: Resize) -> None:
        self.refresh_all()

    def refresh_all(self) -> None:
        self.show_star()
        self.show_words()

    def show_star(self) -> None:
        """The largest lockup that fits (or the compact mark), lit for the twinkle's frame.
        Centred as one block: the drawing's rows keep their own spacing."""
        app = self.polaris
        frame = app.frame if app.animated and app.checking else None
        width, height = self.app.size
        size = brand.lockup_size(width, height)
        mark: Align = Align.center(
            brand.compact(app.palette, frame) if size is None else Group(*brand.LOCKUPS[size].render(app.palette, frame)))
        self.query_one("#brand-mark", Static).update(mark)

    def show_words(self) -> None:
        app = self.polaris
        lines = [view.line((TAGLINE, "muted")), (), *view.checking_lines(app.progress)]
        self.query_one("#brand-words", Static).update(Group(*(
            brand.to_text(value, app.palette, justify="center", end="\n") for value in lines)))


# ---- results -------------------------------------------------------------------------------------


class ResultsScreen(SimpleScreen):
    """Is it safe to ship? The answer first, then the problems by priority, then what was and
    wasn't checked. "Worth a look" starts collapsed (`w`); all clear says what it means."""

    DEFAULT_CSS = PAGE_CSS.format(name="ResultsScreen")
    BINDINGS = [
        Binding("up,k", "move(-1)", show=False), Binding("down,j", "move(1)", show=False),
        Binding("pageup", "move(-10)", show=False), Binding("pagedown", "move(10)", show=False),
        Binding("home", "move(-1000)", show=False), Binding("end", "move(1000)", show=False),
        Binding("enter", "details", show=False), Binding("c", "copy", show=False),
        Binding("a", "app.copy_all", show=False), Binding("w", "worth", show=False),
        Binding("o", "open_file", show=False),
    ]

    def __init__(self, outcome: CheckRun) -> None:
        super().__init__()
        self.outcome = outcome
        self.result = outcome.result
        self.rows: list[ItemRow] = []
        self.worth: list[Static] = []

    def compose(self) -> ComposeResult:
        app = self.polaris
        palette = app.palette
        result = self.result
        yield Bar(self.header_line, id="header")
        yield Divider()
        with Body(id="body"):
            clear = result.status == "clear"
            if clear:
                yield Static(Text(""), id="mark")
            yield Static(block(view.status_lines(result), palette), id="status")
            since = view.since_line(result)
            if since:
                yield Static(block([since], palette), id="since")
            file_width = view.file_column(result.items)
            for priority in PRIORITIES:
                items = [item for item in result.items if item.priority == priority]
                count = len(items) + result.more.get(priority, 0)
                if not count:
                    continue
                folded = priority == "worth_a_look"
                title = Static(block([view.section_title(priority, count, expanded=app.expanded)], palette),
                               id=f"title-{priority}", classes="gap")
                yield title
                for item in items:
                    row = ItemRow(item, file_width, classes=priority)
                    row.display = app.expanded or not folded
                    self.rows.append(row)
                    yield row
                more = view.more_line(result, priority)
                if more:
                    extra = Static(block([more], palette))
                    extra.display = app.expanded or not folded
                    if folded:
                        self.worth.append(extra)
                    yield extra
            closing = view.note_lines(result) if result.status == "clear" else view.checked_lines(result)
            if closing:
                yield Static(block(closing, palette), id="checked", classes="gap")
        yield Divider()
        yield Bar(self.keys_line, id="keys")

    def on_mount(self) -> None:
        self.show_mark()
        visible = self.listed()
        target = next((row for row in visible if row.item.id == self.polaris.selected_id),
                      visible[0] if visible else None)
        if target is not None:
            self.choose(target, scroll=False)
            if target is not visible[0]:
                self.call_after_refresh(self._reveal, target)

    def on_resize(self, event: Resize) -> None:
        self.show_mark()

    def show_mark(self) -> None:
        """All clear: the website's lockup above the answer, steady, when there's room for it."""
        for mark in self.query("#mark").results(Static):
            width, height = self.app.size
            size: brand.Size | None = ("large" if width >= 100 and height >= 34 else
                                       "small" if width >= 50 and height >= 20 else None)
            mark.display = size is not None
            self.query_one("#status").set_class(size is not None, "gap")
            if size is not None:
                mark.update(Group(*brand.LOCKUPS[size].render(self.polaris.palette)))

    # ---- the header and the keys ----------------------------------------------------------------

    def header_line(self, width: int) -> view.Line:
        app = self.polaris
        when = view.ago(app.clock() - app.checked_at) if app.checked_at is not None else ""
        return view.header(view.project_name(self.outcome.root), printable(self.result.scope_label, 200),
                           when, width)

    def keys_line(self, width: int) -> view.Line:
        return view.key_bar(view.results_keys(self.result, expanded=self.polaris.expanded, expert=True), width)

    def refresh_bars(self) -> None:
        for bar in self.query(Bar):
            bar.refresh()

    # ---- choosing a problem --------------------------------------------------------------------

    def listed(self) -> list[ItemRow]:
        expanded = self.polaris.expanded
        return [row for row in self.rows if expanded or row.item.priority != "worth_a_look"]

    @property
    def current(self) -> ItemRow | None:
        return next((row for row in self.rows if row.chosen), None)

    def choose(self, target: ItemRow, *, scroll: bool = True) -> None:
        for row in self.rows:
            row.choose(row is target)
        self.polaris.selected_id = target.item.id
        if scroll:
            self._reveal(target)

    def _reveal(self, target: ItemRow) -> None:
        """Scroll the chosen row into view; at either end, show the answer or what was checked too."""
        body = self.query_one(Body)
        visible = self.listed()
        if visible and target is visible[0]:
            body.scroll_home(animate=False)
        elif visible and target is visible[-1]:
            body.scroll_end(animate=False)
        else:
            body.scroll_to_widget(target, animate=False)

    def action_move(self, delta: int) -> None:
        visible = self.listed()
        if not visible:
            return
        current = self.current
        index = visible.index(current) if current in visible else 0
        self.choose(visible[max(0, min(len(visible) - 1, index + delta))])

    def action_details(self) -> None:
        item = self._chosen()
        if item is not None:
            self.polaris.show_problem(item)

    def on_item_row_picked(self, message: ItemRow.Picked) -> None:
        self.choose(message.row)
        self.polaris.show_problem(message.row.item)

    # ---- keys --------------------------------------------------------------------------------

    def action_worth(self) -> None:
        app = self.polaris
        folded = [row for row in self.rows if row.item.priority == "worth_a_look"]
        if not folded:
            app.notify("Nothing is marked \"worth a look\".", markup=False, timeout=3)
            return
        app.expanded = not app.expanded
        for widget in (*folded, *self.worth):
            widget.display = app.expanded
        count = len(folded) + self.result.more.get("worth_a_look", 0)
        self.query_one("#title-worth_a_look", Static).update(
            block([view.section_title("worth_a_look", count, expanded=app.expanded)], app.palette))
        current = self.current
        visible = self.listed()
        if current is not None and current not in visible:
            if visible:
                self.choose(visible[-1])  # the chosen row was folded away: the nearest one above it
            else:
                current.choose(False)
        elif current is None and visible:
            self.choose(visible[0])
        elif app.expanded:
            self.call_after_refresh(self.query_one(Body).scroll_to_widget, folded[-1], animate=False)
        self.refresh_bars()

    def _chosen(self) -> CheckItem | None:
        """The chosen problem, or None after saying why there isn't one."""
        current = self.current
        if current is None:
            message = ("Press w to show \"worth a look\", then choose a problem." if self.rows
                       else "Polaris found nothing to fix, so there's nothing to choose.")
            self.polaris.notify(message, markup=False, timeout=4)
            return None
        return current.item

    def action_copy(self) -> None:
        item = self._chosen()
        if item is not None:
            self.polaris.copy_prompt(item)

    def action_open_file(self) -> None:
        item = self._chosen()
        if item is not None:
            self.polaris.open_file(item)


# ---- one problem -------------------------------------------------------------------------------


class ProblemScreen(SimpleScreen):
    """One problem in five parts: what's wrong, why it matters, where (with the code exactly as
    it was checked), how to fix, and the copy key for an AI. `t` adds the technical details."""

    DEFAULT_CSS = PAGE_CSS.format(name="ProblemScreen")
    BINDINGS = [
        Binding("escape,backspace", "back", show=False), Binding("c", "copy", show=False),
        Binding("a", "app.copy_all", show=False), Binding("o", "open_file", show=False),
        Binding("t", "technical", show=False),
    ]

    def __init__(self, item: CheckItem, result: CheckResult) -> None:
        super().__init__()
        self.item = item
        self.result = result

    def compose(self) -> ComposeResult:
        yield Bar(lambda width: view.problem_header(self.item, width), id="header")
        yield Divider()
        with VerticalScroll(id="body"):
            yield Static(Text(""), id="detail")
            yield Static(Text(""), id="technical", classes="gap")
        yield Divider()
        yield Bar(self.keys_line, id="keys")

    def on_mount(self) -> None:
        app = self.polaris
        sections = view.problem_sections(self.item, view.code_lines(self.item, app.sources))
        self.query_one("#detail", Static).update(sections_table(sections, app.palette))
        self.query_one("#technical", Static).update(Group(
            heading("Technical details", "heading", app), sections_table(view.technical_sections(self.item),
                                                                          app.palette)))
        self.query_one("#technical").display = app.technical
        self.query_one("#body").focus()

    def keys_line(self, width: int) -> view.Line:
        return view.key_bar(view.problem_keys(self.result, technical=self.polaris.technical, expert=True), width)

    def action_back(self) -> None:
        self.dismiss(None)

    def action_copy(self) -> None:
        self.polaris.copy_prompt(self.item)

    def action_open_file(self) -> None:
        self.polaris.open_file(self.item)

    def action_technical(self) -> None:
        app = self.polaris
        app.technical = not app.technical
        technical = self.query_one("#technical", Static)
        technical.display = app.technical
        if app.technical:
            self.call_after_refresh(self.query_one("#body", VerticalScroll).scroll_to_widget, technical, top=True,
                                    animate=False)
        self.query_one("#keys", Bar).refresh()


# ---- a problem that stopped the check ---------------------------------------------------------


class ErrorScreen(SimpleScreen):
    """Why the check couldn't run, in plain words, and what to do: try again or quit."""

    DEFAULT_CSS = PAGE_CSS.format(name="ErrorScreen")

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        yield Bar(lambda width: view.line(*view.BRAND), id="header")
        yield Divider()
        with Body(id="body"):
            yield Static(block(view.error_lines(self.message), self.polaris.palette), id="problem", classes="gap")
        yield Divider()
        yield Bar(lambda width: view.key_bar([view.Key("r", "try again", rank=0), view.HELP, view.QUIT], width),
                  id="keys")


# ---- panels ---------------------------------------------------------------------------------------


class Panel(ModalScreen[None]):
    @property
    def polaris(self) -> SimpleApp:
        from polaris.tui.simple.app import SimpleApp

        assert isinstance(self.app, SimpleApp)
        return self.app

    def action_close(self) -> None:
        self.dismiss(None)


class HelpScreen(Panel):
    """Every key in words, what each mark means, and why your code stays private."""

    DEFAULT_CSS = DIALOG_CSS.format(name="HelpScreen", body="70vh")
    BINDINGS = [Binding("escape,question_mark,q,enter", "close", show=False)]

    def compose(self) -> ComposeResult:
        palette = self.polaris.palette
        with Vertical(classes="dialog"):
            yield Static(brand.to_text((*view.BRAND, ("  \u203a  ", "muted"), ("Help", "label")), palette))
            with VerticalScroll(classes="dialog-body", id="help-scroll"):
                yield Static(block(view.help_lines(), palette))
            yield Static(brand.to_text((("Esc", "key"), (" close", "text")), palette), classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one("#help-scroll").focus()


class CopyScreen(Panel):
    """The copied prompt, on screen: a terminal may refuse OSC 52 copying without telling us, so
    the text is always shown too, ready to select."""

    DEFAULT_CSS = DIALOG_CSS.format(name="CopyScreen", body="45vh")
    BINDINGS = [Binding("escape,enter,q,c,a", "close", show=False)]

    def __init__(self, title: str, lines: Sequence[str]) -> None:
        super().__init__()
        self.title_text = title
        self.lines = list(lines)

    def compose(self) -> ComposeResult:
        palette = self.polaris.palette
        with Vertical(classes="dialog"):
            yield Static(brand.to_text(((f"{STATUS_MARKS['clear']} ", "clear"), (self.title_text, "label")), palette),
                         id="copy-title")
            yield Static(brand.to_text(((view.COPY_HINT, "muted"),), palette), id="copy-hint")
            with VerticalScroll(classes="dialog-body gap", id="copy-scroll"):
                yield Static(Text("\n".join(self.lines)), id="copy-text")
            yield Static(brand.to_text((("Esc", "key"), (" close", "text")), palette), classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one("#copy-scroll").focus()

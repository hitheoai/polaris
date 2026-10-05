"""The Polaris terminal UI (Textual). Read-only: the only side effects are, after a key press,
opening the user's editor (inside `App.suspend()`), copying a prompt (OSC 52, shown on screen
too) and saving the report to a new file.

Live reviews, PR plans and fix verifications run in thread workers, so the interface stays
responsive and shows the elapsed time; `r` runs the review again. Every widget receives Rich
`Text` built from the view model's cleaned spans: repository text is never parsed as markup.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, ClassVar, Literal

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding, BindingType
from textual.events import Resize
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Input, Static, TabbedContent, TabPane, Tree
from textual.widgets.tree import TreeNode
from textual.worker import Worker, WorkerState

from polaris.review.models import WorkflowFinding
from polaris.tui import brand, panels, theme, view
from polaris.tui.prpreview import PlanState, Verifier
from polaris.tui.session import (
    ReviewData,
    ReviewRequest,
    SessionProblem,
    error_message,
    report_json,
    run_review,
)
from polaris.tui.source import SourceIndex
from polaris.tui.text import clean, clean_block
from polaris.tui.widgets.bars import LineBar
from polaris.tui.widgets.dialogs import FixScreen, PromptScreen, SaveScreen, TextScreen
from polaris.tui.widgets.panes import (
    CoveragePane,
    CoverageTable,
    FileTree,
    FindingsPane,
    FindingsTable,
    NoticePane,
    PlanPane,
    PlanTable,
    SurfacePane,
    SurfaceTable,
)
from polaris.tui.widgets.render import to_block, to_cells, to_text
from polaris.tui.widgets.walk import WalkScreen

TABS = ("findings", "coverage", "surface", "tools", "pr")
TAB_TITLES = {"findings": "1 Findings", "coverage": "2 Coverage", "surface": "3 Attack surface",
              "tools": "4 Other tools", "pr": "5 PR preview"}
MAX_TREE_EXPANDED = 400


@dataclass(frozen=True)
class Options:
    theme: str = "dark"
    fail_on_imported: str | None = None


class PolarisApp(App[None]):
    TITLE = "Polaris"
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (110, "-wide")]
    CSS = """
    Screen {
        layout: vertical;
    }
    #trust {
        background: $boost;
    }
    #tabs {
        height: 1fr;
    }
    TabbedContent > ContentSwitcher {
        height: 1fr;
    }
    TabPane {
        padding: 0;
        height: 1fr;
    }
    #status {
        background: $boost;
    }
    #filter {
        display: none;
        height: 3;
    }
    #filter.-active {
        display: block;
    }
    Screen.-wide FileTree {
        width: 34;
    }
    /* Wide terminals: the coverage matrix and "what ran" side by side, with the legend. */
    Screen.-wide #coverage-legend {
        display: block;
    }
    Screen.-wide #coverage-body {
        layout: horizontal;
    }
    Screen.-wide #matrix-box {
        width: 2fr;
        height: 1fr;
    }
    Screen.-wide #what-ran {
        width: 1fr;
        height: 1fr;
        border-top: none;
        border-left: solid $panel-lighten-2;
    }
    Screen.-wide #what-ran:focus {
        border-left: solid $accent;
    }
    """
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "quit"),
        Binding("question_mark", "help", "help"),
        Binding("slash", "filter", "filter"),
        Binding("colon", "command_palette", "commands", show=False),
        Binding("1", "tab('findings')", show=False), Binding("2", "tab('coverage')", show=False),
        Binding("3", "tab('surface')", show=False), Binding("4", "tab('tools')", show=False),
        Binding("5", "tab('pr')", show=False),
        Binding("s", "floor", "floor"), Binding("v", "questions", "questions"),
        Binding("r", "rerun", "re-run"), Binding("o", "open", "open"), Binding("w", "save", "save"),
        Binding("t", "walk", "walk"), Binding("f", "fix", "fix"), Binding("y", "prompt", "prompt"),
        Binding("escape", "clear", show=False),
    ]

    def __init__(self, *, data: ReviewData | None = None, request: ReviewRequest | None = None,
                 options: Options | None = None) -> None:
        super().__init__()
        if (data is None) == (request is None):
            raise ValueError("a saved report or a live review request is required")
        self.options = options or Options()
        self.request = request
        self.data: ReviewData | None = data
        self.sources: SourceIndex | None = SourceIndex(data) if data is not None else None
        self.filters = view.Filters()
        self.findings: view.FindingView | None = None
        self.selected: view.FindingRow | None = None
        self.verifications: dict[str, Any] = {}
        self.running = False
        self.started: float | None = None
        self.failure: str | None = None
        self.coverage_only: str = "all"
        self.coverage_language: str | None = None
        self.coverage_rows: list[view.CoverageRow] = []
        self.coverage_columns: list[str] = []
        self.editor_runner: Any = None  # tests replace the editor runner; None runs the real editor
        self.detail_lines: list[view.Line] = []
        self.reason_line: view.Line = ()
        self.verifier: Verifier | None = None
        self.pending: set[str] = set()
        self.plan_state = PlanState(fail_on_imported=self.options.fail_on_imported)
        self.plan: Any = None
        self.plan_computing = False
        self.plan_failure: str | None = None
        self.plan_key = "summary"
        self.surface_index = 0
        self._plan_worker: Worker[Any] | None = None
        self._ticker: Timer | None = None
        self._table_width = 0

    # ---- palette and shared lines ------------------------------------------------------------

    @property
    def palette(self) -> theme.PaletteName:
        return theme.palette_for(ansi=self.native_ansi_color, dark=self.current_theme.dark, no_color=self.no_color)

    def activity(self) -> view.Activity:
        elapsed = time.monotonic() - self.started if self.running and self.started is not None else None
        return view.Activity(running=self.running, elapsed=elapsed, failure=self.failure)

    def trust_line(self, width: int) -> view.Line:
        return view.trust_bar(self.data, self.activity(), width)

    def ui_state(self, finding: WorkflowFinding | None = None) -> view.UiState:
        from polaris.tui.editor import EditorProblem, editor_words

        try:
            editor = bool(editor_words())
        except EditorProblem:
            editor = False
        mode: Literal["live", "saved", "none"] = (
            "none" if self.data is None else "live" if self.data.live else "saved")
        return view.UiState(
            mode=mode, running=self.running, finding=finding, editor=editor,
            root=self.data is not None and self.data.root is not None,
            pull_request=self.data is not None and self.data.pull_request is not None,
        )

    # ---- layout --------------------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield LineBar(id="trust")
        with TabbedContent(id="tabs", initial="findings"):
            with TabPane(TAB_TITLES["findings"], id="findings"):
                yield FindingsPane(id="findings-pane")
            with TabPane(TAB_TITLES["coverage"], id="coverage"):
                yield CoveragePane(id="coverage-pane")
            with TabPane(TAB_TITLES["surface"], id="surface"):
                yield SurfacePane(id="surface-pane")
            with TabPane(TAB_TITLES["tools"], id="tools"):
                yield NoticePane(id="tools-pane")
            with TabPane(TAB_TITLES["pr"], id="pr"):
                yield PlanPane(id="pr-pane")
        yield Input(placeholder="Filter findings: text in title, path, rule, message (enter keeps, esc clears)",
                    id="filter")
        yield LineBar(id="status")
        yield LineBar(id="keys")

    def on_mount(self) -> None:
        for custom in brand.CUSTOM_THEMES:  # the website's colours, shared with the simple view
            self.register_theme(custom)
        self.theme = theme.THEMES.get(self.options.theme, theme.THEMES["dark"])
        self.theme_changed_signal.subscribe(self, lambda _: self.refresh_all())
        self._ticker = self.set_interval(0.25, self._tick, pause=True)
        if self.data is not None:
            self.show_data(self.data)
        else:
            self.start_review()
        self.query_one(FindingsTable).focus()

    def on_resize(self, event: Resize) -> None:
        for render in (self.render_findings, self.render_coverage, self.render_surface, self.render_plan):
            self.call_after_refresh(render)

    # ---- the live review worker -------------------------------------------------------------------

    def start_review(self) -> None:
        if self.request is None or self.running:
            return
        self.running = True
        self.failure = None
        self.started = time.monotonic()
        if self._ticker is not None:
            self._ticker.resume()
        self.run_worker(partial(run_review, self.request), thread=True, exclusive=True, group="review",
                        name="review", exit_on_error=False)
        self.refresh_all()

    def _tick(self) -> None:
        self.render_bars()
        if self.data is None:
            self.render_detail()

    @on(Worker.StateChanged)
    def _worker_changed(self, event: Worker.StateChanged) -> None:
        worker = event.worker
        if event.state not in (WorkerState.SUCCESS, WorkerState.ERROR, WorkerState.CANCELLED):
            return
        if worker.group == "plan":
            self._plan_finished(worker, event.state)
            return
        if worker.group == "verify":
            self._verify_finished(worker, event.state)
            return
        if worker.group != "review":
            return
        self.running = False
        if self._ticker is not None:
            self._ticker.pause()
        if event.state == WorkerState.SUCCESS and isinstance(worker.result, ReviewData):
            self.show_data(worker.result)
            return
        error = worker.error
        self.failure = error.code if isinstance(error, SessionProblem) else "workflow_unavailable"
        self.refresh_all()
        self.notify(f"The review could not complete [{self.failure}]. Press r to try again.", severity="error",
                    markup=False)

    def show_data(self, data: ReviewData) -> None:
        self.data = data
        self.sources = SourceIndex(data)
        # One cache per review: the PR preview and the fix preview share its verifications.
        self.verifier = Verifier(data)
        self.verifications = self.verifier.results
        self.pending = set()
        self.failure = None
        self.selected = None
        self.plan = None
        self.plan_failure = None
        self.surface_index = 0
        self.refresh_all()
        if data.live and data.pull_request is not None:
            self.start_plan()

    # ---- the PR plan and fix verification workers ------------------------------------------------

    def start_plan(self) -> None:
        if self.verifier is None or self.data is None or not self.data.live or self.data.pull_request is None:
            return
        self.plan_computing = True
        self.plan_failure = None
        self._plan_worker = self.run_worker(partial(self.verifier.plan, self.plan_state), thread=True, exclusive=True,
                                            group="plan", name="plan", exit_on_error=False)
        self.render_plan()

    def _plan_finished(self, worker: Worker[Any], state: WorkerState) -> None:
        if worker is not self._plan_worker:
            return  # a plan for an earlier review or earlier options
        self.plan_computing = False
        if state == WorkerState.SUCCESS:
            self.plan = worker.result
        else:
            self.plan_failure = "plan_unavailable"
        self.render_plan()
        self.render_detail()
        self.render_bars()

    def verify(self, finding: WorkflowFinding) -> None:
        if self.verifier is None or finding.finding_id in self.pending or self.verifier.known(finding) is not None:
            return
        self.pending.add(finding.finding_id)
        verifier = self.verifier
        self.run_worker(partial(verifier.verify, finding), thread=True, group="verify",
                        name=finding.finding_id, exit_on_error=False)

    def _verify_finished(self, worker: Worker[Any], state: WorkerState) -> None:
        self.pending.discard(worker.name)
        if state != WorkerState.SUCCESS:
            self.notify("The edit could not be re-verified.", severity="warning", markup=False)
        self.render_detail()
        if isinstance(self.screen, FixScreen):
            self.screen.refresh_fix()

    def verification_for(self, finding: WorkflowFinding) -> Any:
        if finding.finding_id in self.pending:
            return "pending"
        return self.verifier.known(finding) if self.verifier is not None else None

    # ---- rendering -------------------------------------------------------------------------------

    def refresh_all(self) -> None:
        self.render_findings()
        self.render_coverage()
        self.render_surface()
        self.render_tools()
        self.render_plan()
        self.render_bars()

    def current_tab(self) -> str:
        try:
            return self.query_one(TabbedContent).active or "findings"
        except Exception:  # noqa: BLE001 - during start-up the tabs may not exist yet
            return "findings"

    def key_context(self) -> str:
        focused = self.focused
        tab = self.current_tab()
        if isinstance(focused, FileTree):
            return "tree"
        if tab in ("coverage", "pr", "surface", "tools"):
            return tab
        return "findings"

    def render_bars(self) -> None:
        palette = self.palette
        self.query_one("#trust", LineBar).show_fitted(self.trust_line, palette)
        tab = self.current_tab()
        if tab == "findings" and self.findings is not None:
            status = self.findings.status(self.filters)
        elif tab == "coverage" and self.data is not None:
            status = view.coverage_summary(self.data, self.coverage_rows)
        elif tab == "surface" and self.data is not None:
            status = panels.surface_summary(self.data.envelope.review.surface)
        elif tab == "tools" and self.data is not None:
            review = self.data.envelope.review
            status = view.line((f"{len(review.imported)} imported result(s) from {len(review.imports)} SARIF file(s)",
                                "label"), (" · untrusted, not verified by Polaris", "muted"))
        elif tab == "pr" and self.plan is not None:
            gate = theme.GATE.get(self.plan.gate, theme.GATE["incomplete"])
            status = view.line(("Gate ", "label"), view.state_span(gate),
                               (f" · {self.plan.counts.inline} inline comment(s) · local preview, nothing is "
                                "published", "muted"))
        elif self.running:
            status = view.line(("Reviewing… the interface stays responsive; q quits.", "running"))
        else:
            status = view.line(("Press ? for keys and glyphs.", "muted"))
        self.query_one("#status", LineBar).show(status, palette)
        finding = self.selected.finding if self.selected is not None and tab == "findings" else None
        hints = view.key_hints(self.key_context(), self.ui_state(finding))
        self.query_one("#keys", LineBar).show_fitted(lambda width: view.key_bar(hints, width), palette)

    def _columns(self, table: FindingsTable) -> list[tuple[str, int]]:
        width = table.size.width or max(40, self.size.width - 28)
        # 6 + 8 for severity and kind, 8 for cell padding, 2 for the scrollbar.
        rest = max(20, width - 6 - 8 - 8 - 2)
        finding = max(12, rest // 2)
        return [("Sev", 6), ("Kind", 8), ("Finding", finding), ("Where", max(10, rest - finding))]

    def render_findings(self) -> None:
        table = self.query_one(FindingsTable)
        if self.data is None:
            table.clear(columns=True)
            self.findings = None
            self.render_tree(None)
            self.render_detail()
            return
        previous = self.selected.key if self.selected is not None else None
        self.findings = view.finding_view(self.data, self.filters)
        palette = self.palette
        columns = self._columns(table)
        widths = sum(width for _, width in columns)
        if not table.columns or widths != self._table_width:
            table.clear(columns=True)
            for label, width in columns:
                table.add_column(Text(label), width=width, key=label.lower())
            self._table_width = widths
        else:
            table.clear()
        where_width = columns[-1][1]
        for row in self.findings.rows:
            table.add_row(*to_cells(row.cells(where_width), palette), key=row.key)
        rows = self.findings.rows
        index = next((position for position, row in enumerate(rows) if row.key == previous), 0)
        self.selected = rows[index] if rows else None
        if rows:
            table.move_cursor(row=index, animate=False)
        self.render_tree(self.findings)
        self.render_detail()

    def render_tree(self, findings: view.FindingView | None) -> None:
        tree = self.query_one(FileTree)
        cursor = tree.cursor_node.data if tree.cursor_node is not None else None
        tree.clear()
        palette = self.palette
        if self.data is None or findings is None:
            tree.root.set_label(Text("All files"))
            return
        root = view.file_tree(self.data, findings)
        tree.root.set_label(to_text(view.line(("All files", "label"), *(
            ((f"  {root.issues}{theme.severity(root.worst).glyph}", theme.severity(root.worst).role),)
            if root.issues else ()), *(((f"  {root.questions}?", "result.verify"),) if root.questions else ())),
            palette, no_wrap=True))
        count = 0

        def add(parent: TreeNode[str], node: view.FileNode) -> None:
            nonlocal count
            for child in node.sorted_children():
                count += 1
                label = to_text(child.label(), palette, no_wrap=True)
                if child.directory:
                    branch = parent.add(label, data=child.path, expand=count < MAX_TREE_EXPANDED)
                    add(branch, child)
                else:
                    parent.add_leaf(label, data=child.path)

        add(tree.root, root)
        tree.root.expand()
        if cursor is not None:
            match = self._tree_node(tree.root, cursor)
            if match is not None:
                tree.move_cursor(match)

    def _tree_node(self, node: TreeNode[str], path: str) -> TreeNode[str] | None:
        if node.data == path:
            return node
        for child in node.children:
            found = self._tree_node(child, path)
            if found is not None:
                return found
        return None

    def render_detail(self) -> None:
        body = self.query_one("#detail-body", Static)
        palette = self.palette
        if self.data is None or self.sources is None:
            if self.running:
                lines = [view.line((f"{theme.FRESHNESS['running'].label} — {view.seconds(self.activity().elapsed)}",
                                    "running")), (),
                         view.line(("The review runs in the background; the interface stays responsive.", "muted")),
                         view.line(("Nothing from the repository is executed, and no model is used.", "muted"))]
            elif self.failure is not None:
                lines = [view.line((f"{theme.FRESHNESS['failed'].label}: ", "stale"),
                                   (error_message(self.failure), "text"), (f" [{self.failure}]", "muted")), (),
                         view.line(("Press ", "muted"), ("r", "key"), (" to try again, or ", "muted"), ("q", "key"),
                                   (" to quit.", "muted"))]
            else:
                lines = []
        elif self.selected is None:
            lines = self.empty_lines()
        else:
            verification = self.verification_for(self.selected.finding)
            lines = view.detail_lines(self.selected, self.data, self.sources, verification=verification)
        self.detail_lines = lines
        body.update(to_block(lines, palette))

    def empty_lines(self) -> list[view.Line]:
        findings = self.findings
        if findings is None:
            return []
        floor = theme.severity(self.filters.floor)
        lines: list[view.Line] = []
        if findings.issues_total == 0 and findings.questions_total == 0:
            lines.append(view.line(("No findings. ", "label"), (
                "These checks found nothing in what was reviewed: that is not proof the code is safe. "
                "See what was and wasn't checked in Coverage (2).", "text")))
        else:
            lines.append(view.line((f"Nothing to show at {floor.label}+ with these filters.", "label")))
            if findings.issues_below_floor:
                lines.append(view.line((f"{findings.issues_below_floor} issue(s) are below the floor: press ", "text"),
                                       ("s", "key"), (" to lower it.", "text")))
            if not self.filters.questions and findings.questions_total:
                lines.append(view.line((f"{findings.questions_total} question(s) are hidden: press ", "text"),
                                       ("v", "key"), (" to show them.", "text")))
            if self.filters.query or self.filters.path:
                lines.append(view.line(("A file or text filter is active: press ", "text"), ("esc", "key"),
                                       (" to clear it.", "text")))
        return lines

    def render_coverage(self) -> None:
        table = self.query_one(CoverageTable)
        palette = self.palette
        if self.data is None:
            table.clear(columns=True)
            self.query_one("#what-ran-body", Static).update(Text(""))
            return
        columns = view.coverage_columns(self.data)
        only: Literal["all", "unreviewed", "excluded"] = (
            "unreviewed" if self.coverage_only == "unreviewed" else "excluded" if self.coverage_only == "excluded"
            else "all")
        rows = view.coverage_rows(self.data, only=only, language=self.coverage_language)
        self.coverage_rows, self.coverage_columns = rows, columns
        cursor = table.cursor_coordinate
        table.clear(columns=True)
        available = table.size.width or (self.size.width if self.size.width < 110 else self.size.width * 2 // 3)
        # The file's overall state leads its name (as in the tree); every other column is a check.
        path_width = max(14, min(50, available - 3 * len(columns) - 1))
        table.add_column(Text("File"), width=path_width, key="path")
        for check in columns:
            table.add_column(Text(view.CHECK_CODES.get(check, "??")), width=3, key=check)
        for row in rows:
            cells = [to_text(view.coverage_file(row, path_width), palette, no_wrap=True)]
            cells.extend(to_text(view.coverage_cell(row.cells[check]), palette, no_wrap=True) for check in columns)
            table.add_row(*cells, key=row.path)
        if rows:
            table.move_cursor(row=min(cursor.row, len(rows) - 1), column=min(cursor.column, len(columns)),
                              animate=False)
        self.query_one("#coverage-legend", Static).update(to_text(view.legend(columns), palette))
        self.query_one("#what-ran-body", Static).update(to_block(view.what_ran(self.data, self.sources), palette))
        self.render_cell_reason()

    def render_cell_reason(self) -> None:
        reason = self.query_one("#coverage-reason", Static)
        table = self.query_one(CoverageTable)
        palette = self.palette
        if not self.coverage_rows:
            filters = {"unreviewed": "files not fully reviewed", "excluded": "excluded files"}.get(self.coverage_only)
            message = f"No {filters} in this review." if filters else "No coverage rows."
            self.reason_line = view.line((message, "muted"))
            reason.update(to_text(self.reason_line, palette))
            return
        row_index = min(table.cursor_row, len(self.coverage_rows) - 1)
        row = self.coverage_rows[max(0, row_index)]
        column = table.cursor_column - 1
        if 0 <= column < len(self.coverage_columns):
            line = view.cell_explanation(row, self.coverage_columns[column])
        else:
            state = theme.COVERAGE.get(row.state, theme.COVERAGE["not_applicable"])
            line = view.line((clean(row.path, 200), "label"), (f" ({clean(row.language, 30)}): ", "muted"),
                             view.state_span(state), *(((f" — {view.reason_text(row.gap)}", "text"),)
                                                       if row.gap else ()))
        self.reason_line = line
        reason.update(to_text(line, palette))

    def render_surface(self) -> None:
        table = self.query_one(SurfaceTable)
        palette = self.palette
        summary = self.query_one("#surface-summary", Static)
        body = self.query_one("#surface-detail-body", Static)
        table.clear(columns=True)
        if self.data is None:
            summary.update(Text(""))
            body.update(Text(""))
            return
        entries = self.data.envelope.review.surface
        summary.update(to_text(panels.surface_summary(entries), palette, no_wrap=True))
        if not entries:
            body.update(to_block([
                view.line(("No entry points were recognized in the reviewed files.", "label")), (),
                view.line(("The attack surface lists TypeScript/JavaScript route handlers, pages/api routes, server "
                           "actions and Express/Hono/Fastify registrations. Python handlers aren't listed yet. Reports "
                           "saved before this field existed have no surface.", "muted"))], palette))
            return
        columns = panels.surface_columns(table.size.width or self.size.width)
        where_width = dict(columns)["Where"]
        for label, size in columns:
            table.add_column(Text(label), width=size, key=label.lower())
        for key, cells in panels.surface_rows(self.data, where_width):
            table.add_row(*to_cells(cells, palette), key=key)
        index = min(self.surface_index, len(entries) - 1)
        table.move_cursor(row=index, animate=False)
        body.update(to_block(panels.surface_detail(entries[index], self.data), palette))

    def render_tools(self) -> None:
        pane = self.query_one("#tools-pane", NoticePane)
        lines = panels.tools_lines(self.data) if self.data is not None else []
        pane.query_one(".notice-body", Static).update(to_block(lines, self.palette))

    def render_plan(self) -> None:
        header = self.query_one("#plan-header", Static)
        table = self.query_one(PlanTable)
        body = self.query_one("#plan-body-text", Static)
        palette = self.palette
        table.clear(columns=True)
        data = self.data
        if data is None or not data.live or data.pull_request is None:
            header.update(to_block(panels.plan_unavailable(data), palette))
            body.update(Text(""))
            return
        header_width = (header.size.width or self.size.width) - 2  # the header's padding
        header.update(to_block(panels.plan_header(self.plan, self.plan_state, data, computing=self.plan_computing,
                                                  width=header_width), palette))
        if self.plan is None:
            message = ("The plan could not be computed [plan_unavailable]." if self.plan_failure else
                       "Computing the plan offline: re-verifying suggested edits in memory…")
            body.update(to_block([view.line((message, "muted"))], palette))
            return
        columns = panels.plan_columns(table.size.width or self.size.width)
        where_width = dict(columns)["Where"]
        for label, size in columns:
            table.add_column(Text(label), width=size, key=label.lower())
        rows = panels.plan_rows(self.plan, where_width)
        for key, cells in rows:
            table.add_row(*to_cells(cells, palette), key=key)
        keys = [key for key, _ in rows]
        if self.plan_key not in keys:
            self.plan_key = "summary"
        table.move_cursor(row=keys.index(self.plan_key), animate=False)
        body.update(to_block(panels.plan_body(self.plan, self.plan_key), palette))

    # ---- events ----------------------------------------------------------------------------------

    @on(DataTable.RowHighlighted, "#table")
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.findings is None:
            return
        key = event.row_key.value
        self.selected = next((row for row in self.findings.rows if row.key == key), None)
        self.render_detail()
        self.render_bars()

    @on(DataTable.RowSelected, "#table")
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        self.query_one("#detail").focus()

    @on(DataTable.CellHighlighted, "#matrix")
    def _cell_highlighted(self, event: DataTable.CellHighlighted) -> None:
        self.render_cell_reason()

    @on(DataTable.RowHighlighted, "#surface-table")
    def _surface_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.data is None or not self.data.envelope.review.surface:
            return
        key = event.row_key.value or "entry-0"
        self.surface_index = int(key.split("-")[1])
        entry = self.data.envelope.review.surface[self.surface_index]
        self.query_one("#surface-detail-body", Static).update(
            to_block(panels.surface_detail(entry, self.data), self.palette))

    @on(DataTable.RowSelected, "#surface-table")
    def _surface_selected(self, event: DataTable.RowSelected) -> None:
        self.surface_jump()

    @on(DataTable.RowHighlighted, "#plan-table")
    def _plan_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.plan is None or event.row_key.value is None:
            return
        self.plan_key = event.row_key.value
        self.query_one("#plan-body-text", Static).update(to_block(panels.plan_body(self.plan, self.plan_key),
                                                                  self.palette))

    @on(Tree.NodeSelected, "#tree")
    def _node_selected(self, event: Tree.NodeSelected[str]) -> None:
        path = event.node.data or None
        self.filters = view.Filters(self.filters.floor, self.filters.questions, self.filters.query,
                                    None if path == self.filters.path else path)
        self.render_findings()
        self.render_bars()

    @on(TabbedContent.TabActivated)
    def _tab_activated(self, event: TabbedContent.TabActivated) -> None:
        tab = self.current_tab()
        target = {"findings": "#table", "coverage": "#matrix", "surface": "#surface-table", "tools": "#tools-pane",
                  "pr": "#plan-table"}.get(tab)
        if target:
            self.query_one(target).focus()
        # Column widths depend on the pane's size, known only once it is shown.
        render = {"coverage": self.render_coverage, "surface": self.render_surface, "pr": self.render_plan}.get(tab)
        if render is not None:
            self.call_after_refresh(render)
        self.render_bars()

    def on_descendant_focus(self) -> None:
        self.render_bars()

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self.filters = view.Filters(self.filters.floor, self.filters.questions, event.value.strip()[:200],
                                    self.filters.path)
        self.render_findings()
        self.render_bars()

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        self._close_filter()

    def _close_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.remove_class("-active")
        self.query_one(FindingsTable).focus()

    # ---- actions -----------------------------------------------------------------------------------

    def _blocked(self, action: str, finding: WorkflowFinding | None = None) -> bool:
        reason = view.availability(action, self.ui_state(finding))
        if reason is not None:
            self.notify(view.notice(reason), severity="warning", markup=False, timeout=6)
            return True
        return False

    def _selected_finding(self) -> WorkflowFinding | None:
        if self.current_tab() != "findings" or self.selected is None:
            return None
        return self.selected.finding

    def action_tab(self, name: str) -> None:
        if name in TABS:
            self.query_one(TabbedContent).active = name

    def action_help(self) -> None:
        self.push_screen(TextScreen("Polaris keys, glyphs and safety",
                                    view.help_lines(self.ui_state(self._selected_finding())), self.palette,
                                    hint="esc closes."))

    def action_filter(self) -> None:
        if self.current_tab() != "findings":
            self.action_tab("findings")
        box = self.query_one("#filter", Input)
        box.add_class("-active")
        box.value = self.filters.query
        box.focus()

    def action_clear(self) -> None:
        box = self.query_one("#filter", Input)
        if box.has_class("-active"):
            box.value = ""
            self._close_filter()
            return
        if self.filters.query or self.filters.path:
            self.filters = view.Filters(self.filters.floor, self.filters.questions)
            self.render_findings()
            self.render_bars()

    def action_floor(self) -> None:
        self.filters = view.Filters(view.next_floor(self.filters.floor), self.filters.questions, self.filters.query,
                                    self.filters.path)
        self.render_findings()
        self.render_bars()

    def action_questions(self) -> None:
        self.filters = view.Filters(self.filters.floor, not self.filters.questions, self.filters.query,
                                    self.filters.path)
        self.render_findings()
        self.render_bars()

    def action_rerun(self) -> None:
        if self._blocked("rerun"):
            return
        self.start_review()

    def action_walk(self) -> None:
        finding = self._selected_finding()
        if self._blocked("walk", finding) or self.selected is None or self.sources is None:
            return
        self.push_screen(WalkScreen(self.selected, view.walk_steps(self.selected.finding, self.sources)))

    def action_fix(self) -> None:
        finding = self._selected_finding()
        if self._blocked("fix", finding) or finding is None or self.data is None or self.sources is None:
            return
        data, sources = self.data, self.sources

        def render() -> list[view.Line]:
            left = self.verifier.left if self.verifier is not None else 0
            return panels.fix_lines(finding, data, sources, self.verification_for(finding), left=left)

        edit_line = finding.suggested_edit.line if finding.suggested_edit is not None else finding.start_line
        self.push_screen(FixScreen(finding.finding_id, render, partial(self.open_in_editor, finding.path, edit_line),
                                   self.palette))
        if data.live:
            self.verify(finding)
            if isinstance(self.screen, FixScreen):
                self.screen.refresh_fix()

    def action_plan_option(self, option: str) -> None:
        if self._blocked("pr_option"):
            return
        if option not in ("inline", "questions", "gate", "imported", "fail_imported", "verify"):
            return
        self.plan_state = self.plan_state.toggled(option)  # type: ignore[arg-type]
        self.start_plan()
        self.render_bars()

    def _surface_entry(self) -> Any:
        if self.data is None or not self.data.envelope.review.surface:
            return None
        entries = self.data.envelope.review.surface
        return entries[min(self.surface_index, len(entries) - 1)]

    def action_surface_open(self) -> None:
        entry = self._surface_entry()
        if entry is None:
            self.notify("No entry point is selected.", severity="warning", markup=False)
            return
        self.open_in_editor(entry.path, entry.line)  # reports a missing editor or root itself

    def surface_jump(self) -> None:
        """Show the selected handler's first finding in the cockpit (lowering the floor if needed)."""
        entry = self._surface_entry()
        if entry is None or self.data is None:
            return
        findings = {finding.finding_id: finding for finding in self.data.envelope.review.findings}
        linked = [findings[item] for item in entry.findings if item in findings]
        if not linked:
            self.notify("No findings inside this handler.", markup=False, timeout=3)
            return
        target = linked[0]
        floor = self.filters.floor
        if target.result == "flagged" and not theme.at_least(target.severity, floor):
            floor = target.severity or "medium"
        self.filters = view.Filters(floor, True, "", None)
        self.action_tab("findings")
        self.render_findings()
        rows = self.findings.rows if self.findings is not None else ()
        index = next((position for position, row in enumerate(rows) if row.finding.finding_id == target.finding_id), None)
        if index is not None:
            self.query_one(FindingsTable).move_cursor(row=index, animate=False)
            self.selected = rows[index]
            self.render_detail()
        self.render_bars()

    def action_open(self) -> None:
        finding = self._selected_finding()
        if self._blocked("open", finding) or finding is None:
            return
        self.open_in_editor(finding.path, finding.start_line)

    def action_prompt(self) -> None:
        finding = self._selected_finding()
        if self._blocked("prompt", finding) or finding is None:
            return
        self.copy_prompt(finding)

    def action_save(self) -> None:
        if self._blocked("save") or self.data is None:
            return
        suggestion = f"polaris-review-{self.data.envelope.report_id.split(':')[-1][:12]}.json"
        self.push_screen(SaveScreen(suggestion, self.save_report, self.palette))

    def action_coverage(self, which: str) -> None:
        if self.data is None:
            return
        if which == "language":
            languages = view.coverage_languages(self.data)
            if not languages:
                return
            current = self.coverage_language
            index = (languages.index(current) + 1) if current in languages else 0
            self.coverage_language = languages[index] if index < len(languages) else None
        elif which == "all":
            self.coverage_only, self.coverage_language = "all", None
        else:
            self.coverage_only = "all" if self.coverage_only == which else which
        self.render_coverage()
        self.render_bars()
        language = self.coverage_language or "all languages"
        self.notify(f"Coverage: {self.coverage_only} files, {language}.", markup=False, timeout=2)

    # ---- side effects (each one only after a key press) ---------------------------------------------------

    def open_in_editor(self, path: str, line: int) -> None:
        from textual.app import SuspendNotSupported

        from polaris.tui.editor import EditorProblem, build_command, run_editor

        try:
            command = build_command(self.data.root if self.data is not None else None, path, line)
        except EditorProblem as problem:
            self.notify(problem.message, severity="warning", markup=False)
            return
        try:
            with self.suspend():
                if self.editor_runner is not None:
                    run_editor(command, runner=self.editor_runner)
                else:
                    run_editor(command)
        except SuspendNotSupported:
            self.notify("This terminal session cannot hand control to an editor.", severity="warning", markup=False)
        except EditorProblem as problem:
            self.notify(problem.message, severity="warning", markup=False)

    def copy_prompt(self, finding: WorkflowFinding) -> None:
        from polaris.integrations.forge.plan import agent_prompt

        prompt = agent_prompt(finding, finding.start_line)
        lines = clean_block(prompt, 3_000)
        self.copy_to_clipboard("\n".join(lines))
        self.push_screen(PromptScreen(lines, self.palette))

    def save_report(self, value: str) -> str | None:
        """Write the report to a new file. Returns a fixed problem message, or None when saved."""
        from polaris.integrations._safe import IntegrationProblem
        from polaris.workflow.cli import _emit

        if self.data is None:
            return "There is no review to save yet."
        if not value or "\0" in value or len(value) > 4_096:
            return "Enter a file name."
        target = Path(value).expanduser()
        if not target.is_absolute():
            target = Path(os.getcwd()) / target
        try:
            _emit(report_json(self.data), target)
        except FileExistsError:
            return "That file already exists; choose a new name (files are never overwritten)."
        except (IntegrationProblem, OSError, ValueError):
            return "The report could not be written there (existing files and symbolic links are refused)."
        self.notify(f"Saved the report to {clean(target.name, 120)}.", markup=False)
        return None

    # ---- the command palette ------------------------------------------------------------------------

    def get_system_commands(self, screen: Screen[Any]) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand("Re-run the review", "Review the same selection again (live reviews)", self.action_rerun)
        yield SystemCommand("Save the report", "Write the review as JSON to a new file", self.action_save)
        yield SystemCommand("Severity floor", "Cycle the lowest issue severity shown", self.action_floor)
        yield SystemCommand("Questions", "Show or hide 'to verify' questions", self.action_questions)
        yield SystemCommand("Filter findings", "Filter by text in title, path, rule or message", self.action_filter)
        yield SystemCommand("Help", "Keys, glyphs and safety", self.action_help)
        for name in TABS:
            yield SystemCommand(f"Show {TAB_TITLES[name][2:]}", f"Switch to the {TAB_TITLES[name][2:]} tab",
                                partial(self.action_tab, name))

"""What the simple view says: lines of (text, role) spans, built from one `CheckResult`.

Plain words only, in the catalog's voice. Jargon (check ids, rules, CWE, severity, the evidence
trail) appears only under "Technical details", which a key press shows. Repository-derived text
(file names, code lines, evidence labels) goes through `printable` or `clean_code_line` first, so
it is displayed and never interpreted. Roles name a style in `polaris.tui.brand`, and every state
has a mark and a word, never colour alone. Nothing here imports Textual, so each screen's
wording is testable on its own.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from rich.cells import cell_len, set_cell_size

from polaris.check import brand
from polaris.check.build import plural
from polaris.check.model import CheckItem, CheckResult, Priority, SuggestedFix
from polaris.review.models import WORKFLOW_DEFAULT_CHECKS
from polaris.review.sarif_import import text as printable
from polaris.tui.source import SourceIndex
from polaris.tui.text import clean_code_line

Span = tuple[str, str]
Line = tuple[Span, ...]
KINDS = len(WORKFLOW_DEFAULT_CHECKS)
DASH = " \u2014 "
ELLIPSIS = "\u2026"
CHOSEN = "\u25b6"  # ▶ the chosen row
BAR = "\u2502"  # │ between a line number and its code
MAX_CODE_LINES = 5
MAX_NOT_CHECKED = 3
FILE_COLUMN = 24
PRIVACY_NOTE = ("Polaris reads your code on this computer. Nothing is sent anywhere, no AI model is used, "
                "and nothing in your project is run.")
COPY_HINT = ("Paste it into your AI chat. If nothing pastes, your terminal blocked the copy: hold Shift "
             "(Option in some terminals), select the text below with your mouse, and copy it.")


def line(*spans: Span) -> Line:
    return tuple(span for span in spans if span[0])


def plain(value: Line) -> str:
    """The text of a line without styles (for tests and text renderings)."""
    return "".join(text for text, _ in value)


def plain_lines(lines: Iterable[Line]) -> str:
    return "\n".join(plain(value) for value in lines)


def is_code(value: Line) -> bool:
    """Code keeps its columns: rendered cropped, never wrapped."""
    return any(role.startswith("code") for _, role in value)


def truncate(value: str, width: int) -> str:
    """At most `width` terminal columns, ending with an ellipsis when cut."""
    if width <= 0:
        return ""
    if cell_len(value) <= width:
        return value
    return set_cell_size(value, width - 1).rstrip() + ELLIPSIS


def sentence(value: str) -> str:
    return value if value.endswith((".", "?", "!")) else value + "."


def file_name(path: str) -> str:
    return printable(PurePosixPath(path).name or path, 120) or "?"


def shown_path(path: str) -> str:
    return printable(path, 300) or "?"


def project_name(root: Path | None) -> str:
    return (printable(root.name, 60) if root is not None else "") or "your project"


def kinds(count: int) -> str:
    return "1 kind of problem" if count == 1 else f"{count} kinds of problems"


def total(result: CheckResult) -> int:
    counts = result.counts
    return counts.fix_now + counts.check_this + counts.worth_a_look


def ago(seconds: float) -> str:
    """When the check ran, in words: "checked just now", "checked 5 minutes ago"."""
    minutes = int(max(0.0, seconds) // 60)
    if minutes < 1:
        return "checked just now"
    if minutes < 60:
        return f"checked {plural(minutes, 'minute')} ago"
    hours = minutes // 60
    return f"checked {plural(hours, 'hour')} ago" if hours < 24 else f"checked {plural(hours // 24, 'day')} ago"


# ---- headers -----------------------------------------------------------------------------------

BRAND: tuple[Span, ...] = ((brand.STAR, "star"), (" ", "text"), (brand.NAME, "brand.name"))


def header(project: str, scope: str, when: str, width: int) -> Line:
    """`✦ POLARIS   my-app · your changes · checked just now`, shortened to fit `width`."""
    room = width - cell_len(plain(BRAND)) - 3
    parts = [(part, role) for part, role in ((project, "label"), (scope, "text"), (when, "muted")) if part]
    if cell_len(" \u00b7 ".join(part for part, _ in parts)) > room:
        parts = parts[:2]  # the time goes first
    joined = " \u00b7 ".join(part for part, _ in parts)
    if cell_len(joined) > room:
        return line(*BRAND, ("   ", "text"), (truncate(joined, room), "text"))
    spans: list[Span] = [*BRAND, ("   ", "text")]
    for index, part in enumerate(parts):
        if index:
            spans.append((" \u00b7 ", "muted"))
        spans.append(part)
    return line(*spans)


def badge(priority: Priority) -> Span:
    return (f"{brand.PRIORITY_MARKS[priority]} {brand.PRIORITY_WORDS[priority]}", priority)


def problem_header(item: CheckItem, width: int) -> Line:
    """`✦ POLARIS  ›  <the problem>   ● Fix now`, the problem shortened to fit `width`."""
    lead = [*BRAND, ("  \u203a  ", "muted")]
    mark = badge(item.priority)
    room = width - cell_len(plain(tuple(lead))) - 3 - cell_len(mark[0])
    if room < 8:
        return line(*lead, (truncate(item.title, width - cell_len(plain(tuple(lead)))), "label"))
    return line(*lead, (truncate(item.title, room), "label"), ("   ", "text"), mark)


# ---- the results screen ------------------------------------------------------------------------


def status_lines(result: CheckResult) -> list[Line]:
    """The answer to "Is it safe to ship?", first. All clear adds the honest line."""
    counts = result.counts
    mark = brand.STATUS_MARKS[result.status]
    word = brand.STATUS_WORDS[result.status]
    if result.status == "fix_needed":
        return [line(("Safe to ship?", "label"), ("  ", "text"), (f"{mark} {word}", "fix_now"),
                     (f"{DASH}{plural(counts.fix_now, 'thing')} to fix.", "text"))]
    if result.status == "incomplete":
        return [line(("Safe to ship?", "label"), ("  ", "text"), (f"{mark} {word}", "check_this"),
                     (f". {printable(result.summary, 600)}", "text"))]
    scope = printable(result.scope_label, 200)
    if counts.files_checked == 0:
        verdict = f"there was no code to check in {scope}."
    elif total(result) == 0:
        verdict = f"no problems found in {scope}."
    else:
        verdict = f"nothing to fix now in {scope}."
    return [line((f"{mark} {word}", "clear"), (f"{DASH}{verdict}", "text")), (), honest_line(result)]


def honest_line(result: CheckResult) -> Line:
    """What "all clear" means, and what it doesn't."""
    counts = result.counts
    if counts.files_checked == 0:
        return line((f"Polaris looks for {kinds(counts.kinds_of_problems)} in code, and found no code to check.",
                     "text"))
    found = "nothing" if total(result) == 0 else "nothing to fix now"
    return line((f"Polaris checked {plural(counts.files_checked, 'file')} for {kinds(counts.kinds_of_problems)}. "
                 f"That means these checks found {found}, not that the code is perfect.", "text"))


def since_line(result: CheckResult) -> Line:
    since = result.since_last_check
    if since is None:
        return ()
    return line((f"Since your last check: {len(since.fixed)} fixed, {len(since.new)} new, "
                 f"{len(since.still_open)} still open.", "muted"))


def section_title(priority: Priority, count: int, *, expanded: bool = True) -> Line:
    """"● Fix now", "? Check this (1)", "○ Worth a look (5) — press w to show"."""
    spans: list[Span] = [badge(priority)]
    if priority != "fix_now":
        spans.append((f" ({count})", "muted"))
    if priority == "worth_a_look":
        spans += [(f"{DASH}press ", "muted"), ("w", "key"), (" to hide" if expanded else " to show", "muted")]
    return line(*spans)


def row_label(item: CheckItem) -> str:
    """A list row's words: the question for "check this" items, the problem otherwise."""
    return item.question if item.priority == "check_this" and item.question else item.title


def file_column(items: Sequence[CheckItem]) -> int:
    return min(FILE_COLUMN, max((cell_len(file_name(item.where.file)) for item in items), default=0))


def row(item: CheckItem, *, chosen: bool, width: int, file_width: int) -> Line:
    """One problem: ▶ when chosen, its plain words, then the file name in its own column.
    Exactly `width` columns, so the chosen row's highlight spans the line."""
    suffix = ".selected" if chosen else ""
    name_width = min(file_width, max(0, (width - 2) // 3)) if width >= 30 else 0
    gap = 2 if name_width else 0
    words_width = max(1, width - 2 - gap - name_width)
    words = truncate(row_label(item), words_width)
    name = truncate(file_name(item.where.file), name_width)
    return line(
        (f"{CHOSEN} " if chosen else "  ", "row.marker" + suffix),
        (words + " " * (words_width - cell_len(words)), "row" + suffix),
        (" " * gap + name + " " * (name_width - cell_len(name)), "row.file" + suffix),
    )


def more_line(result: CheckResult, priority: Priority) -> Line:
    extra = result.more.get(priority, 0)
    if not extra:
        return ()
    tail = " Fix these first, then check again." if priority == "fix_now" else ""
    return line((f"{ELLIPSIS} and {extra} more.{tail}", "muted"))


def checked_lines(result: CheckResult) -> list[Line]:
    """What was checked, and what couldn't be, in plain words (plus the check's notes)."""
    counts = result.counts
    files = plural(counts.files_checked, "file")
    entries = result.not_checked
    missing = counts.files_not_checked
    lines: list[Line] = []
    if not missing:
        lines.append(line((f"Checked {files} for {kinds(counts.kinds_of_problems)}.", "text")))
    else:
        reasons = {entry.reason for entry in entries}
        reason = next(iter(reasons)) if len(reasons) == 1 else ""
        if len(entries) == missing and reason.startswith("Polaris can't check"):
            lines.append(line((f"Checked {files}. {missing} couldn't be checked ({printable(reason, 200)}).",
                               "text")))
        else:
            lines.append(line((f"Checked {files}. {missing} couldn't be checked:", "text")))
            listed = entries[:MAX_NOT_CHECKED]
            for entry in listed:
                lines.append(line((f"  {shown_path(entry.file)}{DASH}{printable(entry.reason, 200)}", "text")))
            if missing > len(listed):
                lines.append(line((f"  {ELLIPSIS} and {missing - len(listed)} more.", "text")))
    return lines + note_lines(result)


def note_lines(result: CheckResult) -> list[Line]:
    lines = [line((printable(note, 600), "muted")) for note in result.notes]
    other = result.other_tools
    if other is not None and other.results:
        names = ", ".join(printable(tool, 60) for tool in other.tools[:3]) or "other tools"
        lines.append(line((f"Other tools ({names}) reported {plural(other.results, 'result')}, which Polaris "
                           "didn't verify. Press x to see them.", "muted")))
    return lines


# ---- keys -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Key:
    """A key and what it does. `rank` 0 is always shown; 1 is a screen's main keys; higher
    ranks give way sooner when the line is short."""

    key: str
    words: str
    short: str = ""
    rank: int = 2


def key_bar(keys: Sequence[Key], width: int) -> Line:
    """Keys as words, in order, fitted to `width`: tighter spacing first; then shorter words, then
    fewer keys, among the secondary keys (least important first); only then the main keys."""
    shown = list(keys)
    labels = {id(key): key.words for key in shown}

    def fitted() -> Line | None:
        size = sum(cell_len(key.key) + 1 + cell_len(labels[id(key)]) for key in shown)
        for gap in (3, 2):
            if size + gap * max(0, len(shown) - 1) <= width:
                return _keys([(key, labels[id(key)]) for key in shown], gap)
        return None

    def weakest(main: bool) -> list[Key]:
        order = {id(key): index for index, key in enumerate(shown)}
        candidates = [key for key in shown if key.rank > 0 and (key.rank == 1) == main]
        return sorted(candidates, key=lambda key: (-key.rank, -order[id(key)]))

    if (done := fitted()) is not None:
        return done
    for main in (False, True):
        for key in weakest(main):
            if key.short:
                labels[id(key)] = key.short
                if (done := fitted()) is not None:
                    return done
        for key in weakest(main):
            shown = [other for other in shown if other is not key]
            if (done := fitted()) is not None:
                return done
    return _keys([(key, labels[id(key)]) for key in shown], 2)


def _keys(entries: Sequence[tuple[Key, str]], gap: int) -> Line:
    spans: list[Span] = []
    for index, (key, label) in enumerate(entries):
        if index:
            spans.append((" " * gap, "text"))
        spans += [(key.key, "key"), (f" {label}", "text")]
    return line(*spans)


HELP = Key("?", "help", rank=0)
QUIT = Key("q", "quit", rank=0)


def results_keys(result: CheckResult, *, expanded: bool, expert: bool) -> list[Key]:
    keys: list[Key] = []
    if result.items:
        keys += [Key("\u2191\u2193", "choose", rank=1), Key("Enter", "details", rank=1)]
    if result.counts.fix_now:
        keys.append(Key("a", "copy all fixes for your AI", "copy all fixes"))
    keys.append(Key("r", "check again"))
    if result.items:
        keys.append(Key("c", "copy fix for your AI", "copy fix", rank=3))
    if any(item.priority == "worth_a_look" for item in result.items):
        keys.append(Key("w", "hide worth a look" if expanded else "show worth a look",
                        "show less" if expanded else "show more", rank=3))
    if expert:
        keys.append(Key("x", "expert view", rank=4))
    if result.items:
        keys.append(Key("o", "open file", rank=4))
    return [*keys, HELP, QUIT]


def problem_keys(result: CheckResult, *, technical: bool, expert: bool) -> list[Key]:
    keys = [Key("c", "copy fix for your AI", "copy fix", rank=1), Key("o", "open file", rank=1),
            Key("t", "hide technical details" if technical else "technical details",
                "less detail" if technical else "more detail", rank=1)]
    if result.counts.fix_now:
        keys.append(Key("a", "copy all fixes for your AI", "copy all fixes", rank=3))
    keys.append(Key("r", "check again", rank=3))
    if expert:
        keys.append(Key("x", "expert view", rank=4))
    # Esc and help always show; q works everywhere and gives way first on a short line.
    return [*keys, Key("Esc", "back", rank=0), HELP, Key("q", "quit", rank=3)]


# ---- the checking and error screens -----------------------------------------------------------


def checking_lines(progress: str) -> list[Line]:
    """Under the wordmark: what is happening now, what Polaris looks for, and the privacy line."""
    return [
        line((f"{brand.STAR} ", "star"), (printable(progress, 200) or "Checking\u2026", "text")),
        line((f"Polaris looks for {kinds(KINDS)}.", "muted")),
        line((brand.PRIVACY, "muted")),
    ]


def error_lines(message: str) -> list[Line]:
    return [
        line((f"{brand.STATUS_MARKS['fix_needed']} ", "fix_now"), ("Polaris couldn't check your code", "label")),
        (),
        line((printable(message, 600), "text")),
    ]


# ---- one problem -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Section:
    """One labelled part of a problem: "What's wrong", "Why it matters", "Where"..."""

    label: str
    lines: tuple[Line, ...]


def key_lines(item: CheckItem) -> list[int]:
    """Lines to show: the problem's line and the evidence lines in the same file, or the first
    lines of its range; at most MAX_CODE_LINES, the closest to the problem's line."""
    where = item.where
    numbers = {where.line} | {step.line for step in item.evidence if step.file == where.file}
    if len(numbers) == 1 and where.end_line > where.line:
        numbers |= set(range(where.line, min(where.end_line, where.line + MAX_CODE_LINES - 1) + 1))
    nearest = sorted(numbers, key=lambda number: (abs(number - where.line), number))[:MAX_CODE_LINES]
    return sorted(nearest)


def code_lines(item: CheckItem, sources: SourceIndex | None) -> list[Line]:
    """The problem's key lines, exactly as they were checked (shown as inert text)."""
    if sources is None:
        return []
    found = []
    notes: list[str] = []
    for number in key_lines(item):
        context = sources.context(item.where.file, number, before=0, after=0)
        found += [code for code in context.lines if code.number == number]
        if context.note and context.note not in notes:
            notes.append(context.note)
    width = len(str(found[-1].number)) if found else 1
    lines = [line((f"  {code.number:>{width}} {BAR} ", "code.number"), (code.text or " ", "code")) for code in found]
    return lines + [line((note, "muted")) for note in notes]


def tested_fix_lines(edit: SuggestedFix) -> tuple[Line, ...]:
    number = str(edit.line)
    return (
        line(("Polaris tried this one-line change and checked again: the problem was gone and nothing new "
              "appeared.", "text")),
        line(("  before  ", "before"), (f"{number} {BAR} ", "code.number"), (clean_code_line(edit.before) or " ", "code")),
        line(("  after   ", "after"), (f"{number} {BAR} ", "code.number"), (clean_code_line(edit.after) or " ", "code")),
    )


def problem_sections(item: CheckItem, code: Sequence[Line] = ()) -> list[Section]:
    """What's wrong, why it matters, where, how to fix: the same parts for every problem.
    "Check this" items add the question to answer, right after what's wrong."""
    where = item.where
    sections = [Section("What's wrong", (line((sentence(item.title), "text")),))]
    if item.question:
        sections.append(Section("Question", (line((item.question, "text")),)))
    sections += [
        Section("Why it matters", (line((item.why, "text")),)),
        Section("Where", (line((f"{shown_path(where.file)}, line {where.line}", "text")), *code)),
        Section("How to fix", (line((item.fix.instruction, "text")),)),
    ]
    edit = item.fix.edit
    if edit is not None and edit.status == "verified":
        sections.append(Section("Tested fix", tested_fix_lines(edit)))
    if item.also_reported_by:
        names = ", ".join(printable(name, 60) for name in item.also_reported_by)
        sections.append(Section("Also found by", (line((names, "text")),)))
    return sections


def technical_sections(item: CheckItem) -> list[Section]:
    """The same problem for developers: the exact check, rule, weakness and evidence."""
    technical = item.technical

    def one(label: str, value: str, role: str = "text") -> Section:
        return Section(label, (line((value, role)),))

    sections = [
        one("Check", f"{printable(technical.title, 200)} ({technical.check})"),
        one("Rule", printable(technical.rule, 200)),
    ]
    if technical.cwe:
        sections.append(one("CWE", printable(technical.cwe, 60)))
    confidence = f" \u00b7 confidence {technical.confidence}" if technical.confidence else ""
    sections.append(one("Severity", f"{technical.severity}{confidence}"))
    if technical.message:
        sections.append(one("Message", printable(technical.message, 600)))
    if item.evidence:
        sections.append(Section("Evidence trail", tuple(
            line((f"{step.kind:<7}", "muted"), (f"{shown_path(step.file)}:{step.line}", "text"),
                 ("  ", "text"), (printable(step.label, 200), "muted"))
            for step in item.evidence)))
    if technical.verify:
        sections.append(one("To verify", printable(technical.verify, 1_000)))
    if item.fix.detail:
        sections.append(one("Guidance", printable(item.fix.detail, 1_200)))
    edit = item.fix.edit
    if edit is not None:
        note = f" \u00b7 {printable(edit.note, 300)}" if edit.note else ""
        sections.append(one("Suggested edit", f"line {edit.line}, {edit.status.replace('_', ' ')}{note}"))
    sections.append(one("Finding", printable(technical.finding_id, 200), "muted"))
    return sections


# ---- help -------------------------------------------------------------------------------------

HELP_KEYS: tuple[tuple[str, str], ...] = (
    ("\u2191 \u2193", "choose a problem"),
    ("Enter", "see what's wrong and how to fix it"),
    ("Esc", "go back"),
    ("c", "copy the fix for your AI"),
    ("a", "copy all the fixes for your AI, as one request"),
    ("o", "open the file in your editor, at the line"),
    ("t", "show or hide the technical details"),
    ("w", "show or hide \"worth a look\""),
    ("r", "check again"),
    ("x", "open the expert view, with everything Polaris knows"),
    ("?", "this help"),
    ("q", "quit"),
)
HELP_MARKS: tuple[tuple[str, str, str], ...] = (
    (f"{brand.PRIORITY_MARKS['fix_now']} {brand.PRIORITY_WORDS['fix_now']}", "fix_now",
     "serious problems: fix these before you ship"),
    (f"{brand.PRIORITY_MARKS['check_this']} {brand.PRIORITY_WORDS['check_this']}", "check_this",
     "questions only you can answer"),
    (f"{brand.PRIORITY_MARKS['worth_a_look']} {brand.PRIORITY_WORDS['worth_a_look']}", "worth_a_look",
     "smaller problems, often fine, but worth a quick look"),
    (f"{brand.STATUS_MARKS['clear']} {brand.STATUS_WORDS['clear']}", "clear", "nothing to fix now"),
    (f"{brand.STATUS_MARKS['fix_needed']} {brand.STATUS_WORDS['fix_needed']}", "fix_now",
     "something to fix first"),
    (f"{brand.STATUS_MARKS['incomplete']} {brand.STATUS_WORDS['incomplete']}", "check_this",
     "some files couldn't be checked"),
)


def help_lines() -> list[Line]:
    lines: list[Line] = [line(("Keys", "heading"))]
    lines += [line((f"  {key:<7}", "key"), (words, "text")) for key, words in HELP_KEYS]
    lines += [(), line(("What the marks mean", "heading"))]
    lines += [line((f"  {mark:<21}", role), (words, "text")) for mark, role, words in HELP_MARKS]
    lines += [(), line(("Your code stays private", "heading")), line((f"  {PRIVACY_NOTE}", "text"))]
    return lines

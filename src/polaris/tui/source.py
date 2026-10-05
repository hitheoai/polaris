"""Code context around findings and trace steps, from text that is provably what was reviewed.

* Live reviews: the exact `after` text of reviewed sources and related context files.
* Saved reports: the worktree file only when its digest equals the one recorded in the report's
  provenance (`source_digests`, `context_digests`); otherwise the finding's stored snippet, with a
  note that the file changed since the review. Worktree reads are bounded and never follow links.

Lines are split on "\\n" only, as the tree-sitter analyzers count them; other line-break
characters are shown as U+FFFD and flagged, since they can make editors number lines differently.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from polaris.jsonio import digest_text
from polaris.review.models import WorkflowFinding, valid_source_path
from polaris.tui.session import ReviewData
from polaris.tui.text import clean_code_line

Origin = Literal["analyzed", "worktree", "snippet", "none"]
MAX_SOURCE_BYTES = 2_000_000
UNUSUAL_BREAKS = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
NOTES = {
    "changed": "Changed since the review: showing the snippet stored in the report.",
    "changed_step": "Changed since the review: the report stores no code for this step.",
    "changed_no_snippet": "Changed since the review, and the report stores no snippet for this location.",
    "no_repository": "No repository to read from: showing the snippet stored in the report.",
    "no_repository_step": "No repository to read from, and the report stores no code for this step.",
    "no_digest": "Not one of the review's recorded inputs, so no code is shown for it.",
    "unavailable": "The analyzed text for this file is not available.",
    "redacted": "The report stores no snippet for this finding (redacted evidence).",
    "breaks": "This file contains unusual line-break characters (shown as \ufffd); other tools may number "
              "its lines differently.",
}


def split_lines(text: str) -> list[str]:
    """Lines as the analyzers number them: "\\n" separates, a trailing "\\r" is dropped."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def unusual_breaks(text: str) -> bool:
    return any(mark in text for mark in UNUSUAL_BREAKS) or "\r" in text.replace("\r\n", "")


@dataclass(frozen=True)
class CodeLine:
    number: int
    text: str
    flagged: bool


@dataclass(frozen=True)
class Context:
    path: str
    lines: tuple[CodeLine, ...]
    origin: Origin
    note: str | None = None


@dataclass(frozen=True)
class _Text:
    lines: tuple[str, ...] | None
    origin: Origin
    reason: str | None = None
    breaks: bool = False


class SourceIndex:
    """Per-path text for one review, read at most once per path."""

    def __init__(self, data: ReviewData) -> None:
        self.data = data
        self._cache: dict[str, _Text] = {}
        self._analyzed: dict[str, str] = {}
        if data.live:
            workspace = data.workspace
            for source in (*workspace.context_sources, *workspace.sources):
                if source.after is not None and source.skip is None:
                    self._analyzed[source.path] = source.after
        provenance = data.envelope.review.provenance
        self._digests: dict[str, str] = {
            **dict(provenance.context_digests),
            **{path: digest for path, digest in provenance.source_digests.items() if digest},
        }

    def _load(self, path: str) -> _Text:
        if path not in self._cache:
            self._cache[path] = self._read(path)
        return self._cache[path]

    def _read(self, path: str) -> _Text:
        if self.data.live:
            text = self._analyzed.get(path)
            if text is None:
                return _Text(None, "none", "unavailable")
            return _Text(tuple(split_lines(text)), "analyzed", breaks=unusual_breaks(text))
        root = self.data.root
        if root is None:
            return _Text(None, "none", "no_repository")
        expected = self._digests.get(path)
        if expected is None or not valid_source_path(path):
            return _Text(None, "none", "no_digest")
        from polaris.review.scope import read_scoped_text

        text, _ = read_scoped_text(Path(root).resolve(), path, MAX_SOURCE_BYTES)
        if text is None or digest_text(text) != expected:
            return _Text(None, "none", "changed")
        return _Text(tuple(split_lines(text)), "worktree", breaks=unusual_breaks(text))

    def origin(self, path: str) -> Origin:
        return self._load(path).origin

    def matches(self, path: str) -> bool:
        """True when code for `path` is exactly the reviewed text."""
        return self._load(path).origin in ("analyzed", "worktree")

    def context(
        self, path: str, line: int, *, end: int | None = None, before: int = 3, after: int = 3,
        finding: WorkflowFinding | None = None,
    ) -> Context:
        """Lines around `line` (through `end`), flagged lines marked. Saved reports whose file
        changed since the review fall back to the snippet the finding stored."""
        loaded = self._load(path)
        last = max(line, end or line)
        if loaded.lines is not None:
            first = max(1, line - before)
            stop = min(len(loaded.lines), last + after)
            lines = tuple(
                CodeLine(number, clean_code_line(loaded.lines[number - 1]), line <= number <= last)
                for number in range(first, stop + 1)
            )
            return Context(path, lines, loaded.origin, NOTES["breaks"] if loaded.breaks else None)
        reason = loaded.reason or "unavailable"
        if finding is not None and finding.path == path:
            if finding.snippet and finding.snippet_start_line:
                start = finding.snippet_start_line
                lines = tuple(
                    CodeLine(start + offset, clean_code_line(value), line <= start + offset <= last)
                    for offset, value in enumerate(finding.snippet.splitlines())
                )
                note = NOTES["no_repository"] if reason == "no_repository" else NOTES["changed"] if (
                    reason == "changed") else NOTES[reason]
                return Context(path, lines, "snippet", note)
            return Context(path, (), "none", NOTES["changed_no_snippet" if reason == "changed" else "redacted"])
        step = {"changed": "changed_step", "no_repository": "no_repository_step"}.get(reason, reason)
        return Context(path, (), "none", NOTES[step])

    def worktree_summary(self) -> tuple[int, int] | None:
        """(matching, recorded) reviewed files for a saved report; None for live reviews."""
        if self.data.live:
            return None
        recorded = [path for path, digest in self.data.envelope.review.provenance.source_digests.items()
                    if digest and valid_source_path(path)]
        if self.data.root is None:
            return (0, len(recorded))
        return (sum(1 for path in recorded[:2_000] if self.matches(path)), len(recorded))

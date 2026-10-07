"""The result type and the exact-position helpers that every codemod module shares.

Codemods edit by exact character ranges taken from a syntax tree, never by searching the text.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Fix:
    text: str
    rationale: str
    name: str


class Positions:
    """Maps the (line, UTF-8 byte column) pairs that `ast` reports to character offsets in `text`.

    `text` must not contain carriage returns: every codemod declines those files.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.split("\n")
        self.starts: list[int] = []
        total = 0
        for line in self.lines:
            self.starts.append(total)
            total += len(line) + 1

    def at(self, line: int, byte_column: int) -> int | None:
        if not 1 <= line <= len(self.lines) or byte_column < 0:
            return None
        current = self.lines[line - 1]
        prefix = current.encode("utf-8")[:byte_column].decode("utf-8", "ignore")
        return self.starts[line - 1] + len(prefix)

    def span(self, node: object) -> tuple[int, int] | None:
        """Start and end offsets of an `ast` node, or None when the node has no usable position."""
        line = getattr(node, "lineno", None)
        end_line = getattr(node, "end_lineno", None)
        column = getattr(node, "col_offset", None)
        end_column = getattr(node, "end_col_offset", None)
        if line is None or end_line is None or column is None or end_column is None:
            return None
        start, end = self.at(line, column), self.at(end_line, end_column)
        if start is None or end is None or end < start:
            return None
        return start, end

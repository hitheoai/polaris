"""Turn Python source and unified diffs into reviewable units. Code is parsed, never run."""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import Literal

from polaris.review.dataflow import module_imports

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class CodeUnit:
    path: str
    symbol: str
    kind: Literal["function", "module"]
    start_line: int
    end_line: int
    source: str
    before: str | None
    node: ast.AST = field(compare=False, repr=False)
    imports: dict[str, str] = field(compare=False, repr=False, default_factory=dict)


def _segment(lines: list[str], start: int, end: int) -> str:
    return textwrap.dedent("\n".join(lines[start - 1 : end])).strip("\n") + "\n"


def _definitions(tree: ast.Module) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Top-level functions and methods (including nested classes); nested functions stay inside."""
    found: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    def visit(body: list[ast.stmt], prefix: str) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append((f"{prefix}{node.name}", node))
            elif isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.")
            elif isinstance(node, (ast.If, ast.Try)):
                # Definitions under `if TYPE_CHECKING:` / `try:` guards are still definitions.
                visit(node.body, prefix)
                visit(getattr(node, "orelse", []), prefix)

    visit(tree.body, "")
    return found


def _span(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, int]:
    start = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
    return start, node.end_lineno or node.lineno


def parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def units_from_source(
    path: str,
    text: str,
    *,
    changed_lines: frozenset[int] | None = None,
    before_text: str | None = None,
) -> tuple[list[CodeUnit], str | None]:
    """Return reviewable units, or a skip reason such as 'parse_error'."""
    tree = parse(text)
    if tree is None:
        return [], "parse_error"
    lines = text.splitlines()
    imports = module_imports(tree)
    previous: dict[str, str] = {}
    if before_text is not None:
        old_tree = parse(before_text)
        if old_tree is not None:
            old_lines = before_text.splitlines()
            for symbol, node in _definitions(old_tree):
                start, end = _span(node)
                previous[symbol] = _segment(old_lines, start, end)
            old_module = _module_statements(old_tree)
            if old_module:
                previous["<module>"] = "\n".join(
                    _segment(old_lines, n.lineno, n.end_lineno or n.lineno).rstrip("\n") for n in old_module
                ) + "\n"
    units: list[CodeUnit] = []
    for symbol, node in _definitions(tree):
        start, end = _span(node)
        if changed_lines is not None and not any(start <= line <= end for line in changed_lines):
            continue
        source = _segment(lines, start, end)
        before = previous.get(symbol)
        units.append(
            CodeUnit(path, symbol, "function", start, end, source,
                     before if before is not None and before != source else None, node, imports)
        )
    statements = _module_statements(tree)
    if statements:
        touched = changed_lines is None or any(
            n.lineno <= line <= (n.end_lineno or n.lineno) for n in statements for line in changed_lines
        )
        if touched:
            source = "\n".join(
                _segment(lines, n.lineno, n.end_lineno or n.lineno).rstrip("\n") for n in statements
            ) + "\n"
            before = previous.get("<module>")
            module = ast.Module(body=list(statements), type_ignores=[])
            units.append(
                CodeUnit(
                    path, "<module>", "module", statements[0].lineno,
                    statements[-1].end_lineno or statements[-1].lineno, source,
                    before if before is not None and before != source else None, module, imports,
                )
            )
    return units, None


def _module_statements(tree: ast.Module) -> list[ast.stmt]:
    """Top-level executable statements that contain calls (scripts often run code here)."""
    kept = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue  # docstrings
        if any(isinstance(child, ast.Call) for child in ast.walk(node)):
            kept.append(node)
    return kept


@dataclass
class FileDiff:
    old_path: str | None
    new_path: str | None
    changed_lines: set[int] = field(default_factory=set)
    binary: bool = False
    hunks: list[list[str]] = field(default_factory=list)


def _diff_path(value: str) -> str | None:
    value = value.split("\t", 1)[0].strip()
    if value == "/dev/null":
        return None
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value[2:] if value[:2] in ("a/", "b/") else value


def parse_unified_diff(text: str) -> list[FileDiff]:
    """Parse `git diff` / unified diff output into per-file changed line numbers (new side)."""
    files: list[FileDiff] = []
    current: FileDiff | None = None
    new_line = old_left = new_left = 0
    for raw in text.splitlines():
        in_hunk = old_left > 0 or new_left > 0
        if in_hunk and current is not None and current.hunks:
            hunk = current.hunks[-1]
            if raw.startswith("\\"):
                continue
            if raw.startswith("+"):
                current.changed_lines.add(new_line)
                hunk.append(raw)
                new_line += 1
                new_left -= 1
                continue
            if raw.startswith("-"):
                # A deletion changes the code around this point in the new file.
                current.changed_lines.add(max(new_line, 1))
                hunk.append(raw)
                old_left -= 1
                continue
            if raw.startswith(" ") or raw == "":
                hunk.append(raw)
                new_line += 1
                old_left -= 1
                new_left -= 1
                continue
            old_left = new_left = 0  # malformed hunk: stop consuming lines
        if raw.startswith("diff --git "):
            current = FileDiff(None, None)
            files.append(current)
            parts = raw.split(" ")
            if len(parts) >= 4:
                current.old_path, current.new_path = _diff_path(parts[2]), _diff_path(parts[3])
            continue
        if raw.startswith("--- "):
            if current is None or current.hunks:
                current = FileDiff(None, None)
                files.append(current)
            current.old_path = _diff_path(raw[4:])
            continue
        if raw.startswith("+++ ") and current is not None:
            current.new_path = _diff_path(raw[4:])
            continue
        if raw.startswith("Binary files ") and current is not None:
            current.binary = True
            continue
        match = HUNK.match(raw)
        if match and current is not None:
            old_left = int(match.group(2)) if match.group(2) is not None else 1
            new_line = int(match.group(3))
            new_left = int(match.group(4)) if match.group(4) is not None else 1
            current.hunks.append([raw])
            if new_left == 0:
                current.changed_lines.add(max(new_line, 1))
    return [item for item in files if item.old_path or item.new_path]


def hunk_snippets(diff: FileDiff) -> list[tuple[int, str]]:
    """Post-change text of each hunk (context + added lines), for review without full files."""
    snippets = []
    for hunk in diff.hunks:
        match = HUNK.match(hunk[0])
        start = int(match.group(3)) if match else 1
        body = [line[1:] for line in hunk[1:] if line.startswith((" ", "+"))]
        if any(line.strip() for line in body):
            snippets.append((start, textwrap.dedent("\n".join(body)) + "\n"))
    return snippets

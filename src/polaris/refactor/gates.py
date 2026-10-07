"""Cheap, deterministic checks every candidate passes before it is re-reviewed.

A fix for one finding should change code near that finding and little else. Nothing here can
prove a fix is right; it only refuses candidates that wander (a model rewriting a whole file, a
codemod editing somewhere else) so that what a person reviews stays small and local.
"""

from __future__ import annotations

import ast
import difflib
import re

from polaris.review.models import WorkflowFinding

WINDOW = 40  # lines around the finding where a fix may change code
MAX_CHANGED_LINES = 60
# Adding an import is the one change a fix often needs far from the finding.
IMPORT_LINE = re.compile(r"^(?:import [A-Za-z_][\w.]*(?: as \w+)?(?:, ?[A-Za-z_][\w.]*(?: as \w+)?)*"
                         r"|from [A-Za-z_][\w.]* import [\w*, ]+)$")
IMPORT_REGION = 200


def argument_names(text: str, line: int) -> set[str]:
    """Variable names read in the arguments of the calls that start on `line` (Python).

    Callees (`str` in `str(x)`, `db` in `db.execute(...)`) are not values, so they are skipped.
    An unparseable file or a line with no call gives an empty set.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    callees = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno == line:
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                for child in ast.walk(argument):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and id(child) not in callees:
                        names.add(child.id)
    return names


def drops_a_value(original: str, replacement: str, finding: WorkflowFinding) -> bool:
    """True when a name the flagged call read no longer appears in any line the fix adds.

    A fix may stop passing a value through the dangerous path, but it must still use it: an AI that
    turns `execute("... " + name)` into `execute("... %s")` removes the injection and the value too,
    and the code stops working. The static re-review can't see that, because a constant query is
    safe, so this check does. It only looks at Python and only at names in the sink call's own
    arguments, so it can miss a drop (it never blocks a fix on a guess about code it can't parse).
    """
    if not finding.path.endswith(".py"):
        return False
    names = argument_names(original, finding.start_line)
    if not names:
        return False
    try:
        fixed = ast.parse(replacement)
    except (SyntaxError, ValueError):
        return False  # a file that doesn't parse is the re-review's to report, as what it is
    before, after = original.splitlines(), replacement.splitlines()
    opcodes = difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes()
    if not any(tag in ("replace", "delete") and start <= finding.start_line - 1 < end
               for tag, start, end, _, _ in opcodes):
        return False  # the flagged line itself is untouched: nothing was dropped from it
    added = {number + 1 for tag, _, _, new_start, new_end in opcodes if tag in ("insert", "replace")
             for number in range(new_start, new_end)}
    # Variable reads, not text: `name` inside a SQL string is not the variable.
    used = {node.id for node in ast.walk(fixed)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.lineno in added}
    return not names <= used


def scope_problem(
    original: str, replacement: str, finding: WorkflowFinding, *,
    window: int = WINDOW, max_changed_lines: int = MAX_CHANGED_LINES,
) -> str | None:
    """A short reason code when the replacement strays from the finding, else None."""
    before, after = original.splitlines(), replacement.splitlines()
    low = finding.start_line - window
    high = max(finding.start_line, finding.end_line or finding.start_line) + window
    changed = 0
    for tag, start, end, new_start, new_end in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        changed += (end - start) + (new_end - new_start)
        if tag == "insert":
            inserted = after[new_start:new_end]
            if start <= IMPORT_REGION and all(IMPORT_LINE.fullmatch(line.strip()) for line in inserted) \
                    and all(line == line.strip() for line in inserted):
                continue  # a top-level import added near the top of the file
            if not low - 1 <= start <= high:
                return "change_outside_scope"
        elif start + 1 < low or end > high:
            return "change_outside_scope"
    if changed == 0:
        return "no_change"
    if changed > max_changed_lines:
        return "change_too_large"
    if drops_a_value(original, replacement, finding):
        return "fix_drops_a_value"
    return None

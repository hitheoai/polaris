"""Cheap, deterministic checks every candidate passes before it is re-reviewed.

A fix for one finding should change code near that finding and little else. Nothing here can
prove a fix is right; it only refuses candidates that wander (a model rewriting a whole file, a
codemod editing somewhere else) so that what a person reviews stays small and local.
"""

from __future__ import annotations

import difflib
import re

from polaris.review.models import WorkflowFinding

WINDOW = 40  # lines around the finding where a fix may change code
MAX_CHANGED_LINES = 60
# Adding an import is the one change a fix often needs far from the finding.
IMPORT_LINE = re.compile(r"^(?:import [A-Za-z_][\w.]*(?: as \w+)?(?:, ?[A-Za-z_][\w.]*(?: as \w+)?)*"
                         r"|from [A-Za-z_][\w.]* import [\w*, ]+)$")
IMPORT_REGION = 200


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
    return None

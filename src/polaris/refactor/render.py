"""A fix plan in plain words. Code and diffs come from the repository, so they are data: control,
invisible and bidirectional characters are replaced before anything reaches a terminal.
"""

from __future__ import annotations

from polaris.refactor.models import FixItem, FixPlan
from polaris.review.models import UNSAFE_TEXT

REASONS = {
    "no_longer_detected": "a fresh check no longer finds the problem and finds nothing new",
    "another_fix_to_this_file_comes_first": "another fix to this file comes first; run `polaris fix` again after it",
    "fix_limit_reached": "left for the next run (the limit for one run was reached)",
    "no_generator_has_a_fix": "Polaris has no automatic fix for this one",
    "source_unavailable": "the file couldn't be read",
    "change_outside_scope": "the fix changed code far from the problem",
    "change_too_large": "the fix was too big to review safely",
    "finding_still_detected": "the fix didn't clear the problem",
    "edit_adds_findings": "the fix would add another problem",
    "edited_file_not_fully_checked": "the fixed file couldn't be fully checked",
    "not_reproduced_in_isolation": "Polaris couldn't reproduce the problem on its own to test the fix",
    "carriage_returns": "the file uses Windows line endings, which fixes don't support yet",
    "secret_detected": "the fix involved something that looks like a secret",
}


def clean(text: str) -> str:
    return UNSAFE_TEXT.sub("\ufffd", text.replace("\t", "    "))


def reason_text(reason: str) -> str:
    return REASONS.get(reason, reason.replace("_", " "))


def diff_lines(item: FixItem) -> list[str]:
    diff = (item.proposal or {}).get("diff")
    if not isinstance(diff, str):
        return []
    return ["    " + clean(line) for line in diff.splitlines() if not line.startswith(("---", "+++"))]


def render_plan(plan: FixPlan, *, diffs: bool = True) -> str:
    counts = plan.counts
    if plan.status == "nothing_to_fix":
        head = "Nothing to fix now."
    elif plan.status == "fixes_ready":
        head = (f"Polaris can fix {counts.verified} of {counts.flagged} problem"
                f"{'s' if counts.flagged != 1 else ''}, and checked each fix.")
    else:
        head = f"Polaris found {counts.flagged} problem{'s' if counts.flagged != 1 else ''} but has no checked fix yet."
    lines = [f"Polaris fix · {plan.scope_label}", head]
    for number, item in enumerate((item for item in plan.items if item.status == "verified"), 1):
        lines += ["", f"{number}. {clean(item.title)} · {clean(item.path)}:{item.line}",
                  f"   Fix ({item.origin}): {reason_text(item.reason)}. {item.changed_lines} line"
                  f"{'s' if item.changed_lines != 1 else ''} changed."]
        if diffs:
            lines += diff_lines(item)
        lines.append(f"   Approve with: polaris fix --approve {item.proposal_digest}")
    rest = [item for item in plan.items if item.status != "verified"]
    if rest:
        lines += ["", "Not fixed:"]
        for item in rest:
            lines.append(f"- {clean(item.title)} · {clean(item.path)}:{item.line}: {reason_text(item.reason)}")
    lines += ["", *plan.notes]
    if plan.status != "nothing_to_fix":
        lines.append("Fixes are checked by Polaris re-checking the code. Your tests were not run: run them after applying.")
    return "\n".join(line for index, line in enumerate(lines) if line or (index and lines[index - 1]))

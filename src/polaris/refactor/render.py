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
    "fix_drops_a_value": "the fix stops using a value the original call used, so it would change what the code does",
    "finding_still_detected": "the fix didn't clear the problem",
    "edit_adds_findings": "the fix would add another problem",
    "edited_file_not_fully_checked": "the fixed file couldn't be fully checked",
    "not_reproduced_in_isolation": "Polaris couldn't reproduce the problem on its own to test the fix",
    "carriage_returns": "the file uses Windows line endings, which fixes don't support yet",
    "secret_detected": "the fix involved something that looks like a secret",
    "ai_not_approved_for_this_file": "you didn't allow this file to be sent to the AI",
    "ai_changed_other_files": "the AI changed more than the file with the problem",
    "ai_invalid_candidate": "the AI's answer wasn't a usable fix",
    "ai_invalid_response": "the AI's answer couldn't be read",
    "ai_secret_detected": "the file or the AI's answer contained something that looks like a secret, so it was not used",
    "ai_refused": "the AI declined to answer",
    "ai_timeout": "the AI didn't answer in time",
    "ai_provider_error": "the AI service returned an error",
    "ai_context_limit": "the file is too large to send to the AI",
    "ai_token_budget": "the file is too large for the AI's size limit",
    "ai_output_limit": "the AI's answer was too long",
    "ai_redirect_rejected": "the AI service tried to redirect the request, which Polaris never follows",
    "ai_hosted_not_enabled": "your AI settings don't allow a hosted service",
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
                  f"   Fix ({'AI suggestion' if item.origin == 'ai' else item.origin}): {reason_text(item.reason)}. "
                  f"{item.changed_lines} line"
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

"""`polaris fix`: fix the problems `polaris check` finds, with every fix checked before you see it.

Nothing is written without your approval of the exact fix. In a terminal `--apply` shows each fix
and asks; in scripts `--approve DIGEST` applies the one fix with that digest. No model is used
and nothing leaves your computer. Exit codes: 0 nothing left to fix (or every approved fix was
applied and confirmed), 1 problems remain, 2 the check couldn't run or a fix wasn't confirmed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXAMPLES = """\
examples:
  polaris fix                 show the fixes Polaris can make to your changes (or your whole project)
  polaris fix --all           look at your whole project
  polaris fix --apply         ask about each fix and apply the ones you approve
  polaris fix --approve DIGEST   apply the one fix with this digest (for scripts)

Fixes are checked by Polaris re-checking the code. Your own tests are not run: run them afterwards.
exit codes: 0 nothing left to fix, 1 problems remain, 2 couldn't run or a fix wasn't confirmed
"""
ERRORS = {
    "not_a_git_project": "`polaris fix` needs a Git project, so you can review and undo what it changes. "
                         "Run `git init` here first.",
    "unknown_digest": "None of the fixes Polaris found has that digest. Run `polaris fix` to see the current ones.",
    "needs_terminal": "`--apply` asks about each fix, so it needs a terminal. In a script, use "
                      "`--approve DIGEST` with a digest from `polaris fix`.",
    "stale": "Your files changed while Polaris was checking them. Run `polaris fix` again.",
    "output_unwritable": "Polaris couldn't write --output. Choose a new file: existing files and symbolic links "
                         "are refused.",
}


def add_fix_parsers(commands: Any) -> None:
    from polaris.refactor.plan import DEFAULT_LIMIT, MAX_LIMIT

    fix = commands.add_parser(
        "fix", help="Fix the problems `polaris check` finds, with each fix checked first.",
        description="Show, and with your approval apply, fixes for the security problems Polaris finds. Each fix is "
                    "checked by re-running Polaris on the fixed code before you see it. No model is used and "
                    "nothing leaves your computer.",
        epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    scope = fix.add_mutually_exclusive_group()
    scope.add_argument("--all", action="store_true", help="Look at your whole project.")
    scope.add_argument("--changes", action="store_true",
                       help="Look only at your changes since the last commit, even if there are none.")
    scope.add_argument("--files", type=Path, nargs="+", metavar="PATH", help="Look at these files or folders.")
    approval = fix.add_mutually_exclusive_group()
    approval.add_argument("--apply", action="store_true",
                          help="Show each fix and ask whether to apply it (needs a terminal).")
    approval.add_argument("--approve", metavar="DIGEST", help="Apply only the fix with this digest (for scripts).")
    fix.add_argument("--root", type=Path, help="Your project folder (default: the current folder).")
    fix.add_argument("--limit", type=int, default=DEFAULT_LIMIT, metavar="N",
                     help=f"Plan up to N fixes in one run (1-{MAX_LIMIT}, default {DEFAULT_LIMIT}).")
    fix.add_argument("--output", type=Path,
                     help="Also write the full plan, with every fix's diff, to a new private file.")
    fix.add_argument("--json", action="store_true",
                     help="Print the plan as JSON (polaris.fix-plan/0.1.0) without source code or diffs.")


def _say(text: str, *, error: bool = False) -> None:
    from polaris.check.cli import write

    write(sys.stderr if error else sys.stdout, text + "\n")


def _review(root: Path, args: argparse.Namespace) -> tuple[Any, str]:
    from polaris.check.runner import _changed
    from polaris.integrations.forge.verify import MEMORY_ONLY
    from polaris.review.models import WorkflowReviewConfig
    from polaris.workflow.cli import _paths
    from polaris.workflow.service import review_workspace_detailed

    config = WorkflowReviewConfig()
    if args.files:
        return review_workspace_detailed(root, paths=_paths(root, list(args.files)), config=config,
                                         runtime=MEMORY_ONLY), "the files you chose"
    if args.all:
        return review_workspace_detailed(root, paths=[root], config=config, runtime=MEMORY_ONLY), "your whole project"
    review = review_workspace_detailed(root, config=config, runtime=MEMORY_ONLY)
    if args.changes or _changed(review.envelope):
        return review, "your changes"
    return review_workspace_detailed(root, paths=[root], config=config, runtime=MEMORY_ONLY), "your whole project"


def _ask(question: str) -> bool:
    try:
        return input(question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _apply(root: Path, items: list[Any], args: argparse.Namespace) -> int:
    from polaris.integrations.forge.verify import MEMORY_ONLY
    from polaris.refactor.apply import apply_fix
    from polaris.refactor.render import clean, diff_lines, reason_text
    from polaris.review.models import WorkflowReviewConfig

    config = WorkflowReviewConfig()
    code = 0
    for item in items:
        if args.apply:
            _say(f"\n{clean(item.title)} · {clean(item.path)}:{item.line}\n" + "\n".join(diff_lines(item)))
            if not _ask("Apply this fix? [y/N] "):
                _say("Left as it is.")
                code = max(code, 1)
                continue
        outcome = apply_fix(root, item.proposal, approved_digest=item.proposal_digest, config=config,
                            runtime=MEMORY_ONLY, known=item.known)
        place = f"{clean(item.path)}:{item.line}"
        if outcome.applied and outcome.verified:
            _say(f"Fixed {place}. A fresh check no longer finds the problem. Run your tests to be sure nothing broke.")
        elif outcome.applied:
            _say(f"Applied the fix at {place}, but Polaris couldn't confirm it ({reason_text(outcome.reason)}). "
                 "Check the change with `git diff` and run `polaris check`.", error=True)
            code = 2
        else:
            stale = outcome.reason in ("stale_context", "stale_source", "race_detected")
            _say(f"Didn't change {place}: " + ("your files changed since the plan, so run `polaris fix` again."
                                                if stale else f"{reason_text(outcome.reason)}."), error=True)
            code = 2
    return code


def run(args: argparse.Namespace) -> int:
    from polaris.check.runner import CheckProblem, check_root
    from polaris.integrations._safe import IntegrationProblem
    from polaris.refactor.generators import deterministic
    from polaris.refactor.plan import MAX_LIMIT, build_plan
    from polaris.refactor.render import render_plan
    from polaris.workflow.cli import _emit

    if not 1 <= args.limit <= MAX_LIMIT:
        _say(f"polaris fix: keep --limit between 1 and {MAX_LIMIT}.", error=True)
        return 2
    try:
        root, git = check_root(args.root)
        if not git:
            _say(ERRORS["not_a_git_project"], error=True)
            return 2
        review, label = _review(root, args)
        if review.envelope.status == "stale":
            _say(ERRORS["stale"], error=True)
            return 2
        plan = build_plan(root, review, deterministic(), limit=args.limit, scope_label=label)
    except CheckProblem as problem:
        _say(f"polaris fix: {problem.message}", error=True)
        return 2
    except (ValueError, OSError, RuntimeError, IntegrationProblem):
        # Never print exception text: it can quote source, paths or credentials.
        _say("polaris fix: Polaris couldn't finish. Try again; if it keeps failing, run `polaris check` to see more.",
             error=True)
        return 2
    if args.output is not None:
        try:
            _emit(plan.model_dump(mode="json"), args.output)
        except (IntegrationProblem, OSError):
            _say(ERRORS["output_unwritable"], error=True)
            return 2
    if args.json:
        _say(json.dumps(plan.summary().model_dump(mode="json"), sort_keys=True, indent=2))
    verified = [item for item in plan.items if item.status == "verified"]
    if args.approve is not None or args.apply:
        chosen = verified
        if args.approve is not None:
            chosen = [item for item in verified if item.proposal_digest == args.approve]
            if not chosen:
                _say(ERRORS["unknown_digest"], error=True)
                return 2
        elif not (sys.stdin.isatty() and sys.stdout.isatty()):
            _say(ERRORS["needs_terminal"], error=True)
            return 2
        code = _apply(root, chosen, args)
        if code:
            return code
        return 0 if plan.counts.flagged <= len(chosen) else 1  # 1: problems remain that weren't fixed
    if not args.json:
        _say(render_plan(plan))
    return 0 if plan.status == "nothing_to_fix" else 1

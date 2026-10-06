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
  polaris fix --ai --apply    also ask your AI model for fixes Polaris has none of its own for

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
    "yes_send_alone": "--yes-send only goes with --ai.",
}
AI_ERRORS = {
    "in_ci": "`--ai` isn't available in CI or other automated jobs, because source code must not be sent to an AI "
             "service from a job that may hold credentials. Run it on your own computer.",
    "not_configured": "`--ai` needs your AI settings in {path}. Create that file, readable only by you "
                      "(chmod 600), with:\n  endpoint = \"https://your-provider/v1/chat/completions\"\n  model = \"your-model\"\n"
                      "  allow_hosted = true\n  key_env = \"NAME_OF_YOUR_KEY_VARIABLE\"\nSee docs/fix.md.",
    "unsafe_file": "{path} can't be used. It must be a regular file (not a link) under 8 KB that only you can read "
                   "(chmod 600), in a folder only you can write to.",
    "inside_project": "{path} is inside your project. Keep your AI settings outside it, so a repository can't "
                      "change where your code is sent.",
    "invalid_file": "{path} has a setting Polaris can't use. It may only hold endpoint (https, or a loopback "
                    "address), model, allow_hosted (true or false) and key_env (the name of a variable).",
    "hosted_not_allowed": "{path} points to a hosted service ({detail}). If you accept sending code there, add "
                          "`allow_hosted = true`.",
    "missing_key": "The variable {detail}, named in {path}, isn't set. Set it in your shell: Polaris never reads "
                   "a key from a file.",
    "invalid_key": "The key in the variable {detail} isn't in a format Polaris accepts.",
    "needs_terminal": "`--ai` asks before sending code, so it needs a terminal. In a script, add --yes-send once "
                      "you have decided that the files `polaris fix --ai` lists may be sent.",
    "json_needs_yes_send": "`--ai --json` can't ask a question first. Add --yes-send once you have decided that "
                           "the files `polaris fix --ai` lists may be sent.",
    "approve": "AI fixes can differ from one run to the next, so a digest from an earlier run may not match. "
               "Use --apply to approve a fix in the same run that found it.",
}


def add_fix_parsers(commands: Any) -> None:
    from polaris.refactor.plan import DEFAULT_LIMIT, MAX_LIMIT

    fix = commands.add_parser(
        "fix", help="Fix the problems `polaris check` finds, with each fix checked first.",
        description="Show, and with your approval apply, fixes for the security problems Polaris finds. Each fix is "
                    "checked by re-running Polaris on the fixed code before you see it. Unless you add --ai, no "
                    "model is used and nothing leaves your computer.",
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
    ai = fix.add_argument_group("AI (off unless you ask)")
    ai.add_argument("--ai", action="store_true",
                    help="Also ask the AI model named in your ai.toml for fixes Polaris has none of its own for. "
                         "You see which files may be sent, and where, before anything is. Every answer is re-checked.")
    ai.add_argument("--yes-send", action="store_true",
                    help="With --ai, don't ask before sending the files that are listed.")


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


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _ai_message(problem: Any) -> str:
    from polaris.refactor.aiconfig import settings_path
    from polaris.refactor.render import clean

    return AI_ERRORS.get(problem.code, "Polaris couldn't set up the AI.").format(
        path=clean(str(settings_path())), detail=clean(problem.detail))


def _ai_ready(root: Path) -> tuple[Any, Any]:
    """Your AI settings and gateway configuration, or an AiProblem. Reads no project file."""
    from polaris.refactor.aiconfig import AiProblem, generation_config, in_ci, load_settings

    if in_ci():
        raise AiProblem("in_ci")
    settings = load_settings(project=root)
    return settings, generation_config(settings)


def _generators(
    args: argparse.Namespace, review: Any, ai: tuple[Any, Any] | None,
) -> tuple[tuple[Any, ...], Any, list[str]]:
    """(generators, the AI generator or None, notes). Shows what may be sent and asks first."""
    from polaris.engineering.errors import EngineeringError
    from polaris.engineering.generation import OpenAICompatibleGateway
    from polaris.integrations.forge.verify import MEMORY_ONLY
    from polaris.refactor.ai import AiGenerator, describe, disclosure_for
    from polaris.refactor.aiconfig import AiProblem
    from polaris.refactor.generators import deterministic
    from polaris.refactor.render import clean
    from polaris.review.models import WorkflowReviewConfig

    base = deterministic()
    if ai is None:
        return base, None, []
    settings, config = ai
    disclosure = disclosure_for(review, settings)
    if disclosure is None:
        return base, None, []
    listing = clean(describe(disclosure.files))
    where = f"{clean(disclosure.model)} at {clean(disclosure.host)}"
    if args.yes_send:
        _say(f"Sending is allowed by --yes-send. Files that may be sent to {where}: {listing}.", error=True)
    else:
        if args.json:
            raise AiProblem("json_needs_yes_send")
        if not _interactive():
            raise AiProblem("needs_terminal")
        _say(f"Polaris can ask {where} for fixes it has none of its own for.\n"
             f"Only these files may be sent, and only when they have such a problem ({disclosure.total_bytes:,} bytes "
             f"at most):\n  {listing}\n"
             "Nothing is written without your approval, and every answer is re-checked like any other fix.")
        if not _ask("Allow sending these files? [y/N] "):
            _say("Nothing was sent. Showing the fixes that need no AI.")
            return base, None, ["The AI wasn't used: you didn't allow any file to be sent."]
    try:
        gateway = OpenAICompatibleGateway(config)
    except EngineeringError:
        raise AiProblem("invalid_file") from None
    generator = AiGenerator(gateway, review, settings, approved=[path for path, _ in disclosure.files],
                            config=WorkflowReviewConfig(), runtime=MEMORY_ONLY)
    return (*base, generator), generator, []


def _sent_note(generator: Any, settings: Any) -> str:
    from polaris.refactor.ai import describe
    from polaris.refactor.render import clean

    if generator.sent:
        return clean(f"Sent to {settings.model} at {settings.host}: {describe(generator.sent.items())}. "
                     "Each answer was re-checked by Polaris like any other fix.")[:600]
    return "The AI was allowed, but no file was sent: Polaris had checked fixes of its own, or none were needed."


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
    from polaris.refactor.aiconfig import AiProblem
    from polaris.refactor.plan import MAX_LIMIT, build_plan
    from polaris.refactor.render import render_plan
    from polaris.workflow.cli import _emit

    if not 1 <= args.limit <= MAX_LIMIT:
        _say(f"polaris fix: keep --limit between 1 and {MAX_LIMIT}.", error=True)
        return 2
    if args.yes_send and not args.ai:
        _say(ERRORS["yes_send_alone"], error=True)
        return 2
    if args.ai and args.approve is not None:
        _say(AI_ERRORS["approve"], error=True)
        return 2
    try:
        root, git = check_root(args.root)
        if not git:
            _say(ERRORS["not_a_git_project"], error=True)
            return 2
        ai = _ai_ready(root) if args.ai else None  # before the review: fail fast, read nothing else
        review, label = _review(root, args)
        if review.envelope.status == "stale":
            _say(ERRORS["stale"], error=True)
            return 2
        generators, ai_generator, notes = _generators(args, review, ai)
        plan = build_plan(root, review, generators, limit=args.limit, scope_label=label)
        if ai_generator is not None and ai is not None:
            note = _sent_note(ai_generator, ai[0])
            notes.append(note)
            if args.apply or args.json:  # the plan text, which also holds the note, isn't printed then
                _say(note, error=True)
        if notes:
            plan = plan.model_copy(update={"notes": [*plan.notes, *notes]})
    except AiProblem as problem:
        _say(f"polaris fix: {_ai_message(problem)}", error=True)
        return 2
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
        elif not _interactive():
            _say(ERRORS["needs_terminal"], error=True)
            return 2
        code = _apply(root, chosen, args)
        if code:
            return code
        return 0 if plan.counts.flagged <= len(chosen) else 1  # 1: problems remain that weren't fixed
    if not args.json:
        _say(render_plan(plan))
    return 0 if plan.status == "nothing_to_fix" else 1

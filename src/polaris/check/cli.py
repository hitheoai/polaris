"""`polaris check`: is my code safe to ship? One command for people and their AI agents.

In a terminal it opens the simple view (with the `tui` extra installed). In pipes and CI, or with
--plain, --markdown or --json, it prints the same result. Building the parser never imports the
analyzers or Textual. Exit codes: 0 nothing to fix now and everything was checked, 1 something
to fix now, 2 not fully checked or the check couldn't run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from polaris.check.runner import CheckProblem, CheckRequest

THEME_CHOICES = ("dark", "light", "ansi-dark", "ansi-light")
EXAMPLES = """\
examples:
  polaris check              check your changes (or your whole project if nothing changed)
  polaris check --all        check your whole project
  polaris check --staged     check only what you're about to commit
  polaris check --json       the full result, for an AI agent or a script

exit codes: 0 nothing to fix now, 1 something to fix now, 2 not fully checked or couldn't run
"""


def add_check_parsers(commands: Any) -> None:
    check = commands.add_parser(
        "check", help="Start here: check your code for security problems.",
        description="Check your code for security problems, explained in plain words, with the fix for each one. "
                    "Polaris checks your changes, or your whole project if nothing changed. Nothing leaves your "
                    "computer, and no AI model is used.",
        epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    scope = check.add_mutually_exclusive_group()
    scope.add_argument("--all", action="store_true", help="Check your whole project.")
    scope.add_argument("--changes", action="store_true",
                       help="Check only your changes since the last commit, even if there are none.")
    scope.add_argument("--staged", action="store_true", help="Check only staged changes (what you're about to commit).")
    scope.add_argument("--diff", metavar="RANGE", help="Check the changes in a Git range, for example main...HEAD.")
    scope.add_argument("--files", type=Path, nargs="+", metavar="PATH", help="Check these files or folders.")
    output = check.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true",
                        help="Print the full result as JSON (polaris.check/1): for AI agents and scripts.")
    output.add_argument("--markdown", action="store_true", help="Print the result as Markdown.")
    output.add_argument("--plain", action="store_true",
                        help="Print plain text instead of opening the interactive view (for screen readers and logs).")
    check.add_argument("--root", type=Path, help="Your project folder (default: the current folder).")
    check.add_argument("--limit", type=int, default=25, metavar="N",
                       help="Show up to N problems in full (1-50, default 25); the rest are counted.")
    check.add_argument("--import-sarif", action="append", type=Path, metavar="PATH",
                       help="Also show results from another tool's SARIF file (repeatable, up to 16). Polaris never "
                            "runs that tool and doesn't verify its results.")
    check.add_argument("--no-animation", action="store_true", help="Don't animate the star while checking.")
    check.add_argument("--theme", choices=THEME_CHOICES, default="dark",
                       help="Colours for the interactive view: dark (default), light, or ansi-dark/ansi-light to use "
                            "your terminal's own colours. NO_COLOR is honoured.")


def request_from(args: argparse.Namespace) -> CheckRequest:
    from polaris.check.model import MAX_ITEMS
    from polaris.check.runner import CheckProblem, CheckRequest, Mode, valid_revision_range

    limit = getattr(args, "limit", 25)
    if (args.diff is not None and not valid_revision_range(args.diff)) or not 1 <= limit <= MAX_ITEMS:
        raise CheckProblem("invalid_selection")
    mode: Mode = ("all" if args.all else "changes" if args.changes else "staged" if args.staged
                  else "range" if args.diff is not None else "files" if args.files else "auto")
    return CheckRequest(
        root=args.root, mode=mode, revision_range=args.diff, paths=tuple(args.files) if args.files else None,
        import_sarif=tuple(args.import_sarif or ()), limit=limit,
    )


def _terminal() -> bool:
    from polaris.tui.cli import _ci

    return sys.stdin.isatty() and sys.stdout.isatty() and not _ci()


def write(stream: TextIO, text: str) -> None:
    """Write text even where the terminal's encoding lacks the ✶ star and other marks."""
    try:
        stream.write(text)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        stream.write(text.encode(encoding, "replace").decode(encoding, "replace"))
    stream.flush()


def _fail(problem: CheckProblem, *, as_json: bool) -> int:
    from polaris.check.output import error_json

    if as_json:
        write(sys.stdout, error_json(problem.code, problem.message))
    else:
        write(sys.stderr, f"polaris check: {problem.message}\n")
    return 2


def _progress(message: str) -> None:
    from polaris.check.brand import STAR

    write(sys.stderr, f"{STAR} {message}\n")


def run(args: argparse.Namespace) -> int:
    from polaris.check.output import render_json, render_markdown, render_text
    from polaris.check.runner import CheckProblem, run_check
    from polaris.tui.cli import textual_available

    try:
        request = request_from(args)
    except CheckProblem as problem:
        return _fail(problem, as_json=args.json)
    chosen = args.json or args.markdown or args.plain
    if not chosen and _terminal():
        if textual_available():
            from polaris.tui.simple import run as run_simple

            return run_simple(request, animation=not args.no_animation, theme=args.theme)
        write(sys.stderr, "Tip: for the interactive view, install it with pip install 'theovex-polaris[tui]'.\n")
    try:
        outcome = run_check(request, progress=_progress if sys.stderr.isatty() and not args.json else None)
    except CheckProblem as problem:
        return _fail(problem, as_json=args.json)
    render = render_json if args.json else render_markdown if args.markdown else render_text
    write(sys.stdout, render(outcome.result))
    return outcome.result.exit_code()

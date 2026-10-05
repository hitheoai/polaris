"""`polaris tui`: the interactive terminal view of a review, or `--plain` text for everyone else.

Building this parser (and `--help`) never imports Textual: it is imported only after the guards
pass. The interface refuses to start without a terminal on stdin and stdout, or when `CI` is set,
and points to the non-interactive outputs instead; `--plain` prints the same text report as
`polaris workflow review` and returns its exit code.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

THEME_CHOICES = ("dark", "light", "ansi-dark", "ansi-light")


def add_tui_parsers(commands: Any) -> None:
    from polaris.workflow.cli import _analysis_options, _import_options

    tui = commands.add_parser(
        "tui", help="Interactive, read-only terminal view of a review (needs the tui extra).",
        description="Browse what Polaris found, how untrusted data reaches each sink, what was and wasn't "
                    "checked, and what the pull-request bot would post. Read-only: nothing from the repository "
                    "is executed, and no model is used.")
    choice = tui.add_mutually_exclusive_group()
    choice.add_argument("--staged", action="store_true", help="Review staged changes.")
    choice.add_argument("--diff", metavar="RANGE", help="Review this Git revision range.")
    choice.add_argument("--files", type=Path, nargs="+", help="Review these files or directories.")
    choice.add_argument("--report", type=Path, metavar="FILE.json",
                        help="Open a saved review (`polaris workflow review --format json --output FILE`) without "
                             "running a new one.")
    choice.add_argument("--base", metavar="REV",
                        help="Preview, offline, the pull-request review of --head against this base commit.")
    tui.add_argument("--head", metavar="REV", help="The head commit for --base (default HEAD).")
    tui.add_argument("--plain", action="store_true",
                     help="Print the plain text report instead of the interface (works without a terminal, in CI "
                          "and with screen readers).")
    tui.add_argument("--theme", choices=THEME_CHOICES, default="dark",
                     help="Colours: dark (default), light, or ansi-dark/ansi-light to use your terminal's own "
                          "palette. NO_COLOR is honoured; every state also has a glyph and a word.")
    tui.add_argument("--no-mouse", action="store_true",
                     help="Leave the mouse to the terminal, so its own text selection works.")
    _analysis_options(tui)
    _import_options(tui, gate="fail --plain's exit code and the PR preview's gate")


def _fail(code: str) -> int:
    from polaris.tui.session import error_message

    sys.stderr.write(f"polaris tui: {error_message(code)} [{code}]\n")
    return 2


def _arguments_valid(args: argparse.Namespace) -> bool:
    if args.head is not None and args.base is None:
        return False
    return all(not value or (not value.startswith("-") and "\0" not in value and len(value) <= 256)
               for value in (args.base, args.head, args.diff))


def _limits(config: Any, *, whole: bool) -> Any:
    """The larger limits local `workflow review` and `pr plan` runs use (the shared defaults are
    sized for MCP and HTTP callers)."""
    from polaris.review.models import WorkflowReviewConfig

    return WorkflowReviewConfig.model_validate({
        **config.model_dump(mode="python"), "max_files": 50_000 if whole else 5_000,
        "max_total_bytes": 512_000_000 if whole else 128_000_000, "max_units": 500_000 if whole else 100_000,
        "max_findings": 10_000,
    })


def _settings_factory(args: argparse.Namespace) -> Any:
    from polaris.jsonio import digest_json
    from polaris.tui.session import Settings
    from polaris.workflow.cli import analysis_settings
    from polaris.workflow.service import review_policy

    def settings() -> Settings:
        config, runtime, policy = analysis_settings(args)
        config = _limits(config, whole=args.files is not None)
        return Settings(config, runtime, policy, digest_json(review_policy(config, policy, runtime)))

    return settings


def _repository(args: argparse.Namespace, *, required: bool) -> tuple[Path | None, str | None]:
    from polaris.integrations._safe import IntegrationProblem
    from polaris.integrations.freshness import repository_identity
    from polaris.tui.session import SessionProblem

    try:
        identity = repository_identity(args.root or Path.cwd())
    except (IntegrationProblem, OSError, ValueError, RuntimeError):
        if required:
            raise SessionProblem("not_a_repository") from None
        return (args.root.resolve() if args.root else None), None
    return identity.root, identity.repository_id


def prepare(args: argparse.Namespace) -> tuple[Any, Any]:
    """(saved report data, None) or (None, live review request). Raises SessionProblem."""
    from pydantic import ValidationError

    from polaris.errors import PolarisError
    from polaris.integrations._safe import IntegrationProblem
    from polaris.review.analyzers.registry import PLUGIN_ERRORS, PluginProblem
    from polaris.review.models import MAX_SARIF_IMPORTS
    from polaris.tui.session import ReviewRequest, Selection, SessionProblem, load_report
    from polaris.workflow.cli import _paths

    if args.report is not None:
        root, repository_id = _repository(args, required=False)
        data = load_report(args.report, root=root, repository_id=repository_id)
        return data, None
    root, _ = _repository(args, required=True)
    assert root is not None
    if len(args.import_sarif or ()) > MAX_SARIF_IMPORTS:
        raise SessionProblem("too_many_sarif_files")
    settings = _settings_factory(args)
    try:
        settings()  # fail early, with a fixed code, before the interface starts
    except PluginProblem as problem:
        raise SessionProblem(str(problem) if str(problem) in PLUGIN_ERRORS else "invalid_analyzer_plugin") from None
    except (PolarisError, IntegrationProblem, ValidationError, OSError, ValueError, RuntimeError):
        raise SessionProblem("workflow_unavailable") from None
    selection = Selection(
        staged=args.staged, revision_range=args.diff,
        paths=tuple(_paths(root, args.files) or ()) if args.files is not None else None,
        base=args.base, head=args.head,
    )
    return None, ReviewRequest(root=root, selection=selection, settings=settings,
                               sarif_paths=tuple(args.import_sarif or ()))


def _plain(args: argparse.Namespace) -> int:
    from polaris.tui.session import SessionProblem, run_review
    from polaris.workflow.cli import _emit
    from polaris.workflow.service import imported_exit_code, render_workflow

    try:
        data, request = prepare(args)
        if data is None:
            data = run_review(request)
    except SessionProblem as problem:
        return _fail(problem.code)
    if data.settings_changed:
        return _fail("workflow_unavailable")
    envelope = data.envelope
    _emit(render_workflow(envelope), None, text=True)
    code = envelope.exit_code()
    if args.fail_on_imported is not None:
        code = imported_exit_code(envelope, args.fail_on_imported, code)
    return code


def _ci() -> bool:
    return bool(os.environ.get("CI", "").strip())


def textual_available() -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec("textual") is not None
    except (ImportError, ValueError):
        return False


def run(args: argparse.Namespace) -> int:
    if not _arguments_valid(args):
        return _fail("invalid_arguments")
    if args.plain:
        return _plain(args)
    if _ci():
        return _fail("ci_environment")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return _fail("not_a_terminal")
    if not textual_available():
        return _fail("textual_missing")
    from polaris.tui.session import SessionProblem

    try:
        data, request = prepare(args)
    except SessionProblem as problem:
        return _fail(problem.code)
    from polaris.tui.app import Options, PolarisApp

    app = PolarisApp(data=data, request=request, options=Options(
        theme=args.theme, fail_on_imported=args.fail_on_imported,
    ))
    app.run(mouse=not args.no_mouse)
    return 0

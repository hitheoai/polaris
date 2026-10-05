"""`polaris pr plan|publish`: pull-request review comments from a fresh static review.

`plan` needs only the repository's Git objects: it never contacts a forge, reads credentials,
checks out the pull request, or runs its code. `publish` needs a token and talks only to the
configured GitHub API; it executes nothing.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
EXIT = {"pass": 0, "fail": 1, "incomplete": 2}
ERRORS = {
    "invalid_plan": "The review plan is missing, malformed, oversized or contains Polaris state markers.",
    "plan_mismatch": "The plan was made for a different repository, pull request or head commit.",
    "missing_token": "No GitHub token was found in the configured environment variable.",
    "invalid_token": "The configured GitHub token is not a valid bearer token.",
    "invalid_api_url": "The GitHub API URL must be https:// (or http:// on this machine) without credentials.",
    "invalid_revision": "The base or head commit could not be resolved in this repository.",
    "invalid_arguments": "Check --repository (owner/name), --pr and the commit arguments.",
    "review_unavailable": "The review could not be completed; nothing was published.",
}


def add_pr_parsers(commands: Any) -> None:
    from polaris.workflow.cli import _analysis_options, _import_options, _output_option

    pr = commands.add_parser("pr", help="Plan and publish pull-request review comments from a Polaris review.")
    actions = pr.add_subparsers(dest="pr_command", required=True)
    plan = actions.add_parser(
        "plan", help="Review a pull request's commits offline and write a review plan (no network, no token).")
    plan.add_argument("--base", required=True, help="Base commit; the change is compared with merge-base(base, head).")
    plan.add_argument("--head", required=True, help="The pull request's head commit.")
    plan.add_argument("--repository", required=True, help="owner/name the plan is bound to.")
    plan.add_argument("--pr", dest="pull_request", type=int, required=True, help="Pull request number.")
    plan.add_argument("--format", choices=("json", "markdown"), default="json",
                      help="json: the plan for `pr publish`; markdown: a local preview of what would be posted.")
    plan.add_argument("--min-inline-severity", choices=SEVERITIES, default="high",
                      help="Lowest severity commented inline (default high; others are listed in the summary).")
    plan.add_argument("--inline-questions", action="store_true",
                      help="Also comment inline on 'to verify' questions at or above that severity.")
    plan.add_argument("--max-comments", type=int, default=25, help="Inline comment cap (0-100, default 25).")
    plan.add_argument("--fail-severity", choices=SEVERITIES, default="high",
                      help="Flagged findings on changed lines at or above this severity fail the gate (default high).")
    plan.add_argument("--no-verify-fixes", action="store_true",
                      help="Do not re-review suggested edits; no one-click suggestions are offered then.")
    _analysis_options(plan)
    _import_options(plan, gate="on changed lines fail the gate (incomplete if an import was rejected)")
    plan.add_argument("--inline-imported", choices=("security", "errors"),
                      help="Opt in to inline comments for imported results on changed lines: 'security' (security "
                           "results the tool rated error, or high/critical) or 'errors' (also every other "
                           "error-level result). Default: summary only.")
    _output_option(plan)
    publish = actions.add_parser(
        "publish", help="Post a review plan to a GitHub pull request using a token from the environment.")
    publish.add_argument("--plan", type=Path, required=True, help="Plan written by `polaris pr plan`.")
    publish.add_argument("--repository", required=True, help="owner/name from the trusted event, not the plan.")
    publish.add_argument("--pr", dest="pull_request", type=int, required=True, help="Pull request number from the event.")
    publish.add_argument("--head", required=True, help="Head commit SHA from the event; the plan must match it.")
    publish.add_argument("--api-url", help="GitHub API URL (default: $GITHUB_API_URL or https://api.github.com).")
    publish.add_argument("--token-env", default="GITHUB_TOKEN", help="Environment variable holding the token.")
    publish.add_argument("--bot-login", default="github-actions[bot]",
                         help="Account whose earlier Polaris comments are trusted as state (default github-actions[bot]).")
    publish.add_argument("--fail-on", choices=("findings", "incomplete", "never"), default="findings",
                         help="Exit 1 on gate failures (findings), also 2 on incomplete reviews, or never fail.")
    publish.add_argument("--dry-run", action="store_true", help="Read the pull request and report what would change.")
    publish.add_argument("--no-resolve", action="store_true",
                         help="Leave earlier comments untouched when Polaris no longer detects their findings.")
    _output_option(publish)


def _error(code: str) -> int:
    from polaris.review.analyzers.registry import PLUGIN_ERRORS
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS
    from polaris.workflow.cli import _emit

    message = ERRORS.get(code) or PLUGIN_ERRORS.get(code) or SARIF_ERRORS.get(code)
    _emit({"format": "polaris.pr-error/0.1.0", "code": code,
           "message": message or "The pull-request operation could not be completed; nothing was authorized."}, None)
    return 2


def _arguments(args: argparse.Namespace) -> None:
    from polaris.integrations.forge.github import GitHubProblem

    valid = (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}", args.repository) is not None
             and 1 <= args.pull_request <= 2_147_483_647)
    if args.pr_command == "plan":
        valid = valid and 0 <= args.max_comments <= 100 and all(
            value and not value.startswith("-") and len(value) <= 256 for value in (args.base, args.head))
    else:
        valid = (valid and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", args.head) is not None
                 and re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", args.token_env) is not None)
    if not valid:
        raise GitHubProblem("invalid_arguments")


def _plan(args: argparse.Namespace) -> int:
    from polaris.integrations.forge.github import GitHubProblem
    from polaris.integrations.forge.plan import PlanOptions, build_plan, render_markdown
    from polaris.review.git import GitError, changed_lines, revision_identity
    from polaris.review.models import WorkflowReviewConfig
    from polaris.workflow.cli import _emit, _root, analysis_settings, sarif_inputs
    from polaris.workflow.service import review_workspace_detailed

    imports = sarif_inputs(args.import_sarif)
    root = _root(args)
    config, runtime, policy = analysis_settings(args)
    # A pull request review can afford the larger local diff-review limits.
    config = WorkflowReviewConfig.model_validate({
        **config.model_dump(mode="python"), "max_files": 5_000, "max_total_bytes": 128_000_000,
        "max_units": 100_000, "max_findings": 10_000,
    })
    try:
        base_sha, head_sha = revision_identity(root, f"{args.base}..{args.head}")
        merge_base, target, changed = changed_lines(root, f"{args.base}...{args.head}")
    except GitError:
        raise GitHubProblem("invalid_revision") from None
    if base_sha is None or head_sha is None or target != head_sha:
        raise GitHubProblem("invalid_revision")
    review = review_workspace_detailed(
        root, revision_range=f"{base_sha}...{head_sha}", config=config, runtime=runtime, guard_policy=policy,
        imports=imports,
    )
    plan = build_plan(
        review, repository=args.repository, pull_request=args.pull_request, base_sha=base_sha, head_sha=head_sha,
        merge_base=merge_base, changed=changed,
        options=PlanOptions(
            min_inline_severity=args.min_inline_severity, inline_questions=args.inline_questions,
            max_comments=args.max_comments, fail_severity=args.fail_severity,
            verify_fixes=not args.no_verify_fixes, inline_imported=args.inline_imported or "none",
            fail_on_imported=args.fail_on_imported,
        ),
    )
    if args.format == "markdown":
        _emit(render_markdown(plan), args.output, text=True)
    else:
        _emit(plan.model_dump(mode="json"), args.output)
    imported = ""
    if imports:
        imported = (f"; {plan.counts.imported_in_change} imported result(s) on changed lines "
                    f"({plan.counts.imported_inline} inline, {plan.counts.imports_rejected} SARIF file(s) rejected)")
    print(f"Polaris PR plan: {plan.counts.inline} inline comment(s), {plan.counts.issues_in_change} issue(s) and "
          f"{plan.counts.questions_in_change} question(s) in the change{imported}; gate {plan.gate}.", file=sys.stderr)
    return 0


def _publish(args: argparse.Namespace) -> int:
    from polaris.integrations.forge import github
    from polaris.integrations.forge.models import MAX_PLAN_BYTES
    from polaris.workflow.cli import _emit, read_input

    try:
        data = read_input(args.plan, limit=MAX_PLAN_BYTES)
    except (OSError, ValueError):
        raise github.GitHubProblem("invalid_plan") from None
    plan = github.load_plan(data)
    token = os.environ.get(args.token_env, "")
    if not token:
        raise github.GitHubProblem("missing_token")
    client = github.GitHubClient(args.api_url or os.environ.get("GITHUB_API_URL"), token, transport=github.TRANSPORT)
    del token
    receipt = github.publish(
        plan, client, repository=args.repository, pull_request=args.pull_request, head_sha=args.head,
        options=github.PublishOptions(bot_login=args.bot_login, resolve=not args.no_resolve, dry_run=args.dry_run),
    )
    _emit(receipt.model_dump(mode="json"), args.output)
    print(f"Polaris PR publish: {receipt.status}; {receipt.posted} posted, {receipt.already_posted} already posted, "
          f"{receipt.moved_to_summary} in the summary, {receipt.resolved} resolved; gate {receipt.gate}.",
          file=sys.stderr)
    if receipt.status not in ("published", "dry_run") or args.fail_on == "never":
        return 0
    code = EXIT[receipt.gate]
    return code if code == 1 or (code == 2 and args.fail_on == "incomplete") else 0


def run(args: argparse.Namespace) -> int:
    from pydantic import ValidationError

    from polaris.engineering.errors import EngineeringError
    from polaris.errors import PolarisError
    from polaris.integrations._safe import IntegrationProblem
    from polaris.integrations.forge.github import GitHubProblem
    from polaris.onboarding.errors import OnboardingProblem
    from polaris.review.analyzers.registry import PLUGIN_ERRORS, PluginProblem
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS
    from polaris.review.sarif_import import SarifProblem

    try:
        _arguments(args)
        return _plan(args) if args.pr_command == "plan" else _publish(args)
    except GitHubProblem as problem:
        return _error(problem.code)
    except PluginProblem as problem:
        code = str(problem) if str(problem) in PLUGIN_ERRORS else "invalid_analyzer_plugin"
        return _error(code)
    except SarifProblem as problem:
        return _error(problem.code if problem.code in SARIF_ERRORS else "invalid_sarif")
    except (EngineeringError, PolarisError, IntegrationProblem, OnboardingProblem, ValidationError, OSError,
            ValueError, RuntimeError):
        # Never print exception text: parser, path and API errors can contain source or credentials.
        return _error("review_unavailable")

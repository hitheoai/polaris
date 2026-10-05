"""`polaris review` and `polaris scan`: fast local security review from the terminal or CI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from polaris.review.models import RESULTS

FAIL_CHOICES = frozenset(RESULTS) - {"ok"}
NO_MODEL = (
    "No Polaris model found. Sign in to the hosted model with `polaris login`, install one with "
    "`polaris model pull`, point --model or POLARIS_MODEL at a model folder, or run with "
    "--engine rules for simple static rules."
)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json", "sarif", "codequality"), default="text",
                        help="text, json, sarif (GitHub/code scanning) or codequality (GitLab merge requests).")
    parser.add_argument("--output", type=Path, help="Write the report to a file (overwrites it).")
    parser.add_argument("--fail-on", default="flagged", metavar="RESULTS",
                        help="Comma-separated results that make the exit code 1, or 'none' (default: flagged).")
    parser.add_argument("--engine", choices=("hybrid", "model", "rules"), default="hybrid",
                        help="hybrid (default): static rules decide and the model adds a second opinion "
                             "when one is available; model: the model alone; rules: static rules only.")
    parser.add_argument("--no-model", choices=("fail", "skip", "rules"), default="fail",
                        help="With --engine model, if no model is available: fail (exit 3, default), "
                             "skip (warn, exit 0) or rules (use the static rules instead).")
    parser.add_argument("--model-source", choices=("auto", "local", "remote"), default="auto",
                        help="auto (default): the hosted model when signed in (`polaris login` or "
                             "POLARIS_API_KEY), otherwise an installed one; local: only a model on this "
                             "machine, nothing is sent; remote: only the hosted model.")
    parser.add_argument("--model", help="Model folder (default: $POLARIS_MODEL or ~/.polaris/models/current).")
    parser.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    parser.add_argument("--root", type=Path, help="Repository root (default: the current git repository).")
    parser.add_argument("--no-cache", action="store_true", help="Don't read or write .polaris-cache.")
    parser.add_argument("--show-ok", action="store_true", help="Also list functions that look OK.")


def add_review_parsers(commands: Any) -> None:
    review = commands.add_parser(
        "review", help="Review changed Python code for SQL and command injection (never runs it).",
        description="Review uncommitted changes by default. Findings estimate risk; they don't authorize anything.",
    )
    source = review.add_mutually_exclusive_group()
    source.add_argument("--staged", action="store_true", help="Review staged changes only.")
    source.add_argument("--diff", metavar="RANGE", help="Review a git range, for example main..HEAD.")
    source.add_argument("--files", nargs="+", type=Path, metavar="PATH", help="Review whole files or folders.")
    _common(review)
    scan = commands.add_parser("scan", help="Review every Python function in a codebase.")
    scan.add_argument("paths", nargs="*", type=Path, help="Files or folders (default: the repository root).")
    scan.add_argument("--quiet", action="store_true", help="Hide the progress line.")
    _common(scan)


def _fail_on(value: str) -> frozenset[str]:
    if value.strip().lower() == "none":
        return frozenset()
    chosen = frozenset(part.strip() for part in value.split(",") if part.strip())
    unknown = chosen - FAIL_CHOICES
    if unknown:
        raise ValueError("--fail-on accepts: " + ", ".join(sorted(FAIL_CHOICES)) + " or none")
    return chosen


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
        return
    if output.is_symlink():
        raise ValueError("refusing to write through a symlink")
    output.write_text(text, encoding="utf-8")
    print(f"Wrote {output}", file=sys.stderr)


def run(args: argparse.Namespace) -> int:
    from polaris.errors import PolarisError
    from polaris.remote import RemoteUnavailable, connect, use_remote
    from polaris.review.cache import ReviewCache
    from polaris.review.config import ConfigError, load_config
    from polaris.review.engine import Reviewer
    from polaris.review.git import GitError, repo_root, sources_from_git
    from polaris.review.output import to_codequality, to_sarif, to_text

    try:
        fail_on = _fail_on(args.fail_on)
        cwd = Path.cwd()
        root = (args.root or repo_root(cwd) or cwd).resolve()
        config, _ = load_config(root)
        backend: Any = None
        notices: list[str] = []
        engine = args.engine
        hosted = engine in ("hybrid", "model") and use_remote(args.model_source, args.model)
        if hosted:
            try:
                backend = connect()
            except RemoteUnavailable as exc:
                if engine == "hybrid":
                    print(f"Polaris: {exc} The static rules will review alone.", file=sys.stderr)
                    notices.append(f"{exc} The static rules reviewed this alone.")
                elif args.no_model == "skip":
                    print(f"Polaris: {exc} This code was NOT reviewed.", file=sys.stderr)
                    return 0
                elif args.no_model == "rules":
                    print(f"Polaris: {exc} Using the static rules instead.", file=sys.stderr)
                    engine = "rules"
                else:
                    print(f"Polaris: {exc}", file=sys.stderr)
                    return 3
        if engine == "hybrid" and not hosted:
            from polaris.review.loader import load_backend, resolve_model

            if resolve_model(args.model) is not None:
                try:
                    backend = load_backend(args.model, device=args.device)
                except PolarisError as exc:
                    print(f"Polaris: the model couldn't be loaded ({exc.code}); the static rules will "
                          "review alone. Check it with `polaris model selftest`.", file=sys.stderr)
        if engine == "model" and not hosted:
            from polaris.review.loader import load_backend

            try:
                backend = load_backend(args.model, device=args.device)
            except PolarisError as exc:
                missing = exc.code == "model_unavailable"
                if missing and args.no_model == "skip":
                    print("Polaris: no model installed, so this code was NOT reviewed. "
                          "Install one with `polaris model install` or `polaris model pull`.", file=sys.stderr)
                    return 0
                if missing and args.no_model == "rules":
                    print("Polaris: no model installed; using the static rules instead.", file=sys.stderr)
                    engine = "rules"
                else:
                    print(NO_MODEL if missing else f"Could not load the model: {exc}", file=sys.stderr)
                    return 3
        cache = None
        if backend is not None and not args.no_cache:
            cache = ReviewCache(root / ".polaris-cache" / "review.sqlite")
        reviewer = Reviewer(backend, config=config, engine=engine, cache=cache, notices=notices)
        if args.command == "scan":
            paths = args.paths or [root]
            show = not args.quiet and sys.stderr.isatty()

            def progress(done: int, total: int) -> None:
                if show:
                    print(f"\rPolaris: assessed {done}/{total} functions with SQL or process calls", end="",
                          file=sys.stderr, flush=True)

            report = reviewer.review_paths([Path(p) for p in paths], root=root, progress=progress)
            if show:
                print(file=sys.stderr)
        elif args.files:
            report = reviewer.review_paths(args.files, root=root)
        else:
            if repo_root(root) is None:
                print("Not a git repository. Use --files PATH, or `polaris scan` for a folder.", file=sys.stderr)
                return 2
            sources = sources_from_git(root, staged=args.staged, revision_range=args.diff,
                                       max_bytes=config.max_file_bytes)
            report = reviewer.review_sources(sources)
        if cache is not None:
            cache.close()
    except ConfigError as exc:
        print(f"Polaris settings problem: {exc}", file=sys.stderr)
        return 2
    except GitError as exc:
        print(f"git problem: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"Polaris could not run: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        text = report.model_dump_json(indent=2) + "\n"
    elif args.format == "sarif":
        text = json.dumps(to_sarif(report), indent=2) + "\n"
    elif args.format == "codequality":
        text = json.dumps(to_codequality(report), indent=2) + "\n"
    else:
        color = args.output is None and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        text = to_text(report, color=color, show_ok=args.show_ok)
    try:
        _emit(text, args.output)
    except (OSError, ValueError) as exc:
        print(f"Could not write the report: {exc}", file=sys.stderr)
        return 2
    return report.exit_code(fail_on)

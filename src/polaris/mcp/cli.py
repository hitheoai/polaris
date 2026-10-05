"""`polaris mcp`: the MCP server for AI editors, over stdio.

Standard output carries the MCP protocol, so every human-readable message goes to stderr, which
editors show in their MCP logs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

NEEDS_EXTRA = "The MCP server needs the optional 'mcp' dependency: pip install 'theovex-polaris[mcp]'"


def add_mcp_parsers(commands: Any) -> None:
    mcp = commands.add_parser(
        "mcp", help="Run the Polaris MCP server for Warp, Cursor, Claude Code, VS Code, Windsurf and others.",
        description="Speaks MCP over stdio. Editors start it for you; see `polaris setup`. It reads "
                    "your repository but never writes to it. Code stays on this machine unless you "
                    "signed in to the hosted model; then only functions with SQL or process calls are sent.",
    )
    mcp.add_argument("--root", help="Project folder (default: the editor's workspace, or the "
                                    "folder the editor starts Polaris in).")
    mcp.add_argument("--model", help="Model folder (default: $POLARIS_MODEL or ~/.polaris/models/current).")
    mcp.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    mcp.add_argument("--engine", choices=("hybrid", "model", "rules"), default="hybrid",
                     help="Default engine for the tools: hybrid (rules decide, the model adds a second "
                          "opinion), model, or rules (never loads a model).")
    mcp.add_argument("--model-source", choices=("auto", "local", "remote"), default="auto",
                     help="auto (default): the hosted model when signed in, otherwise an installed one; "
                          "local: only a model on this machine; remote: only the hosted model.")
    mcp.add_argument("--semgrep", "--semgrep-executable", dest="semgrep", type=Path,
                     help="Also run Semgrep CE from this trusted absolute path (optional).")
    mcp.add_argument("--with-semgrep", action="store_true",
                     help="Also run the Semgrep CE installed by `theo setup` (optional, slower).")
    mcp.add_argument("--no-external-analyzers", action="store_true",
                     help="Forbid subprocess analyzers and transient source files.")
    mcp.add_argument("--guard-policy", type=Path,
                     help="Caller-approved authorization-guard policy, fixed at server startup.")
    mcp.add_argument("--action-policy", type=Path,
                     help="Application-owned action scope policy; never accepted from tool calls.")
    mcp.add_argument("--advanced-tools", action="store_true",
                     help="Also list the advanced tools (review_workflow, review_snippet, explain_finding, "
                          "review_details, propose_repair, review_action, capabilities) for CI, the PR bot and "
                          "integrators. By default only polaris_check, polaris_explain and polaris_fix are listed; "
                          "the advanced tools stay callable by name either way.")
    mcp.add_argument("--legacy-tools", action="store_true",
                     help="Also expose the older Python-only review_changes/review_code/assess tools "
                          "(implies --advanced-tools).")


def run(args: argparse.Namespace) -> int:
    try:
        from polaris.mcp.server import build_server, usable_folder
    except ImportError:
        print(NEEDS_EXTRA, file=sys.stderr)
        return 2
    from polaris.integrations import ReviewService
    from polaris.review.analyzers.base import local_workers
    from polaris.workflow.host import host_settings

    try:
        runtime, guard_policy, action_policy = host_settings(
            semgrep=args.semgrep, external=not args.no_external_analyzers,
            managed_semgrep=getattr(args, "with_semgrep", False),
            guard_path=args.guard_policy, action_path=args.action_policy, workers=local_workers(),
        )
    except ValueError:
        print("Polaris MCP: invalid or unreadable trusted analyzer/policy configuration.", file=sys.stderr)
        return 2

    root = usable_folder(args.root)
    if args.root is not None and (root is None or root == Path(root.anchor)
                                  or Path.home().resolve().is_relative_to(root)):
        print("Polaris MCP: --root must be a real, bounded, non-symlink project directory; "
              "unexpanded host variables are not supported.", file=sys.stderr)
        return 2
    if args.engine == "rules":
        service = ReviewService(problem="not_requested")
    else:
        # Loading in the background lets the editor connect right away; tools wait for it.
        service = ReviewService.load(args.model, device=args.device, background=True,
                                     source=args.model_source)
    server = build_server(
        service, root=root, default_engine=args.engine, analysis_runtime=runtime,
        guard_policy=guard_policy, action_policy=action_policy,
        legacy_tools=getattr(args, "legacy_tools", False),
        advanced_tools=getattr(args, "advanced_tools", False),
    )
    print("Polaris MCP server is ready on stdio (the editor talks to it; nothing to type here).",
          file=sys.stderr, flush=True)
    try:
        server.run("stdio")
    except KeyboardInterrupt:
        pass
    return 0

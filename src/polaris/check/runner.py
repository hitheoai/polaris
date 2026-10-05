"""Run one `polaris check`: choose what to check, run the full review, re-check suggested fixes,
and build the plain-language result.

The simple terminal view, `polaris check` (text, Markdown, `--json`), the MCP tools and the agent
hooks all call `run_check`. "auto" checks your changes, or the whole project when there are none.
A folder that doesn't use Git is checked as plain files (scope "folder"); "since last check"
needs Git, so nothing is remembered there. Problems carry fixed codes with plain messages:
exception text is never shown, since it can quote source, paths or credentials.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from polaris.check.model import MAX_ITEMS, CheckResult, Scope

if TYPE_CHECKING:
    from polaris.integrations.forge.verify import Verification
    from polaris.review.analyzers import AnalysisRuntime
    from polaris.review.models import TrustedGuardPolicy, WorkflowReviewConfig
    from polaris.workflow.models import WorkflowEnvelope
    from polaris.workflow.service import WorkspaceReview

Mode = Literal["auto", "changes", "all", "staged", "range", "files"]
Progress = Callable[[str], None]
# Reviews and fix re-checks share the analyzers' process-wide registries: never run two at once.
ANALYSIS_LOCK = threading.Lock()
VERIFY_LIMIT = 20
ERRORS: dict[str, str] = {
    "not_a_git_project": "This folder doesn't use Git yet, so Polaris can't tell what you changed. Run "
                         "`polaris check` to check the whole folder, or run `git init` here first.",
    "folder_too_broad": "Polaris won't check your whole home folder or disk. Open your project folder and run "
                        "it there.",
    "not_a_folder": "Polaris couldn't open that folder (it may not exist, or it may be a link to another "
                    "folder). Open your project folder and run `polaris check` there.",
    "invalid_selection": "Choose only one of --all, --changes, --staged, --diff or --files, don't start a "
                         "--diff range with '-', and keep --limit between 1 and 50.",
    "invalid_revision": "Polaris couldn't find that --diff range in this project. Try something like main...HEAD.",
    "check_failed": "Polaris couldn't finish the check. Try again; if it keeps failing, run "
                    "`polaris workflow review` to see more.",
}
SCOPES: dict[str, Scope] = {
    "changes": "changes", "all": "project", "staged": "staged", "range": "range", "files": "files",
}


class CheckProblem(Exception):
    """A fixed code (see ERRORS, plus the SARIF and plugin code tables) with a plain message."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def message(self) -> str:
        from polaris.review.analyzers.registry import PLUGIN_ERRORS
        from polaris.review.sarif_import import ERRORS as SARIF_ERRORS

        return ERRORS.get(self.code) or SARIF_ERRORS.get(self.code) or PLUGIN_ERRORS.get(self.code) or ERRORS[
            "check_failed"]


@dataclass(frozen=True)
class CheckRequest:
    """What to check. `root` defaults to the current folder's project; `paths` is for "files".

    `runtime` and `guard_policy` are trusted host settings (the MCP server's startup flags, such
    as --semgrep or --guard-policy); None means the built-in analyzers and no guard policy.
    `limit` is how many items get full detail (1 to 50); the rest are counted in `more`, and "since
    last check" always covers every item.
    """

    root: Path | None = None
    mode: Mode = "auto"
    revision_range: str | None = None
    paths: tuple[Path, ...] | None = None
    import_sarif: tuple[Path, ...] = ()
    verify_fixes: bool = True
    remember: bool = True
    runtime: AnalysisRuntime | None = None
    guard_policy: TrustedGuardPolicy | None = None
    limit: int = 25


@dataclass(frozen=True)
class CheckRun:
    """One finished check. `workspace` holds the exact text that was analyzed (for code views and
    fix previews); `envelope` is the full review behind the plain result."""

    result: CheckResult
    envelope: WorkflowEnvelope
    workspace: WorkspaceReview | None
    root: Path
    elapsed_s: float


def valid_revision_range(value: str | None) -> bool:
    return value is not None and 0 < len(value) <= 256 and not value.startswith("-") and "\0" not in value


def _too_broad(folder: Path) -> bool:
    """The disk itself, the home folder, or a folder that contains it."""
    return folder == Path(folder.anchor) or Path.home().resolve().is_relative_to(folder)


def check_root(path: Path | None) -> tuple[Path, bool]:
    """What to check and whether it uses Git: the Git project containing `path` (default: the
    current folder), else that folder itself, checked as plain files. A Git project as wide as
    the home folder (a dotfiles repository) is never checked whole: the folder is, as plain files.
    """
    from polaris.integrations._safe import IntegrationProblem, no_symlinks
    from polaris.integrations.freshness import repository_identity

    try:
        folder = no_symlinks(path if path is not None else Path.cwd())
        usable = folder.is_dir()
    except (IntegrationProblem, OSError, ValueError):
        usable = False
    if not usable:
        raise CheckProblem("not_a_folder")
    if _too_broad(folder):
        raise CheckProblem("folder_too_broad")
    try:
        root = repository_identity(folder).root
    except (IntegrationProblem, OSError, ValueError, RuntimeError):
        return folder, False
    return (folder, False) if _too_broad(root) else (root, True)


def project_root(path: Path | None) -> Path:
    """The folder a check of `path` covers: its Git project, or the folder itself without Git."""
    return check_root(path)[0]


def folder_note(skipped: Iterable[str]) -> str:
    """What a check of a folder without Git means, and how to get "since last check"."""
    from polaris.workflow.service import skipped_names

    names = skipped_names(skipped)
    shown = ", ".join(names[:4]) + (" and others" if len(names) > 4 else "")
    return ("This folder doesn't use Git, so Polaris checked all of its files"
            + (f" (it skipped dependency and build folders: {shown})" if names else "")
            + ". To see what you fixed and what's new since your last check, run `git init` here.")


def run_check(request: CheckRequest, *, progress: Progress | None = None) -> CheckRun:
    """Run one check (blocking). `progress` receives short, plain status lines."""
    from pydantic import ValidationError

    from polaris.engineering.errors import EngineeringError
    from polaris.errors import PolarisError
    from polaris.integrations._safe import IntegrationProblem
    from polaris.onboarding.errors import OnboardingProblem
    from polaris.review.analyzers.registry import PLUGIN_ERRORS, PluginProblem
    from polaris.review.git import GitError
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS
    from polaris.review.sarif_import import SarifProblem

    if ((request.mode == "range") != valid_revision_range(request.revision_range)
            or (request.mode == "files") != bool(request.paths)
            or isinstance(request.limit, bool) or not isinstance(request.limit, int)
            or not 1 <= request.limit <= MAX_ITEMS):
        raise CheckProblem("invalid_selection")
    try:
        with ANALYSIS_LOCK:
            return _run(request, progress or (lambda message: None))
    except CheckProblem:
        raise
    except PluginProblem as problem:
        raise CheckProblem(str(problem) if str(problem) in PLUGIN_ERRORS else "invalid_analyzer_plugin") from None
    except SarifProblem as problem:
        raise CheckProblem(problem.code if problem.code in SARIF_ERRORS else "invalid_sarif") from None
    except GitError:
        raise CheckProblem("invalid_revision" if request.mode == "range" else "check_failed") from None
    except (EngineeringError, PolarisError, IntegrationProblem, OnboardingProblem, ValidationError, OSError,
            ValueError, RuntimeError):
        raise CheckProblem("check_failed") from None


def _settings(*, whole: bool, runtime: AnalysisRuntime | None = None,
              ) -> tuple[WorkflowReviewConfig, AnalysisRuntime]:
    """The same analysis `polaris workflow review` runs locally, with its larger local limits.
    A host's own trusted runtime replaces only the runtime, never the limits."""
    from polaris.review.analyzers import AnalysisRuntime
    from polaris.review.analyzers.base import local_workers
    from polaris.review.models import WorkflowReviewConfig

    config = WorkflowReviewConfig(
        max_files=50_000 if whole else 5_000, max_total_bytes=512_000_000 if whole else 128_000_000,
        max_units=500_000 if whole else 100_000, max_findings=10_000,
    )
    return config, runtime if runtime is not None else AnalysisRuntime(parallel_workers=local_workers())


def _changed(envelope: WorkflowEnvelope) -> bool:
    return any(not change.path.startswith("__polaris") for change in envelope.changes)


def _run(request: CheckRequest, progress: Progress) -> CheckRun:
    from polaris.check import state
    from polaris.check.build import build_check, finding_ids
    from polaris.review.sarif_import import text as printable
    from polaris.workflow.cli import _paths, sarif_inputs
    from polaris.workflow.service import review_folder_detailed, review_workspace_detailed

    started = time.monotonic()
    root, git = check_root(request.root)
    if not git and request.mode not in ("auto", "all", "files"):
        raise CheckProblem("not_a_git_project")  # changes, staged and ranges need Git
    imports = sarif_inputs(list(request.import_sarif)) if request.import_sarif else []
    notes: list[str] = []
    mode = request.mode
    detail: str | None = None
    guard = request.guard_policy
    paths: list[Path] | None = None
    if not git:
        scope: Scope = "files" if mode == "files" else "folder"
        progress("Checking the files in this folder\u2026" if scope == "folder" else "Checking\u2026")
        config, runtime = _settings(whole=True, runtime=request.runtime)
        if mode == "files":
            paths = _paths(root, list(request.paths or ()))
        workspace = review_folder_detailed(root, paths=paths, config=config, runtime=runtime, guard_policy=guard,
                                           imports=imports)
        notes.append(folder_note(workspace.skipped))
    elif mode in ("auto", "changes"):
        progress("Looking at your changes\u2026")
        config, runtime = _settings(whole=False, runtime=request.runtime)
        workspace = review_workspace_detailed(root, config=config, runtime=runtime, guard_policy=guard,
                                              imports=imports)
        scope = "changes"
        if mode == "auto" and not _changed(workspace.envelope):
            progress("No changes since your last commit, so checking your whole project\u2026")
            config, runtime = _settings(whole=True, runtime=request.runtime)
            workspace = review_workspace_detailed(root, paths=[root], config=config, runtime=runtime,
                                                  guard_policy=guard, imports=imports)
            scope = "project"
            notes.append("You have no changes since your last commit, so Polaris checked your whole project.")
    else:
        scope = SCOPES[mode]
        progress("Checking your whole project\u2026" if mode == "all" else "Checking\u2026")
        config, runtime = _settings(whole=mode in ("all", "files"), runtime=request.runtime)
        if mode == "all":
            paths = [root]
        elif mode == "files":
            paths = _paths(root, list(request.paths or ()))
            detail = "\0".join(sorted(str(path) for path in paths or ()))
        if mode == "range":
            detail = request.revision_range
        workspace = review_workspace_detailed(
            root, staged=mode == "staged", revision_range=request.revision_range if mode == "range" else None,
            paths=paths, config=config, runtime=runtime, guard_policy=guard, imports=imports,
        )
    envelope = workspace.envelope
    verifications: dict[str, Verification] = {}
    if request.verify_fixes:
        candidates = [finding for finding in envelope.review.findings
                      if finding.suggested_edit is not None and finding.result in ("flagged", "needs_context")]
        if candidates:
            from polaris.integrations.forge.verify import verify_edits

            progress("Testing the suggested fixes\u2026")
            verifications = verify_edits(workspace, candidates, limit=VERIFY_LIMIT)
    label = None
    if scope == "range" and request.revision_range:
        label = f"the changes in {printable(request.revision_range, 120)}"
    elif scope == "files" and request.paths:
        names = [printable(path.name or str(path), 60) for path in request.paths[:3]]
        label = ", ".join(name for name in names if name) + (f" and {len(request.paths) - 3} more"
                                                             if len(request.paths) > 3 else "")
    key = state.scope_key(scope, detail)
    # Without Git there is nowhere private to remember a check, so nothing is read or written.
    previous = state.load_previous(root, key) if git else None
    result = build_check(envelope, scope=scope, scope_label=label or None, verifications=verifications,
                         previous=previous, limit=request.limit, notes=notes)
    if request.remember and git:
        state.save(root, key, finding_ids(envelope.review))
    return CheckRun(result=result, envelope=envelope, workspace=workspace, root=root,
                    elapsed_s=time.monotonic() - started)

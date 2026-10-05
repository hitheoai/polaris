"""What the terminal UI shows: a live review it runs itself, or a saved report it only reads.

Live reviews call `review_workspace_detailed` (in a Textual thread worker), which also returns the
exact text that was analyzed, so code context never comes from a file that changed afterwards.
Settings are re-read before every run and compared again afterwards, as `workflow review` does;
`--import-sarif` files are re-read on every run. Saved reports are bounded, duplicate-free JSON
validated against the strict `WorkflowEnvelope` schema. Problems carry fixed, value-free codes:
exception text is never shown, since it can quote source, paths or credentials.
"""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

# Reviews and fix verifications share the analyzers' process-wide registries: never run two at
# once. One lock for the whole process, shared with `polaris check` and the simple view.
from polaris.check.runner import ANALYSIS_LOCK
from polaris.workflow.models import WorkflowEnvelope

MAX_REPORT_BYTES = 32_000_000
# An upper bound on JSON values (every value follows "[", "{", ":" or ","), counted before parsing.
MAX_REPORT_NODES = 4_000_000
ERRORS: dict[str, str] = {
    "not_a_terminal": "polaris tui needs an interactive terminal on stdin and stdout. For scripts and CI, use "
                      "`polaris workflow review --format text|json|sarif`, or `polaris tui --plain`.",
    "ci_environment": "polaris tui does not start when CI is set. Use `polaris workflow review --format "
                      "text|json|sarif`, or `polaris tui --plain`.",
    "textual_missing": "The terminal UI needs the optional `tui` extra: pip install 'theovex-polaris[tui]' "
                       "(or uv sync --extra tui). `polaris tui --plain` works without it.",
    "not_a_repository": "No Git repository was found here; run polaris tui inside one or pass --root PATH.",
    "report_unavailable": "The report file could not be read (missing, not a regular file, or a symbolic link). "
                          "Save one first with `polaris workflow review --format json --output review.json`, or run "
                          "`polaris tui` without --report to review your changes now.",
    "report_too_large": f"The report file is larger than the terminal UI's limit ({MAX_REPORT_BYTES // 1_000_000} MB).",
    "invalid_report": "The report file is not valid JSON or not a valid Polaris workflow report.",
    "unsupported_report": "The report file is not a polaris.workflow/0.1.0 report "
                          "(save one with `polaris workflow review --format json --output FILE`).",
    "invalid_arguments": "Choose one of --staged, --diff, --files, --report or --base (--head needs --base), "
                         "and revisions can't start with '-'.",
    "invalid_revision": "The base or head commit could not be resolved in this repository.",
    "workflow_unavailable": "Invalid, unavailable or stale input/context; review did not complete.",
}


class SessionProblem(Exception):
    """A fixed, value-free code (see ERRORS, plus the SARIF and plugin code tables)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def message(self) -> str:
        return error_message(self.code)


def error_message(code: str) -> str:
    from polaris.review.analyzers.registry import PLUGIN_ERRORS
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS

    return ERRORS.get(code) or SARIF_ERRORS.get(code) or PLUGIN_ERRORS.get(code) or ERRORS["workflow_unavailable"]


@dataclass(frozen=True)
class Selection:
    """Which changes a live review covers. `base` turns on the pull-request preview."""

    staged: bool = False
    revision_range: str | None = None
    paths: tuple[Path, ...] | None = None
    base: str | None = None
    head: str | None = None

    @property
    def label(self) -> str:
        if self.base is not None:
            return f"PR preview {self.base}...{self.head or 'HEAD'}"
        if self.staged:
            return "staged changes"
        if self.revision_range is not None:
            return f"range {self.revision_range}"
        if self.paths is not None:
            return "files " + ", ".join(path.name or "." for path in self.paths[:3]) + (
                f" +{len(self.paths) - 3}" if len(self.paths) > 3 else "")
        return "worktree changes"


@dataclass(frozen=True)
class Settings:
    config: Any
    runtime: Any
    guard_policy: Any
    digest: str


@dataclass(frozen=True)
class ReviewRequest:
    """Everything needed to run (and re-run) one live review. `settings` re-reads the caller's
    options each time, so a re-run sees the current guard policy and analyzer configuration."""

    root: Path
    selection: Selection
    settings: Callable[[], Settings]
    sarif_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class PullRequestContext:
    base_sha: str
    head_sha: str
    merge_base: str
    changed: Mapping[str, frozenset[int]]


@dataclass(frozen=True)
class ReviewData:
    """One review as the UI shows it. `workspace` (live mode only) holds the analyzed sources."""

    envelope: WorkflowEnvelope
    mode: Literal["live", "saved"]
    label: str
    root: Path | None = None
    workspace: Any = None
    pull_request: PullRequestContext | None = None
    elapsed_s: float | None = None
    settings_changed: bool = False
    report_name: str | None = None
    other_repository: bool = False
    fail_on_imported: str | None = None
    notes: tuple[str, ...] = field(default=())

    @property
    def live(self) -> bool:
        return self.mode == "live" and self.workspace is not None

    @property
    def stale(self) -> bool:
        return self.envelope.status == "stale" or self.settings_changed


def run_review(request: ReviewRequest) -> ReviewData:
    """Run one live review (blocking; the app calls this from a thread worker)."""
    from pydantic import ValidationError

    from polaris.engineering.errors import EngineeringError
    from polaris.errors import PolarisError
    from polaris.integrations._safe import IntegrationProblem
    from polaris.onboarding.errors import OnboardingProblem
    from polaris.review.analyzers.registry import PLUGIN_ERRORS, PluginProblem
    from polaris.review.git import GitError
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS
    from polaris.review.sarif_import import SarifProblem

    try:
        with ANALYSIS_LOCK:
            return _run(request)
    except SessionProblem:
        raise
    except PluginProblem as problem:
        raise SessionProblem(str(problem) if str(problem) in PLUGIN_ERRORS else "invalid_analyzer_plugin") from None
    except SarifProblem as problem:
        raise SessionProblem(problem.code if problem.code in SARIF_ERRORS else "invalid_sarif") from None
    except GitError:
        raise SessionProblem("workflow_unavailable") from None
    except (EngineeringError, PolarisError, IntegrationProblem, OnboardingProblem, ValidationError, OSError,
            ValueError, RuntimeError):
        # Never surface exception text: parser, path and Git errors can quote source or credentials.
        raise SessionProblem("workflow_unavailable") from None


def _run(request: ReviewRequest) -> ReviewData:
    from polaris.review.git import GitError, changed_lines, revision_identity
    from polaris.workflow.cli import sarif_inputs
    from polaris.workflow.service import review_workspace_detailed

    started = time.monotonic()
    settings = request.settings()
    imports = sarif_inputs(list(request.sarif_paths)) if request.sarif_paths else []
    selection = request.selection
    root = request.root
    pull_request: PullRequestContext | None = None
    common: dict[str, Any] = {
        "config": settings.config, "runtime": settings.runtime, "guard_policy": settings.guard_policy,
        "imports": imports,
    }
    if selection.base is not None:
        head = selection.head or "HEAD"
        try:
            base_sha, head_sha = revision_identity(root, f"{selection.base}..{head}")
            merge_base, target, changed = changed_lines(root, f"{selection.base}...{head}")
        except GitError:
            raise SessionProblem("invalid_revision") from None
        if base_sha is None or head_sha is None or target != head_sha:
            raise SessionProblem("invalid_revision")
        workspace = review_workspace_detailed(root, revision_range=f"{base_sha}...{head_sha}", **common)
        pull_request = PullRequestContext(base_sha, head_sha, merge_base, dict(changed))
    else:
        workspace = review_workspace_detailed(
            root, staged=selection.staged, revision_range=selection.revision_range,
            paths=list(selection.paths) if selection.paths is not None else None, **common,
        )
    again = request.settings()
    return ReviewData(
        envelope=workspace.envelope, mode="live", label=selection.label, root=root, workspace=workspace,
        pull_request=pull_request, elapsed_s=time.monotonic() - started,
        settings_changed=again.digest != settings.digest,
    )


# ---- saved reports ------------------------------------------------------------------------------


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _constant(_: str) -> None:
    raise ValueError("non-finite number")


def parse_report(data: bytes) -> WorkflowEnvelope:
    """Validate an untrusted report: size, structure (no duplicate keys or NaN), then schema."""
    from pydantic import ValidationError

    if len(data) > MAX_REPORT_BYTES:
        raise SessionProblem("report_too_large")
    if data.count(b"[") + data.count(b"{") + data.count(b":") + data.count(b",") + 1 > MAX_REPORT_NODES:
        raise SessionProblem("report_too_large")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise SessionProblem("invalid_report") from None
    if not isinstance(value, dict) or value.get("format") != "polaris.workflow/0.1.0":
        raise SessionProblem("unsupported_report")
    del value
    try:
        return WorkflowEnvelope.model_validate_json(data)
    except (ValidationError, ValueError):
        raise SessionProblem("invalid_report") from None


def read_report(path: Path) -> bytes:
    from polaris.integrations._safe import IntegrationProblem, read_bytes
    from polaris.workflow.cli import _system_resolved

    location = _system_resolved(path.expanduser().absolute())
    try:
        info = os.lstat(location)
    except OSError:
        raise SessionProblem("report_unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise SessionProblem("report_unavailable")
    if info.st_size > MAX_REPORT_BYTES:
        raise SessionProblem("report_too_large")
    try:
        data = read_bytes(location, limit=MAX_REPORT_BYTES)
    except (IntegrationProblem, OSError):
        raise SessionProblem("report_unavailable") from None
    if data is None:
        raise SessionProblem("report_unavailable")
    return data


def load_report(path: Path, *, root: Path | None, repository_id: str | None = None) -> ReviewData:
    envelope = parse_report(read_report(path))
    from polaris.review.sarif_import import text as printable

    recorded = envelope.snapshot.repository_id
    return ReviewData(
        envelope=envelope, mode="saved", label="saved report", root=root,
        elapsed_s=envelope.review.summary.elapsed_ms / 1000, report_name=printable(path.name, 120) or "report",
        other_repository=repository_id is not None and recorded is not None and recorded != repository_id,
    )


def report_json(data: ReviewData) -> dict[str, Any]:
    """The envelope exactly as `workflow review --format json` writes it (for `w`)."""
    return data.envelope.model_dump(mode="json")

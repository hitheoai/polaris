"""Repository review settings and the accepted-findings baseline.

`.polaris.toml`:

    [workflow]
    auth_guards = ["requireUser", "withOrgAuth"]      # calls that count as authentication
    public_routes = ["app/api/health/**", "app/api/webhooks/**"]  # intentionally public
    honor_suppressions = true                          # inline `polaris-ignore[check]: reason`
    exclude = ["src/generated/**", "**/*.sh"]          # out of scope; reported as excluded

`.polaris/baseline.json` lists fingerprints of findings that already existed when the
baseline was written (`polaris workflow baseline`), so diff reviews report only new issues.

Both are advisory local configuration read from the worktree. A CI gate should load them
from the base branch, never from the change under review.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

from polaris.integrations._safe import IntegrationProblem, atomic_write, no_symlinks, read_bytes
from polaris.review.models import ProjectSettings, WorkflowFinding

SETTINGS_PATH = ".polaris.toml"
BASELINE_PATH = ".polaris/baseline.json"
BASELINE_FORMAT = "polaris.baseline/0.1.0"
MAX_SETTINGS_BYTES = 256_000
MAX_BASELINE_BYTES = 16_000_000
MAX_BASELINE_ENTRIES = 100_000
FINGERPRINT = re.compile(r"^[0-9a-f]{16,64}$")


class ProjectSettingsError(ValueError):
    """A present but unreadable or invalid project settings/baseline file."""


def _read(root: Path, relative: str, limit: int) -> bytes | None:
    try:
        return read_bytes(root / relative, limit=limit)
    except (OSError, IntegrationProblem) as exc:
        raise ProjectSettingsError(f"{relative} is unreadable, a symbolic link, or too large") from exc


def load_project_settings(root: Path) -> ProjectSettings:
    """Return `[workflow]` settings from the worktree, or defaults when absent."""
    return parse_project_settings(_read(root, SETTINGS_PATH, MAX_SETTINGS_BYTES))


def parse_project_settings(content: bytes | None) -> ProjectSettings:
    """Parse `.polaris.toml` bytes (from the worktree or a base revision)."""
    if content is None:
        return ProjectSettings()
    if len(content) > MAX_SETTINGS_BYTES:
        raise ProjectSettingsError(f"{SETTINGS_PATH} is too large")
    try:
        data = tomllib.loads(content.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ProjectSettingsError(f"{SETTINGS_PATH} is not valid TOML: {exc}") from exc
    section = data.get("workflow", {})
    if not isinstance(section, dict):
        raise ProjectSettingsError(f"{SETTINGS_PATH} [workflow] must be a table")
    unknown = set(section) - set(ProjectSettings.model_fields)
    if unknown:
        raise ProjectSettingsError(f"unknown {SETTINGS_PATH} [workflow] settings: " + ", ".join(sorted(unknown)))
    try:
        return ProjectSettings.model_validate(section)
    except ValueError as exc:
        raise ProjectSettingsError(
            f"invalid {SETTINGS_PATH} [workflow] settings (guards are dotted identifiers; "
            "public_routes and exclude are path globs)"
        ) from exc


def load_baseline(root: Path) -> frozenset[str]:
    """Fingerprints of accepted existing findings in the worktree; empty when absent."""
    return parse_baseline(_read(root, BASELINE_PATH, MAX_BASELINE_BYTES))


def parse_baseline(content: bytes | None) -> frozenset[str]:
    """Parse `.polaris/baseline.json` bytes (from the worktree or a base revision)."""
    if content is None:
        return frozenset()
    if len(content) > MAX_BASELINE_BYTES:
        raise ProjectSettingsError(f"{BASELINE_PATH} is too large")
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProjectSettingsError(f"{BASELINE_PATH} is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT or not isinstance(data.get("findings"), list):
        raise ProjectSettingsError(f"{BASELINE_PATH} is not a {BASELINE_FORMAT} file")
    prints = set()
    for item in data["findings"][:MAX_BASELINE_ENTRIES]:
        value = item.get("fingerprint") if isinstance(item, dict) else item
        if isinstance(value, str) and FINGERPRINT.fullmatch(value):
            prints.add(value)
    return frozenset(prints)


def baseline_entries(findings: Iterable[WorkflowFinding]) -> list[dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for finding in findings:
        if finding.fingerprint and finding.result in ("flagged", "needs_context"):
            entries[finding.fingerprint] = {
                "fingerprint": finding.fingerprint, "check_id": finding.check_id, "path": finding.path,
                "rule_id": finding.rule_id or "", "result": finding.result,
            }
    ordered = sorted(entries.values(), key=lambda item: (item["path"], item["check_id"], item["fingerprint"]))
    return ordered[:MAX_BASELINE_ENTRIES]


def write_baseline(root: Path, findings: Iterable[WorkflowFinding]) -> tuple[Path, int]:
    """Write `.polaris/baseline.json` atomically; returns its path and entry count."""
    entries = baseline_entries(findings)
    document = {
        "format": BASELINE_FORMAT,
        "note": ("Accepted existing findings. Diff reviews report these as baselined instead of new. "
                 "Regenerate with `polaris workflow baseline`; remove entries as issues are fixed."),
        "findings": entries,
    }
    content = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    try:
        path = no_symlinks(root / BASELINE_PATH)
        atomic_write(path, content.encode("utf-8"), mode=0o644)
    except (OSError, IntegrationProblem) as exc:
        raise ProjectSettingsError(f"could not write {BASELINE_PATH}") from exc
    return path, len(entries)

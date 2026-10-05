"""Load review settings from `.polaris.toml` or `[tool.polaris.review]` in `pyproject.toml`.

Example `.polaris.toml`:

    [review]
    checks = ["sql_injection", "command_injection"]
    policy = ["Request handlers receive untrusted HTTP input.", "Admin scripts run with trusted arguments."]
    flag_threshold = 0.8
    exclude = ["scripts/legacy/**"]
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from polaris.review.models import DEFAULT_EXCLUDES, ReviewConfig

ALLOWED = {"checks", "policy", "flag_threshold", "include", "exclude", "max_units", "max_file_bytes", "report_ok"}


class ConfigError(ValueError):
    pass


def _section(root: Path) -> tuple[dict[str, Any], str | None]:
    dedicated = root / ".polaris.toml"
    if dedicated.is_file() and not dedicated.is_symlink():
        data = tomllib.loads(dedicated.read_text(encoding="utf-8"))
        # `[workflow]` holds settings for the workflow reviewer (polaris.review.project).
        section = data.get("review", {key: value for key, value in data.items() if key != "workflow"})
        return dict(section), str(dedicated)
    project = root / "pyproject.toml"
    if project.is_file() and not project.is_symlink():
        data = tomllib.loads(project.read_text(encoding="utf-8"))
        section = data.get("tool", {}).get("polaris", {}).get("review")
        if isinstance(section, dict):
            return dict(section), f"{project} [tool.polaris.review]"
    return {}, None


def load_config(root: Path | None, overrides: dict[str, Any] | None = None) -> tuple[ReviewConfig, str | None]:
    """Return the effective configuration and where it came from (None for defaults)."""
    values: dict[str, Any] = {}
    origin = None
    if root is not None:
        try:
            values, origin = _section(root)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"could not read Polaris settings: {exc}") from exc
    unknown = set(values) - ALLOWED
    if unknown:
        raise ConfigError("unknown Polaris settings: " + ", ".join(sorted(unknown)))
    if "exclude" in values:
        values["exclude"] = [*DEFAULT_EXCLUDES, *values["exclude"]]
    if "policy" in values:
        values["policy_source"] = "repository"
    if isinstance(values.get("flag_threshold"), int):
        values["flag_threshold"] = float(values["flag_threshold"])
    values.update(overrides or {})
    try:
        return ReviewConfig.model_validate(values), origin
    except ValueError as exc:
        raise ConfigError(f"invalid Polaris settings in {origin or 'arguments'}") from exc

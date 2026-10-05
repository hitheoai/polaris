"""Explicit startup configuration. No repository discovery or request-controlled policy."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from polaris.engineering import ActionPolicy
from polaris.engineering.errors import EngineeringError
from polaris.engineering.models import parse_model
from polaris.errors import PolarisError
from polaris.integrations._safe import IntegrationProblem, read_bytes
from polaris.jsonio import load_json
from polaris.onboarding.errors import OnboardingProblem
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import TrustedGuardPolicy


def host_settings(
    *, semgrep: Path | None = None, external: bool = False, managed_semgrep: bool = False,
    guard_path: Path | None = None, action_path: Path | None = None, workers: int = 0,
) -> tuple[AnalysisRuntime, TrustedGuardPolicy | None, ActionPolicy | None]:
    """Semgrep is opt-in: an explicit path, or the managed install when `managed_semgrep`.

    `workers` > 1 lets large reviews use worker processes (the local MCP server; never HTTP).
    """
    try:
        if semgrep is not None and not semgrep.is_absolute():
            raise ValueError("an absolute trusted analyzer path is required")
        if semgrep is None and external and managed_semgrep:
            from polaris.onboarding.installation import analyzer

            semgrep = analyzer()
            if semgrep is None:
                raise ValueError("the managed analyzer is not installed")
        runtime = AnalysisRuntime(
            allow_external_analyzers=external, allow_temporary_source_files=external,
            semgrep_executable=str(semgrep) if semgrep else None, parallel_workers=workers,
        )
        guard = None
        if guard_path is not None:
            raw = read_bytes(guard_path.expanduser().absolute(), limit=256_000)
            if raw is None:
                raise ValueError("guard policy missing")
            guard = TrustedGuardPolicy.model_validate(load_json(raw))
        action = None
        if action_path is not None:
            raw = read_bytes(action_path.expanduser().absolute(), limit=256_000)
            if raw is None:
                raise ValueError("action policy missing")
            action = parse_model(ActionPolicy, raw)
        return runtime, guard, action
    except (EngineeringError, IntegrationProblem, OnboardingProblem, PolarisError, ValidationError, OSError, ValueError):
        raise ValueError("invalid trusted host configuration") from None

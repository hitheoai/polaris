"""Automatic security review of Python code changes: the shared engine behind every integration.

Typical use:

    from polaris.review import Reviewer, load_backend, load_config
    config, _ = load_config(repo_root)
    reviewer = Reviewer(load_backend(), config=config)
    report = reviewer.review_snippet(code)

Findings estimate risk; they never authorize or execute anything.
"""

from polaris.review.cache import ReviewCache
from polaris.review.config import ConfigError, load_config
from polaris.review.engine import Reviewer
from polaris.review.loader import auto_device, load_backend, polaris_home, resolve_model
from polaris.review.models import (
    REVIEW_FORMAT,
    Finding,
    ModelInfo,
    ReviewConfig,
    ReviewReport,
    ReviewSummary,
    SourceFile,
)
from polaris.review.output import to_sarif, to_text

__all__ = [
    "REVIEW_FORMAT",
    "ConfigError",
    "Finding",
    "ModelInfo",
    "ReviewCache",
    "ReviewConfig",
    "ReviewReport",
    "ReviewSummary",
    "Reviewer",
    "SourceFile",
    "auto_device",
    "load_backend",
    "load_config",
    "polaris_home",
    "resolve_model",
    "to_sarif",
    "to_text",
]

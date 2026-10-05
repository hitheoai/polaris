"""Shared pieces behind the REST API, the MCP server and editor setup.

Everything here runs locally: nothing downloads a model or sends code anywhere.
"""

from polaris.integrations.service import (
    ENGINES,
    Engine,
    ModelStatus,
    ModelUnavailable,
    ReviewService,
    request_config,
    settings_problem,
)

__all__ = [
    "ENGINES",
    "Engine",
    "ModelStatus",
    "ModelUnavailable",
    "ReviewService",
    "request_config",
    "settings_problem",
]

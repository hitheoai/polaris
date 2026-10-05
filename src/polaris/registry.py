from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from polaris.contract import (
    CONTRACT_VERSION,
    MAX_TOKENS,
    REGISTRY_VERSION,
    AssessmentRequest,
    CodeChange,
    ReasonCode,
    ToolAction,
)


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    description: str
    kinds: tuple[str, ...]
    required_context: tuple[str, ...]
    required_evidence: tuple[str, ...] = ()
    revision: int = 1


CHECKS = (
    CheckSpec(
        "api_authorization",
        "Missing or weakened subject/resource/tenant authorization in the proposed result.",
        ("code_change",),
        ("principal", "scope", "policy"),
        ("code_after",),
    ),
    CheckSpec(
        "tool_scope",
        "Proposed tool action conflicts with caller-supplied actor, environment, or scope.",
        ("tool_action",),
        ("principal", "environment", "scope"),
    ),
    CheckSpec(
        "sql_injection",
        "Untrusted data enters SQL construction without appropriate data/code separation.",
        ("code_change",),
        ("scope",),
        ("code_after", "data_flow"),
    ),
    CheckSpec(
        "command_injection",
        "Untrusted data enters a shell or process execution context unsafely.",
        ("code_change", "tool_action"),
        ("scope",),
        ("data_flow",),
    ),
    CheckSpec(
        "prompt_injection",
        "Untrusted evidence attempts to redirect an agent from its trusted task or policy.",
        ("code_change", "tool_action"),
        ("policy", "purpose"),
    ),
    CheckSpec(
        "secret_exposure",
        "Credentials are exposed in code, logs, process arguments, or destinations.",
        ("code_change", "tool_action"),
        ("policy", "scope"),
    ),
    CheckSpec(
        "sensitive_data_exposure",
        "Non-credential data flow conflicts with supplied access, purpose, or destination policy.",
        ("code_change", "tool_action"),
        ("policy", "purpose", "scope"),
        ("data_flow",),
    ),
)
CHECK_IDS = tuple(check.check_id for check in CHECKS)
BY_ID = {check.check_id: check for check in CHECKS}
TOOL_NAMES = ("shell", "process", "filesystem", "network")


def capabilities() -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "registry_version": REGISTRY_VERSION,
        "registry_status": "experimental",
        "qualified_checks": [],
        "max_input_tokens": MAX_TOKENS,
        "languages": ["python"],
        "tool_names": list(TOOL_NAMES),
        "checks": [asdict(check) for check in CHECKS],
        "authorization": False,
        "weights_included": False,
    }


def precheck(
    request: AssessmentRequest, check_id: str, revision: int
) -> tuple[str | None, ReasonCode | None, list[str]]:
    spec = BY_ID.get(check_id)
    if spec is None:
        return "unsupported", "unknown_check", []
    if revision != spec.revision:
        return "unsupported", "unsupported_revision", []
    action = request.action
    if action.kind not in spec.kinds:
        return "unsupported", "unsupported_domain", []
    if isinstance(action, CodeChange) and action.language != "python":
        return "unsupported", "unsupported_domain", []
    if isinstance(action, ToolAction) and action.tool_name not in TOOL_NAMES:
        return "unsupported", "unsupported_domain", []
    contexts = {context.kind for context in request.trusted_context}
    evidence = {item.kind for item in request.evidence}
    missing = [f"context:{kind}" for kind in spec.required_context if kind not in contexts]
    missing.extend(f"evidence:{kind}" for kind in spec.required_evidence if kind not in evidence)
    if check_id == "prompt_injection" and not request.evidence:
        missing.append("evidence:any")
    if missing:
        return "abstain", "missing_context", missing
    if any(context.conflicts_with for context in request.trusted_context):
        return "abstain", "conflicting_context", []
    if request.known_omissions:
        return "abstain", "known_omissions", []
    return None, None, []

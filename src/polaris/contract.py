from __future__ import annotations

import math
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from polaris.errors import ErrorCode, PolarisInputError
from polaris.jsonio import (
    MAX_PAYLOAD_BYTES,
    canonical_bytes,
    check_structure,
    digest_json,
    digest_text,
    load_json,
)

CONTRACT_VERSION: Literal["polaris.assessment/0.1.0"] = "polaris.assessment/0.1.0"
PREPROCESSING_VERSION: Literal["snapshot-json/0.2.0"] = "snapshot-json/0.2.0"
REGISTRY_VERSION: Literal["polaris.checks/0.1.0"] = "polaris.checks/0.1.0"
MAX_TOKENS = 2048

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:/@-]+$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=1024)]
Probability = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
ContextKind = Literal["policy", "principal", "tenant", "purpose", "environment", "scope"]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        revalidate_instances="always",
        allow_inf_nan=False,
    )


class CheckRequest(StrictModel):
    check_id: Identifier
    check_revision: Annotated[int, Field(ge=1)] = 1


class SourceLocation(StrictModel):
    path: ShortText
    start_line: Annotated[int, Field(ge=1)] | None = None


class Evidence(StrictModel):
    evidence_id: Identifier
    kind: Literal[
        "code_before", "code_after", "diff", "tool_output", "document", "log", "data_flow"
    ]
    origin: ShortText
    revision: Identifier
    digest: Digest
    content: Annotated[str, Field(min_length=1, max_length=131_072)]
    location: SourceLocation | None = None

    @model_validator(mode="after")
    def verify_content(self) -> Self:
        if digest_text(self.content) != self.digest:
            raise ValueError("evidence digest mismatch")
        return self


class TrustedContext(StrictModel):
    context_id: Identifier
    kind: ContextKind
    source: ShortText
    revision: Identifier
    digest: Digest
    content: Annotated[str, Field(min_length=1, max_length=65_536)]
    conflicts_with: Annotated[list[Identifier], Field(max_length=64)] = Field(default_factory=list)

    @model_validator(mode="after")
    def verify_content(self) -> Self:
        if digest_text(self.content) != self.digest:
            raise ValueError("context digest mismatch")
        return self


class CodeChange(StrictModel):
    action_id: Identifier
    kind: Literal["code_change"]
    language: Identifier
    before_refs: Annotated[list[Identifier], Field(max_length=64)] = Field(default_factory=list)
    after_refs: Annotated[list[Identifier], Field(min_length=1, max_length=64)]
    diff_refs: Annotated[list[Identifier], Field(max_length=64)] = Field(default_factory=list)
    summary: Annotated[str, Field(max_length=4096)] = ""


class ToolAction(StrictModel):
    action_id: Identifier
    kind: Literal["tool_action"]
    tool_name: Identifier
    arguments: dict[str, JsonValue]
    targets: Annotated[list[ShortText], Field(max_length=64)]
    summary: Annotated[str, Field(max_length=4096)] = ""


Action = Annotated[CodeChange | ToolAction, Field(discriminator="kind")]


class AssessmentRequest(StrictModel):
    contract_version: Literal["polaris.assessment/0.1.0"]
    request_id: Identifier
    requested_checks: Annotated[list[CheckRequest], Field(min_length=1, max_length=32)]
    action: Action
    evidence: Annotated[list[Evidence], Field(max_length=64)]
    trusted_context: Annotated[list[TrustedContext], Field(max_length=64)]
    known_omissions: Annotated[list[ShortText], Field(max_length=64)] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def bound_python_input(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if isinstance(value.get("action"), BaseModel):
                value["action"] = value["action"].model_dump(mode="json")
            for key in ("requested_checks", "evidence", "trusted_context"):
                if isinstance(value.get(key), list):
                    value[key] = [
                        item.model_dump(mode="json") if isinstance(item, BaseModel) else item
                        for item in value[key]
                    ]
            check_structure(value)
            if len(canonical_bytes(value)) > MAX_PAYLOAD_BYTES:
                raise PolarisInputError("payload_limit")
        return value

    @model_validator(mode="after")
    def references_are_consistent(self) -> Self:
        checks = [(check.check_id, check.check_revision) for check in self.requested_checks]
        evidence = {item.evidence_id: item for item in self.evidence}
        contexts = {item.context_id: item for item in self.trusted_context}
        if len(checks) != len(set(checks)):
            raise ValueError("duplicate requested check")
        if len(evidence) != len(self.evidence) or len(contexts) != len(self.trusted_context):
            raise ValueError("duplicate source identifier")
        if evidence.keys() & contexts.keys():
            raise ValueError("evidence and trusted context must use distinct identifiers")
        for context in self.trusted_context:
            if context.context_id in context.conflicts_with:
                raise ValueError("self-conflicting context")
            if not set(context.conflicts_with) <= contexts.keys():
                raise ValueError("unknown conflicting context")
        if isinstance(self.action, CodeChange):
            for refs, kind in (
                (self.action.before_refs, "code_before"),
                (self.action.after_refs, "code_after"),
                (self.action.diff_refs, "diff"),
            ):
                if len(refs) != len(set(refs)):
                    raise ValueError("duplicate artifact reference")
                if any(ref not in evidence or evidence[ref].kind != kind for ref in refs):
                    raise ValueError("missing or mistyped artifact reference")
        return self

    @property
    def request_digest(self) -> str:
        return digest_json(self.model_dump(mode="json"))


class RiskProbabilities(StrictModel):
    risk_present: Probability
    risk_absent: Probability

    @model_validator(mode="after")
    def normalized(self) -> Self:
        if not math.isclose(self.risk_present + self.risk_absent, 1.0, abs_tol=1e-8):
            raise ValueError("probabilities must sum to one")
        return self


class EvidenceReference(StrictModel):
    evidence_id: Identifier
    digest: Digest
    relation: Literal["considered", "supporting"]
    method: Literal["input_coverage", "validated_extractor", "deterministic_finding"]
    start_byte: Annotated[int, Field(ge=0)] | None = None
    end_byte: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def valid_range(self) -> Self:
        if (self.start_byte is None) != (self.end_byte is None):
            raise ValueError("both byte offsets are required")
        if self.start_byte is not None and self.end_byte is not None:
            if self.end_byte <= self.start_byte:
                raise ValueError("byte range must be nonempty")
        if self.relation == "supporting" and self.method == "input_coverage":
            raise ValueError("consumed input is not supporting evidence")
        return self


class TokenCoverage(StrictModel):
    action: Annotated[int, Field(ge=0)]
    evidence: Annotated[int, Field(ge=0)]
    trusted_context: Annotated[int, Field(ge=0)]
    framing: Annotated[int, Field(ge=0)]
    total: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def valid_total(self) -> Self:
        if self.total != self.action + self.evidence + self.trusted_context + self.framing:
            raise ValueError("token accounting mismatch")
        return self


class Coverage(StrictModel):
    scope: Literal["supplied_snapshot_only"] = "supplied_snapshot_only"
    supplied_evidence: list[Identifier]
    consumed_evidence: list[Identifier] = Field(default_factory=list)
    consumed_context: list[Identifier] = Field(default_factory=list)
    supplied_tokens: TokenCoverage | None = None
    consumed_tokens: TokenCoverage | None = None
    known_omissions: list[ShortText] = Field(default_factory=list)
    missing_required_context: list[str] = Field(default_factory=list)
    truncated: Literal[False] = False


ReasonCode = Literal[
    "supported_assessment",
    "unknown_check",
    "unsupported_revision",
    "unsupported_domain",
    "unreleased_check",
    "missing_context",
    "conflicting_context",
    "known_omissions",
    "insufficient_context",
    "uncertain",
]


class CheckResult(StrictModel):
    check_id: Identifier
    check_revision: Annotated[int, Field(ge=1)]
    status: Literal["assessed", "abstain", "unsupported"]
    reason_codes: Annotated[list[ReasonCode], Field(min_length=1)]
    probabilities: RiskProbabilities | None
    coverage: Coverage
    evidence_refs: list[EvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_assessment_status(self) -> Self:
        if (self.status == "assessed") != (self.probabilities is not None):
            raise ValueError("only assessed results have probabilities")
        return self


class RuntimeIdentity(StrictModel):
    model_version: str | None = None
    model_digest: Digest | None = None
    tokenizer_version: str | None = None
    preprocessing_version: str = PREPROCESSING_VERSION
    calibration_version: str | None = None
    calibration_digest: Digest | None = None
    operating_profile_version: str | None = None
    operating_profile_digest: Digest | None = None
    max_input_tokens: Annotated[int, Field(ge=1, le=MAX_TOKENS)] | None = None
    runtime_variant: str | None = None
    release_status: Literal["not_loaded", "experimental", "qualified"] = "not_loaded"


class AssessmentResponse(StrictModel):
    kind: Literal["assessment"] = "assessment"
    contract_version: Literal["polaris.assessment/0.1.0"] = CONTRACT_VERSION
    registry_version: Literal["polaris.checks/0.1.0"] = REGISTRY_VERSION
    request_id: Identifier
    request_digest: Digest
    runtime: RuntimeIdentity
    results: Annotated[list[CheckResult], Field(min_length=1, max_length=32)]


class ErrorResponse(StrictModel):
    kind: Literal["error"] = "error"
    contract_version: Literal["polaris.assessment/0.1.0"] = CONTRACT_VERSION
    request_id: Identifier | None = None
    category: Literal["input", "runtime"]
    code: ErrorCode
    message: str
    retryable: bool = False


def parse_request(value: AssessmentRequest | dict[str, Any] | str | bytes) -> AssessmentRequest:
    if isinstance(value, AssessmentRequest):
        value = value.model_dump(mode="json")
    if isinstance(value, (str, bytes)):
        value = load_json(value)
    if not isinstance(value, dict):
        raise PolarisInputError("invalid_input")
    if value.get("contract_version") != CONTRACT_VERSION:
        raise PolarisInputError("unsupported_contract")
    try:
        return AssessmentRequest.model_validate(value)
    except ValidationError as exc:
        # Do not expose Pydantic's input excerpts: they can contain secrets.
        raise PolarisInputError("invalid_input") from exc


def schema(kind: Literal["request", "response", "error"]) -> dict[str, Any]:
    models: dict[str, type[StrictModel]] = {
        "request": AssessmentRequest,
        "response": AssessmentResponse,
        "error": ErrorResponse,
    }
    result = models[kind].model_json_schema()
    result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    result["$id"] = f"urn:polaris:assessment:0.1.0:{kind}"
    if kind == "response":
        result["$defs"]["CheckResult"]["allOf"] = [
            {
                "if": {"properties": {"status": {"const": "assessed"}}},
                "then": {"properties": {"probabilities": {"$ref": "#/$defs/RiskProbabilities"}}},
                "else": {"properties": {"probabilities": {"type": "null"}}},
            }
        ]
    return result

"""Optional coding-provider contract, independent of the experimental Polaris classifier."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal, Self

from pydantic import Field, SecretStr, model_validator

from polaris.engineering.actions import scope_url
from polaris.engineering.models import (
    CandidateEdit,
    Digest,
    EngineeringLimits,
    EngineeringModel,
    Identifier,
    PatchProposal,
    PathText,
    ProcessAction,
    ReviewedSnapshot,
    Text,
)
from polaris.engineering.security import guard_output, relative_path, utf8_bytes
from polaris.jsonio import digest_bytes

GenerationCode = Literal[
    "generated", "disabled", "not_configured", "hosted_not_enabled",
    "invalid_request", "context_limit", "token_budget", "secret_detected",
    "timeout", "output_limit", "redirect_rejected", "provider_error",
    "invalid_response", "invalid_candidate", "refused", "attempts_exhausted",
]


class GenerationBudget(EngineeringModel):
    max_context_bytes: Annotated[int, Field(ge=1, le=262_144)] = 65_536
    max_input_tokens: Annotated[int, Field(ge=1, le=65_536)] = 16_384
    max_output_tokens: Annotated[int, Field(ge=1, le=8192)] = 1024
    max_total_tokens: Annotated[int, Field(ge=1, le=196_608)] = 32_768
    max_output_bytes: Annotated[int, Field(ge=1, le=262_144)] = 65_536
    max_attempts: Annotated[int, Field(ge=1, le=3)] = 1
    total_timeout_seconds: Annotated[float, Field(gt=0.0, le=120.0)] = 20.0


class GenerationConfig(EngineeringModel):
    """Application-only configuration. No ambient key, login, repo file, or URL discovery."""

    enabled: bool = False
    endpoint: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    model: Identifier | None = None
    allow_hosted: bool = False
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    budget: GenerationBudget = Field(default_factory=GenerationBudget)
    proposal_limits: EngineeringLimits = Field(default_factory=EngineeringLimits)

    @model_validator(mode="after")
    def configured_endpoint_is_safe(self) -> Self:
        if self.endpoint is not None:
            scheme, host, _, _ = scope_url(self.endpoint)
            if scheme == "http":
                try:
                    loopback = ipaddress.ip_address(host).is_loopback
                except ValueError:
                    loopback = False
                if not loopback:
                    raise ValueError("cleartext endpoints require a literal loopback IP")
            guard_output(self.endpoint)
        if self.model is not None:
            guard_output(self.model)
        if self.api_key is not None:
            value = self.api_key.get_secret_value()
            if not 8 <= len(value) <= 4096 or any(not 33 <= ord(char) <= 126 for char in value):
                raise ValueError("invalid credential format")
        return self


class GenerationSource(EngineeringModel):
    path: PathText
    sha256: Digest
    content: Annotated[str, Field(max_length=262_144, repr=False)]

    @model_validator(mode="after")
    def content_matches_digest(self) -> Self:
        relative_path(self.path)
        if digest_bytes(utf8_bytes(self.content)) != self.sha256:
            raise ValueError("source digest mismatch")
        return self


class GenerationRequest(EngineeringModel):
    format: Literal["polaris.generation/0.1.0"] = "polaris.generation/0.1.0"
    snapshot: ReviewedSnapshot
    goal: Text = Field(repr=False)
    sources: Annotated[tuple[GenerationSource, ...], Field(min_length=1, max_length=64, repr=False)]
    context_sources: Annotated[tuple[GenerationSource, ...], Field(max_length=64, repr=False)] = ()

    @model_validator(mode="after")
    def exact_snapshot_content(self) -> Self:
        for sources, expected in (
            (self.sources, self.snapshot.files),
            (self.context_sources, self.snapshot.context_files),
        ):
            by_path = {item.path: item for item in sources}
            if len(by_path) != len(sources) or by_path.keys() != {item.path for item in expected}:
                raise ValueError("source scope mismatch")
            for state in expected:
                item = by_path[state.path]
                if item.sha256 != state.sha256 or len(utf8_bytes(item.content)) != state.size_bytes:
                    raise ValueError("source snapshot mismatch")
        return self


class GeneratedCandidate(EngineeringModel):
    edits: Annotated[tuple[CandidateEdit, ...], Field(min_length=1, max_length=16, repr=False)]
    rationale: Text = Field(repr=False)
    verification_commands: Annotated[tuple[ProcessAction, ...], Field(max_length=16)] = ()


class GenerationUsage(EngineeringModel):
    source: Literal["unknown", "provider_reported"] = "unknown"
    prompt_tokens: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    completion_tokens: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    total_tokens: Annotated[int, Field(ge=0, le=20_000_000)] | None = None
    # OpenAI-compatible token counts do not establish billed cost.
    cost_usd: Literal[None] = None

    @model_validator(mode="after")
    def coherent_usage(self) -> Self:
        values = (self.prompt_tokens, self.completion_tokens, self.total_tokens)
        if self.source == "unknown" and any(value is not None for value in values):
            raise ValueError("unknown usage cannot have measured values")
        if self.source == "provider_reported":
            if any(value is None for value in values):
                raise ValueError("incomplete usage")
            if self.total_tokens != (self.prompt_tokens or 0) + (self.completion_tokens or 0):
                raise ValueError("usage mismatch")
        return self


class GenerationReceipt(EngineeringModel):
    """Safe to persist: no source, prompt, candidate, credential, URL, or provider error body."""

    format: Literal["polaris.generation-receipt/0.1.0"] = "polaris.generation-receipt/0.1.0"
    status: Literal["generated", "unavailable", "error"]
    code: GenerationCode
    request_digest: Digest | None = None
    proposal_digest: Digest | None = None
    model: Identifier | None = None
    attempts: Annotated[int, Field(ge=0, le=3)] = 0
    elapsed_ms: Annotated[float, Field(ge=0.0)]
    input_budget_units: Annotated[int, Field(ge=0)] | None = None
    input_budget_method: Literal["utf8_upper_bound", "configured_tokenizer"]
    usage: GenerationUsage = Field(default_factory=GenerationUsage)


class GenerationResult(EngineeringModel):
    format: Literal["polaris.generation/0.1.0"] = "polaris.generation/0.1.0"
    receipt: GenerationReceipt
    proposal: PatchProposal | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def coherent_result(self) -> Self:
        if (self.receipt.status == "generated") != (self.proposal is not None):
            raise ValueError("only generated responses contain a proposal")
        if self.proposal is not None and self.receipt.proposal_digest != self.proposal.proposal_digest:
            raise ValueError("proposal receipt mismatch")
        return self

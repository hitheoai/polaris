"""Workflow inputs never accept an analyzer executable, provider URL, or trusted policy."""

from __future__ import annotations

from typing import Annotated, Any, Self

from pydantic import Field, field_validator, model_validator

from polaris.contract import StrictModel
from polaris.engineering.errors import EngineeringError
from polaris.engineering.models import CandidateEdit, ProcessAction, parse_model
from polaris.review.models import WorkflowReviewConfig, valid_source_path


class WorkflowFile(StrictModel):
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    content: Annotated[str, Field(max_length=2_000_000)]
    before: Annotated[str, Field(max_length=2_000_000)] | None = None

    @field_validator("path")
    @classmethod
    def relative_label(cls, value: str) -> str:
        if not valid_source_path(value):
            raise ValueError("a portable relative file label is required")
        return value


class WorkflowReviewRequest(StrictModel):
    files: Annotated[list[WorkflowFile], Field(min_length=1, max_length=500)]
    config: WorkflowReviewConfig | None = None

    @model_validator(mode="after")
    def unique_files(self) -> Self:
        if len({item.path for item in self.files}) != len(self.files):
            raise ValueError("file labels must be unique")
        return self


class CandidateRequest(StrictModel):
    edits: Annotated[list[CandidateEdit], Field(min_length=1, max_length=8)]
    rationale: Annotated[str, Field(min_length=1, max_length=4096)]
    verification_commands: Annotated[list[ProcessAction], Field(max_length=16)] = Field(default_factory=list)
    expected_snapshot_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None

    @field_validator("edits", mode="before")
    @classmethod
    def parse_edits(cls, values: Any) -> Any:
        if not isinstance(values, list) or not 1 <= len(values) <= 8:
            raise ValueError("provide one to eight bounded candidate edits")
        try:
            return [parse_model(CandidateEdit, item) for item in values]
        except EngineeringError:
            raise ValueError("invalid candidate edit") from None

    @field_validator("verification_commands", mode="before")
    @classmethod
    def parse_commands(cls, values: Any) -> Any:
        if not isinstance(values, list) or len(values) > 16:
            raise ValueError("provide at most sixteen typed verification proposals")
        try:
            return [parse_model(ProcessAction, item) for item in values]
        except EngineeringError:
            raise ValueError("invalid verification proposal") from None


class WorkflowRepairRequest(WorkflowReviewRequest):
    candidate: CandidateRequest

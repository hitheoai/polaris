"""Request and response shapes of the Polaris REST API; all of them appear in its OpenAPI."""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, Field, model_validator

from polaris.contract import AssessmentResponse, ErrorResponse, Probability, StrictModel
from polaris.integrations import Engine, ModelStatus

MAX_BATCH = 64

ApiErrorCode = Literal[
    "unauthorized",
    "invalid_host",
    "not_found",
    "method_not_allowed",
    "unsupported_media_type",
    "payload_too_large",
    "too_many_files",
    "invalid_json",
    "invalid_request",
    "rate_limited",
    "queue_full",
    "model_unavailable",
    "internal_error",
]


def _no_control_characters(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("control characters are not allowed")
    return value


FilePath = Annotated[
    str, Field(min_length=1, max_length=1024), AfterValidator(_no_control_characters)
]
PolicyStatement = Annotated[str, Field(min_length=1, max_length=2000)]


class ApiError(StrictModel):
    """Every error that isn't an assessment-contract envelope. Never echoes submitted code."""

    kind: Literal["api_error"] = "api_error"
    code: ApiErrorCode
    message: str
    retryable: bool = False
    fields: list[str] = Field(default_factory=list, description="Invalid field names, never values.")


class FileInput(StrictModel):
    """A whole file. `path` is only a label for findings; nothing is read from disk."""

    path: FilePath
    content: str
    before: str | None = Field(None, description="The previous version, if the file changed.")


class ReviewSettings(StrictModel):
    """Per-request settings. Policy statements are trusted context about your own code."""

    checks: Annotated[list[str], Field(min_length=1, max_length=7)] | None = None
    policy: Annotated[list[PolicyStatement], Field(min_length=1, max_length=16)] | None = None
    flag_threshold: Probability | None = None


class ReviewRequest(StrictModel):
    """Send exactly one of `diff`, `files` or `code`."""

    diff: str | None = Field(None, description="A unified diff. Reviewed from its hunks only.")
    files: list[FileInput] | None = Field(None, description="Whole files, reviewed function by function.")
    code: str | None = Field(None, description="A Python snippet.")
    path: FilePath | None = Field(None, description="Label for `code` (default snippet.py).")
    config: ReviewSettings | None = None
    engine: Engine = Field("hybrid", description='"hybrid" (default): static rules decide and the model adds a '
                                                 'second opinion; "model": the model alone; "rules": static rules only.')
    format: Literal["json", "sarif"] = "json"

    @model_validator(mode="after")
    def one_input(self) -> Self:
        given = [name for name in ("diff", "files", "code") if getattr(self, name) is not None]
        if len(given) != 1:
            raise ValueError("send exactly one of diff, files or code")
        if self.path is not None and self.code is None:
            raise ValueError("path is only used together with code")
        if self.files is not None:
            if not self.files:
                raise ValueError("files must not be empty")
            paths = [item.path for item in self.files]
            if len(set(paths)) != len(paths):
                raise ValueError("each file path must be unique")
        return self


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    version: str
    model_loaded: bool
    api_keys_required: bool


class EngineInfo(StrictModel):
    engine: Engine
    available: bool
    message: str


class ModelsResponse(StrictModel):
    model: ModelStatus
    engines: list[EngineInfo]


class UsageCounts(StrictModel):
    requests: int = 0
    reviews: int = 0
    assessments: int = 0
    files_reviewed: int = 0
    functions_total: int = 0
    functions_assessed: int = 0
    rejected: int = 0


class UsageResponse(StrictModel):
    """Counts for the calling key since the server started. Never includes code."""

    key_id: str
    since: str
    usage: UsageCounts


class AssessBatchRequest(StrictModel):
    """Independent polaris.assessment/0.1.0 requests, assessed together."""

    requests: Annotated[list[dict[str, Any]], Field(min_length=1, max_length=MAX_BATCH)] = Field(
        description="Each item is an AssessmentRequest; an invalid item gets an error envelope in its place.",
        json_schema_extra={"items": {"$ref": "#/components/schemas/AssessmentRequest"}})


class AssessBatchResponse(StrictModel):
    """One envelope per request, in the same order."""

    results: list[Annotated[AssessmentResponse | ErrorResponse, Field(discriminator="kind")]]

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from polaris.contract import ErrorResponse

ErrorCode = Literal[
    "invalid_input",
    "unsupported_contract",
    "payload_limit",
    "context_limit",
    "model_unavailable",
    "artifact_invalid",
    "unqualified_model",
    "calibration_mismatch",
    "timeout",
    "non_finite_output",
    "inference_error",
]

MESSAGES: dict[str, str] = {
    "invalid_input": "The request does not conform to the assessment contract.",
    "unsupported_contract": "The requested contract version is not supported.",
    "payload_limit": "The JSON payload exceeds a size, depth, or collection limit.",
    "context_limit": "The complete input exceeds the model's validated token limit.",
    "model_unavailable": "A local model bundle and its optional dependencies are required.",
    "artifact_invalid": "The local bundle failed integrity or compatibility validation.",
    "unqualified_model": "This bundle is experimental; explicit opt-in is required.",
    "calibration_mismatch": "No matching fitted calibration and operating profile is available.",
    "timeout": "The assessment exceeded its configured deadline.",
    "non_finite_output": "The model returned invalid numeric outputs.",
    "inference_error": "Local inference failed; no assessments are available.",
}


class PolarisError(Exception):
    category: Literal["input", "runtime"] = "runtime"

    def __init__(
        self, code: ErrorCode, *, request_id: str | None = None, retryable: bool = False
    ) -> None:
        self.code = code
        self.request_id = request_id
        self.retryable = retryable
        super().__init__(MESSAGES[code])

    def as_response(self) -> ErrorResponse:
        from polaris.contract import ErrorResponse

        return ErrorResponse(
            request_id=self.request_id,
            category=self.category,
            code=self.code,
            message=MESSAGES[self.code],
            retryable=self.retryable,
        )


class PolarisInputError(PolarisError):
    category: Literal["input", "runtime"] = "input"


class PolarisRuntimeError(PolarisError):
    pass

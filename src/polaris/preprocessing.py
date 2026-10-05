from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from polaris.contract import AssessmentRequest, TokenCoverage
from polaris.errors import PolarisInputError, PolarisRuntimeError
from polaris.jsonio import canonical_bytes


class Tokenizer(Protocol):
    all_special_tokens: list[str]
    all_special_ids: list[int]
    cls_token_id: int
    sep_token_id: int

    def encode(self, text: str, *, add_special_tokens: bool) -> list[int]: ...


@dataclass(frozen=True)
class PreparedInput:
    input_ids: tuple[int, ...]
    coverage: TokenCoverage


def _render(section: str, content: Any, special_tokens: list[str]) -> str:
    text = canonical_bytes({section: content}).decode("utf-8")
    # Payload spellings cannot inject tokenizer control IDs. The JSON structure
    # remains distinct from caller-owned text; the model must still be evaluated
    # for semantic prompt injection, which escaping alone does not prevent.
    for token in sorted(set(special_tokens), key=len, reverse=True):
        if token:
            replacement = "".join(f"\\u{ord(char):04x}" for char in token)
            text = text.replace(token, replacement)
    return text


def _model_view(item: Any) -> dict[str, Any]:
    # Digests protect integrity; they carry no meaning for the model. snapshot-json/0.2.0
    # removes them from model input only (they remain in the request and response).
    value: dict[str, Any] = item.model_dump(mode="json")
    value.pop("digest", None)
    return value


def prepare(request: AssessmentRequest, tokenizer: Tokenizer, max_tokens: int) -> PreparedInput:
    if not 1 <= max_tokens <= 8192:
        raise PolarisRuntimeError("artifact_invalid")
    chunks: list[tuple[str, Any]] = [
        ("trusted_context", [_model_view(item) for item in request.trusted_context]),
        ("action", request.action.model_dump(mode="json")),
        ("evidence", [_model_view(item) for item in request.evidence]),
    ]
    input_ids = [tokenizer.cls_token_id]
    counts: dict[str, int] = {}
    forbidden = set(tokenizer.all_special_ids)
    for section, content in chunks:
        text = _render(section, content, tokenizer.all_special_tokens)
        ids = tokenizer.encode(text, add_special_tokens=False)
        if forbidden.intersection(ids):
            raise PolarisRuntimeError("artifact_invalid")
        counts[section] = len(ids)
        input_ids.extend(ids)
        input_ids.append(tokenizer.sep_token_id)
        if len(input_ids) > max_tokens:
            raise PolarisInputError("context_limit", request_id=request.request_id)
    return PreparedInput(
        input_ids=tuple(input_ids),
        coverage=TokenCoverage(
            action=counts["action"],
            evidence=counts["evidence"],
            trusted_context=counts["trusted_context"],
            framing=4,
            total=len(input_ids),
        ),
    )

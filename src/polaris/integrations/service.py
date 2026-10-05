"""One loaded model shared by every API or MCP request. Nothing here downloads anything.

Model loading is the slow part, so long-lived servers load once and reuse the backend. Rule
reviews need no model. Local model work runs one request at a time: the tokenizer is not safe
to share between threads, and inference inside a backend is serialized anyway. A hosted model
(after `polaris login`) runs on the Polaris API instead; only assessment requests are sent.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Sequence
from typing import Any, Literal, TypeVar

from pydantic import Field, ValidationError

from polaris import __version__
from polaris.contract import (
    AssessmentResponse,
    ErrorResponse,
    Probability,
    RuntimeIdentity,
    StrictModel,
)
from polaris.engine import Assessor
from polaris.errors import PolarisError
from polaris.registry import capabilities as registry_capabilities
from polaris.remote import ModelSource, RemoteUnavailable, connect, use_remote
from polaris.review import REVIEW_FORMAT, ReviewConfig, Reviewer, load_backend, resolve_model
from polaris.review.engine import RemoteModel, ReviewModel

Engine = Literal["hybrid", "model", "rules"]
ENGINES: tuple[Engine, ...] = ("hybrid", "model", "rules")
HYBRID_MESSAGE = "Static rules decide each result; the model adds a second opinion that never changes it."
Problem = Literal[
    "loading",
    "no_model",
    "model_not_found",
    "model_unavailable",
    "artifact_invalid",
    "unqualified_model",
    "calibration_mismatch",
    "not_requested",
    "not_signed_in",
    "remote_unavailable",
]
T = TypeVar("T")
LOAD_PROBLEMS: dict[str, Problem] = {
    "model_unavailable": "model_unavailable",
    "artifact_invalid": "artifact_invalid",
    "unqualified_model": "unqualified_model",
    "calibration_mismatch": "calibration_mismatch",
}

RULES_HINT = 'Simple static rules work without a model: use engine "rules".'
PROBLEMS: dict[str, str] = {
    "loading": "The Polaris model is still loading. Try again in a few seconds.",
    "no_model": (
        "No Polaris model is installed. Install one with `polaris model pull`, or point "
        "POLARIS_MODEL (or --model) at a model folder, then restart Polaris. " + RULES_HINT
    ),
    "model_not_found": (
        "The model folder given with --model or POLARIS_MODEL doesn't exist or isn't a folder. "
        "Fix the path and restart Polaris. " + RULES_HINT
    ),
    "model_unavailable": (
        "A Polaris model was found but couldn't be loaded. Its dependencies (PyTorch and "
        "Transformers) may be missing, or the chosen device isn't available. " + RULES_HINT
    ),
    "artifact_invalid": (
        "The Polaris model folder failed its integrity or compatibility checks. Reinstall it "
        "with `polaris model pull`. " + RULES_HINT
    ),
    "unqualified_model": "This model isn't approved for use here. " + RULES_HINT,
    "calibration_mismatch": (
        "This model wasn't calibrated for this machine's software or chip (or the chosen "
        "--device), so its scores can't be trusted here. " + RULES_HINT
    ),
    "not_requested": "This server was started for simple static rules only. " + RULES_HINT,
    "not_signed_in": (
        "You're not signed in to the hosted Polaris model. Run `polaris login` (or set "
        "POLARIS_API_KEY), then restart Polaris. " + RULES_HINT
    ),
    "remote_unavailable": "The hosted Polaris model can't be used right now. " + RULES_HINT,
}
RESULT_MEANINGS: dict[str, str] = {
    "flagged": "Estimated risk is at or above the flag threshold.",
    "ok": "Below the threshold, or no SQL or process calls. Not a safety guarantee.",
    "needs_context": "Can't judge from this function alone; check where the input comes from.",
    "uncertain": "Enough context, but the model isn't confident. Take a closer look.",
    "unsupported": "This check isn't supported by the loaded model.",
    "too_large": "Over the 2,048-token limit. Review it manually or split the function.",
    "error": "No assessment was produced; the finding says why.",
}


class ModelStatus(StrictModel):
    """Whether a model is loaded, in plain words. Never includes file paths."""

    loaded: bool
    status: Literal["loaded"] | Problem
    message: str
    model_version: str | None = None
    release_status: str | None = None
    runtime_variant: str | None = None
    calibration_version: str | None = None
    max_input_tokens: int | None = None
    supported_checks: list[str] = Field(default_factory=list)
    source: Literal["local", "remote"] | None = Field(
        default=None, description='"local": runs on this server; "remote": forwarded to the Polaris API.')
    flag_thresholds: dict[str, Probability] = Field(
        default_factory=dict, description="Estimated risk at or above which each check is flagged.")
    identity: RuntimeIdentity | None = Field(default=None, description="The loaded model's full runtime identity.")


def describe(problem: str, detail: str | None = None) -> str:
    """The message for a model problem, with specifics (such as a connection error) when known."""
    message = PROBLEMS.get(problem, PROBLEMS["no_model"])
    if detail:
        message = message.replace(" " + RULES_HINT, "")
        message = f"{message} {detail.rstrip()} {RULES_HINT}"
    return message


class ModelUnavailable(Exception):
    """engine="model" was requested but no model is loaded; the message says how to fix it."""

    def __init__(self, problem: str, detail: str | None = None) -> None:
        self.problem = problem
        super().__init__(describe(problem, detail))

    @property
    def advice(self) -> str:
        """The message without the generic rules hint, for callers that phrase their own."""
        return str(self).removesuffix(" " + RULES_HINT)


def settings_problem(exc: ValidationError) -> str:
    """Describe invalid settings by field name only: never echo submitted values."""
    fields = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"]) or "settings"
        fields.append(f"{where} ({error['msg']})")
    return "Invalid settings: " + "; ".join(fields[:10])


def request_config(
    *,
    checks: list[str] | None = None,
    policy: list[str] | None = None,
    flag_threshold: float | None = None,
    base: ReviewConfig | None = None,
) -> ReviewConfig:
    """Apply per-request overrides. A supplied policy is reported as policy_source="request".

    Raises pydantic.ValidationError for invalid values; use `settings_problem` to describe it.
    """
    values: dict[str, Any] = base.model_dump() if base is not None else {}
    if checks is not None:
        values["checks"] = list(checks)
    if policy is not None:
        values["policy"] = list(policy)
        values["policy_source"] = "request"
    if flag_threshold is not None:
        values["flag_threshold"] = float(flag_threshold)
    return ReviewConfig.model_validate(values)


def _load(model: str | None, device: str,
          source: ModelSource = "local") -> tuple[ReviewModel | None, Problem | None, str | None]:
    """(model, problem, detail). Hosted when chosen (see `polaris.remote.use_remote`)."""
    if use_remote(source, model):
        try:
            return connect(), None, None
        except RemoteUnavailable as exc:
            return None, exc.problem, str(exc) if exc.problem == "remote_unavailable" else None
    if resolve_model(model) is None:
        chosen = model or os.environ.get("POLARIS_MODEL")
        return None, "model_not_found" if chosen else "no_model", None
    try:
        return load_backend(model, device=device), None, None
    except PolarisError as exc:
        return None, LOAD_PROBLEMS.get(exc.code, "artifact_invalid"), None
    except Exception:
        # A broken model folder must never take the server down; rules still work.
        return None, "artifact_invalid", None


class ReviewService:
    """Holds the one loaded model (or why there is none) and hands out reviewers."""

    def __init__(
        self, backend: ReviewModel | None = None, *, problem: Problem | None = None, batch_size: int = 16
    ) -> None:
        self._backend = backend
        self._problem: Problem | None = None if backend is not None else (problem or "no_model")
        self._detail: str | None = None
        self._ready = threading.Event()
        self._ready.set()
        self._shared: dict[tuple[Engine, bool], Reviewer] = {}
        self.batch_size = batch_size
        self.lock = threading.Lock()

    @classmethod
    def load(
        cls, model: str | None = None, *, device: str = "auto", background: bool = False,
        source: ModelSource = "local",
    ) -> ReviewService:
        """Load the model once. With `background`, callers can start serving immediately.

        `source` "local" (the default, used by `polaris serve`) never contacts the Polaris API;
        "remote" always uses it; "auto" uses it when signed in and no local model was named.
        """
        service = cls(problem="loading")
        service._ready.clear()

        def work() -> None:
            service._backend, service._problem, service._detail = _load(model, device, source)
            service._ready.set()

        if background:
            threading.Thread(target=work, name="polaris-model-load", daemon=True).start()
        else:
            work()
        return service

    def wait_until_loaded(self, timeout: float | None = None) -> bool:
        return self._ready.wait(timeout)

    @property
    def backend(self) -> ReviewModel | None:
        return self._backend if self._ready.is_set() else None

    @property
    def problem(self) -> Problem | None:
        return self._problem if self._ready.is_set() else "loading"

    @property
    def remote(self) -> bool:
        """Whether assessments go to the Polaris API instead of a model on this machine."""
        return isinstance(self.backend, RemoteModel)

    def _unavailable(self) -> ModelUnavailable:
        problem = self.problem or "no_model"
        return ModelUnavailable(problem, self._detail if problem == self._problem else None)

    def reviewer(self, engine: Engine, config: ReviewConfig | None = None) -> Reviewer:
        """A reviewer sharing the loaded model. Raises ModelUnavailable when engine="model" has
        no model; engine="hybrid" without a model reviews with the static rules alone."""
        backend: ReviewModel | None = None
        notices: list[str] = []
        if engine in ("model", "hybrid"):
            backend = self.backend
            if backend is None and engine == "model":
                raise self._unavailable()
            problem = self.problem
            if backend is None and problem is not None and problem not in ("no_model", "not_requested"):
                # Say what's wrong with the model instead of pretending none is installed.
                notices.append(self._unavailable().advice + " The static rules reviewed this alone.")
        if config is not None or notices:
            return Reviewer(backend, config=config, engine=engine, batch_size=self.batch_size, notices=notices)
        key = (engine, backend is not None)
        if key not in self._shared:
            self._shared[key] = Reviewer(backend, engine=engine, batch_size=self.batch_size)
        return self._shared[key]

    def run(self, engine: Engine, work: Callable[[], T]) -> T:
        """Run review work; local model work waits for its turn so requests never share the model."""
        backend = self.backend
        local_model = backend is not None and not isinstance(backend, RemoteModel)
        if engine == "model" or (engine == "hybrid" and local_model):
            with self.lock:
                return work()
        return work()

    def assess(self, value: dict[str, Any] | str | bytes) -> AssessmentResponse | ErrorResponse:
        """The polaris.assessment/0.1.0 contract. Responses report the model's release status."""
        backend = self.backend
        if isinstance(backend, RemoteModel):
            return backend.assess_envelope(value)
        assessor = Assessor(backend, allow_experimental=True)
        with self.lock:
            return assessor.assess_envelope(value)

    def assess_batch(self, values: Sequence[dict[str, Any] | str | bytes]) -> list[AssessmentResponse | ErrorResponse]:
        """Several independent contract requests, batched; one envelope per request, in order."""
        backend = self.backend
        if isinstance(backend, RemoteModel):
            return backend.assess_many(values)
        assessor = Assessor(backend, allow_experimental=True)
        with self.lock:
            return assessor.assess_many(values, batch_size=self.batch_size)

    def model_status(self) -> ModelStatus:
        backend = self.backend
        if backend is None:
            problem = self.problem or "no_model"
            detail = self._detail if problem == self._problem else None
            return ModelStatus(loaded=False, status=problem, message=describe(problem, detail))
        identity = backend.identity
        remote = isinstance(backend, RemoteModel)
        experimental = identity.release_status != "qualified"
        message = f"Model {identity.model_version or 'unknown'} is loaded"
        if isinstance(backend, RemoteModel):
            message = f"Model {identity.model_version or 'unknown'} runs on the Polaris API ({backend.api_url})"
        message += (
            " (experimental: findings are research diagnostics, not a security qualification)."
            if experimental else "."
        )
        profile = backend.profile.checks
        return ModelStatus(
            loaded=True,
            status="loaded",
            message=message,
            model_version=identity.model_version,
            release_status=identity.release_status,
            runtime_variant=identity.runtime_variant,
            calibration_version=identity.calibration_version,
            max_input_tokens=identity.max_input_tokens,
            supported_checks=sorted(backend.supported_checks),
            source="remote" if remote else "local",
            flag_thresholds={check: profile[check].evaluation_risk_threshold
                             for check in sorted(backend.supported_checks) if check in profile},
            identity=identity,
        )

    def capabilities(self, *, limits: dict[str, int] | None = None) -> dict[str, Any]:
        """What this installation can review, which engines work, and the assessment registry."""
        status = self.model_status()
        return {
            "product": "Polaris by TheoVex",
            "version": __version__,
            "review_format": REVIEW_FORMAT,
            "languages": ["python"],
            "checks": ReviewConfig().checks,
            "engines": [
                {"engine": "hybrid", "available": True,
                 "message": HYBRID_MESSAGE + ("" if status.loaded else " No model is loaded, so the rules work alone.")},
                {"engine": "model", "available": status.loaded,
                 "message": status.message},
                {"engine": "rules", "available": True,
                 "message": "Simple static rules; no model needed."},
            ],
            "model": status.model_dump(mode="json"),
            "results": RESULT_MEANINGS,
            "limits": dict(limits or {}),
            "assessment": registry_capabilities(),
            "workflow": {
                "format": "polaris.workflow/0.1.0",
                "review_format": "polaris.review/0.2.0",
                "capabilities_endpoint": "/v1/workflow/capabilities",
                "review_endpoint": "/v1/workflow/review",
                "message": "Separate static workflow; query actual analyzer availability before assuming coverage.",
                "generation_default": "disabled; host candidates need no additional model call",
                "executes_project_code": False,
            },
            "notes": [
                "Findings estimate risk; they never approve, block or authorize anything.",
                "Polaris parses code; it never runs or imports it.",
                "Source is not persistently stored or logged. Explicitly enabled external workflow analysis uses temporary copies.",
            ],
        }

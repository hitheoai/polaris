from __future__ import annotations

import math
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from polaris.calibration import CalibrationArtifact, OperatingProfile
from polaris.contract import (
    AssessmentRequest,
    AssessmentResponse,
    CheckResult,
    Coverage,
    ErrorResponse,
    EvidenceReference,
    ReasonCode,
    RiskProbabilities,
    RuntimeIdentity,
    parse_request,
)
from polaris.errors import PolarisError, PolarisRuntimeError
from polaris.jsonio import digest_json
from polaris.preprocessing import PreparedInput
from polaris.registry import precheck


@dataclass(frozen=True)
class Logits:
    risk: float
    sufficiency: float


Pending = tuple[str | None, ReasonCode | None, list[str]]


class Backend(Protocol):
    identity: RuntimeIdentity
    supported_checks: frozenset[str]
    calibration: CalibrationArtifact
    profile: OperatingProfile

    def prepare(self, request: AssessmentRequest) -> PreparedInput: ...
    def predict(self, prepared: PreparedInput) -> dict[str, Logits]: ...
    def synchronize(self) -> None: ...


class Assessor:
    def __init__(
        self,
        backend: Backend | None = None,
        *,
        allow_experimental: bool = False,
        timeout_seconds: float | None = None,
    ) -> None:
        if timeout_seconds is not None and (
            not math.isfinite(timeout_seconds) or timeout_seconds <= 0
        ):
            raise ValueError("deadline must be positive and finite")
        self.backend = backend
        self.allow_experimental = allow_experimental
        self.timeout_seconds = timeout_seconds

    def _validate_backend(self) -> Backend:
        backend = self.backend
        if backend is None:
            raise PolarisRuntimeError("model_unavailable")
        if backend.identity.release_status == "not_loaded":
            raise PolarisRuntimeError("model_unavailable")
        if backend.identity.release_status != "qualified" and not self.allow_experimental:
            raise PolarisRuntimeError("unqualified_model")
        calibration, profile = backend.calibration, backend.profile
        if (
            not calibration.fitted
            or not profile.tuned
            or calibration.model_digest != backend.identity.model_digest
            or profile.model_digest != backend.identity.model_digest
            or (calibration.runtime_variant != backend.identity.runtime_variant
                and not getattr(backend, "runtime_verified", False))
            or calibration.version != backend.identity.calibration_version
            or profile.version != backend.identity.operating_profile_version
            or profile.calibration_version != calibration.version
            or digest_json(calibration.model_dump(mode="json"))
            != backend.identity.calibration_digest
            or digest_json(profile.model_dump(mode="json"))
            != backend.identity.operating_profile_digest
            or set(calibration.source_groups) & set(profile.source_groups)
            or not backend.supported_checks <= calibration.heads.keys()
            or not backend.supported_checks <= profile.checks.keys()
        ):
            raise PolarisRuntimeError("calibration_mismatch")
        return backend

    @staticmethod
    def _pending(request: AssessmentRequest) -> tuple[list[Pending], list[str]]:
        pending = [
            precheck(request, check.check_id, check.check_revision)
            for check in request.requested_checks
        ]
        eligible = [
            check.check_id
            for check, (status, _, _) in zip(request.requested_checks, pending, strict=True)
            if status is None
        ]
        return pending, eligible

    @staticmethod
    def _checked(
        outputs: dict[str, Logits], eligible: list[str], backend: Backend
    ) -> dict[str, Logits]:
        required = set(eligible) & backend.supported_checks
        if not required <= outputs.keys():
            raise PolarisRuntimeError("inference_error")
        if any(
            not math.isfinite(logit)
            for result in outputs.values()
            for logit in (result.risk, result.sufficiency)
        ):
            raise PolarisRuntimeError("non_finite_output")
        return outputs

    @staticmethod
    def _respond(
        request: AssessmentRequest,
        pending: list[Pending],
        outputs: dict[str, Logits],
        prepared: PreparedInput | None,
        backend: Backend | None,
    ) -> AssessmentResponse:
        results = []
        for check, (initial_status, initial_reason, missing) in zip(
            request.requested_checks, pending, strict=True
        ):
            status = initial_status
            reason = initial_reason
            probabilities = None
            consumed = False
            if status is None:
                assert backend is not None
                if check.check_id not in backend.supported_checks:
                    status, reason = "unsupported", "unreleased_check"
                else:
                    consumed = True
                    logits = outputs[check.check_id]
                    calibrator = backend.calibration.heads[check.check_id]
                    point = backend.profile.checks[check.check_id]
                    risk = calibrator.probability(logits.risk)
                    sufficiency = calibrator.sufficiency(logits.sufficiency)
                    if sufficiency < point.minimum_sufficiency:
                        status, reason = "abstain", "insufficient_context"
                    elif point.abstain_below < risk < point.abstain_above:
                        status, reason = "abstain", "uncertain"
                    else:
                        status, reason = "assessed", "supported_assessment"
                        probabilities = RiskProbabilities(risk_present=risk, risk_absent=1 - risk)
            evidence_ids = [item.evidence_id for item in request.evidence]
            coverage = Coverage(
                supplied_evidence=evidence_ids,
                consumed_evidence=evidence_ids if consumed else [],
                consumed_context=(
                    [item.context_id for item in request.trusted_context] if consumed else []
                ),
                supplied_tokens=prepared.coverage if prepared else None,
                consumed_tokens=prepared.coverage if consumed and prepared else None,
                missing_required_context=missing,
                known_omissions=request.known_omissions,
            )
            refs = (
                [
                    EvidenceReference(
                        evidence_id=item.evidence_id,
                        digest=item.digest,
                        relation="considered",
                        method="input_coverage",
                    )
                    for item in request.evidence
                ]
                if consumed
                else []
            )
            results.append(
                CheckResult(
                    check_id=check.check_id,
                    check_revision=check.check_revision,
                    status=cast(Literal["assessed", "abstain", "unsupported"], status),
                    reason_codes=[cast(ReasonCode, reason)],
                    probabilities=probabilities,
                    coverage=coverage,
                    evidence_refs=refs,
                )
            )
        return AssessmentResponse(
            request_id=request.request_id,
            request_digest=request.request_digest,
            runtime=backend.identity if backend is not None else RuntimeIdentity(),
            results=results,
        )

    def assess(self, value: AssessmentRequest | dict[str, Any] | str | bytes) -> AssessmentResponse:
        request = parse_request(value)
        started = time.perf_counter()
        try:
            pending, eligible = self._pending(request)
            prepared: PreparedInput | None = None
            outputs: dict[str, Logits] = {}
            backend: Backend | None = None
            if eligible:
                backend = self._validate_backend()
                if any(check in backend.supported_checks for check in eligible):
                    prepared = backend.prepare(request)
                    backend.synchronize()
                    outputs = self._checked(backend.predict(prepared), eligible, backend)
                    backend.synchronize()
            if (
                self.timeout_seconds is not None
                and time.perf_counter() - started > self.timeout_seconds
            ):
                # A deadline discards late results; it does not claim to preempt GPU kernels.
                raise PolarisRuntimeError("timeout", retryable=True)
            return self._respond(request, pending, outputs, prepared, backend)
        except PolarisError as exc:
            exc.request_id = request.request_id
            raise
        except Exception as exc:
            raise PolarisRuntimeError("inference_error", request_id=request.request_id) from exc

    def assess_many(
        self,
        values: Sequence[AssessmentRequest | dict[str, Any] | str | bytes],
        *,
        batch_size: int = 16,
    ) -> list[AssessmentResponse | ErrorResponse]:
        """Assess independent requests, batching model work; one envelope per request.

        Each request succeeds or fails atomically. Deadlines apply only to `assess`.
        """
        if not 1 <= batch_size <= 16:
            raise ValueError("batch size must be between 1 and 16")
        responses: list[AssessmentResponse | ErrorResponse | None] = [None] * len(values)

        def failed(exc: PolarisError, request_id: str) -> ErrorResponse:
            return exc.as_response().model_copy(update={"request_id": request_id})

        queued: list[tuple[int, AssessmentRequest, list[Pending], list[str]]] = []
        for index, value in enumerate(values):
            try:
                request = parse_request(value)
            except PolarisError as exc:
                responses[index] = exc.as_response()
                continue
            pending, eligible = self._pending(request)
            if eligible:
                queued.append((index, request, pending, eligible))
            else:
                responses[index] = self._respond(request, pending, {}, None, None)
        if not queued:
            return cast(list[AssessmentResponse | ErrorResponse], responses)
        try:
            backend = self._validate_backend()
        except PolarisError as exc:
            for index, request, _, _ in queued:
                responses[index] = failed(exc, request.request_id)
            return cast(list[AssessmentResponse | ErrorResponse], responses)
        work: list[tuple[int, AssessmentRequest, list[Pending], list[str], PreparedInput]] = []
        for index, request, pending, eligible in queued:
            if not any(check in backend.supported_checks for check in eligible):
                responses[index] = self._respond(request, pending, {}, None, backend)
                continue
            try:
                work.append((index, request, pending, eligible, backend.prepare(request)))
            except PolarisError as exc:
                responses[index] = failed(exc, request.request_id)
            except Exception:
                responses[index] = failed(PolarisRuntimeError("inference_error"), request.request_id)
        # Similar lengths share a batch, so little compute is spent on padding.
        work.sort(key=lambda item: len(item[4].input_ids))
        predict_batch = getattr(backend, "predict_batch", None)
        for start in range(0, len(work), batch_size):
            chunk = work[start : start + batch_size]
            try:
                backend.synchronize()
                batch = (
                    predict_batch([item[4] for item in chunk])
                    if predict_batch is not None
                    else [backend.predict(item[4]) for item in chunk]
                )
                backend.synchronize()
                if len(batch) != len(chunk):
                    raise PolarisRuntimeError("inference_error")
            except PolarisError as exc:
                for item in chunk:
                    responses[item[0]] = failed(exc, item[1].request_id)
                continue
            except Exception:
                for item in chunk:
                    responses[item[0]] = failed(
                        PolarisRuntimeError("inference_error"), item[1].request_id
                    )
                continue
            for (index, request, pending, eligible, prepared), outputs in zip(
                chunk, batch, strict=True
            ):
                try:
                    checked = self._checked(outputs, eligible, backend)
                    responses[index] = self._respond(request, pending, checked, prepared, backend)
                except PolarisError as exc:
                    responses[index] = failed(exc, request.request_id)
        assert all(response is not None for response in responses)
        return cast(list[AssessmentResponse | ErrorResponse], responses)

    def assess_envelope(
        self, value: AssessmentRequest | dict[str, Any] | str | bytes
    ) -> AssessmentResponse | ErrorResponse:
        try:
            return self.assess(value)
        except PolarisError as exc:
            return exc.as_response()

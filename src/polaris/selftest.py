"""Runtime self-test: lets a calibrated model run on machines other than the one it was built on.

Each release ships reference requests with the raw model outputs recorded on the reference
runtime. On another machine Polaris re-runs them once. The machine is accepted only if every
output stays within a tight tolerance and no decision changes (flagged, OK, unsure, needs
context). The verdict is cached per model and runtime.
"""

from __future__ import annotations

import datetime
import json
import math
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from polaris.calibration import CalibrationArtifact, OperatingProfile
from polaris.contract import Digest, StrictModel, parse_request
from polaris.jsonio import digest_json, load_json

if TYPE_CHECKING:
    from polaris.runtime import LocalBackend

SELFTEST_FORMAT: Literal["polaris.selftest/0.1.0"] = "polaris.selftest/0.1.0"
DEFAULT_TOLERANCE = 0.05
# Reference cases sit at least this far (in raw logits, the unit of the tolerance) from every
# decision threshold, so no output within tolerance can change a reference decision.
MARGIN = 0.5


class SelfTestCase(StrictModel):
    request: dict[str, Any]
    outputs: dict[str, Annotated[list[float], Field(min_length=2, max_length=2)]]


class SelfTest(StrictModel):
    format: Literal["polaris.selftest/0.1.0"] = SELFTEST_FORMAT
    model_digest: Digest
    calibration_version: str
    reference_runtime: str
    tolerance: Annotated[float, Field(gt=0, le=1)] = DEFAULT_TOLERANCE
    cases: Annotated[list[SelfTestCase], Field(min_length=4, max_length=512)]


def decision(check: str, risk_logit: float, sufficiency_logit: float, calibration: CalibrationArtifact,
             profile: OperatingProfile) -> tuple[str, float, float]:
    """The engine's decision for one check, with calibrated risk and sufficiency."""
    head, point = calibration.heads[check], profile.checks[check]
    risk, sufficiency = head.probability(risk_logit), head.sufficiency(sufficiency_logit)
    if sufficiency < point.minimum_sufficiency:
        return "needs_context", risk, sufficiency
    if point.abstain_below < risk < point.abstain_above:
        return "uncertain", risk, sufficiency
    return ("flagged" if risk >= point.evaluation_risk_threshold else "ok"), risk, sufficiency


def _raw_edge(probability: float, temperature: float, bias: float) -> float | None:
    """The raw logit at which a calibrated probability threshold is crossed (None: never)."""
    if not 0.0 < probability < 1.0:
        return None
    return (math.log(probability / (1.0 - probability)) - bias) * temperature


def _margin(check: str, risk_logit: float, sufficiency_logit: float, calibration: CalibrationArtifact,
            profile: OperatingProfile) -> float:
    """Distance in raw logits from the nearest threshold that could change the decision."""
    head, point = calibration.heads[check], profile.checks[check]
    edges = [
        (risk_logit, _raw_edge(value, head.temperature, head.bias))
        for value in (point.abstain_below, point.abstain_above, point.evaluation_risk_threshold)
    ]
    edges.append((sufficiency_logit, _raw_edge(point.minimum_sufficiency, head.sufficiency_temperature,
                                               head.sufficiency_bias)))
    distances = [abs(value - edge) for value, edge in edges if edge is not None]
    return min(distances) if distances else math.inf


def _outputs(backend: LocalBackend, requests: list[dict[str, Any]], *,
             batch_size: int = 8) -> list[dict[str, list[float]]]:
    """Raw logits per request, in request order. Similar lengths share a batch, so padding (and
    CPU memory) stays small; padded positions are masked, so batching doesn't change outputs."""
    prepared = [backend.prepare(parse_request(request)) for request in requests]
    order = sorted(range(len(prepared)), key=lambda index: len(prepared[index].input_ids))
    results: list[dict[str, list[float]]] = [{} for _ in prepared]
    for start in range(0, len(order), batch_size):
        chunk = order[start : start + batch_size]
        for index, logits in zip(chunk, backend.predict_batch([prepared[i] for i in chunk]), strict=True):
            results[index] = {
                check: [value.risk, value.sufficiency]
                for check, value in logits.items() if check in backend.supported_checks
            }
    return results


def create(backend: LocalBackend, requests: list[dict[str, Any]], *, limit: int = 48,
           margin: float = MARGIN) -> SelfTest:
    """Record reference outputs on the calibrated runtime, keeping cases clear of every threshold."""
    if backend.identity.runtime_variant != backend.calibration.runtime_variant:
        raise ValueError("create the self-test on the runtime the model was calibrated on")
    chosen: list[SelfTestCase] = []
    per_decision: dict[tuple[str, ...], int] = {}
    outputs = _outputs(backend, requests)
    for request, output in zip(requests, outputs, strict=True):
        margins = []
        kinds = []
        for check, (risk_logit, sufficiency_logit) in sorted(output.items()):
            kind, _, _ = decision(check, risk_logit, sufficiency_logit, backend.calibration, backend.profile)
            margins.append(_margin(check, risk_logit, sufficiency_logit, backend.calibration, backend.profile))
            kinds.append(f"{check}:{kind}")
        if min(margins) < margin:
            continue
        key = tuple(kinds)
        # Keep a spread of decisions instead of many copies of the same one.
        if per_decision.get(key, 0) >= max(4, limit // 4):
            continue
        per_decision[key] = per_decision.get(key, 0) + 1
        chosen.append(SelfTestCase(request=request, outputs=output))
        if len(chosen) >= limit:
            break
    return SelfTest(
        model_digest=backend.manifest.model_digest,
        calibration_version=backend.calibration.version,
        reference_runtime=backend.calibration.runtime_variant,
        cases=chosen,
    )


def seal(bundle: Path, test: SelfTest) -> None:
    """Write selftest.json into a bundle and re-seal its integrity manifest."""
    from polaris.artifacts import read_manifest, reseal, write_json

    manifest = read_manifest(bundle)
    if manifest.model_digest != test.model_digest:
        raise ValueError("self-test was recorded for a different model")
    write_json(bundle / "selftest.json", test.model_dump(mode="json"))
    reseal(bundle, manifest)
    read_manifest(bundle)


def load(bundle: Path) -> SelfTest | None:
    path = bundle / "selftest.json"
    if not path.is_file() or path.is_symlink():
        return None
    return SelfTest.model_validate(load_json(path.read_bytes()))


def verify(backend: LocalBackend, test: SelfTest) -> dict[str, Any]:
    """Run the reference cases on this machine and compare outputs and decisions."""
    if test.model_digest != backend.manifest.model_digest or test.calibration_version != backend.calibration.version:
        return {"passed": False, "reason": "self_test_does_not_match_model", "max_delta": None, "decision_changes": None}
    observed = _outputs(backend, [case.request for case in test.cases])
    worst, changes = 0.0, 0
    for case, output in zip(test.cases, observed, strict=True):
        for check, (risk_logit, sufficiency_logit) in case.outputs.items():
            if check not in output:
                return {"passed": False, "reason": "missing_output", "max_delta": None, "decision_changes": None}
            new_risk, new_sufficiency = output[check]
            worst = max(worst, abs(new_risk - risk_logit), abs(new_sufficiency - sufficiency_logit))
            before = decision(check, risk_logit, sufficiency_logit, backend.calibration, backend.profile)[0]
            after = decision(check, new_risk, new_sufficiency, backend.calibration, backend.profile)[0]
            changes += before != after
    passed = worst <= test.tolerance and changes == 0
    return {"passed": passed, "reason": None if passed else "outputs_differ", "max_delta": round(worst, 6),
            "decision_changes": changes, "cases": len(test.cases), "tolerance": test.tolerance}


def cache_path(model_digest: str, runtime: str, test: SelfTest) -> Path:
    from polaris.review.loader import polaris_home

    key = digest_json({"model": model_digest, "runtime": runtime, "test": test.model_dump(mode="json")})[7:31]
    return polaris_home() / "selftest-cache" / f"{key}.json"


def cached_verify(backend: LocalBackend, test: SelfTest, runtime: str) -> dict[str, Any]:
    path = cache_path(backend.manifest.model_digest, runtime, test)
    try:
        if path.is_file() and not path.is_symlink():
            result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            if result.get("runtime") == runtime and isinstance(result.get("passed"), bool):
                return {**result, "cached": True}
    except (OSError, ValueError):
        pass
    result = {**verify(backend, test), "runtime": runtime,
              "checked_at": datetime.datetime.now(datetime.UTC).isoformat()}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass  # a read-only home only means the check runs again next time
    return {**result, "cached": False}

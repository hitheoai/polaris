from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from polaris.contract import Digest, Probability, StrictModel


def sigmoid(logit: float) -> float:
    if not math.isfinite(logit):
        raise ValueError("non-finite logit")
    if logit >= 0:
        return 1.0 / (1.0 + math.exp(-logit))
    exp = math.exp(logit)
    return exp / (1.0 + exp)


class HeadCalibration(StrictModel):
    temperature: Annotated[float, Field(gt=0.0, le=150.0)] = 1.0
    bias: Annotated[float, Field(ge=-50.0, le=50.0)] = 0.0
    sufficiency_temperature: Annotated[float, Field(gt=0.0, le=150.0)] = 1.0
    sufficiency_bias: Annotated[float, Field(ge=-50.0, le=50.0)] = 0.0

    def probability(self, logit: float) -> float:
        return sigmoid(logit / self.temperature + self.bias)

    def sufficiency(self, logit: float) -> float:
        return sigmoid(logit / self.sufficiency_temperature + self.sufficiency_bias)


class CalibrationArtifact(StrictModel):
    version: str
    model_digest: Digest
    runtime_variant: str
    method: Literal["temperature", "platt"]
    fitted: bool
    fitted_split: Literal["calibration"] = "calibration"
    source_digest: Digest | None = None
    source_groups: list[str] = Field(default_factory=list)
    heads: dict[str, HeadCalibration]

    @model_validator(mode="after")
    def require_provenance(self) -> Self:
        if self.fitted and (self.source_digest is None or not self.source_groups):
            raise ValueError("fitted calibration requires provenance")
        return self


class CheckOperatingPoint(StrictModel):
    minimum_sufficiency: Probability = 0.9
    abstain_below: Probability = 0.2
    abstain_above: Probability = 0.8
    evaluation_risk_threshold: Probability = 0.5

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if not self.abstain_below <= self.evaluation_risk_threshold <= self.abstain_above:
            raise ValueError("abstention interval must bracket the evaluation threshold")
        return self


class OperatingProfile(StrictModel):
    version: str
    model_digest: Digest
    calibration_version: str
    tuned: bool
    tuned_split: Literal["tuning"] = "tuning"
    source_digest: Digest | None = None
    source_groups: list[str] = Field(default_factory=list)
    checks: dict[str, CheckOperatingPoint]

    @model_validator(mode="after")
    def require_provenance(self) -> Self:
        if self.tuned and (self.source_digest is None or not self.source_groups):
            raise ValueError("tuned profile requires provenance")
        return self


def log_loss(
    logits: Sequence[float], labels: Sequence[int], temperature: float, bias: float
) -> float:
    terms = []
    for logit, label in zip(logits, labels, strict=True):
        scaled = logit / temperature + bias
        terms.append(max(scaled, 0.0) - scaled * label + math.log1p(math.exp(-abs(scaled))))
    return sum(terms) / len(terms)


def _minimize(fn: Callable[[float], float], low: float, high: float) -> float:
    ratio = (math.sqrt(5.0) - 1.0) / 2.0
    left = high - ratio * (high - low)
    right = low + ratio * (high - low)
    f_left, f_right = fn(left), fn(right)
    for _ in range(80):
        if f_left < f_right:
            high, right, f_right = right, left, f_left
            left = high - ratio * (high - low)
            f_left = fn(left)
        else:
            low, left, f_left = left, right, f_right
            right = low + ratio * (high - low)
            f_right = fn(right)
    return (low + high) / 2.0


# Calibration may soften a model's confidence but never sharpen it. A fine-tuned classifier is
# rarely underconfident; a fitted temperature below 1 almost always means the small calibration
# set happened to be perfectly separated, and sharpening would turn every score into 0% or 100%.
MIN_LOG_TEMPERATURE = 0.0
MAX_LOG_TEMPERATURE = 5.0


def fit_binary_calibration(
    logits: Sequence[float], labels: Sequence[int], *, method: str = "temperature"
) -> tuple[float, float]:
    if len(logits) != len(labels) or len(logits) < 2 or set(labels) != {0, 1}:
        raise ValueError("calibration requires aligned data with both classes")
    if any(not math.isfinite(x) for x in logits) or any(type(y) is not int for y in labels):
        raise ValueError("invalid calibration observations")
    if method not in ("temperature", "platt"):
        raise ValueError("unknown calibration method")
    temperature, bias = 1.0, 0.0
    for _ in range(1 if method == "temperature" else 20):

        def temperature_objective(value: float, offset: float = bias) -> float:
            return log_loss(logits, labels, math.exp(value), offset)

        log_t = _minimize(temperature_objective, MIN_LOG_TEMPERATURE, MAX_LOG_TEMPERATURE)
        temperature = math.exp(log_t)
        if method == "platt":

            def bias_objective(value: float, scale: float = temperature) -> float:
                return log_loss(logits, labels, scale, value)

            bias = _minimize(bias_objective, -30.0, 30.0)
    if log_loss(logits, labels, temperature, bias) > log_loss(logits, labels, 1.0, 0.0):
        return 1.0, 0.0
    return temperature, bias

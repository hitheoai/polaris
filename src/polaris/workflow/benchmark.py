"""Aggregate caller-recorded complete-task experiments; never manufacture measurements.

This module does not run an editor, invoke a model, execute tests, or establish that
caller-supplied labels are correct. Thresholds and evaluation repositories must be
registered before the experiment. Unknown token counts and costs stay unknown.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from polaris.contract import StrictModel
from polaris.jsonio import digest_json

Label = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_./:@+-]+$")]
Count = Annotated[int, Field(ge=0, le=1_000_000_000)]
FiniteNonnegative = Annotated[float, Field(ge=0, le=1_000_000_000_000, allow_inf_nan=False)]
Rate = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Strategy = Literal["editor_baseline", "editor_with_polaris"]
STRATEGIES: tuple[Strategy, ...] = ("editor_baseline", "editor_with_polaris")


class AcceptanceThresholds(StrictModel):
    """Predeclared experiment criteria, not security qualification or authorization."""

    minimum_tasks: Annotated[int, Field(ge=1, le=100_000)]
    minimum_repositories: Annotated[int, Field(ge=1, le=100_000)]
    maximum_missed_findings: Count
    maximum_false_positives: Count
    minimum_verified_completion_rate: Rate
    maximum_cost_ratio: Annotated[float, Field(gt=0, allow_inf_nan=False)] | None = None


class ExperimentDefinition(StrictModel):
    format: Literal["polaris.experiment/0.1.0"] = "polaris.experiment/0.1.0"
    experiment_id: Label
    evaluation_repositories: Annotated[list[Label], Field(min_length=1, max_length=100_000)]
    training_repositories: Annotated[list[Label], Field(max_length=100_000)] = Field(default_factory=list)
    thresholds: AcceptanceThresholds

    @model_validator(mode="after")
    def independent_repositories(self) -> Self:
        if len(set(self.evaluation_repositories)) != len(self.evaluation_repositories):
            raise ValueError("evaluation repository identifiers must be unique")
        if set(self.evaluation_repositories) & set(self.training_repositories):
            raise ValueError("evaluation and training repositories must be disjoint")
        return self

    @property
    def digest(self) -> str:
        return digest_json(self.model_dump(mode="json"))


class AttemptMeasurement(StrictModel):
    elapsed_ms: FiniteNonnegative
    input_tokens: Count | None = None
    output_tokens: Count | None = None
    cost_usd: FiniteNonnegative | None = None


class TaskMeasurement(StrictModel):
    """One full task, including every attempt and retry, with independently checked labels."""

    task_id: Label
    repository_id: Label
    strategy: Strategy
    experiment_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    attempts: Annotated[list[AttemptMeasurement], Field(min_length=1, max_length=100)]
    elapsed_ms: FiniteNonnegative
    human_review_ms: FiniteNonnegative | None = None
    independently_reviewed: bool = False
    completed: bool = False
    patch_required: bool = True
    patch_correct: bool | None = None
    behavioral_tests: Literal["passed", "failed", "not_run"] = "not_run"
    regressions: Count | None = None
    true_positives: Count | None = None
    false_positives: Count | None = None
    false_negatives: Count | None = None

    @model_validator(mode="after")
    def elapsed_includes_attempts(self) -> Self:
        if self.elapsed_ms + 0.001 < sum(attempt.elapsed_ms for attempt in self.attempts):
            raise ValueError("task elapsed time must include all sequential attempts")
        return self

    @property
    def verified_completion(self) -> bool:
        return (
            self.completed
            and self.independently_reviewed
            and (not self.patch_required or self.patch_correct is True)
            and self.behavioral_tests == "passed"
            and self.regressions == 0
        )


class ExperimentMeasurements(StrictModel):
    definition: ExperimentDefinition
    measurements: Annotated[list[TaskMeasurement], Field(min_length=2, max_length=200_000)]

    @model_validator(mode="after")
    def paired_and_bound(self) -> Self:
        paired: dict[tuple[str, str], set[str]] = {}
        allowed = set(self.definition.evaluation_repositories)
        expected_digest = self.definition.digest
        for item in self.measurements:
            if item.repository_id not in allowed or item.experiment_digest != expected_digest:
                raise ValueError("measurement is not bound to this experiment and its repositories")
            key = item.repository_id, item.task_id
            strategies = paired.setdefault(key, set())
            if item.strategy in strategies:
                raise ValueError("duplicate strategy for an experiment task")
            strategies.add(item.strategy)
        if any(len(strategies) != 2 for strategies in paired.values()):
            raise ValueError("every task needs both the same-task editor baseline and Polaris run")
        return self


class StrategySummary(StrictModel):
    tasks: int
    verified_completions: int
    verified_completion_rate: float
    attempts: int
    retries: int
    latency_p50_ms: float
    latency_p95_ms: float
    input_tokens: int | None
    output_tokens: int | None
    total_cost_usd: float | None
    cost_per_verified_completion_usd: float | None
    human_review_ms: float | None
    true_positives: int | None
    false_positives: int | None
    false_negatives: int | None
    regressions: int | None
    independently_reviewed_tasks: int


class BenchmarkReport(StrictModel):
    format: Literal["polaris.workflow-benchmark/0.1.0"] = "polaris.workflow-benchmark/0.1.0"
    experiment_digest: str
    measurement_digest: str
    provenance: Literal["caller_recorded"] = "caller_recorded"
    paired_tasks: int
    repositories: int
    strategies: dict[Strategy, StrategySummary]
    cost_ratio: float | None
    acceptance: Literal["met", "not_met", "insufficient_evidence"]
    reasons: list[str]
    security_qualified: Literal[False] = False
    notes: list[str]


def _total(values: list[int | None]) -> int | None:
    return None if any(value is None for value in values) else sum(value for value in values if value is not None)


def _amount(values: list[float | None]) -> float | None:
    return None if any(value is None for value in values) else math.fsum(value for value in values if value is not None)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = (len(ordered) - 1) * fraction
    lower = math.floor(rank)
    upper = math.ceil(rank)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def _summarize(items: list[TaskMeasurement]) -> StrategySummary:
    attempts = [attempt for item in items for attempt in item.attempts]
    completed = sum(item.verified_completion for item in items)
    cost = _amount([attempt.cost_usd for attempt in attempts])
    return StrategySummary(
        tasks=len(items), verified_completions=completed,
        verified_completion_rate=completed / len(items),
        attempts=len(attempts), retries=len(attempts) - len(items),
        latency_p50_ms=_percentile([item.elapsed_ms for item in items], 0.5),
        latency_p95_ms=_percentile([item.elapsed_ms for item in items], 0.95),
        input_tokens=_total([attempt.input_tokens for attempt in attempts]),
        output_tokens=_total([attempt.output_tokens for attempt in attempts]),
        total_cost_usd=cost,
        cost_per_verified_completion_usd=cost / completed if cost is not None and completed else None,
        human_review_ms=_amount([item.human_review_ms for item in items]),
        true_positives=_total([item.true_positives for item in items]),
        false_positives=_total([item.false_positives for item in items]),
        false_negatives=_total([item.false_negatives for item in items]),
        regressions=_total([item.regressions for item in items]),
        independently_reviewed_tasks=sum(item.independently_reviewed for item in items),
    )


def benchmark_report(experiment: ExperimentMeasurements) -> BenchmarkReport:
    """Summarize declared observations without running code, models, or network requests."""
    strategies: dict[Strategy, StrategySummary] = {
        strategy: _summarize([item for item in experiment.measurements if item.strategy == strategy])
        for strategy in STRATEGIES
    }
    baseline, polaris = strategies["editor_baseline"], strategies["editor_with_polaris"]
    counts = Counter(item.repository_id for item in experiment.measurements)
    thresholds = experiment.definition.thresholds
    insufficient: list[str] = []
    failed: list[str] = []
    if polaris.tasks < thresholds.minimum_tasks:
        insufficient.append("too_few_paired_tasks")
    if len(counts) < thresholds.minimum_repositories:
        insufficient.append("too_few_repositories")
    if any(item.independently_reviewed_tasks != item.tasks for item in strategies.values()):
        insufficient.append("independent_review_incomplete")
    if any(
        value is None for item in strategies.values()
        for value in (item.false_positives, item.false_negatives, item.true_positives, item.regressions)
    ):
        insufficient.append("quality_measurements_incomplete")
    if polaris.false_negatives is not None and polaris.false_negatives > thresholds.maximum_missed_findings:
        failed.append("missed_findings_above_threshold")
    if polaris.false_positives is not None and polaris.false_positives > thresholds.maximum_false_positives:
        failed.append("false_positives_above_threshold")
    if polaris.verified_completion_rate < thresholds.minimum_verified_completion_rate:
        failed.append("verified_completion_below_threshold")
    if polaris.regressions:
        failed.append("observed_regressions")
    baseline_cost = baseline.cost_per_verified_completion_usd
    polaris_cost = polaris.cost_per_verified_completion_usd
    ratio = (
        polaris_cost / baseline_cost
        if baseline_cost is not None and baseline_cost > 0 and polaris_cost is not None else None
    )
    if thresholds.maximum_cost_ratio is not None:
        if ratio is None:
            insufficient.append("cost_comparison_unavailable")
        elif ratio > thresholds.maximum_cost_ratio:
            failed.append("cost_ratio_above_threshold")
    return BenchmarkReport(
        experiment_digest=experiment.definition.digest,
        measurement_digest=digest_json(experiment.model_dump(mode="json")),
        paired_tasks=polaris.tasks,
        repositories=len(counts),
        strategies=strategies,
        cost_ratio=ratio,
        acceptance="not_met" if failed else "insufficient_evidence" if insufficient else "met",
        reasons=[*failed, *insufficient],
        notes=[
            "Measurements and independent-review labels are supplied by the caller, not certified by Polaris.",
            "All attempts and failed tasks count toward cost; unknown usage/cost is not zero.",
            "A static finding disappearing is not a verified completion or a passed behavioral test.",
            "Passing predeclared experiment criteria is not security qualification or execution permission.",
        ],
    )

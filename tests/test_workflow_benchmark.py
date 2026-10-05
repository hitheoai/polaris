from __future__ import annotations

import pytest
from pydantic import ValidationError

from polaris.workflow.benchmark import (
    AcceptanceThresholds,
    AttemptMeasurement,
    ExperimentDefinition,
    ExperimentMeasurements,
    TaskMeasurement,
    benchmark_report,
)


def definition(**thresholds):
    return ExperimentDefinition(
        experiment_id="test-software-only",
        evaluation_repositories=["held-out"],
        training_repositories=["training"],
        thresholds=AcceptanceThresholds(
            **{
                "minimum_tasks": 1, "minimum_repositories": 1,
                "maximum_missed_findings": 0, "maximum_false_positives": 0,
                "minimum_verified_completion_rate": 1.0, **thresholds,
            }
        ),
    )


def pair(experiment, **changes):
    common = {
        "task_id": "synthetic-test", "repository_id": "held-out",
        "experiment_digest": experiment.digest,
        "attempts": [AttemptMeasurement(elapsed_ms=20.0)],
        "elapsed_ms": 30.0, "independently_reviewed": True, "completed": True,
        "patch_correct": True, "behavioral_tests": "passed",
        "regressions": 0, "true_positives": 1, "false_positives": 0, "false_negatives": 0,
    }
    return [
        TaskMeasurement(**common, strategy="editor_baseline"),
        TaskMeasurement(**{**common, **changes}, strategy="editor_with_polaris"),
    ]


def test_unknown_tokens_and_costs_are_never_zero_or_savings():
    experiment = definition(maximum_cost_ratio=0.8)
    report = benchmark_report(ExperimentMeasurements(definition=experiment, measurements=pair(experiment)))
    assert report.cost_ratio is None and report.acceptance == "insufficient_evidence"
    assert report.strategies["editor_with_polaris"].input_tokens is None
    assert report.strategies["editor_with_polaris"].total_cost_usd is None
    assert report.security_qualified is False


def test_retry_cost_and_failed_work_count_against_complete_task_cost():
    experiment = definition()
    measures = pair(experiment, attempts=[
        AttemptMeasurement(elapsed_ms=10.0, input_tokens=100, output_tokens=10, cost_usd=0.01),
        AttemptMeasurement(elapsed_ms=10.0, input_tokens=200, output_tokens=20, cost_usd=0.02),
    ])
    report = benchmark_report(ExperimentMeasurements(definition=experiment, measurements=measures))
    summary = report.strategies["editor_with_polaris"]
    assert summary.retries == 1 and summary.input_tokens == 300 and summary.output_tokens == 30
    assert summary.cost_per_verified_completion_usd == pytest.approx(0.03)
    assert report.acceptance == "met"


@pytest.mark.parametrize("changes", [
    {"behavioral_tests": "not_run"},
    {"behavioral_tests": "failed"},
    {"patch_correct": None},
    {"regressions": None},
    {"regressions": 1},
    {"independently_reviewed": False},
    {"completed": False},
])
def test_static_or_unverified_results_are_not_verified_completions(changes):
    experiment = definition()
    report = benchmark_report(ExperimentMeasurements(definition=experiment, measurements=pair(experiment, **changes)))
    assert report.strategies["editor_with_polaris"].verified_completions == 0
    assert report.acceptance != "met"


def test_thresholds_repository_identity_and_baseline_pairs_are_bound():
    experiment = definition()
    with pytest.raises(ValidationError, match="duplicate"):
        ExperimentMeasurements(definition=experiment, measurements=pair(experiment)[:1] * 2)
    with pytest.raises(ValidationError, match="both"):
        ExperimentMeasurements(
            definition=experiment,
            measurements=[
                pair(experiment)[0],
                pair(experiment, task_id="different-task")[1],
            ],
        )
    with pytest.raises(ValidationError):
        ExperimentMeasurements(definition=definition(minimum_tasks=2), measurements=pair(experiment))
    with pytest.raises(ValidationError):
        ExperimentMeasurements(definition=experiment, measurements=pair(experiment, repository_id="training"))
    with pytest.raises(ValidationError):
        ExperimentDefinition(
            experiment_id="invalid", evaluation_repositories=["same"],
            training_repositories=["same"], thresholds=experiment.thresholds,
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0])
def test_nonfinite_or_negative_measurements_are_rejected(value):
    with pytest.raises(ValidationError):
        AttemptMeasurement(elapsed_ms=value)
    with pytest.raises(ValidationError):
        AttemptMeasurement(elapsed_ms=1.0, cost_usd=value)

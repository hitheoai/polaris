import math

import pytest

from polaris.benchmark import benchmark, cost_report, percentiles
from polaris.contract import parse_request
from polaris.engine import Assessor


def test_percentiles_handle_empty_and_single_samples():
    assert percentiles([]) == {"p50": None, "p95": None, "p99": None}
    assert percentiles([2.0]) == {"p50": 2.0, "p95": 2.0, "p99": 2.0}
    assert percentiles([0.0, 100.0]) == {"p50": 50.0, "p95": 95.0, "p99": 99.0}


def test_unknown_cost_is_not_free_and_abstention_is_not_assessed():
    assert cost_report(3600, 1000, 500)["attributable_cost"] is None
    report = cost_report(3600, 1000, 500, hourly_cost=2.0, utilization=0.5)
    assert report["attributable_cost"] == 4.0
    assert report["per_1000_completed_requests"] == 4.0
    assert report["per_1000_fully_assessed_requests"] == 8.0
    assert cost_report(1, 0, 0, hourly_cost=2.0)["per_1000_completed_requests"] is None
    assert cost_report(1, 2, 0, hourly_cost=2.0)["per_1000_fully_assessed_requests"] is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hourly_cost": -1.0},
        {"hourly_cost": math.nan},
        {"utilization": 0.0},
        {"utilization": 1.1},
        {"utilization": math.inf},
    ],
)
def test_invalid_cost_assumptions(kwargs):
    with pytest.raises(ValueError):
        cost_report(1, 1, 1, **kwargs)


def test_concurrent_benchmark_counts_requests_not_heads(request_data, backend):
    result = benchmark(
        Assessor(backend, allow_experimental=True),
        [parse_request(request_data)],
        iterations=13,
        warmups=2,
        concurrency=4,
    )
    assert (
        result["attempts"]
        == result["completed_requests"]
        == result["fully_assessed_requests"]
        == 13
    )
    assert result["errors"] == {}
    assert result["conditions"]["requested_check_counts"] == [1]
    assert len(result["conditions"]["input_token_lengths"]) == 1
    assert result["headline_eligible"] is False
    assert result["cost"]["per_1000_completed_requests"] is None
    assert backend.calls == 15


def test_errors_and_abstentions_stay_in_benchmark_denominators(request_data):
    requests = [parse_request(request_data)]
    failed = benchmark(Assessor(), requests, iterations=3, warmups=0)
    assert failed["completed_requests"] == 0
    assert failed["errors"] == {"model_unavailable": 3}
    request_data["trusted_context"] = []
    abstained = benchmark(Assessor(), [parse_request(request_data)], iterations=3, warmups=0)
    assert abstained["completed_requests"] == 3
    assert abstained["fully_assessed_requests"] == 0
    assert abstained["headline_eligible"] is False


def test_warmup_failures_are_not_silently_dropped(request_data):
    result = benchmark(
        Assessor(),
        [parse_request(request_data)],
        iterations=1,
        warmups=2,
    )
    assert result["warmup_errors"] == {"model_unavailable": 2}
    assert result["headline_eligible"] is False

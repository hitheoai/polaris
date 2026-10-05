"""Labeled corpus: the real in-process engines on vulnerable and safe look-alike code (always run)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks" / "workflow_corpus"
sys.path.insert(0, str(CORPUS))

from harness import load, metrics, run_case  # noqa: E402

# Measured gaps on the held-out split. When an analyzer change fixes one, move that case to the
# dev split (it was then used for tuning) and remove it here; never edit holdout cases to pass.
# (ho-py-ssrf-fastapi-httpx, ho-py-path-pathlib and ho-rs-cmd-axum-query were fixed and moved.)
KNOWN_HOLDOUT_MISSES = {
    "ho-ts-secret-github-token",  # token contains "FAKE": the placeholder filter skips it by design
}


@pytest.fixture(scope="module")
def results():
    return {split: [run_case(case) for case in load(split)] for split in ("dev", "evaluator", "holdout")}


@pytest.mark.parametrize("split", ["dev", "evaluator"])
def test_tuning_splits_pass_completely(results, split):
    failed = [item["id"] for item in results[split] if not item["passed"]]
    assert failed == [], failed
    assert all(item["complete"] for item in results[split])
    for check, row in metrics(results[split])["checks"].items():
        assert row["precision"] in (None, 1.0) and row["recall"] in (None, 1.0), check


def test_evaluator_reconstruction_is_sixteen_of_sixteen(results):
    scored = [item for item in results["evaluator"] if item["expect"] != "needs_context"]
    assert len(scored) == 16 and sum(item["expect"] == "flagged" for item in scored) == 9
    assert all(item["passed"] for item in scored)


def test_holdout_matches_its_measured_baseline(results):
    failed = {item["id"] for item in results["holdout"] if not item["passed"]}
    assert failed == KNOWN_HOLDOUT_MISSES
    total = metrics(results["holdout"])["total"]
    assert total["precision"] >= 0.95 and total["recall"] >= 0.8


def test_corpus_has_safe_look_alikes_for_every_check(results):
    cases = [*load("dev"), *load("holdout")]
    checks = {case.check for case in cases}
    # The eleven code checks plus the five CI-workflow and container checks.
    assert len(checks) == 16
    for check in checks:
        assert any(case.check == check and case.expect == "none" for case in cases), check
    safe = sum(case.expect == "none" for case in cases)
    assert safe / len(cases) >= 0.4

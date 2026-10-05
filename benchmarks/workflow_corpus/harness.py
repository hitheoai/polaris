"""Measure the workflow reviewer on labeled cases: per-check precision and recall.

Each case is a tiny project held in memory. The first file is the one under review (as in a
diff review); the others are related files passed as read-only context, so cross-file flows
are exercised the same way `review_workflow` exercises them. Nothing is written or executed.

    uv run --no-sync python benchmarks/workflow_corpus/harness.py [--split dev|holdout|evaluator|all] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Expect = Literal["flagged", "needs_context", "none"]


@dataclass(frozen=True)
class Case:
    id: str
    check: str
    expect: Expect
    files: dict[str, str]
    line: int | None = None
    language: str = "typescript"
    note: str = ""
    split: str = "dev"
    project: dict[str, Any] = field(default_factory=dict)


def run_case(case: Case) -> dict[str, Any]:
    from polaris.review.analyzers import AnalysisRuntime
    from polaris.review.engine import WorkflowReviewer
    from polaris.review.models import ProjectSettings, SourceFile, WorkflowReviewConfig

    (primary, primary_text), *others = case.files.items()
    sources = [SourceFile(primary, primary_text), *(SourceFile(path, text, role="context") for path, text in others)]
    config = WorkflowReviewConfig(project=ProjectSettings.model_validate(case.project))
    started = time.perf_counter()
    report = WorkflowReviewer(
        config=config, runtime=AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False),
    ).review_sources(sources)
    elapsed = (time.perf_counter() - started) * 1000
    relevant = [item for item in report.findings if item.check_id == case.check and item.path == primary]
    flagged = [item for item in relevant if item.result == "flagged"]
    verify = [item for item in relevant if item.result == "needs_context"]
    if case.expect == "flagged":
        passed = bool(flagged) and (case.line is None or any(item.start_line == case.line for item in flagged))
    elif case.expect == "needs_context":
        passed = bool(verify) and not flagged
    else:
        passed = not flagged
    return {
        "id": case.id, "split": case.split, "language": case.language, "check": case.check, "expect": case.expect,
        "passed": passed, "flagged_lines": [item.start_line for item in flagged],
        "verify_lines": [item.start_line for item in verify], "complete": report.coverage.complete,
        "other_flagged": sorted({item.check_id for item in report.findings
                                 if item.result == "flagged" and item.check_id != case.check}),
        "elapsed_ms": round(elapsed, 2),
    }


def metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Per check: flagged-recall over vulnerable cases, precision over flagged outcomes."""
    table: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "verify_ok": 0,
                                                            "verify_total": 0, "safe_verify": 0})
    for item in results:
        row = table[item["check"]]
        if item["expect"] == "flagged":
            row["tp" if item["passed"] else "fn"] += 1
        elif item["expect"] == "none":
            row["tn" if item["passed"] else "fp"] += 1
            row["safe_verify"] += bool(item["verify_lines"])
        else:
            row["verify_total"] += 1
            row["verify_ok"] += item["passed"]
    summary: dict[str, Any] = {}
    for check, row in sorted(table.items()):
        precision = row["tp"] / (row["tp"] + row["fp"]) if row["tp"] + row["fp"] else None
        recall = row["tp"] / (row["tp"] + row["fn"]) if row["tp"] + row["fn"] else None
        summary[check] = {**row, "precision": precision, "recall": recall}
    total = {key: sum(row[key] for row in table.values()) for key in ("tp", "fn", "fp", "tn", "verify_ok", "verify_total")}
    total["precision"] = total["tp"] / (total["tp"] + total["fp"]) if total["tp"] + total["fp"] else None
    total["recall"] = total["tp"] / (total["tp"] + total["fn"]) if total["tp"] + total["fn"] else None
    total["cases"] = len(results)
    total["passed"] = sum(item["passed"] for item in results)
    return {"checks": summary, "total": total}


def load(split: str) -> list[Case]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cases_dev import CASES as DEV
    from cases_evaluator import CASES as EVALUATOR
    from cases_holdout import CASES as HOLDOUT

    chosen = {"dev": DEV, "holdout": HOLDOUT, "evaluator": EVALUATOR, "all": [*DEV, *EVALUATOR, *HOLDOUT]}[split]
    return list(chosen)


def _format(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:5.2f}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=("dev", "holdout", "evaluator", "all"), default="all")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    results = [run_case(case) for case in load(args.split)]
    measured = metrics(results)
    if args.json:
        print(json.dumps({"results": results, "metrics": measured}, indent=2))
        return 0
    print(f"{'check':32} {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3}  prec  recall")
    for check, row in measured["checks"].items():
        print(f"{check:32} {row['tp']:3} {row['fn']:3} {row['fp']:3} {row['tn']:3} {_format(row['precision'])} "
              f"{_format(row['recall'])}")
    total = measured["total"]
    print(f"{'all':32} {total['tp']:3} {total['fn']:3} {total['fp']:3} {total['tn']:3} {_format(total['precision'])} "
          f"{_format(total['recall'])}   ({total['passed']}/{total['cases']} cases pass; "
          f"verify cases {total['verify_ok']}/{total['verify_total']})")
    for item in results:
        if not item["passed"]:
            print(f"  FAIL {item['id']} ({item['check']}, expected {item['expect']}): flagged {item['flagged_lines']}, "
                  f"verify {item['verify_lines']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

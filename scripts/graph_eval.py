"""Count what the cross-file graph does with today's Python `needs_context` findings.

    uv run python scripts/graph_eval.py PATH [--out RESULTS.json] [--show N]

Runs the built-in Python review on every Python file below PATH (static, offline, no model),
builds the graph, and for each `needs_context` finding that is a parameter question walks its
callers across files. Reports how many become: (b) a traced request-derived flow from a known
entry point, (a) constant at every caller, sanitized, or (c) unknown. Nothing here changes a
review; it measures an experiment. The verdicts are static facts, not proof of exploitability.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from polaris.graph import (
    FlowRefusal,
    Limits,
    build_graph,
    flow_from_finding,
    load_directory,
    trace_callers,
)
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.analyzers.python import ANALYZER_ID, TEST_PATH
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import WorkflowReviewConfig
from polaris.review.scope import workflow_sources_from_paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path)
    parser.add_argument("--out", type=Path, help="write per-finding results as JSON")
    parser.add_argument("--show", type=int, default=0, help="print N evenly spaced request-verdict flows")
    args = parser.parse_args()
    root = args.path.resolve()

    config = WorkflowReviewConfig(
        include=["**/*.py"], max_files=50_000, max_findings=10_000, max_units=500_000,
        max_total_bytes=512_000_000, max_file_bytes=1_000_000,
    )
    runtime = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
    started = time.perf_counter()
    sources = workflow_sources_from_paths([root], root=root, config=config)
    review = WorkflowReviewer(config=config, runtime=runtime).review_sources(sources)
    review_seconds = time.perf_counter() - started
    asked = [item for item in review.findings if item.analyzer_id == ANALYZER_ID and item.result == "needs_context"]
    flagged = sum(1 for item in review.findings if item.analyzer_id == ANALYZER_ID and item.result == "flagged")

    started = time.perf_counter()
    loaded = load_directory(root, limits=Limits())
    graph = build_graph(loaded.files, skipped=loaded.skipped, limits=Limits(), extra_incomplete=loaded.incomplete)
    graph_seconds = time.perf_counter() - started

    records: list[dict[str, Any]] = []
    refused: Counter[str] = Counter()
    started = time.perf_counter()
    for finding in sorted(asked, key=lambda item: (item.path, item.start_line, item.check_id)):
        flow = flow_from_finding(graph, finding)
        test_file = bool(TEST_PATH.search(finding.path))
        if isinstance(flow, FlowRefusal):
            refused[flow.reason] += 1
            records.append({"path": finding.path, "symbol": finding.symbol, "line": finding.start_line,
                            "check": finding.check_id, "test_file": test_file, "refused": flow.reason})
            continue
        report = trace_callers(graph, flow)
        leaves = Counter(chain.leaf for chain in report.chains)
        records.append({
            "path": finding.path, "symbol": finding.symbol, "line": finding.start_line, "check": finding.check_id,
            "test_file": test_file, "verdict": report.verdict, "parameters": list(flow.parameters),
            "leaves": dict(leaves), "chains": len(report.chains), "notes": list(report.notes[1:]),
            "unknown_reasons": sorted({chain.reason or "" for chain in report.chains if chain.leaf == "unknown"}),
            "request_chain": next((chain.to_dict() for chain in report.chains if chain.leaf == "request"), None),
        })
    consumer_seconds = time.perf_counter() - started

    answered = [item for item in records if "verdict" in item]
    summary: dict[str, Any] = {
        "path": str(args.path), "graph_digest": graph.digest, "graph_complete": not graph.incomplete,
        "python_findings_flagged": flagged, "python_needs_context": len(asked),
        "parameter_questions": len(answered), "refused": dict(sorted(refused.items())),
        "verdicts": dict(Counter(item["verdict"] for item in answered)),
        "verdicts_non_test": dict(Counter(item["verdict"] for item in answered if not item["test_file"])),
        "parameter_questions_non_test": sum(1 for item in answered if not item["test_file"]),
        "needs_context_non_test": sum(1 for item in records if not item["test_file"]),
        "seconds": {"review": round(review_seconds, 1), "graph": round(graph_seconds, 1), "consumer": round(consumer_seconds, 1)},
        "unknown_reasons": dict(Counter(reason for item in answered if item["verdict"] == "unknown"
                                        for reason in (item["unknown_reasons"] or ["(blocked)"])).most_common(12)),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.out:
        args.out.write_text(json.dumps({"summary": summary, "findings": records}, indent=1, sort_keys=True), encoding="utf-8")
    if args.show:
        requests = [item for item in answered if item["verdict"] == "request" and not item["test_file"]]
        step = max(1, len(requests) // args.show)
        for item in requests[::step][: args.show]:
            chain = item["request_chain"]
            print(f"\n{item['path']}:{item['line']} {item['symbol']} [{item['check']}] parameters {item['parameters']}")
            for step_item in chain["trace"] if chain else []:
                print(f"    {step_item['kind']:6} {step_item.get('path', '')}:{step_item['line']}  {step_item['label']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Large TypeScript reviews are analyzed in batches; findings must not depend on the batch size
or on whether batches run in worker processes."""

from __future__ import annotations

import sys

import pytest

from polaris.review.analyzers import AnalysisRuntime
from polaris.review.analyzers import typescript as ts
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import SourceFile, WorkflowReviewConfig
from polaris.workflow.service import review_policy

NEXT = 'import { NextRequest, NextResponse } from "next/server";\n'
FILES = {
    "app/api/unfurl/route.ts": NEXT + """import { loadPage } from "@/lib/unfurl";

export async function POST(request: NextRequest) {
  const { link } = await request.json();
  const html = await loadPage(link);
  return NextResponse.json({ size: html.length });
}
""",
    "app/api/status/route.ts": NEXT + """import { loadPage } from "@/lib/unfurl";

export async function GET() {
  const html = await loadPage("https://status.example.com/");
  return NextResponse.json({ up: html.length > 0 });
}
""",
    "src/lib/unfurl.ts": """export async function loadPage(target: string) {
  const response = await fetch(target, { redirect: "follow" });
  return response.text();
}
""",
    "src/lib/files.ts": """import fs from "fs/promises";

export async function readUpload(name: string) {
  return fs.readFile(name, "utf8");
}
""",
}


def _review(monkeypatch, batch_files: int, workers: int = 0):
    monkeypatch.setattr(ts, "BATCH_FILES", batch_files)
    runtime = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False,
                              parallel_workers=workers)
    reviewer = WorkflowReviewer(config=WorkflowReviewConfig(), runtime=runtime)
    return reviewer.review_sources([SourceFile(path, text) for path, text in FILES.items()])


def _outcomes(report) -> list[tuple[str, int, str, str]]:
    return sorted((item.path, item.start_line, item.check_id, item.result) for item in report.findings)


def test_batch_size_does_not_change_findings(monkeypatch):
    whole = _review(monkeypatch, 400)
    split = _review(monkeypatch, 1)
    assert _outcomes(split) == _outcomes(whole)
    assert split.coverage.complete and whole.coverage.complete
    outcomes = _outcomes(whole)
    # Request input reaches fetch() inside the helper: reported at the caller, across batches.
    assert ("app/api/unfurl/route.ts", 6, "ssrf", "flagged") in outcomes
    # The helper isn't reported again: call records from every batch show a caller passing input.
    assert not any(path == "src/lib/unfurl.ts" and check == "ssrf" for path, _, check, _ in outcomes)
    # An exported helper with no observed callers stays a question for the reviewer.
    assert ("src/lib/files.ts", 4, "path_traversal", "needs_context") in outcomes


def _split_every_file(monkeypatch) -> list[tuple[int, bool]]:
    """Treat this small review like a large one (one file per batch); record pool use."""
    monkeypatch.setattr(ts, "PARALLEL_MIN_FILES", 1)
    monkeypatch.setattr(ts, "PARALLEL_MIN_BATCH", 1)
    calls: list[tuple[int, bool]] = []
    original = ts._parallel

    def spy(batches, shared, workers):
        result = original(batches, shared, workers)
        calls.append((len(batches), result is not None))
        return result

    monkeypatch.setattr(ts, "_parallel", spy)
    return calls


def test_worker_processes_do_not_change_results(monkeypatch):
    calls = _split_every_file(monkeypatch)
    sequential = _review(monkeypatch, 400)
    parallel = _review(monkeypatch, 400, workers=2)
    assert calls == [(4, True)]  # only the second review used (real, spawned) worker processes
    assert [item.model_dump() for item in parallel.findings] == [item.model_dump() for item in sequential.findings]
    assert parallel.coverage.entries == sequential.coverage.entries and parallel.coverage.complete
    # The worker count is not part of the review's identity.
    assert parallel.provenance.snapshot_digest == sequential.provenance.snapshot_digest
    assert ("app/api/unfurl/route.ts", 6, "ssrf", "flagged") in _outcomes(parallel)


def test_unusable_worker_processes_fall_back_to_in_process_analysis(monkeypatch):
    calls = _split_every_file(monkeypatch)
    monkeypatch.setattr(sys, "frozen", True, raising=False)  # spawn can't re-run a frozen app
    report = _review(monkeypatch, 400, workers=2)
    assert calls == [(4, False)]
    assert report.coverage.complete
    assert ("app/api/unfurl/route.ts", 6, "ssrf", "flagged") in _outcomes(report)


def test_batch_plan_depends_only_on_review_size():
    assert ts._batch_size(ts.PARALLEL_MIN_FILES - 1) == ts.BATCH_FILES
    assert ts._batch_size(ts.PARALLEL_MIN_FILES) == ts.PARALLEL_MIN_BATCH
    assert ts._batch_size(572) == 72
    assert ts._batch_size(100_000) == ts.BATCH_FILES


def test_worker_count_is_validated_and_not_part_of_review_policy():
    config = WorkflowReviewConfig()
    assert review_policy(config, None, AnalysisRuntime()) == review_policy(
        config, None, AnalysisRuntime(parallel_workers=8))
    for invalid in (-1, 33, True, 2.0):
        with pytest.raises(ValueError):
            AnalysisRuntime(parallel_workers=invalid)  # type: ignore[arg-type]

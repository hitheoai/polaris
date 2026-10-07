"""Run `polaris fix --ai` against a corpus of vulnerable snippets and report what happened.

    uv run python benchmarks/refactor_eval/run.py            # replay scripted answers: offline, no key
    uv run python benchmarks/refactor_eval/run.py --json
    uv run python benchmarks/refactor_eval/run.py --live --yes-send   # ask YOUR provider (see ai.toml)

Replay is deterministic and is what CI runs. It checks that Polaris stops bad answers and passes
good ones; the answers are scripted by hand (see cases.py), so replay numbers say nothing about any
model. Live mode sends the corpus's synthetic snippets to the provider in your own ai.toml and
reports verified rate, rejection reasons, new-problem rate and changed lines, labelled with the
model and the date. Only live results should ever be quoted as a model's quality.

Exit codes: 0 every replayed case behaved as expected (always 0 for live), 1 a case didn't, 2 setup.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from polaris.engineering.generation import OpenAICompatibleGateway
from polaris.engineering.generation_models import GenerationConfig
from polaris.engineering.transport import (
    GenerationTransport,
    HTTPResult,
    TransportError,
)
from polaris.integrations.forge.verify import MEMORY_ONLY
from polaris.refactor.ai import AiGenerator
from polaris.refactor.aiconfig import (
    AiSettings,
    generation_config,
    in_ci,
    load_settings,
)
from polaris.refactor.plan import build_plan
from polaris.review.models import WorkflowReviewConfig
from polaris.workflow.service import review_workspace_detailed

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cases import CASES  # noqa: E402  (the corpus sits next to this file)

FORMAT = "polaris.refactor-eval/0.1.0"
ENDPOINT = "http://127.0.0.1:9/v1/chat/completions"  # never contacted in replay
GIT_ENV = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def scripted(answer: dict[str, Any]) -> GenerationTransport:
    """A stand-in provider that reads the request like a model would and gives the scripted answer."""

    def transport(endpoint: str, *, body: bytes, api_key: Any, timeout_seconds: float,
                  max_response_bytes: int) -> HTTPResult:
        user = json.loads(json.loads(body)["messages"][1]["content"])
        if "error" in answer:
            raise TransportError(answer["error"])
        if "status" in answer:
            return HTTPResult(answer["status"], b"")
        text = user["untrusted_file"]
        if "raw" in answer:
            content = answer["raw"]
        else:
            if "file" in answer:
                text = answer["file"]
            for old, new in answer.get("edits", ()):
                text = text.replace(old, new)
            # The reply is the corrected file plus a sentence; whatever else a model adds is ignored.
            content = json.dumps({"replacement": text, "rationale": "Scripted answer.", **answer.get("extra", {})})
        reply = {"choices": [{"index": 0, "finish_reason": "stop",
                              "message": {"role": "assistant", "content": content}}],
                 "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        return HTTPResult(200, json.dumps(reply).encode())

    return transport


def _project(root: Path, files: dict[str, str]) -> None:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("run.py needs git on PATH")
    root.mkdir()
    subprocess.run([git, "--no-pager", "init", "-q", str(root)], check=True,
                   env={**GIT_ENV, "HOME": str(root.parent)})
    for path, text in files.items():
        (root / path).write_text(text)


def run_case(case: dict[str, Any], settings: AiSettings, config: GenerationConfig,
             transport: GenerationTransport | None, *, live: bool = False) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="polaris-eval-") as temporary:
        root = Path(temporary).resolve() / "project"
        _project(root, case["files"])
        review_config = WorkflowReviewConfig()
        review = review_workspace_detailed(root, paths=[root], config=review_config, runtime=MEMORY_ONLY)
        generator = AiGenerator(OpenAICompatibleGateway(config, transport=transport), review, settings,
                                approved=list(case["files"]), config=review_config, runtime=MEMORY_ONLY)
        plan = build_plan(root, review, [generator], limit=1)
    item = plan.items[0] if plan.items else None
    status = "not_flagged" if item is None else "verified" if item.status == "verified" else item.reason
    result = {"id": case["id"], "result": status, "changed_lines": item.changed_lines if item else 0,
              "expected": case["expect"], "sent": sorted(generator.sent),
              **({"limit": case["limit"]} if "limit" in case else {})}
    if live and item is not None and item.proposal:
        # "verified" means the problem is gone and nothing new appears, not that the code is right:
        # a live report carries each diff so a person can judge the changes.
        result["diff"] = item.proposal["diff"]
    return result


def summarize(results: list[dict[str, Any]], *, mode: str, model: str) -> dict[str, Any]:
    rejected = Counter(r["result"] for r in results if r["result"] != "verified")
    verified = [r for r in results if r["result"] == "verified"]
    reached = [r for r in results if not r["result"].startswith("ai_") and r["result"] != "not_flagged"]
    report: dict[str, Any] = {
        "format": FORMAT, "mode": mode, "model": model, "cases": len(results),
        "verified": len(verified), "verified_rate": round(len(verified) / len(results), 3),
        "reached_the_checks": len(reached),
        "rejections": dict(sorted(rejected.items())),
        "new_problem_rate": round(rejected["edit_adds_findings"] / len(reached), 3) if reached else 0.0,
        "median_changed_lines": statistics.median(r["changed_lines"] for r in verified) if verified else 0,
        "behavior_unchecked": True,
        "mismatches": [r["id"] for r in results if r["result"] != r["expected"]] if mode == "replay" else [],
        "results": results,
    }
    if mode == "live":
        report["date"] = datetime.date.today().isoformat()
    else:
        report["scripted"] = True  # hand-written answers: not a measurement of any model
    return report


def evaluate(*, live: bool = False, cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    chosen = cases if cases is not None else CASES
    results: list[dict[str, Any]] = []
    if live:
        settings = load_settings()
        config = generation_config(settings)
        model = settings.model
        # Only the distinct fix tasks: the other cases script a failure mode and would repeat a snippet.
        for case in (item for item in chosen if item.get("live", True)):
            results.append(run_case(case, settings, config, None, live=True))
        return summarize(results, mode="live", model=model)
    settings = AiSettings(ENDPOINT, "scripted-replay", False, None, Path("-"))
    config = GenerationConfig(enabled=True, endpoint=ENDPOINT, model="scripted-replay")
    for case in chosen:
        results.append(run_case(case, settings, config, scripted(case["answer"])))
    return summarize(results, mode="replay", model="scripted-replay")


def render(report: dict[str, Any]) -> str:
    title = ("scripted answers, not a model" if report["mode"] == "replay"
             else f"live: {report['model']}, {report['date']}")
    lines = [f"Polaris fix evaluation ({title})", ""]
    for result in report["results"]:
        mark = "ok  " if result["result"] == result["expected"] or report["mode"] == "live" else "FAIL"
        lines.append(f"  {mark} {result['id']}: {result['result']}")
        if "limit" in result and report["mode"] == "replay":  # about the scripted answer, not a model's
            lines.append(f"       note: {result['limit']}")
        for diff_line in (result.get("diff") or "").splitlines():
            if not diff_line.startswith(("---", "+++")):
                lines.append(f"       | {diff_line}")
    # A replay's rate would only describe the hand-written corpus, so it is not printed there.
    rate = f" ({report['verified_rate']:.0%})" if report["mode"] == "live" else ""
    lines += ["", f"cases {report['cases']} · verified {report['verified']}{rate} · "
              f"reached the checks {report['reached_the_checks']} · new-problem rate {report['new_problem_rate']:.0%} · "
              f"median changed lines {report['median_changed_lines']}",
              "rejections: " + (", ".join(f"{k} {v}" for k, v in report["rejections"].items()) or "none"),
              "Behavior is not checked: a verified fix means the problem is gone and nothing new appears."]
    if report["mismatches"]:
        lines.append("DIFFERENT FROM EXPECTED: " + ", ".join(report["mismatches"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None, out: Callable[[str], object] = print) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="Ask the provider in your ai.toml (sends the corpus).")
    parser.add_argument("--yes-send", action="store_true", help="Required with --live: allow sending the snippets.")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    args = parser.parse_args(argv)
    if args.live:
        if in_ci():
            print("run.py: --live isn't available in CI.", file=sys.stderr)
            return 2
        if not args.yes_send:
            print("run.py: --live sends the corpus's synthetic snippets to the provider in your ai.toml. "
                  "Add --yes-send to allow that.", file=sys.stderr)
            return 2
    try:
        report = evaluate(live=args.live)
    except Exception as problem:  # setup errors carry fixed codes; never print values from the settings
        print(f"run.py: couldn't run ({type(problem).__name__}).", file=sys.stderr)
        return 2
    out(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    return 1 if report["mismatches"] else 0


if __name__ == "__main__":
    sys.exit(main())

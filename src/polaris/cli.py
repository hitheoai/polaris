from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

from polaris import __version__
from polaris.contract import AssessmentRequest, ErrorResponse, parse_request, schema
from polaris.data import SplitManifest, audit, make_splits, read_records
from polaris.engine import Assessor
from polaris.errors import PolarisError, PolarisInputError, PolarisRuntimeError
from polaris.fixtures import smoke_records
from polaris.jsonio import MAX_PAYLOAD_BYTES, load_json
from polaris.registry import capabilities


def emit(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, allow_nan=False))


def write_new(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def read_requests(path: Path) -> list[AssessmentRequest]:
    requests = []
    with path.open("rb") as stream:
        while line := stream.readline(MAX_PAYLOAD_BYTES + 1):
            if len(line) > MAX_PAYLOAD_BYTES:
                raise PolarisInputError("payload_limit")
            if line.strip():
                requests.append(parse_request(line))
    if not requests:
        raise ValueError("requests file is empty")
    return requests


@contextmanager
def input_stream(path: str) -> Iterator[BinaryIO]:
    if path == "-":
        yield sys.stdin.buffer
    else:
        with Path(path).open("rb") as stream:
            yield stream


def _assess(args: argparse.Namespace) -> int:
    backend = None
    if args.bundle:
        from polaris.runtime import LocalBackend

        backend = LocalBackend(
            Path(args.bundle), device=args.device, allow_experimental=args.allow_experimental
        )
    assessor = Assessor(
        backend, allow_experimental=args.allow_experimental, timeout_seconds=args.timeout
    )
    exit_code = 0
    with input_stream(args.input) as stream:
        if args.jsonl:
            while line := stream.readline(MAX_PAYLOAD_BYTES + 1):
                if len(line) > MAX_PAYLOAD_BYTES:
                    # Do not parse subsequent fragments as fresh requests.
                    emit(PolarisInputError("payload_limit").as_response().model_dump(mode="json"))
                    return 2
                if not line.strip():
                    continue
                response = assessor.assess_envelope(line)
                emit(response.model_dump(mode="json"))
                if isinstance(response, ErrorResponse):
                    exit_code = max(exit_code, 2 if response.category == "input" else 3)
        else:
            response = assessor.assess_envelope(stream.read(MAX_PAYLOAD_BYTES + 1))
            emit(response.model_dump(mode="json"))
            if isinstance(response, ErrorResponse):
                exit_code = 2 if response.category == "input" else 3
    return exit_code


def available(module: str) -> bool:
    """True when an optional part of Polaris is installed (the public package leaves out the Lab
    and training tools)."""
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Polaris: a security check for your code. Start with `polaris check`.",
        epilog="Polaris assessments are not authorization.")
    root.add_argument("--version", action="version", version=f"Polaris {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    from polaris.check.cli import add_check_parsers

    add_check_parsers(commands)  # first in --help: the one command most people need
    commands.add_parser(
        "capabilities", help="Show the experimental registry, not claimed model support."
    )
    if available("polaris.lab"):
        lab = commands.add_parser(
            "lab", help="Open Polaris Lab in your browser (already unlocked) to build examples and train."
        )
        lab.add_argument("--data-dir", type=Path, help="Data folder (default: lab-data, or lab-practice).")
        lab.add_argument("--port", type=int, default=8765, help="Port on 127.0.0.1 (default: 8765).")
        lab.add_argument("--no-browser", action="store_true", help="Don't open a browser window.")
        lab.add_argument("--open", action="store_true", help=argparse.SUPPRESS)  # Now the default.
        lab.add_argument(
            "--practice", action="store_true",
            help="Use a separate practice folder with made-up examples and simulated reviewers.",
        )
        lab.add_argument(
            "--bundle", action="append", default=[], metavar="ID=PATH",
            help="Register a trained model (bundle) to try; repeat for more.",
        )
        lab.add_argument("--device", choices=("cpu", "mps", "cuda"), default="cpu")
    schema_parser = commands.add_parser("schema", help="Print a canonical JSON Schema.")
    schema_parser.add_argument("kind", choices=("request", "response", "error"))
    schema_parser.add_argument("--output", type=Path)
    assess = commands.add_parser(
        "assess", help="Assess supplied JSON locally; never execute actions."
    )
    assess.add_argument("--input", default="-")
    assess.add_argument(
        "--jsonl", action="store_true", help="Reuse a persistent worker for JSONL stdin."
    )
    assess.add_argument("--bundle")
    assess.add_argument("--device", choices=("cpu", "mps", "cuda"), default="cpu")
    assess.add_argument("--allow-experimental", action="store_true")
    assess.add_argument(
        "--timeout", type=float, help="Discard late results; not kernel preemption."
    )
    commands.add_parser(
        "fixtures", help="Print unreviewed original software smoke fixtures as JSONL."
    )
    data = commands.add_parser(
        "data-audit", help="Audit declared rights, labels, groups, and splits."
    )
    data.add_argument("--dataset", type=Path, required=True)
    data.add_argument("--splits", type=Path)
    split = commands.add_parser("split", help="Create deterministic connected-group splits.")
    split.add_argument("--dataset", type=Path, required=True)
    split.add_argument("--seed", default="polaris-0.1")
    split.add_argument("--output", type=Path, required=True)
    if available("polaris.training"):
        training = commands.add_parser(
            "train", help="Estimate first; train only with explicit consent and reviewed data."
        )
        training.add_argument("--dataset", type=Path, required=True)
        training.add_argument("--splits", type=Path, required=True)
        training.add_argument("--config", type=Path, required=True)
        training.add_argument("--confirm-local-training", action="store_true")
        training.add_argument("--resume", type=Path, help="Verified checkpoint directory or its parent.")
        training.add_argument("--stop-after-steps", type=int, help="Pause this invocation after N steps.")
        training.add_argument("--progress", action="store_true", help="Write structured step progress to stderr.")
    if available("polaris.posttraining"):
        calibration = commands.add_parser(
            "calibrate", help="Fit calibration and tune a different held-out split."
        )
        calibration.add_argument("--dataset", type=Path, required=True)
        calibration.add_argument("--splits", type=Path, required=True)
        calibration.add_argument("--bundle", type=Path, required=True)
        calibration.add_argument("--output", type=Path, required=True)
        calibration.add_argument("--device", choices=("cpu", "mps", "cuda"), default="cpu")
        calibration.add_argument("--method", choices=("temperature", "platt"), default="temperature")
    if available("polaris.evaluation"):
        evaluation = commands.add_parser(
            "evaluate", help="Evaluate a locked test split; never grant permissions."
        )
        evaluation.add_argument("--dataset", type=Path, required=True)
        evaluation.add_argument("--splits", type=Path, required=True)
        evaluation.add_argument("--bundle", type=Path, required=True)
        evaluation.add_argument("--output", type=Path)
        evaluation.add_argument("--device", choices=("cpu", "mps", "cuda"), default="cpu")
        evaluation.add_argument(
            "--allow-unreviewed",
            action="store_true",
            help="Diagnostics only; qualification cannot pass.",
        )
    bench = commands.add_parser(
        "benchmark", help="Measure end-to-end local assessment throughput and cost."
    )
    bench.add_argument("--bundle", type=Path, required=True)
    bench.add_argument("--requests", type=Path, required=True)
    bench.add_argument("--device", choices=("cpu", "mps", "cuda"), default="cpu")
    bench.add_argument("--iterations", type=int, default=10_000)
    bench.add_argument("--warmups", type=int, default=100)
    bench.add_argument("--concurrency", type=int, default=1)
    bench.add_argument("--cold-runs", type=int, default=0)
    bench.add_argument("--hourly-cost", type=float)
    bench.add_argument("--utilization", type=float, default=1.0)
    bench.add_argument("--allow-experimental", action="store_true")
    bench.add_argument("--output", type=Path)
    architecture = commands.add_parser(
        "benchmark-architecture", help="Random-weight architecture only; no model download."
    )
    architecture.add_argument("--device", choices=("cpu", "mps", "cuda"), default="cpu")
    architecture.add_argument("--length", choices=(512, 2048, 8192), type=int, default=512)
    architecture.add_argument("--batch", choices=(1, 4, 16), type=int, default=1)
    architecture.add_argument("--iterations", type=int, default=20)
    architecture.add_argument("--warmups", type=int, default=5)
    architecture.add_argument("--output", type=Path)
    if available("polaris.exporting"):
        export = commands.add_parser(
            "export-candidate", help="Experimental ONNX/INT8 export, not a serving bundle."
        )
        export.add_argument("--bundle", type=Path, required=True)
        export.add_argument("--requests", type=Path, required=True)
        export.add_argument("--output", type=Path, required=True)
        export.add_argument("--int8", action="store_true")
    from polaris.account_cli import add_account_parsers
    from polaris.api.cli import add_serve_parsers
    from polaris.integrations.doctor import add_doctor_parsers
    from polaris.integrations.forge.cli import add_pr_parsers
    from polaris.integrations.hooks import add_agent_hook_parsers
    from polaris.integrations.setup import add_setup_parsers
    from polaris.mcp.cli import add_mcp_parsers
    from polaris.model_cli import add_model_parsers
    from polaris.review.cli import add_review_parsers
    from polaris.tui.cli import add_tui_parsers
    from polaris.workflow.cli import add_workflow_parsers

    add_review_parsers(commands)
    add_account_parsers(commands)
    add_model_parsers(commands)
    add_serve_parsers(commands)
    add_mcp_parsers(commands)
    add_setup_parsers(commands)
    add_workflow_parsers(commands)
    add_pr_parsers(commands)
    add_tui_parsers(commands)
    add_agent_hook_parsers(commands)
    add_doctor_parsers(commands)
    return root


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv and sys.stdin.isatty() and sys.stdout.isatty():
        argv = ["check"]  # `polaris` on its own, in a terminal, checks your code
    args = parser().parse_args(argv)
    if args.command == "check":
        from polaris.check.cli import run as run_check

        return run_check(args)
    if args.command in ("agent-hook", "doctor"):
        from polaris.integrations.doctor import run as run_doctor
        from polaris.integrations.hooks import run as run_hook

        return {"agent-hook": run_hook, "doctor": run_doctor}[args.command](args)
    if args.command == "workflow":
        from polaris.workflow.cli import run as run_workflow

        return run_workflow(args)
    if args.command == "pr":
        from polaris.integrations.forge.cli import run as run_pr

        return run_pr(args)
    if args.command == "tui":
        from polaris.tui.cli import run as run_tui

        return run_tui(args)
    if args.command in ("review", "scan"):
        from polaris.review.cli import run

        return run(args)
    if args.command == "model":
        from polaris.model_cli import run as run_model

        return run_model(args)
    if args.command in ("login", "logout", "whoami"):
        from polaris.account_cli import run as run_account

        return run_account(args)
    if args.command in ("serve", "mcp", "setup"):
        from polaris.api.cli import run as serve
        from polaris.integrations.setup import run as setup
        from polaris.mcp.cli import run as mcp

        return {"serve": serve, "mcp": mcp, "setup": setup}[args.command](args)
    try:
        output = getattr(args, "output", None)
        if output is not None and output.exists():
            raise ValueError("output already exists")
        if args.command == "benchmark" and not (
            args.iterations >= 1
            and args.warmups >= 0
            and 1 <= args.concurrency <= 16
            and 0 <= args.cold_runs <= 100
        ):
            raise ValueError("invalid benchmark configuration")
        if args.command == "lab":
            try:
                from polaris.lab.server import run_lab
            except ImportError:
                print("Polaris Lab needs extra packages: run `uv sync --extra lab`.", file=sys.stderr)
                return 2
            return run_lab(args)
        elif args.command == "capabilities":
            emit(capabilities())
        elif args.command == "schema":
            result = schema(args.kind)
            if args.output:
                write_new(args.output, result)
            else:
                emit(result)
        elif args.command == "assess":
            return _assess(args)
        elif args.command == "fixtures":
            for record in smoke_records():
                emit(record.model_dump(mode="json"))
        elif args.command == "data-audit":
            manifest = (
                SplitManifest.model_validate(load_json(args.splits.read_bytes()))
                if args.splits
                else None
            )
            result = audit(read_records(args.dataset), manifest)
            emit(result)
            return 0 if result["status"] == "ready_for_experiment" else 2
        elif args.command == "split":
            manifest = make_splits(read_records(args.dataset), args.seed)
            write_new(args.output, manifest.model_dump(mode="json"))
        elif args.command == "train":
            from polaris.training import TrainConfig, train

            config = TrainConfig.model_validate(load_json(args.config.read_bytes()))
            manifest = SplitManifest.model_validate(load_json(args.splits.read_bytes()))

            def training_progress(event: dict[str, Any]) -> None:
                print(json.dumps(event, allow_nan=False), file=sys.stderr, flush=True)
            emit(
                train(
                    read_records(args.dataset),
                    manifest,
                    config,
                    confirm_local_training=args.confirm_local_training,
                    resume=args.resume,
                    stop_after_steps=args.stop_after_steps,
                    progress=training_progress if args.progress else None,
                )
            )
        elif args.command == "calibrate":
            from polaris.posttraining import calibrate_bundle

            manifest = SplitManifest.model_validate(load_json(args.splits.read_bytes()))
            emit(
                calibrate_bundle(
                    read_records(args.dataset),
                    manifest,
                    args.bundle,
                    args.output,
                    device=args.device,
                    method=args.method,
                )
            )
        elif args.command == "evaluate":
            from polaris.evaluation import evaluate
            from polaris.runtime import LocalBackend

            manifest = SplitManifest.model_validate(load_json(args.splits.read_bytes()))
            model = LocalBackend(args.bundle, device=args.device, allow_experimental=True)
            result = evaluate(
                read_records(args.dataset), manifest, model, allow_unreviewed=args.allow_unreviewed
            )
            if args.output:
                write_new(args.output, result)
            else:
                emit(result)
            return 0 if result["qualification"] == "pass" else 2
        elif args.command == "benchmark":
            from polaris.benchmark import benchmark, benchmark_cold
            from polaris.runtime import LocalBackend

            requests = read_requests(args.requests)
            model = LocalBackend(
                args.bundle, device=args.device, allow_experimental=args.allow_experimental
            )
            result = benchmark(
                Assessor(model, allow_experimental=args.allow_experimental),
                requests,
                iterations=args.iterations,
                warmups=args.warmups,
                concurrency=args.concurrency,
                hourly_cost=args.hourly_cost,
                utilization=args.utilization,
            )
            if args.cold_runs:
                result["cold"] = benchmark_cold(
                    args.bundle, requests[0], device=args.device, runs=args.cold_runs
                )
            if args.output:
                write_new(args.output, result)
            else:
                emit(result)
            return 0 if not result["errors"] and not result.get("cold", {}).get("errors") else 3
        elif args.command == "benchmark-architecture":
            from polaris.benchmark import benchmark_architecture

            result = benchmark_architecture(
                device=args.device,
                length=args.length,
                batch=args.batch,
                iterations=args.iterations,
                warmups=args.warmups,
            )
            if args.output:
                write_new(args.output, result)
            else:
                emit(result)
        elif args.command == "export-candidate":
            from polaris.exporting import export_candidate
            from polaris.runtime import LocalBackend

            model = LocalBackend(args.bundle, device="cpu", allow_experimental=True)
            emit(
                export_candidate(
                    model, read_requests(args.requests), args.output, quantize=args.int8
                )
            )
        return 0
    except PolarisError as exc:
        emit(exc.as_response().model_dump(mode="json"))
        return 2 if exc.category == "input" else 3
    except (OSError, ValueError) as exc:
        del exc
        emit(PolarisInputError("invalid_input").as_response().model_dump(mode="json"))
        return 2
    except ImportError:
        emit(PolarisRuntimeError("model_unavailable").as_response().model_dump(mode="json"))
        return 3
    except RuntimeError:
        emit(PolarisRuntimeError("inference_error").as_response().model_dump(mode="json"))
        return 3

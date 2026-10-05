from __future__ import annotations

import importlib.metadata
import json
import math
import os
import platform
import resource
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from polaris.contract import AssessmentRequest, AssessmentResponse, ErrorResponse
from polaris.engine import Assessor
from polaris.jsonio import canonical_bytes


def percentiles(values: list[float]) -> dict[str, float | None]:
    ordered = sorted(values)
    if not ordered:
        return {name: None for name in ("p50", "p95", "p99")}
    result: dict[str, float | None] = {}
    for name, quantile in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
        position = (len(ordered) - 1) * quantile
        low, high = math.floor(position), math.ceil(position)
        result[name] = ordered[low] + (ordered[high] - ordered[low]) * (position - low)
    return result


def hardware() -> dict[str, Any]:
    info: dict[str, Any] = {
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "logical_cpus": os.cpu_count(),
        "power_mode": "unmeasured",
    }
    if sys.platform == "darwin":
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string", "hw.memsize"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        lines = result.stdout.splitlines()
        if result.returncode == 0 and len(lines) == 2:
            info.update(cpu=lines[0], system_memory_bytes=int(lines[1]))
    info["versions"] = {}
    for name in ("theovex-polaris", "pydantic", "torch", "transformers", "tokenizers", "onnxruntime"):
        try:
            info["versions"][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
    return info


def peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def cost_report(
    elapsed_seconds: float,
    completed: int,
    fully_assessed: int,
    *,
    hourly_cost: float | None = None,
    utilization: float = 1.0,
) -> dict[str, Any]:
    if not math.isfinite(elapsed_seconds) or elapsed_seconds < 0:
        raise ValueError("invalid elapsed time")
    if not math.isfinite(utilization) or not 0 < utilization <= 1:
        raise ValueError("utilization must be in (0, 1]")
    if hourly_cost is not None and (not math.isfinite(hourly_cost) or hourly_cost < 0):
        raise ValueError("hourly cost must be finite and nonnegative")
    if not 0 <= fully_assessed <= completed:
        raise ValueError("invalid assessment counts")
    total = None if hourly_cost is None else hourly_cost * elapsed_seconds / 3600 / utilization
    return {
        "currency": "USD",
        "provided_all_in_hourly_cost": hourly_cost,
        "utilization_assumption": utilization,
        "attributable_cost": total,
        "per_1000_completed_requests": None
        if total is None or not completed
        else total * 1000 / completed,
        "per_1000_fully_assessed_requests": None
        if total is None or not fully_assessed
        else total * 1000 / fully_assessed,
        "cost_basis": "operator-supplied all-in allocation including amortization/rental and electricity; idle scaled by utilization",
        "energy_measured": False,
        "training_and_annotation_cost_included": False,
    }


def benchmark(
    assessor: Assessor,
    requests: list[AssessmentRequest],
    *,
    iterations: int = 10_000,
    warmups: int = 100,
    concurrency: int = 1,
    hourly_cost: float | None = None,
    utilization: float = 1.0,
) -> dict[str, Any]:
    if not requests or iterations < 1 or warmups < 0 or not 1 <= concurrency <= 16:
        raise ValueError("invalid benchmark configuration")
    cost_report(0.0, 0, 0, hourly_cost=hourly_cost, utilization=utilization)
    # A serialized input includes the actual SDK parse/validation cost.
    payloads = [canonical_bytes(request.model_dump(mode="json")) for request in requests]
    warmup_errors: dict[str, int] = {}
    for index in range(warmups):
        warmup = assessor.assess_envelope(payloads[index % len(payloads)])
        if isinstance(warmup, ErrorResponse):
            warmup_errors[warmup.code] = warmup_errors.get(warmup.code, 0) + 1

    def worker(worker_id: int) -> list[tuple[float, bool, bool, int | None, str | None]]:
        output: list[tuple[float, bool, bool, int | None, str | None]] = []
        for index in range(worker_id, iterations, concurrency):
            start = time.perf_counter()
            response = assessor.assess_envelope(payloads[index % len(payloads)])
            canonical_bytes(response.model_dump(mode="json"))
            duration_ms = (time.perf_counter() - start) * 1000
            completed = isinstance(response, AssessmentResponse)
            fully = False
            tokens = None
            error = None
            if isinstance(response, AssessmentResponse):
                fully = all(result.status == "assessed" for result in response.results)
                tokens = next(
                    (
                        result.coverage.consumed_tokens.total
                        for result in response.results
                        if result.coverage.consumed_tokens is not None
                    ),
                    None,
                )
            else:
                error = response.code
            output.append((duration_ms, completed, fully, tokens, error))
        return output

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        samples = [sample for batch in pool.map(worker, range(concurrency)) for sample in batch]
    elapsed = time.perf_counter() - started
    completed = sum(sample[1] for sample in samples)
    fully = sum(sample[2] for sample in samples)
    durations = [sample[0] for sample in samples]
    token_lengths = sorted({sample[3] for sample in samples if sample[3] is not None})
    failures: dict[str, int] = {}
    for sample in samples:
        if sample[4]:
            failures[sample[4]] = failures.get(sample[4], 0) + 1
    backend = assessor.backend
    return {
        "format_version": "polaris.benchmark/0.1.0",
        "hardware": hardware(),
        "runtime": backend.identity.model_dump(mode="json") if backend else None,
        "conditions": {
            "state": "warm",
            "warmups": warmups,
            "iterations": iterations,
            "concurrency": concurrency,
            "batch_size": 1,
            "load_model": "closed-loop clients; backend-lock wait included; not an open-loop saturation test",
            "includes": [
                "JSON validation",
                "tokenization",
                "backend queueing",
                "inference",
                "calibration",
                "serialization",
            ],
            "input_token_lengths": token_lengths,
            "requested_check_counts": sorted(
                {len(request.requested_checks) for request in requests}
            ),
            "filesystem_cache": "uncontrolled; not purged",
            "compile_cold": "not_measured",
        },
        "latency_ms": percentiles(durations),
        "elapsed_seconds": elapsed,
        "attempts": iterations,
        "completed_requests": completed,
        "fully_assessed_requests": fully,
        "completed_requests_per_second": completed / elapsed,
        "errors": failures,
        "warmup_errors": warmup_errors,
        "peak_process_rss_bytes": peak_rss_bytes(),
        "device_memory": getattr(backend, "memory", lambda: None)(),
        "cost": cost_report(
            elapsed, completed, fully, hourly_cost=hourly_cost, utilization=utilization
        ),
        "headline_eligible": bool(
            backend
            and backend.identity.release_status == "qualified"
            and iterations >= 10_000
            and warmups >= 100
            and completed == iterations
            and fully > 0
            and token_lengths
            and not warmup_errors
        ),
    }


def benchmark_cold(
    bundle: Path, request: AssessmentRequest, *, device: str = "cpu", runs: int = 5
) -> dict[str, Any]:
    if not 1 <= runs <= 100:
        raise ValueError("cold runs must be between 1 and 100")
    durations, errors = [], []
    payload = canonical_bytes(request.model_dump(mode="json"))
    for _ in range(runs):
        start = time.perf_counter()
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "polaris",
                    "assess",
                    "--bundle",
                    str(bundle),
                    "--device",
                    device,
                    "--allow-experimental",
                ],
                input=payload,
                capture_output=True,
                check=False,
                timeout=120,
            )
            response = json.loads(result.stdout)
            if not isinstance(response, dict):
                errors.append("invalid_response")
            elif result.returncode or response.get("kind") != "assessment":
                errors.append(response.get("code", "process_error"))
        except (subprocess.TimeoutExpired, ValueError):
            errors.append("process_timeout_or_invalid_response")
        durations.append((time.perf_counter() - start) * 1000)
    return {
        "state": "process_cold",
        "runs": runs,
        "latency_ms": percentiles(durations),
        "includes": [
            "interpreter imports",
            "bundle integrity verification",
            "model load",
            "first assessment",
            "process exit",
        ],
        "filesystem_cache": "uncontrolled; subsequent runs may use OS page cache",
        "compile_cold": "compilation disabled",
        "errors": errors,
        "headline_eligible": False,
    }


def benchmark_architecture(
    *,
    device: str = "cpu",
    length: int = 512,
    batch: int = 1,
    iterations: int = 20,
    warmups: int = 5,
) -> dict[str, Any]:
    """Random ModernBERT-base shape; no weights downloaded or security claims."""
    import torch
    from transformers import ModernBertConfig, ModernBertModel

    from polaris.model import ParallelDecisionModel, model_parameter_counts

    if length not in (512, 2048, 8192) or batch not in (1, 4, 16) or iterations < 1 or warmups < 0:
        raise ValueError("invalid architecture benchmark")
    if device not in ("cpu", "mps", "cuda"):
        raise ValueError("unsupported device")
    if device == "mps" and not torch.backends.mps.is_available():
        raise ValueError("MPS unavailable")
    if device == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA unavailable")
    torch.manual_seed(17)
    torch.set_num_threads(min(8, os.cpu_count() or 1))
    config = ModernBertConfig(reference_compile=False, _attn_implementation="sdpa")
    started = time.perf_counter()
    model = ParallelDecisionModel(ModernBertModel(config), config.hidden_size).eval().to(device)
    ids = torch.randint(10, config.vocab_size - 10, (batch, length), device=device)
    mask = torch.ones_like(ids)

    def sync() -> None:
        if device == "mps":
            torch.mps.synchronize()
        elif device == "cuda":
            torch.cuda.synchronize()

    sync()
    initialization = time.perf_counter() - started
    durations = []
    with torch.inference_mode():
        for index in range(warmups + iterations):
            sync()
            before = time.perf_counter()
            output = model(ids, mask)
            sync()
            duration = (time.perf_counter() - before) * 1000
            if not all(torch.isfinite(value).all() for value in output.values()):
                raise ValueError("non-finite architecture output")
            if index >= warmups:
                durations.append(duration)
    return {
        "kind": "architecture_only_benchmark",
        "weights": "random_initialization_not_security_trained",
        "hardware": hardware(),
        "parameters": model_parameter_counts(model),
        "device": device,
        "precision": "float32",
        "attention": "sdpa",
        "input_tokens": length,
        "batch_size": batch,
        "heads_computed": 7,
        "concurrency": 1,
        "cpu_threads": torch.get_num_threads(),
        "warmups": warmups,
        "iterations": iterations,
        "random_initialization_seconds": initialization,
        "forward_latency_ms": percentiles(durations),
        "tokenization_queueing_serialization_included": False,
        "peak_process_rss_bytes": peak_rss_bytes(),
        "model_quality": "unmeasured",
        "cost_per_1000_assessments": None,
        "headline_eligible": False,
    }

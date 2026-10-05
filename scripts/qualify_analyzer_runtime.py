"""Local runtime diagnostics, not a release gate or support for enabled telemetry.

Run with a trusted application interpreter and --python pointing at the exact
disposable analyzer environment. Each worker uses the unchanged production
sandbox from an unsandboxed parent. No dependency source files are patched.
"""

from __future__ import annotations

import argparse
import atexit
import errno
import hashlib
import importlib
import json
import logging
import os
import socket
import sys
import time
from collections.abc import Callable, Sequence
from functools import partial
from pathlib import Path
from typing import Any

CASES = ("success", "configuration", "trace-shutdown", "log-shutdown",
         "both-shutdown", "all-failures", "exit-error", "exit-timeout")


class InjectedConfigurationFailure(RuntimeError):
    pass


class InjectedShutdownFailure(RuntimeError):
    pass


class InjectedExitFailure(RuntimeError):
    pass


def finish_actions(
    actions: Sequence[tuple[str, Callable[[], Any]]], primary: BaseException | None = None,
) -> tuple[BaseException | None, list[tuple[str, BaseException]], list[str]]:
    """Attempt every independent action, retaining the original exception object."""
    errors: list[tuple[str, BaseException]] = []
    attempted = []
    for name, action in actions:
        attempted.append(name)
        try:
            action()
        except BaseException as error:
            errors.append((name, error))
            if primary is None:
                primary = error
    return primary, errors, attempted


def outcome(
    result: tuple[BaseException | None, list[tuple[str, BaseException]], list[str]],
) -> dict[str, Any]:
    primary, errors, attempted = result
    return {
        "primaryFailure": type(primary).__name__ if primary is not None else None,
        "errors": [{"action": name, "type": type(error).__name__} for name, error in errors],
        "attempted": attempted,
    }


def write_json(path: Path, data: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(data, output, sort_keys=True, indent=2)
        output.write("\n")


def sandbox_probes(root: Path) -> dict[str, bool]:
    """Calibrate OS denial before adding Python transport interception."""
    try:
        with socket.socket() as connection:
            connection.settimeout(1)
            connection.connect(("127.0.0.1", 9))
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise RuntimeError("Network denial was not enforced by the OS.") from None
    else:
        raise RuntimeError("Network denial was not enforced by the OS.")
    outside = root.parent / (root.name + "-outside-canary")
    try:
        with outside.open("x") as stream:
            stream.write("Synthetic qualification canary.")
    except PermissionError:
        pass
    else:
        raise RuntimeError("Write denial was not enforced by the OS.")
    return {"networkDeniedByOS": True, "externalWriteDeniedByOS": True}


def install_transport_guards(state: dict[str, Any]) -> tuple[Any, Any]:
    """Process-lifetime guards: intentionally no restoration before interpreter exit."""
    def audit(event: str, arguments: tuple[Any, ...]) -> None:
        if event in ("socket.connect", "socket.bind", "socket.getaddrinfo"):
            state["blockedPythonTransportCalls"] += 1
            raise PermissionError(errno.EPERM, "Qualification transport guard")

    sys.addaudithook(audit)
    requests = importlib.import_module("requests")

    def post(session: Any, url: str, data: Any = None, **kwargs: Any) -> Any:
        if url not in (
            "https://polaris-qualification.invalid/v1/traces",
            "https://polaris-qualification.invalid/v1/logs",
        ):
            raise RuntimeError("Unexpected qualification mock destination.")
        state["mockExports"].append({
            "signal": "traces" if url.endswith("/traces") else "logs",
            "bytes": len(data) if isinstance(data, bytes) else 0,
            "duringExit": state["exiting"],
        })
        response = requests.Response()
        response.status_code, response._content = 200, b""
        return response

    def blocked_send(*args: Any, **kwargs: Any) -> Any:
        state["blockedPythonTransportCalls"] += 1
        raise PermissionError(errno.EPERM, "Qualification transport guard")

    requests.Session.post = post
    requests.adapters.HTTPAdapter.send = blocked_send
    return requests, post


def telemetry_worker(root: Path, case: str) -> None:
    if case not in CASES or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("Use an isolated bounded qualification worker.")
    state: dict[str, Any] = {
        "format": "polaris.analyzer-cleanup-worker/1", "case": case, **sandbox_probes(root),
        "mockExports": [], "blockedPythonTransportCalls": 0, "exiting": False,
        "releaseQualified": False, "nativeInitializationObserved": False,
    }
    # Registered first, so real SDK atexit callbacks run while interception is
    # still installed, before this last report. Never use a patch context here.
    requests, post = install_transport_guards(state)

    def final_report() -> None:
        state["transportGuardsRetained"] = requests.Session.post is post
        state["finalAtexitReached"] = True
        write_json(root / "worker-final.json", state)

    atexit.register(final_report)
    telemetry: Any = importlib.import_module("semgrep.telemetry")
    trace = importlib.import_module("opentelemetry.trace")
    logs = importlib.import_module("opentelemetry._logs._internal")
    snapshots = [
        (module, name, getattr(module, name))
        for module, names in (
            (trace, ("_TRACER_PROVIDER", "_TRACER_PROVIDER_SET_ONCE")),
            (logs, ("_LOGGER_PROVIDER", "_LOGGER_PROVIDER_SET_ONCE")),
        )
        for name in names
    ]
    # The Once objects are mutable. Let this diagnostic mutate fresh instances,
    # not the saved originals, so restoration actually restores their state.
    for module, name, value in snapshots:
        if name.endswith("_SET_ONCE"):
            setattr(module, name, type(value)())
    actions: list[tuple[str, Callable[[], Any]]] = []
    providers = []

    def provider(factory: Callable[..., Any], kind: str, *args: Any, **kwargs: Any) -> Any:
        value = factory(*args, **kwargs)
        providers.append(value)

        def shutdown() -> None:
            if case in (kind + "-shutdown", "both-shutdown", "all-failures"):
                raise InjectedShutdownFailure()
            value.shutdown()

        actions.append(("provider:" + kind, shutdown))
        return value

    trace_factory, log_factory = telemetry.TracerProvider, telemetry.LoggerProvider
    telemetry.TracerProvider = lambda *a, **k: provider(trace_factory, "trace", *a, **k)
    telemetry.LoggerProvider = lambda *a, **k: provider(log_factory, "log", *a, **k)
    if case in ("configuration", "all-failures"):
        def fail_configuration(instance: Any) -> None:
            raise InjectedConfigurationFailure()
        telemetry.Telemetry.extract = fail_configuration
        state["configurationFaultPoint"] = "Telemetry.extract"
    initial: BaseException | None = None
    try:
        instance = telemetry.Telemetry()
        instance.configure(True, "https://polaris-qualification.invalid")
        with trace.get_tracer("polaris-qualification").start_as_current_span("synthetic"):
            logging.getLogger("polaris-qualification").warning("Synthetic qualification log.")
        for value in providers:
            if not value.force_flush(timeout_millis=3000):
                raise RuntimeError("Mock telemetry flushing did not complete.")
        processors = trace.get_tracer_provider()._active_span_processor._span_processors
        state["duplicateSpanProcessorRegistration"] = len(processors) == 2 and processors[0] is processors[1]
    except BaseException as error:
        initial = error
    finally:
        actions.extend([
            ("instrumentor:requests", lambda: telemetry.RequestsInstrumentor().uninstrument()),
            ("instrumentor:threading", lambda: telemetry.ThreadingInstrumentor().uninstrument()),
        ])
        for handler in list(logging.getLogger().handlers):
            if handler.get_name() == "otel-logging-handler":
                actions.extend([
                    ("handler:remove", partial(logging.getLogger().removeHandler, handler)),
                    ("handler:close", handler.close),
                ])
        for module, name, value in snapshots:
            actions.append(("global:" + name, partial(setattr, module, name, value)))
        state["cleanup"] = outcome(finish_actions(actions, initial))
        state["providersCreated"] = len(providers)
        state["globalsRestored"] = all(getattr(module, name) is value for module, name, value in snapshots)

    def exit_fault() -> None:
        if case in ("exit-error", "all-failures"):
            raise InjectedExitFailure()
        if case == "exit-timeout":
            write_json(root / "worker-before-timeout.json", state)
            time.sleep(120)

    def exit_probe() -> None:
        with requests.Session() as session:
            session.post("https://polaris-qualification.invalid/v1/logs", data=b"exit-canary")
        try:
            with socket.socket() as connection:
                connection.connect(("127.0.0.1", 9))
        except PermissionError:
            state["exitTransportGuardObserved"] = True
        else:
            raise RuntimeError("Exit transport guard was removed.")

    def on_exit() -> None:
        state["exiting"] = True
        state["exitCleanup"] = outcome(finish_actions([
            ("exit:injected", exit_fault), ("exit:transport-probe", exit_probe),
        ]))

    atexit.register(on_exit)
    write_json(root / "worker-before-exit.json", state)


def validate_report(case: str, report: dict[str, Any]) -> None:
    if (report.get("case") != case or report.get("networkDeniedByOS") is not True
            or report.get("externalWriteDeniedByOS") is not True or report.get("providersCreated") != 2
            or report.get("globalsRestored") is not True or report.get("finalAtexitReached") is not True
            or report.get("transportGuardsRetained") is not True
            or report.get("exitTransportGuardObserved") is not True):
        raise ValueError("Runtime cleanup or process-lifetime containment was not observed.")
    primary = report["cleanup"]["primaryFailure"]
    expected = ("InjectedConfigurationFailure" if case in ("configuration", "all-failures")
                else "InjectedShutdownFailure" if "shutdown" in case else None)
    errors = report["cleanup"]["errors"]
    expected_actions = (["provider:trace", "provider:log"] if case in ("both-shutdown", "all-failures")
                        else ["provider:trace"] if case == "trace-shutdown"
                        else ["provider:log"] if case == "log-shutdown" else [])
    if (primary != expected or [item["action"] for item in errors] != expected_actions
            or any(item["type"] != "InjectedShutdownFailure" for item in errors)):
        raise ValueError("A primary failure was lost or unexpected cleanup failed.")
    if not {
        "provider:trace", "provider:log", "instrumentor:requests", "instrumentor:threading",
        "global:_TRACER_PROVIDER", "global:_TRACER_PROVIDER_SET_ONCE",
        "global:_LOGGER_PROVIDER", "global:_LOGGER_PROVIDER_SET_ONCE",
    } <= set(report["cleanup"]["attempted"]):
        raise ValueError("Not every independent cleanup action was attempted.")
    expected_exit = "InjectedExitFailure" if case in ("exit-error", "all-failures") else None
    expected_errors = ([{"action": "exit:injected", "type": "InjectedExitFailure"}] if expected_exit else [])
    if report["exitCleanup"] != {
        "primaryFailure": expected_exit, "errors": expected_errors,
        "attempted": ["exit:injected", "exit:transport-probe"],
    }:
        raise ValueError("Unexpected exit-time cleanup result.")
    if not any(item["duringExit"] for item in report["mockExports"]):
        raise ValueError("Mock export interception was not exercised during atexit.")


def qualify(python: Path, output: Path) -> dict[str, Any]:
    from polaris.review.analyzers.base import AnalysisRuntime
    from polaris.review.analyzers.identity import installed_identity, qualified_platform
    from polaris.review.analyzers.process import (
        controlled_environment,
        run_bounded,
        sandboxed_command,
    )

    if not qualified_platform() or not python.is_absolute() or python.name != "python":
        raise ValueError("Qualification requires the managed macOS ARM64 interpreter.")
    identity = installed_identity(str(python.with_name("semgrep")))
    if output.exists() or not output.is_absolute() or output.resolve() != output:
        raise ValueError("Qualification output must be a new absolute non-link directory.")
    output.mkdir(mode=0o700)
    records = {}
    source = Path(__file__).resolve()
    helper_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    for case in CASES:
        root = output / case
        root.mkdir(mode=0o700)
        for name in ("home", "tmp"):
            (root / name).mkdir(mode=0o700)
        timeout = 10 if case == "exit-timeout" else 30
        command = sandboxed_command(
            [str(python), "-I", "-B", str(source), "_worker", case, str(root)],
            workspace=root, runtime=AnalysisRuntime(), timeout=timeout,
        )
        if command is None:
            raise ValueError("Production OS sandbox is unavailable.")
        result = run_bounded(
            command, cwd=root, env=controlled_environment(root, str(python)),
            timeout=timeout, max_output_bytes=2_000_000,
        )
        for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            with (root / (name + ".txt")).open("xb") as stream:
                stream.write(data)
        record: dict[str, Any] = {
            "status": result.status, "returncode": result.returncode,
            "elapsedMs": result.elapsed_ms, "argv": command, "passed": False,
        }
        try:
            if case == "exit-timeout":
                if (result.status != "timeout" or not (root / "worker-before-timeout.json").is_file()
                        or (root / "worker-final.json").exists()):
                    raise ValueError("The exit-time hang did not require bounded parent termination.")
            else:
                if result.status != "ok" or result.returncode != 0:
                    raise ValueError("Qualification worker failed.")
                validate_report(case, json.loads((root / "worker-final.json").read_bytes()))
            record["passed"] = True
        except (OSError, ValueError, KeyError, TypeError) as error:
            record["validationError"] = type(error).__name__
        write_json(root / "receipt.json", record)
        records[case] = record
    if hashlib.sha256(source.read_bytes()).hexdigest() != helper_sha256:
        raise ValueError("Runtime qualification helper changed during execution.")
    report = {
        "format": "polaris.analyzer-cleanup-qualification/1", "identity": identity,
        "helperSha256": helper_sha256, "cases": records,
        "passed": all(item["passed"] for item in records.values()),
        "productionSandboxUnmodified": True, "outerSandboxRemoved": False,
        "enabledTelemetrySupported": False, "nativeInitializationObserved": False,
        "trustedCIEvidence": False, "releaseQualified": False,
    }
    write_json(output / "result.json", report)
    return report


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "_worker":
        telemetry_worker(Path(sys.argv[3]), sys.argv[2])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.python, args.output)
    print(json.dumps({key: result[key] for key in ("format", "passed", "releaseQualified")}))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Observe the fixed CE interface without substituting for production fixture tests.

Python profiling covers original function bodies, including copied aliases, before
their bodies execute. It does not survive native exec. Default/legacy/experimental
subprocess checks therefore retain an explicit native-initialization observation gap.
"""

from __future__ import annotations

import argparse
import atexit
import errno
import hashlib
import importlib
import importlib.util
import json
import os
import shutil
import sys
import threading
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn

MODES = ("calibrate-tracing", "calibrate-mcp", "python-fallback", "default", "legacy", "experimental")
GUARDED = {
    "opentelemetry.sdk.trace": {"TracerProvider.__init__", "TracerProvider.add_span_processor"},
    "opentelemetry.sdk._logs._internal": {
        "LoggerProvider.__init__", "LoggerProvider.add_log_record_processor", "LoggingHandler.__init__",
    },
    "opentelemetry.sdk.trace.export": {"BatchSpanProcessor.__init__"},
    "opentelemetry.sdk._logs._internal.export": {"BatchLogRecordProcessor.__init__"},
    "opentelemetry.exporter.otlp.proto.http.trace_exporter": {
        "OTLPSpanExporter.__init__", "OTLPSpanExporter.export", "OTLPSpanExporter._export",
    },
    "opentelemetry.exporter.otlp.proto.http._log_exporter": {
        "OTLPLogExporter.__init__", "OTLPLogExporter.export", "OTLPLogExporter._export",
    },
    "opentelemetry.trace": {"set_tracer_provider"},
    "opentelemetry._logs._internal": {"set_logger_provider"},
    "opentelemetry.instrumentation.instrumentor": {"BaseInstrumentor.instrument"},
    "opentelemetry.instrumentation.requests": {"RequestsInstrumentor._instrument"},
    "opentelemetry.instrumentation.threading": {"ThreadingInstrumentor._instrument"},
    "mcp.server.fastmcp.server": {
        "FastMCP.__init__", "FastMCP.run", "FastMCP.run_stdio_async",
        "FastMCP.run_sse_async", "FastMCP.run_streamable_http_async",
    },
    "semgrep.commands.mcp": {"semgrep_mcp", "setup_mcp_server"},
    "semgrep.mcp.server": {"server_lifespan"},
    "semgrep.mcp.utilities.tracing": {"start_tracing"},
    "semgrep.mcp.semgrep": {"mk_context"},
    "semgrep.mcp.utilities.token_verifier": {
        "make_token_verifier", "IntrospectionTokenVerifier.__init__", "IntrospectionTokenVerifier.verify_token",
    },
    "jwt.jwks_client": {"PyJWKClient.__init__"},
}


def helper() -> Any:
    path = Path(__file__).resolve().with_name("qualify_analyzer_runtime.py")
    spec = importlib.util.spec_from_file_location("ce_runtime_cleanup", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_activation(module: str, qualified_name: str) -> bool:
    return qualified_name in GUARDED.get(module, set())


def fixed_arguments() -> list[str]:
    return [
        "scan", "--oss-only", "--config", "polaris-rules.yaml", "--json", "--quiet",
        "--metrics=off", "--disable-version-check", "--no-trace", "--disable-nosem",
        "--no-git-ignore", "--no-rewrite-rule-ids", "--strict", "--jobs=1",
        "--max-target-bytes", "1000000", "--max-memory", "512", "--timeout", "5",
        "--timeout-threshold=1", "--", "source/input-000000.js", "source/input-000001.js",
    ]


def cli_arguments(executable: str, mode: str) -> list[str]:
    if mode not in ("default", "legacy", "experimental"):
        raise ValueError("Only explicit diagnostic CLI modes are supported.")
    arguments = fixed_arguments()
    return [executable, arguments[0], *(["--" + mode] if mode != "default" else []), *arguments[1:]]


def python_worker(root: Path, mode: str) -> None:
    if mode not in MODES[:3] or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("An isolated Python CE diagnostic worker is required.")
    tools = helper()
    state: dict[str, Any] = {
        "format": "polaris.python-ce-observation/1", "mode": mode, **tools.sandbox_probes(root),
        "configureCalls": [], "processes": [], "blockedImportProbes": [],
        "nativeInitializationObserved": False,
        "releaseQualified": False,
    }

    def stop(reason: str) -> NoReturn:
        # Raising from a profiler disables it and can be caught by upstream code.
        # Retain a fatal latch and terminate instead; the parent still reaps the
        # process group under its deadline. Do not allow the forbidden body to run.
        state["forbiddenActivation"] = reason
        tools.write_json(root / "activation-stop.json", state)
        os._exit(86)

    configure_frames: dict[int, dict[str, Any]] = {}

    def observe(frame: FrameType, event: str, argument: Any) -> None:
        module = frame.f_globals.get("__name__", "")
        if module not in GUARDED and module != "semgrep.telemetry":
            return
        name = frame.f_code.co_qualname
        if event == "call" and is_activation(module, name):
            stop(module + "." + name)
        if module == "semgrep.telemetry" and name == "Telemetry.configure":
            if event == "call":
                if frame.f_locals.get("enabled") is not False:
                    stop("semgrep.telemetry.Telemetry.configure(enabled)")
                entry = {
                    "enabled": False, "traceEndpoint": frame.f_locals.get("trace_endpoint"),
                    "returned": False, "resourceConfigured": False,
                }
                state["configureCalls"].append(entry)
                configure_frames[id(frame)] = entry
            elif event == "return":
                completed = configure_frames.pop(id(frame), None)
                if completed is not None:
                    completed["returned"] = True
                    completed["resourceConfigured"] = frame.f_locals["self"].resource is not None

    def audit(event: str, arguments: tuple[Any, ...]) -> None:
        if event == "socket.bind":
            frame = sys._getframe(1)
            if (frame.f_globals.get("__name__") == "urllib3.util.connection"
                    and frame.f_code.co_qualname == "_has_ipv6" and arguments[1] == ("::1", 0)):
                # urllib3 catches this local feature-probe failure under the OS
                # sandbox too. Deny the bind; do not equate importing it with
                # starting an MCP service or enabling telemetry.
                state["blockedImportProbes"].append("urllib3.util.connection._has_ipv6")
                raise PermissionError(errno.EPERM, "Qualification import-probe denial")
        if event in ("socket.connect", "socket.bind", "socket.getaddrinfo"):
            stop("python-network:" + event)
        if event not in ("subprocess.Popen", "os.exec", "os.posix_spawn"):
            return
        executable, argv = arguments[:2]
        executable = os.fsdecode(executable)
        resolved = shutil.which(executable)
        if (resolved is None or not isinstance(argv, (list, tuple)) or len(argv) > 300
                or len(state["processes"]) >= 100):
            stop("unbounded-or-unresolved-process")
        vector = [os.fsdecode(item) for item in argv]
        if any(len(item) > 4096 for item in vector):
            stop("unbounded-process-argument")
        actual = Path(resolved).resolve()
        if actual.stat().st_size > 300_000_000 or not actual.is_file():
            stop("unbounded-process-executable")
        if ("semgrep-core-proprietary" in actual.name
                or any(item in ("-trace", "--trace", "--pro", "mcp") for item in vector)):
            stop("unsupported-child-interface")
        state["processes"].append({
            "event": event, "executable": str(actual),
            "executableSha256": hashlib.sha256(actual.read_bytes()).hexdigest(),
            "argv": vector,
            "argvSha256": hashlib.sha256(json.dumps(vector, separators=(",", ":")).encode()).hexdigest(),
            "ordinaryCoreRPC": actual.name == "semgrep-core" and "-rpc" in vector,
        })

    sys.addaudithook(audit)
    sys.setprofile(observe)
    threading.setprofile(observe)

    def on_exit() -> None:
        state["profileRetainedThroughExit"] = sys.getprofile() is observe and threading.getprofile() is observe
        state["mcpImported"] = "semgrep.commands.mcp" in sys.modules
        state["finalAtexitReached"] = True
        tools.write_json(root / "python-ce-final.json", state)

    atexit.register(on_exit)
    if mode == "calibrate-tracing":
        importlib.import_module("opentelemetry.sdk.trace").TracerProvider()
        raise RuntimeError("Tracing constructor tripwire did not fire.")
    if mode == "calibrate-mcp":
        importlib.import_module("mcp.server.fastmcp.server").FastMCP("synthetic-tripwire")
        raise RuntimeError("MCP constructor tripwire did not fire.")
    sys.argv = ["pysemgrep", *fixed_arguments()]
    # This is the actual Python fallback entry, not a fake configure() or adapter
    # replacement. It is deliberately separate from uninstrumented CLI checks.
    importlib.import_module("semgrep.main").main()


def validate_python_observation(value: dict[str, Any], core_sha256: str) -> None:
    if (value.get("forbiddenActivation") is not None or value.get("networkDeniedByOS") is not True
            or value.get("externalWriteDeniedByOS") is not True or value.get("finalAtexitReached") is not True
            or value.get("profileRetainedThroughExit") is not True or value.get("mcpImported") is not True):
        raise ValueError("Python CE activation containment was not observed.")
    calls = value.get("configureCalls")
    if not calls or any(item != {
        "enabled": False, "traceEndpoint": None, "returned": True, "resourceConfigured": True,
    } for item in calls):
        raise ValueError("The real disabled telemetry configuration was not observed.")
    processes = value.get("processes", [])
    cores = [item for item in processes if Path(item["executable"]).name == "semgrep-core"]
    if (not cores or not any(item["ordinaryCoreRPC"] for item in cores)
            or any(item["executableSha256"] != core_sha256 for item in cores)):
        raise ValueError("Ordinary CE core/RPC execution was not bound to the inspected native bytes.")


def qualify(python: Path, output: Path) -> dict[str, Any]:
    from polaris.review.analyzers.base import AnalysisRuntime
    from polaris.review.analyzers.identity import contract, installed_identity, qualified_platform
    from polaris.review.analyzers.process import (
        controlled_environment,
        run_bounded,
        sandboxed_command,
    )
    from polaris.review.analyzers.rule_pack import RULE_PACK_DIGEST, rule_pack_bytes

    if not qualified_platform() or not python.is_absolute() or python.name != "python":
        raise ValueError("Qualification requires the managed macOS ARM64 interpreter.")
    executable = str(python.with_name("semgrep"))
    identity = installed_identity(executable)
    core_pins = [item["sha256"] for name, item in contract()["packages"]["semgrep"]["nativeMembers"].items()
                 if name.endswith("/semgrep/bin/semgrep-core")]
    if len(core_pins) != 1:
        raise ValueError("The inspected CE core must have an unambiguous native binding.")
    if output.exists() or not output.is_absolute() or output.resolve() != output:
        raise ValueError("Qualification output must be a new absolute non-link directory.")
    output.mkdir(mode=0o700)
    tools, source = helper(), Path(__file__).resolve()
    input_digests = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (source, source.with_name("qualify_analyzer_runtime.py"))
    }
    records = {}
    for mode in MODES:
        root = output / mode
        root.mkdir(mode=0o700)
        for name in ("home", "tmp", "source"):
            (root / name).mkdir(mode=0o700)
        (root / "polaris-rules.yaml").write_bytes(rule_pack_bytes({"unsafe_security_configuration"}, {"javascript"}))
        (root / ".semgrepignore").write_bytes(b"")
        for index, enabled in enumerate(("false", "true")):
            (root / f"source/input-{index:06d}.js").write_text(
                'import https from "node:https";\n'
                f"export const client = new https.Agent({{ rejectUnauthorized: {enabled} }});\n",
            )
        instrumented = mode in MODES[:3]
        argv = ([str(python), "-I", "-B", str(source), "_worker", mode, str(root)] if instrumented
                else cli_arguments(executable, mode))
        command = sandboxed_command(argv, workspace=root, runtime=AnalysisRuntime(), timeout=60)
        if command is None:
            raise ValueError("The unchanged production sandbox is unavailable.")
        result = run_bounded(
            command, cwd=root, env=controlled_environment(root, str(python)),
            timeout=60, max_output_bytes=4_000_000,
        )
        for name, content in (("stdout", result.stdout), ("stderr", result.stderr)):
            with (root / (name + ".txt")).open("xb") as stream:
                stream.write(content)
        record: dict[str, Any] = {
            "status": result.status, "returncode": result.returncode, "argv": command, "passed": False,
            "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderrSha256": hashlib.sha256(result.stderr).hexdigest(),
            "pythonInstrumented": instrumented, "nativeInitializationObserved": False,
        }
        try:
            if mode.startswith("calibrate-"):
                observation = json.loads((root / "activation-stop.json").read_bytes())
                expected = ("opentelemetry.sdk.trace.TracerProvider.__init__" if mode == "calibrate-tracing"
                            else "mcp.server.fastmcp.server.FastMCP.__init__")
                if (result.status != "ok" or result.returncode != 86
                        or observation.get("forbiddenActivation") != expected
                        or observation.get("networkDeniedByOS") is not True
                        or observation.get("externalWriteDeniedByOS") is not True):
                    raise ValueError("The activation tripwire was not calibrated.")
            else:
                if result.status != "ok" or result.returncode != 0:
                    raise ValueError("Fixed CE invocation failed.")
                value = json.loads(result.stdout)
                if (value.get("version") != identity["runtimeVersion"] or value.get("errors") != []
                        or len(value["results"]) != 1
                        or value["results"][0]["path"] != "source/input-000000.js"
                        or set(value["paths"]["scanned"]) != {"source/input-000000.js", "source/input-000001.js"}):
                    raise ValueError("The original positive/negative CE fixture was not fully scanned.")
                if instrumented:
                    validate_python_observation(json.loads((root / "python-ce-final.json").read_bytes()), core_pins[0])
            record["passed"] = True
        except (OSError, ValueError, TypeError, KeyError) as error:
            record["validationError"] = type(error).__name__
        tools.write_json(root / "receipt.json", record)
        records[mode] = record
    if any(hashlib.sha256(source.with_name(name).read_bytes()).hexdigest() != digest
           for name, digest in input_digests.items()):
        raise ValueError("Qualification inputs changed during execution.")
    report = {
        "format": "polaris.ce-runtime-qualification/1", "identity": identity,
        "inputDigests": input_digests, "rulePackDigest": RULE_PACK_DIGEST, "cases": records,
        "passed": all(item["passed"] for item in records.values()), "releaseQualified": False,
        "productionSandboxUnmodified": True, "trustedCIEvidence": False,
        "nativeInitializationObserved": False,
        "limitations": [
            "Python observers do not survive native exec or observe native telemetry initialization.",
            "The profiled Python fallback body is a separate diagnostic, not the full default exec chain.",
            "Uninstrumented CLI checks retain OS network/write denial but do not prove absence of initialization.",
            "This does not qualify MCP service/authentication, enabled tracing, or arbitrary plugin interfaces.",
        ],
    }
    tools.write_json(output / "result.json", report)
    return report


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "_worker":
        python_worker(Path(sys.argv[3]), sys.argv[2])
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

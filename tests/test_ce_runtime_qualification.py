"""Unit regressions for diagnostic tripwires; live CE tests remain explicitly opt-in."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ce_runtime_test", ROOT / "scripts/qualify_ce_runtime.py")
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


@pytest.mark.parametrize(("module", "names"), runtime.GUARDED.items())
def test_each_exact_activation_body_is_guarded(module, names):
    assert all(runtime.is_activation(module, name) for name in names)
    assert not runtime.is_activation(module, "different_body")


@pytest.mark.parametrize(("module", "name"), [
    ("semgrep.telemetry", "Telemetry.configure"),
    ("semgrep.telemetry", "Telemetry.inject"),
    ("opentelemetry.sdk.resources", "Resource.__init__"),
    ("opentelemetry.trace", "get_tracer"),
    ("opentelemetry.trace", "ProxyTracer.start_as_current_span"),
    ("opentelemetry.instrumentation.instrumentor", "BaseInstrumentor.uninstrument"),
    ("opentelemetry.sdk.trace", "TracerProvider.shutdown"),
    ("mcp.server.fastmcp.server", "<module>"),
])
def test_disabled_setup_imports_proxy_spans_and_cleanup_are_not_activation(module, name):
    assert not runtime.is_activation(module, name)


def test_fixed_interface_disables_tracing_and_has_only_generated_targets():
    argv = runtime.fixed_arguments()
    assert argv[0] == "scan"
    assert "--no-trace" in argv and "--oss-only" in argv and "--metrics=off" in argv
    assert argv[argv.index("--") + 1:] == ["source/input-000000.js", "source/input-000001.js"]
    assert not {"--trace", "--pro", "mcp"} & set(argv)


def test_missing_observation_is_not_clean():
    with pytest.raises(ValueError):
        runtime.validate_python_observation({}, "0" * 64)


@pytest.mark.parametrize("mode", ["default", "legacy", "experimental"])
def test_cli_diagnostic_preserves_scan_subcommand_position(mode):
    command = runtime.cli_arguments("/trusted/bin/semgrep", mode)
    assert command[:2] == ["/trusted/bin/semgrep", "scan"]
    if mode != "default":
        assert command[2] == "--" + mode
    assert command.count("scan") == 1


def test_worker_argument_dispatch(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(runtime.sys, "argv", [str(runtime.__file__), "_worker", "python-fallback", str(tmp_path)])
    monkeypatch.setattr(runtime, "python_worker", lambda root, mode: observed.append((root, mode)))
    assert runtime.main() == 0 and observed == [(tmp_path, "python-fallback")]

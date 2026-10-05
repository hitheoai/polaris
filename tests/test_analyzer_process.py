"""Trusted synthetic worker processes only; no project source is executed."""

from __future__ import annotations

import errno
import sys
import time
from pathlib import Path

import pytest

from polaris.review.analyzers import AnalysisRuntime
from polaris.review.analyzers.process import (
    controlled_environment,
    installed_semgrep,
    run_bounded,
    sandboxed_command,
)


def worker(tmp_path, code, *, timeout=2, limit=1024):
    return run_bounded(
        [str(Path(sys.executable).absolute()), "-I", "-S", "-c", code],
        cwd=tmp_path, env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        timeout=timeout, max_output_bytes=limit,
    )


def test_subprocess_drains_both_pipes_and_preserves_exit_status(tmp_path):
    result = worker(tmp_path, "import os; os.write(1,b'out'); os.write(2,b'err'); raise SystemExit(7)")
    assert result.status == "ok" and result.returncode == 7
    assert result.stdout == b"out" and result.stderr == b"err"


def test_subprocess_kills_on_shared_output_cap(tmp_path):
    result = worker(tmp_path, "import os; os.write(1,b'x'*100000); os.write(2,b'y'*100000)", limit=1024)
    assert result.status == "output_limit" and len(result.stdout) + len(result.stderr) <= 1024


def test_subprocess_wall_timeout_is_bounded(tmp_path):
    started = time.monotonic()
    result = worker(tmp_path, "import time; time.sleep(60)", timeout=0.2)
    assert result.status == "timeout" and time.monotonic() - started < 3


def test_subprocess_timeout_includes_descendant_inherited_pipes(tmp_path):
    code = (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-I','-S','-c','import time; time.sleep(60)']);"
        "raise SystemExit(0)"
    )
    result = worker(tmp_path, code, timeout=0.3)
    assert result.status == "timeout"


def test_environment_and_binary_discovery_ignore_project_path(tmp_path, monkeypatch):
    candidate = tmp_path / "semgrep"
    candidate.write_text("do not execute")
    candidate.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "synthetic-canary")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    environment = controlled_environment(tmp_path, "/trusted/bin/semgrep")
    assert "SEMGREP_APP_TOKEN" not in environment and "PYTHONPATH" not in environment
    assert environment["HOME"] == str(tmp_path / "home")
    assert installed_semgrep(AnalysisRuntime()) != str(candidate)
    assert installed_semgrep(AnalysisRuntime(semgrep_executable="relative/semgrep")) is None


def test_poisoned_parent_cannot_enable_telemetry_services_or_python_plugins(tmp_path, monkeypatch):
    clean = controlled_environment(tmp_path, "/trusted/bin/semgrep")
    for name in (
        "SEMGREP_APP_TOKEN", "SEMGREP_OTEL_ENDPOINT", "SEMGREP_SEND_METRICS", "SEMGREP_CORE_EXTRA",
        "SEMGREP_ENABLE_VERSION_CHECK", "SEMGREP_SETTINGS_FILE", "SEMGREP_LOG_FILE",
        "SEMGREP_MCP_HOST", "SEMGREP_MCP_PORT", "USE_SEMGREP_RPC",
        "OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_SERVICE_NAME",
        "OTEL_PYTHON_TRACER_PROVIDER", "OTEL_PYTHON_LOGGER_PROVIDER",
        "OTEL_PYTHON_AUTO_INSTRUMENTATION_EXPERIMENTAL_GEVENT_PATCH",
        "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
        "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "HTTP_PROXY", "PATH",
    ):
        monkeypatch.setenv(name, "synthetic-poison-never-propagated")
    assert controlled_environment(tmp_path, "/trusted/bin/semgrep") == clean


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_resource_launcher_disables_bytecode_before_entering_sandbox(tmp_path, monkeypatch, platform):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(Path, "is_file", lambda path: str(path) in {
        "/usr/bin/sandbox-exec", "/usr/bin/bwrap",
    })
    executable = str(Path(sys.executable).absolute())
    command = sandboxed_command(
        ["/usr/bin/true"], workspace=tmp_path, runtime=AnalysisRuntime(), timeout=5,
    )
    assert command is not None
    assert command[:5] == [executable, "-I", "-B", "-S", "-c"]
    # Exercise startup flags without invoking either platform's sandbox.
    # An inherited variable must not be necessary to protect the installed runtime.
    result = run_bounded(
        [*command[:5], "import sys; print(sys.flags.isolated, sys.flags.no_site, sys.dont_write_bytecode)"],
        cwd=tmp_path, env={"HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "0"},
        timeout=5, max_output_bytes=1024,
    )
    assert result.returncode == 0 and result.stdout == b"1 1 True\n"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS network sandbox integration check")
def test_macos_sandbox_actually_denies_network_and_external_writes(tmp_path):
    workspace = tmp_path / "private"
    workspace.mkdir(mode=0o700)
    for name in ("home", "tmp"):
        (workspace / name).mkdir(mode=0o700)
    outside = tmp_path / "must-not-be-written"
    # This trusted test worker attempts no project operation or external service call:
    # a loopback connection and a canary write are expected to be denied by the OS.
    code = (
        "import socket,pathlib,sys;"
        "s=socket.socket();"
        "\ntry: s.connect(('127.0.0.1',9))\n"
        f"except OSError as e: print('network-denied' if e.errno in ({errno.EPERM},{errno.EACCES}) else 'not-enforced')\n"
        f"try: pathlib.Path({str(outside)!r}).write_text('canary')\n"
        "except PermissionError: print('write-denied')\n"
    )
    executable = str(Path(sys.executable).absolute())
    runtime = AnalysisRuntime()
    command = sandboxed_command(
        [executable, "-I", "-S", "-c", code], workspace=workspace, runtime=runtime, timeout=5,
    )
    assert command is not None
    result = run_bounded(command, cwd=workspace, env=controlled_environment(workspace, executable),
                         timeout=5, max_output_bytes=2048)
    assert result.returncode == 0 and b"network-denied" in result.stdout and b"write-denied" in result.stdout
    assert not outside.exists()


def test_subprocess_requires_absolute_executable_and_finite_limits(tmp_path):
    assert run_bounded(["python"], cwd=tmp_path, env={}, timeout=1, max_output_bytes=1024).status == "unavailable"
    with pytest.raises(ValueError):
        run_bounded([sys.executable], cwd=tmp_path, env={}, timeout=float("nan"), max_output_bytes=1024)

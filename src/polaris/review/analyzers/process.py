"""Bounded process IO. No shell, inherited secrets, repository CWD, or unbounded communicate()."""

from __future__ import annotations

import json
import math
import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from polaris.review.analyzers.base import AnalysisRuntime

ProcessStatus = Literal["ok", "timeout", "output_limit", "unavailable", "error"]


@dataclass(frozen=True)
class ProcessResult:
    status: ProcessStatus
    returncode: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    elapsed_ms: float = 0.0


MAX_STDIN_BYTES = 65_536  # fits in a pipe buffer: written in full before reading, so it can't deadlock


def run_bounded(
    argv: Sequence[str], *, cwd: Path, env: Mapping[str, str],
    timeout: float, max_output_bytes: int, stdin: bytes | None = None,
) -> ProcessResult:
    """Drain both pipes with a shared byte cap; kill the process group on timeout/overflow.

    The caller owns interpretation. Raw stderr/stdout must never be copied into user-visible
    errors: analyzers and Git can include source text, credentials, or terminal controls.
    """
    if not argv or not Path(argv[0]).is_absolute():
        return ProcessResult("unavailable")
    if not math.isfinite(timeout) or timeout <= 0 or max_output_bytes < 1:
        raise ValueError("invalid subprocess limits")
    if stdin is not None and len(stdin) > MAX_STDIN_BYTES:
        raise ValueError("subprocess input too large")
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            start_new_session=True,
        )
    except OSError:
        return ProcessResult("unavailable")
    if stdin is not None and process.stdin is not None:
        try:
            process.stdin.write(stdin)
            process.stdin.close()
        except OSError:
            pass  # the process exited early; its status and output decide the result
    stdout, stderr = bytearray(), bytearray()
    status: ProcessStatus = "ok"

    def stop() -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass

    try:
        assert process.stdout is not None and process.stderr is not None
        with selectors.DefaultSelector() as selector:
            for pipe, buffer in ((process.stdout, stdout), (process.stderr, stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, buffer)
            while selector.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    status = "timeout"
                    stop()
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, min(65_536, max_output_bytes + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    room = max_output_bytes - len(stdout) - len(stderr)
                    key.data.extend(chunk[:max(0, room)])
                    if len(chunk) > room:
                        status = "output_limit"
                        stop()
                        break
                if status != "ok":
                    break
        remaining = max(0.001, timeout - (time.monotonic() - started))
        try:
            process.wait(timeout=remaining if status == "ok" else 2)
        except subprocess.TimeoutExpired:
            status = "timeout" if status == "ok" else status
            stop()
            process.wait(timeout=2)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        status = "error" if status == "ok" else status
        stop()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    finally:
        # Also reap descendants that closed their pipes and outlived a successful parent.
        stop()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    return ProcessResult(
        status, process.returncode, bytes(stdout), bytes(stderr),
        round((time.monotonic() - started) * 1000, 3),
    )


def installed_semgrep(runtime: AnalysisRuntime) -> str | None:
    """Only an explicitly configured absolute executable; never a PATH, cwd or repository search.

    The built-in analyzers cover every default check, so Semgrep is opt-in: picking up whatever
    happens to be installed would silently change review scope, latency and completeness.
    """
    if runtime.semgrep_executable is None:
        return None
    path = Path(runtime.semgrep_executable)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        return None
    # Preserve the venv script path; resolving a Python symlink can change its environment.
    return str(path)


def sandbox_available() -> bool:
    if sys.platform == "darwin":
        return Path("/usr/bin/sandbox-exec").is_file()
    if sys.platform.startswith("linux"):
        return any(Path(path).is_file() for path in ("/usr/bin/bwrap", "/bin/bwrap"))
    return False


# -I -S loads only the trusted Python standard library; no editable installs, .pth files,
# user site, PYTHONPATH, or project code. -B is explicit because -I ignores
# PYTHONDONTWRITEBYTECODE, and this launcher starts before the filesystem sandbox.
# Avoid preexec_fn in multithreaded API servers.
_RESOURCE_LAUNCHER = (
    "import os,resource,sys;"
    "resource.setrlimit(resource.RLIMIT_CORE,(0,0));"
    "resource.setrlimit(resource.RLIMIT_CPU,(int(sys.argv[1]),int(sys.argv[1])+1));"
    "resource.setrlimit(resource.RLIMIT_FSIZE,(int(sys.argv[2]),int(sys.argv[2])));"
    "os.execv(sys.argv[3],sys.argv[3:])"
)


def sandboxed_command(
    argv: Sequence[str], *, workspace: Path, runtime: AnalysisRuntime, timeout: float,
) -> list[str] | None:
    """OS-enforced network denial and writes restricted to the temporary workspace.

    Runtime/library reads remain possible. Only explicit private source-copy targets are
    sent to Semgrep; this is not a claim to sandbox a hostile analyzer binary.
    """
    if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file():
        profile = (
            "(version 1)(allow default)(deny network*)(deny file-write*)"
            f"(allow file-write* (subpath {json.dumps(str(workspace.resolve()))}))"
            '(allow file-write* (literal "/dev/null"))'
        )
        command = ["/usr/bin/sandbox-exec", "-p", profile, *argv]
    elif sys.platform.startswith("linux"):
        executable = next((path for path in ("/usr/bin/bwrap", "/bin/bwrap") if Path(path).is_file()), None)
        if executable is None:
            return None
        command = [
            executable, "--die-with-parent", "--unshare-net", "--unshare-pid",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--bind", str(workspace), str(workspace), "--chdir", str(workspace), "--", *argv,
        ]
    else:
        return None
    return [
        str(Path(sys.executable).absolute()), "-I", "-B", "-S", "-c", _RESOURCE_LAUNCHER,
        str(max(1, math.ceil(timeout))), str(runtime.max_output_bytes), *command,
    ]


def controlled_environment(workspace: Path, executable: str) -> dict[str, str]:
    """An allowlist, not a copy of os.environ. In particular there are no auth/cloud tokens."""
    return {
        "PATH": os.pathsep.join((str(Path(executable).parent), "/usr/bin", "/bin")),
        "HOME": str(workspace / "home"),
        "TMPDIR": str(workspace / "tmp"),
        "XDG_CONFIG_HOME": str(workspace / "home" / "config"),
        "XDG_CACHE_HOME": str(workspace / "home" / "cache"),
        "XDG_DATA_HOME": str(workspace / "home" / "data"),
        "SEMGREP_SETTINGS_FILE": str(workspace / "home" / "settings.yml"),
        "SEMGREP_LOG_FILE": str(workspace / "home" / "semgrep.log"),
        "SEMGREP_VERSION_CACHE_PATH": str(workspace / "home" / "version"),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_IN_DOCKER": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        # Defense in depth; the OS sandbox, not these proxy variables, enforces no network.
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
    }

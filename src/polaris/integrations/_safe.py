"""Small integration-only boundaries: no project commands, symlinks, or inherited credentials."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class IntegrationProblem(ValueError):
    """A safe, fixed diagnostic; never include command output or configuration values."""


def no_symlinks(path: Path) -> Path:
    """Check the whole lexical path, not just the leaf (including dangling links)."""
    path = Path(os.path.abspath(path.expanduser()))
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            raise IntegrationProblem("A path or its ancestor is a symbolic link.")
    return path


def trusted_executable(path: Path | None) -> Path | None:
    """Validate an explicitly supplied local analyzer, never discover or run project commands."""
    if path is None:
        return None
    if not path.is_absolute():
        raise IntegrationProblem("Analyzer executable must be an explicit absolute path.")
    path = no_symlinks(path)
    try:
        regular = stat.S_ISREG(path.stat().st_mode)
    except OSError as exc:
        raise IntegrationProblem("Analyzer executable is unavailable.") from exc
    if not regular or not os.access(path, os.X_OK):
        raise IntegrationProblem("Analyzer executable must be a regular executable file.")
    return path


@contextmanager
def parent_descriptor(path: Path, *, create: bool = False) -> Iterator[int]:
    """Open each parent with O_NOFOLLOW; a concurrent directory swap cannot escape it.

    These integrations currently require POSIX directory-descriptor support. Fail closed on
    platforms without it instead of silently weakening the write boundary.
    """
    path = no_symlinks(path)
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise IntegrationProblem("Safe integration filesystem operations require POSIX support.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parent.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class FileSnapshot:
    value: bytes
    identity: tuple[int, ...]
    mode: int


def _file_snapshot(value: bytes, info: os.stat_result) -> FileSnapshot:
    return FileSnapshot(value, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                                info.st_ctime_ns, info.st_mode), stat.S_IMODE(info.st_mode))


def _read_at(parent: int, name: str, limit: int) -> FileSnapshot | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise IntegrationProblem("Expected a regular file.")
            if before.st_size > limit:
                raise IntegrationProblem("File exceeds the configured byte limit.")
            value = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(value) > limit or _file_snapshot(value, before) != _file_snapshot(value, after):
                raise IntegrationProblem("File changed during the bounded read.")
            return _file_snapshot(value, after)
    except FileNotFoundError:
        return None

def read_snapshot(path: Path, *, limit: int = 2_000_000) -> FileSnapshot | None:
    """Bounded content and identity from one non-symlink descriptor; None means missing."""
    try:
        with parent_descriptor(path) as parent:
            return _read_at(parent, path.name, limit)
    except FileNotFoundError:
        return None


def read_bytes(path: Path, *, limit: int = 2_000_000) -> bytes | None:
    """Read a bounded regular file without following any symlink; None means missing."""
    snapshot = read_snapshot(path, limit=limit)
    return snapshot.value if snapshot is not None else None


def _same_parent(path: Path, parent: int) -> None:
    """Reject a directory replaced between planning/opening and the final write."""
    with parent_descriptor(path) as current:
        old, new = os.fstat(parent), os.fstat(current)
        if (old.st_dev, old.st_ino) != (new.st_dev, new.st_ino):
            raise IntegrationProblem("Destination directory changed; rerun setup.")


def atomic_write(path: Path, value: bytes, *, mode: int = 0o600,
                 expected: bytes | None = None, check_expected: bool = False,
                 expected_snapshot: FileSnapshot | None = None) -> FileSnapshot:
    """Atomic replace, with content/identity checks on the same parent descriptor.

    Setup also takes an advisory lock to serialize its own writers. Arbitrary external writers
    cannot participate in a POSIX compare-and-swap; check again immediately before replacement.
    """
    path = no_symlinks(path)
    with parent_descriptor(path, create=True) as parent:
        def check() -> None:
            _same_parent(path, parent)
            if check_expected:
                current = _read_at(parent, path.name, max(2_000_000, len(value)))
                if ((current.value if current is not None else None) != expected
                        or expected_snapshot is not None and current != expected_snapshot):
                    raise IntegrationProblem("File changed after planning; rerun setup.")
            else:
                try:
                    info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        raise IntegrationProblem("Refusing to replace a non-regular file.")
                except FileNotFoundError:
                    pass

        check()
        temporary = f".polaris-{os.urandom(12).hex()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             mode, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), mode)
                check()
                os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                return _file_snapshot(value, os.fstat(stream.fileno()))
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass

def checked_unlink(path: Path, expected: FileSnapshot) -> None:
    """Rollback only the exact file this application wrote, never a concurrent replacement."""
    path = no_symlinks(path)
    with parent_descriptor(path) as parent:
        _same_parent(path, parent)
        if _read_at(parent, path.name, max(2_000_000, len(expected.value))) != expected:
            raise IntegrationProblem("Destination changed; rollback left it untouched.")
        os.unlink(path.name, dir_fd=parent)


def offline_environment(home: Path) -> dict[str, str]:
    """An allowlist, not a redaction list: no caller credentials or Python injection variables."""
    return {
        "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.defpath)),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "POLARIS_HOME": str(home / ".polaris"),
        "HF_HOME": str(home / ".cache" / "huggingface"),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_ATTR_NOSYSTEM": "1",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "POLARIS_AGENT_HOOK_ACTIVE": "1",
    }


def module_command(module: str, function: str = "main") -> list[str]:
    """Run only this installed Polaris package, never a project-local `polaris.py`.

    -I ignores PYTHONPATH/site-user customizations and cwd. The explicit package location also
    makes a read-only shared venv safe when its editable install points at a different checkout.
    Module and function are internal constants, never hook-input strings.
    """
    package_parent = str(Path(__file__).resolve().parents[2])
    bootstrap = (f"import sys; sys.argv[0] = 'polaris'; sys.path.insert(0, {package_parent!r}); "
                 f"from {module} import {function}; sys.exit({function}())")
    return [sys.executable, "-I", "-B", "-c", bootstrap]


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_bounded(command: Sequence[str], *, cwd: Path, env: Mapping[str, str],
                timeout: float, input_bytes: bytes | None = None,
                max_output_bytes: int = 4_000_000) -> ProcessResult:
    """Bound time and both output streams; kill the process group on timeout/overflow."""
    if not 0 < timeout <= 120 or max_output_bytes < 1:
        raise IntegrationProblem("Invalid process bounds.")
    overflow = threading.Event()
    outputs: list[bytearray] = [bytearray(), bytearray()]
    with tempfile.TemporaryFile() as source:
        source.write(input_bytes or b"")
        source.seek(0)
        try:
            child = subprocess.Popen(
                list(command), cwd=cwd, env=dict(env), stdin=source,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != "nt",
            )
        except OSError as exc:
            raise IntegrationProblem("Required local process is unavailable.") from exc

        def terminate() -> None:
            try:
                if os.name != "nt":
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
            except ProcessLookupError:
                pass

        def drain(index: int) -> None:
            stream = child.stdout if index == 0 else child.stderr
            assert stream is not None
            with stream:
                while chunk := stream.read(65_536):
                    remaining = max_output_bytes + 1 - len(outputs[index])
                    outputs[index].extend(chunk[:max(0, remaining)])
                    if len(outputs[index]) > max_output_bytes:
                        overflow.set()
                        terminate()
                        break

        readers = [threading.Thread(target=drain, args=(index,), daemon=True) for index in (0, 1)]
        deadline = time.monotonic() + timeout
        for reader in readers:
            reader.start()
        try:
            # Wait on the readers (both pipes reach EOF when the child exits) instead of
            # Popen.wait(timeout=...), which polls with sleeps of up to 50 ms per process.
            for reader in readers:
                reader.join(timeout=max(0.0, deadline - time.monotonic()))
            if any(reader.is_alive() for reader in readers):
                raise subprocess.TimeoutExpired(list(command), timeout)
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            terminate()
            child.wait()
            raise IntegrationProblem("Required local process timed out; review is unavailable.") from exc
        finally:
            for reader in readers:
                reader.join(timeout=1)
            if any(reader.is_alive() for reader in readers):
                terminate()
        if overflow.is_set() or any(reader.is_alive() for reader in readers):
            raise IntegrationProblem("Required local process exceeded its output bound.")
        return ProcessResult(child.returncode, bytes(outputs[0]), bytes(outputs[1]))

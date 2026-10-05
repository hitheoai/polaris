"""Second stage of the pinned Theo bootstrap; never run from an unverified download."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

RELEASE_ID = "theo-0.3.3-macos-arm64-r1"
VERSION = "0.3.3"
MINIMUM_MACOS = "15.0"
NETWORK_DENIED = "(version 1)(allow default)(deny network*)"
PROFILE_START = "# >>> theo managed PATH >>>"
PROFILE_END = "# <<< theo managed PATH <<<"


class InstallProblem(Exception):
    """Only static, actionable errors are printed; no subprocess output or credential data."""


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise InstallProblem("Invalid installer arguments. Use --help; never supply an API key as an argument.")


def check_macos_version(value: str) -> None:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){1,2}", value):
        raise InstallProblem("Could not establish the macOS version; installation was not started.")
    parts = tuple(map(int, value.split(".")))
    if (*parts, *(0 for _ in range(3 - len(parts)))) < (15, 0, 0):
        raise InstallProblem("This release requires macOS 15.0 or later, including its bundled analyzer.")


def no_links(path: Path) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    for item in (*reversed(path.parents), path):
        if item.is_symlink():
            raise InstallProblem("An installation or configuration path is a symlink; it was left unchanged.")
    return path


def regular(path: Path, limit: int = 2_000_000) -> bytes:
    no_links(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise InstallProblem("An artifact or receipt is not a bounded regular file.")
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise InstallProblem("An artifact exceeds its declared byte limit.")
        return value


def private_dir(path: Path) -> Path:
    path = no_links(path)
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise InstallProblem("The managed destination must be a private user-owned directory. Its existing permissions were not changed.")
    return path


def write(path: Path, value: bytes, *, mode: int = 0o600) -> None:
    no_links(path)
    temporary = path.with_name(f".theo-{secrets.token_hex(12)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def json_write(path: Path, value: Any) -> None:
    write(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def sha256(path: Path) -> str:
    no_links(path)
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InstallProblem("An installed file is not regular.")
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, specification: dict[str, Any]) -> None:
    if (not isinstance(specification.get("bytes"), int) or not 0 < specification["bytes"] <= 1_000_000_000
            or not re.fullmatch(r"[a-f0-9]{64}", str(specification.get("sha256", "")))
            or path.stat().st_size != specification["bytes"] or sha256(path) != specification["sha256"]):
        raise InstallProblem("An immutable artifact failed its size or SHA256 check. Nothing from it was executed.")


def origin(value: str, *, local_api: bool = False) -> str:
    import ipaddress

    try:
        parsed = urllib.parse.urlsplit(value)
        try:
            loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        allowed = parsed.scheme == "https" or local_api and parsed.scheme == "http" and loopback
        if (not allowed or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment or "\\" in value
                or not value.isascii() or any(c.isspace() or ord(c) < 33 for c in value)
                or not re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", parsed.netloc)
                or parsed.port is not None and not 0 < parsed.port <= 65535):
            raise ValueError
    except ValueError:
        raise InstallProblem("Use a credential-free HTTPS origin without a path, query or fragment.") from None
    return f"{parsed.scheme}://{parsed.netloc}"


def clean_environment(root: Path, *, user_home: bool = False) -> dict[str, str]:
    home = Path.home() if user_home else private_dir(root / "installer-home")
    temporary = private_dir(root / "tmp")
    hints = {}
    if user_home:
        program = os.environ.get("TERM_PROGRAM", "")
        if program in ("WarpTerminal", "warp", "vscode", "cursor", "windsurf"):
            hints["TERM_PROGRAM"] = program
        for name in ("CLAUDE_CODE_ENTRYPOINT", "CURSOR_SESSION_ID", "CURSOR_TRACE_ID",
                     "CODEX_THREAD_ID", "CODEX_SESSION_ID", "WINDSURF_SESSION_ID"):
            if os.environ.get(name):
                hints[name] = "detected"
        if os.environ.get("CLAUDECODE") == "1":
            hints["CLAUDECODE"] = "1"
    return {
        **hints,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home), "TMPDIR": str(temporary), "LANG": "en_US.UTF-8",
        "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"),
        "UV_CACHE_DIR": str(root / "uv-cache"), "UV_PYTHON_DOWNLOADS": "never",
        "UV_NO_CONFIG": "1", "UV_OFFLINE": "1", "UV_COMPILE_BYTECODE": "0",
        "PIP_CONFIG_FILE": os.devnull, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SETTINGS_FILE": str(root / "installer-home" / "semgrep-settings.yml"),
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
        "NO_COLOR": os.environ.get("NO_COLOR", ""),
        "TERM": os.environ.get("TERM", "dumb"),
    }


def run(command: list[str], root: Path, label: str, *, timeout: int = 180) -> str:
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(command, cwd=root, env=clean_environment(root),
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                 start_new_session=True, umask=0o077)
        try:
            child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise InstallProblem(f"{label} was interrupted. Rerun this installer to resume; no completion is claimed.") from None
        if child.returncode:
            raise InstallProblem(f"{label} failed. Rerun this installer after checking your local prerequisites; no completion is claimed.")
        output.seek(0)
        value = output.read(1_000_001)
        errors.seek(0)
        diagnostics = errors.read(1_000_001)
        if len(value) + len(diagnostics) > 1_000_000:
            raise InstallProblem(f"{label} exceeded its output bound.")
    return value.decode("utf-8", errors="replace")


@contextmanager
def installation_lock(prefix: Path) -> Iterator[None]:
    path = no_links(prefix / "install.lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise InstallProblem("The installation lock is not a private user-owned file.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallProblem("Another Theo installer is running. Let it finish, then rerun.") from None
        yield
    finally:
        os.close(descriptor)


def claim(prefix: Path, project: Path | None = None) -> None:
    no_links(prefix)
    home = Path.home().resolve()
    if (prefix == Path(prefix.anchor) or prefix == home or home.is_relative_to(prefix)
            or project is not None and (
                prefix.is_relative_to(no_links(project)) or project.is_relative_to(prefix))):
        raise InstallProblem("Use a bounded private installation prefix, not your home, filesystem root or project.")
    marker = {"format": "polaris.theo-prefix/1", "uid": os.getuid()}
    if prefix.exists():
        private_dir(prefix)
        existing = prefix / "owner.json"
        if existing.exists():
            if json.loads(regular(existing)) != marker:
                raise InstallProblem("This prefix belongs to another installation; it was left unchanged.")
            return
        if any(prefix.iterdir()):
            raise InstallProblem("The chosen prefix has unrelated files and no Theo ownership marker; it was left unchanged.")
    private_dir(prefix)
    json_write(prefix / "owner.json", marker)


def quarantine(root: Path, component: str) -> None:
    path = no_links(root / component)
    if path.exists():
        # Preserve a partially created environment rather than deleting unknown user additions.
        os.rename(path, root / f".interrupted-{component}-{secrets.token_hex(8)}")


def extract_payload(archive: Path, destination: Path, *,
                    roots: tuple[str, ...] = ("app", "analyzer"), max_members: int = 1000,
                    preserve_modes: bool = False) -> None:
    private_dir(destination)
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        total = 0
        seen: set[str] = set()
        for member in members:
            path = Path(member.name)
            total += member.size
            if (len(members) > max_members or total > 1_500_000_000 or member.size < 0
                    or member.size > 250_000_000 or member.name in seen
                    or preserve_modes and member.mode not in (0o644, 0o755)
                    or path.is_absolute() or ".." in path.parts
                    or not path.parts or path.parts[0] not in roots
                    or path.as_posix() != member.name.rstrip("/") or "\\" in member.name
                    or not (member.isfile() or member.isdir())):
                raise InstallProblem("The release payload has an unsafe or excessive archive entry.")
            seen.add(member.name)
        for member in members:
            target = no_links(destination / member.name)
            if member.isdir():
                private_dir(target)
            else:
                private_dir(target.parent)
                stream = bundle.extractfile(member)
                if stream is None:
                    raise InstallProblem("The release payload entry is missing.")
                with stream:
                    write(target, stream.read(member.size + 1),
                          mode=member.mode if preserve_modes else 0o600)


def inventory(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    components = ["python", "uv", "app", "analyzer"]
    if (root / "third-party-sources").exists() or (root / "third-party-sources").is_symlink():
        components.append("third-party-sources")
    if (root / "compliance").exists() or (root / "compliance").is_symlink():
        components.append("compliance")
    for component in components:
        folder = no_links(root / component)
        for base, directories, filenames in os.walk(folder, followlinks=False):
            directories[:] = [name for name in directories if name != "__pycache__"]
            for name in [*directories, *filenames]:
                path = Path(base) / name
                if path.suffix == ".pyc":
                    continue
                relative = str(path.relative_to(root))
                info = path.lstat()
                if info.st_uid != os.getuid() or not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
                    raise InstallProblem("An installed runtime path has unsafe ownership or write permissions.")
                if stat.S_ISLNK(info.st_mode):
                    target = path.resolve()
                    if not target.is_relative_to(root) or not target.exists():
                        raise InstallProblem("A private runtime link escapes its immutable release.")
                    result[relative] = {"link": os.readlink(path)}
                elif stat.S_ISREG(info.st_mode):
                    result[relative] = {"sha256": sha256(path), "mode": stat.S_IMODE(info.st_mode)}
                elif not stat.S_ISDIR(info.st_mode):
                    raise InstallProblem("An installed runtime contains a special file.")
    return result


def seal_environment_lock(path: Path) -> None:
    # uv deliberately creates shared-write locks, even under a private umask.
    # Only its empty, single-link, user-owned lock may have permissions tightened.
    path = no_links(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size != 0):
            raise InstallProblem("The environment lock is not an empty user-owned regular file.")
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def validate(root: Path, manifest: dict[str, Any], *, complete: bool) -> None:
    if complete:
        recorded = json.loads(regular(root / "installed-files.json", limit=20_000_000))
        if recorded != inventory(root):
            raise InstallProblem("Installed runtime files differ from the completion receipt. They were not executed or overwritten; use a new prefix to recover.")
    app_python = str(root / "app" / "bin" / "python")
    executable = str(root / "analyzer" / "bin" / "semgrep")
    run([app_python, "-I", "-B", "-c",
         "import json,sys; from polaris.review.analyzers.identity import installed_identity,validate_manifest; "
         "from pathlib import Path; from polaris.onboarding.sources import verify_installed_sources; "
         "m=json.loads(sys.argv[2]); validate_manifest(m); "
         "assert installed_identity(sys.argv[1]) == m['analyzerIdentity']; "
         "verify_installed_sources(Path(sys.argv[3]),m['thirdPartySources'])",
         executable, json.dumps(manifest), str(root / "third-party-sources")], root,
        "Exact analyzer metadata, graph and recipient source validation")
    uv = str(root / "uv" / "uv")
    for component in ("app", "analyzer"):
        python = str(root / component / "bin" / "python")
        run([uv, "--no-config", "--offline", "pip", "check", "--python", python], root,
            f"{component} dependency validation")
        seal_environment_lock(root / component / ".lock")
        code = (
            "import importlib.metadata as m,json,re,sys;"
            "assert sys.version_info[:3] == (3,11,16);"
            "packages=list(m.distributions());"
            "observed={re.sub(r'[-_.]+','-',d.metadata['Name']).lower():d.version for d in packages};"
            "assert len(observed)==len(packages); print(json.dumps(observed))"
        )
        observed = json.loads(run([python, "-I", "-B", "-c", code], root, f"{component} version validation"))
        if observed != manifest["environments"][component]:
            raise InstallProblem("An environment's installed package versions differ from the pinned release.")
    run([app_python, "-I", "-B", "-c",
         "import mcp,tomlkit; from polaris import __version__; "
         "from polaris.integrations.setup import configure_project; "
         f"assert __version__ == {VERSION!r}"], root, "Theo/MCP/connector import check")
    run([app_python, "-I", "-B", "-m", "polaris.onboarding", "--version"], root, "Theo entry point check")
    run([app_python, "-I", "-B", "-m", "polaris", "--version"], root, "Polaris entry point check")
    run([app_python, "-I", "-B", "-c",
         "import sys; from polaris.review.analyzers.base import AnalysisRuntime; "
         "from polaris.review.analyzers.semgrep import SemgrepAnalyzer; "
         "cap=SemgrepAnalyzer(AnalysisRuntime(semgrep_executable=sys.argv[1])).capability(probe=True); "
         "assert cap.availability == 'available'; print(cap.model_dump_json())", executable],
        root, "Exact analyzer production sandbox probe")


def fetch_release_artifact(root: Path, name: str, expected: dict[str, Any], *,
                           base_url: str | None, release_dir: Path | None) -> Path:
    if name not in ("payload.tar.gz", "compliance.tar.gz", "third-party-sources.tar.gz") or expected.get("name") != name:
        raise InstallProblem("A release artifact has an incompatible name.")
    artifacts = private_dir(root / "artifacts")
    target = artifacts / name
    if target.exists():
        verify(target, expected)
        return target
    temporary = artifacts / f".download-{secrets.token_hex(12)}"
    try:
        if release_dir is not None:
            source = no_links(release_dir / name)
            verify(source, expected)
            shutil.copyfile(source, temporary)
        else:
            command = ["/usr/bin/curl", "-q", "--fail", "--silent", "--show-error", "--proto", "=https",
                       "--connect-timeout", "15", "--max-time", "300", "--retry", "2",
                       "--max-filesize", str(expected["bytes"]), "--output", str(temporary),
                       f"{base_url}/releases/{RELEASE_ID}/{name}"]
            run(command, root, "Pinned release download", timeout=900)
        verify(temporary, expected)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def install_runtime(prefix: Path, bootstrap: Path, manifest: dict[str, Any],
                    manifest_digest: str, *, base_url: str | None, release_dir: Path | None,
                    quiet: bool) -> Path:
    releases = private_dir(prefix / "releases")
    root = releases / RELEASE_ID
    owner = {"format": "polaris.theo-release/1", "release": RELEASE_ID,
             "manifest_sha256": manifest_digest, "uid": os.getuid()}
    if root.exists():
        private_dir(root)
        if json.loads(regular(root / "owner.json")) != owner:
            raise InstallProblem("This immutable release ID has different content or ownership. It was not overwritten.")
    else:
        private_dir(root)
        json_write(root / "owner.json", owner)
    expected_receipt = {
        "format": "polaris.theo-install/2", "release": RELEASE_ID, "version": VERSION,
        "platform": "macos-arm64", "manager": "standalone",
        "manifest_sha256": manifest_digest, "status": "installed",
        "packageValidated": True, "analyzerRuntime": "identity_and_runtime_checked_offline",
    }
    if (root / "install-receipt.json").exists():
        if json.loads(regular(root / "install-receipt.json")) != expected_receipt:
            raise InstallProblem("The completion receipt does not belong to this immutable release.")
        validate(root, manifest, complete=True)
        return root
    run(["/usr/bin/sandbox-exec", "-p", NETWORK_DENIED, "/usr/bin/true"],
        root, "macOS analyzer sandbox check", timeout=15)
    artifacts = private_dir(root / "artifacts")
    payload = fetch_release_artifact(root, "payload.tar.gz", manifest["payload"],
                                     base_url=base_url, release_dir=release_dir)
    stage_file = root / "stages.json"
    stages = json.loads(regular(stage_file)) if stage_file.exists() else {}
    if not stages.get("thirdPartySources"):
        source_packet = fetch_release_artifact(
            root, "third-party-sources.tar.gz", manifest["thirdPartySources"],
            base_url=base_url, release_dir=release_dir,
        )
        quarantine(root, "third-party-sources")
        extract_payload(source_packet, root, roots=("third-party-sources",),
                        max_members=30_000, preserve_modes=True)
        stages["thirdPartySources"] = True
        json_write(stage_file, stages)
    if "compliance" in manifest and not stages.get("compliance"):
        compliance = fetch_release_artifact(root, "compliance.tar.gz", manifest["compliance"],
                                            base_url=base_url, release_dir=release_dir)
        quarantine(root, "compliance")
        extract_payload(compliance, root, roots=("compliance",), max_members=30_000)
        stages["compliance"] = True
        json_write(stage_file, stages)
    for name, source in (("python", bootstrap / "python"), ("uv", bootstrap / "uv-aarch64-apple-darwin")):
        if not stages.get(name):
            quarantine(root, name)
            shutil.copytree(source, root / name, symlinks=True)
            stages[name] = True
            json_write(stage_file, stages)
    payload_dir = artifacts / "payload"
    if not stages.get("payload"):
        quarantine(artifacts, "payload")
        extract_payload(payload, payload_dir)
        stages["payload"] = True
        json_write(stage_file, stages)
    uv = str(root / "uv" / "uv")
    for name in ("app", "analyzer"):
        if stages.get(name):
            continue
        if not quiet:
            print(f"  Preparing your private {'Polaris/MCP' if name == 'app' else 'qualified Semgrep'} environment…", file=sys.stderr, flush=True)
        quarantine(root, name)
        run([uv, "--no-config", "--offline", "venv", "--python",
             str(root / "python" / "bin" / "python3.11"), str(root / name)], root, f"{name} environment creation")
        run([uv, "--no-config", "--offline", "pip", "install", "--python", str(root / name / "bin" / "python"),
             "--no-index", "--find-links", str(payload_dir / name / "wheels"), "--require-hashes",
             "--no-build", "--link-mode", "copy", "-r", str(payload_dir / name / "requirements.txt")],
            root, f"{name} pinned dependency installation", timeout=900)
        stages[name] = True
        json_write(stage_file, stages)
    validate(root, manifest, complete=False)
    write(root / "manifest.json", regular(bootstrap / "manifest.json"))
    json_write(root / "installed-files.json", inventory(root))
    json_write(root / "install-receipt.json", expected_receipt)
    run([str(root / "app" / "bin" / "python"), "-I", "-B", "-c",
         "from polaris.onboarding.installation import seal_uninstall_inventory; seal_uninstall_inventory()"],
        root, "Owned removal inventory", timeout=180)
    return root


def activate_launcher(prefix: Path, root: Path) -> Path:
    folder = private_dir(prefix / "bin")
    launches = {
        name: (
            "#!/bin/sh\n# theo-managed-launcher:2\n"
            f"exec {shlex.quote(str(root / 'app' / 'bin' / 'python'))} -I -B -m {module} \"$@\"\n"
        ).encode()
        for name, module in (("theo", "polaris.onboarding"), ("polaris", "polaris"))
    }
    current_path = prefix / "current.json"
    current = json.loads(regular(current_path)) if current_path.exists() else {}
    if not isinstance(current, dict) or current and current.get("format") not in (
        "polaris.theo-current/1", "polaris.theo-current/2",
    ):
        raise InstallProblem("The command ownership receipt is invalid; no command was replaced.")
    owned = current.get("launchers", {}) if current.get("format") == "polaris.theo-current/2" else {
        "theo": current.get("launcher_sha256"),
    }
    if not isinstance(owned, dict):
        raise InstallProblem("The command ownership receipt is invalid; no command was replaced.")
    # Check both names before replacing either; a rerun may resume our exact new launcher.
    for name, launch in launches.items():
        path = no_links(folder / name)
        if path.exists():
            existing = regular(path)
            info = path.stat()
            if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink != 1
                    or existing != launch and hashlib.sha256(existing).hexdigest() != owned.get(name)):
                raise InstallProblem("An unrelated or modified command exists in the managed bin directory; it was not overwritten.")
    for name, launch in launches.items():
        write(folder / name, launch, mode=0o700)
    json_write(current_path, {
        "format": "polaris.theo-current/2", "release": RELEASE_ID,
        "launchers": {name: hashlib.sha256(launch).hexdigest() for name, launch in launches.items()},
    })
    return folder / "theo"


def managed_path(prefix: Path) -> str:
    shell = Path(os.environ.get("SHELL", "/bin/zsh")).name
    if shell not in ("zsh", "bash"):
        return "not_changed_unsupported_shell"
    profile = no_links(Path.home() / (".zprofile" if shell == "zsh" else ".bash_profile"))
    before = regular(profile) if profile.exists() else b""
    text = before.decode("utf-8")
    marker = hashlib.sha256(str(prefix).encode()).hexdigest()[:16]
    block = (
        f"{PROFILE_START}\n# owner: {marker}\n"
        f"export PATH=\"$PATH\":{shlex.quote(str(prefix / 'bin'))}\n{PROFILE_END}"
    )
    if PROFILE_START in text or PROFILE_END in text:
        if text.count(PROFILE_START) != 1 or text.count(PROFILE_END) != 1:
            raise InstallProblem("The shell profile has ambiguous Theo markers; it was not changed.")
        begin, end = text.index(PROFILE_START), text.index(PROFILE_END) + len(PROFILE_END)
        if text[begin:end] != block:
            raise InstallProblem("An existing Theo PATH block belongs to different or edited content; it was left unchanged.")
        return "unchanged"
    after = text + ("" if not text or text.endswith("\n") else "\n") + "\n" + block + "\n"
    backups = private_dir(prefix / "profile-backups")
    backup = backups / f"{profile.name}.{secrets.token_hex(12)}"
    write(backup, before)
    mode = stat.S_IMODE(profile.stat().st_mode) if profile.exists() else 0o600
    if profile.exists() and regular(profile) != before:
        raise InstallProblem("The shell profile changed while planning the PATH block; it was not overwritten.")
    write(profile, after.encode(), mode=mode)
    json_write(prefix / "path-receipt.json", {
        "format": "polaris.theo-path/1", "profile": str(profile), "backup": str(backup),
        "before_sha256": hashlib.sha256(before).hexdigest(),
        "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
        "mode": mode, "block": block,
    })
    return "configured_for_new_shells"


def main(argv: list[str] | None = None) -> int:
    parser = Parser(description=__doc__)
    parser.add_argument("--bootstrap-root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--base-url")
    source.add_argument("--release-dir", type=Path)
    parser.add_argument("--prefix", type=Path)
    path_options = parser.add_mutually_exclusive_group()
    path_options.add_argument("--add-path", action="store_true",
                              help="Explicitly add an owned PATH block to your shell profile.")
    path_options.add_argument("--no-path", action="store_true",
                              help="Leave shell profiles unchanged (the default).")
    parser.add_argument("--install-only", action="store_true",
                        help="Compatibility alias: installation never configures a project.")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if platform.system() != "Darwin" or platform.machine() != "arm64" or sys.version_info[:3] != (3, 11, 16):
            raise InstallProblem("This pinned installer supports Apple Silicon macOS with its private Python 3.11.16 only.")
        check_macos_version(platform.mac_ver()[0])
        if os.getuid() == 0 or os.getuid() != os.geteuid():
            raise InstallProblem("Run as your normal account, never with sudo.")
        base_url = origin(args.base_url) if args.base_url else None
        prefix = no_links(args.prefix or Path.home() / ".local" / "share" / "theo")
        bootstrap = no_links(args.bootstrap_root)
        raw = regular(bootstrap / "manifest.json")
        if hashlib.sha256(raw).hexdigest() != args.manifest_sha256:
            raise InstallProblem("The manifest no longer matches the verified bootstrap.")
        manifest = json.loads(raw)
        if (manifest.get("format") != "polaris.theo-bundle/1" or manifest.get("id") != RELEASE_ID
                or manifest.get("version") != VERSION or manifest.get("platform") != "macos-arm64"
                or manifest.get("minimumMacOS") != MINIMUM_MACOS):
            raise InstallProblem("The bootstrap and immutable release manifest are incompatible.")
        claim(prefix)
        with installation_lock(prefix):
            root = install_runtime(prefix, bootstrap, manifest, args.manifest_sha256,
                                   base_url=base_url, release_dir=args.release_dir, quiet=args.json)
            launcher = activate_launcher(prefix, root)
            path_status = managed_path(prefix) if args.add_path else "not_requested"
        report: dict[str, Any] = {
            "format": "polaris.onboarding/1", "status": "installed_not_configured",
            "release": RELEASE_ID, "version": VERSION, "launcher": str(launcher),
            "commands": {name: str(prefix / "bin" / name) for name in ("theo", "polaris")},
            "configuration": "not_requested", "activation": {"status": "not_requested"},
            "path": path_status, "host_verified": False,
            "next_action": "Use polaris workflow capabilities; optionally run theo setup --local from your intended Git project.",
        }
        if args.json:
            print(json.dumps(report))
        else:
            print("Polaris and Theo installed. No project, editor configuration or credentials were changed.", file=sys.stderr)
            for name, path in report["commands"].items():
                print(f"  {name}: {path}", file=sys.stderr)
            if path_status == "configured_for_new_shells":
                print("The explicitly requested PATH block applies to new shells.", file=sys.stderr)
            elif path_status == "not_requested":
                print("Shell profiles were left unchanged; use the absolute command paths above.", file=sys.stderr)
            print(report["next_action"], file=sys.stderr)
        return 0
    except InstallProblem as exc:
        message = str(exc)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        message = "A bounded filesystem, archive or compatibility check failed. Existing files were retained; rerun the matching verified installer."
    except KeyboardInterrupt:
        message = "Installation interrupted. Rerun the same verified installer to resume; no completion is claimed."
    if "--json" in (argv if argv is not None else sys.argv[1:]):
        print(json.dumps({"format": "polaris.onboarding/1", "status": "error", "code": "install_failed",
                          "message": message, "host_verified": False}))
    else:
        print(f"Theo: {message}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

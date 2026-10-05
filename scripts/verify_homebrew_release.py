"""Verify pinned Homebrew releases without using the live prefix.

Phases are explicit: init, fetch-gems, provision, isolate-test-temp, fetch-candidate,
stage, stage-upgrade, install, upgrade, test, review, reinstall, uninstall.
Only fetch-gems and explicitly approved fetch-candidate permit HTTPS retrieval.
Homebrew itself retains file-only transport, sandboxing and normal tap trust.
Nothing is signed, published, committed, or configured in a real project/editor.

isolate-test-temp explicitly creates a fresh owned OS temporary directory outside
Git checkouts; it changes only HOMEBREW_TEMP/TMPDIR and retains the original marker.
HTTPS acceptance uses the unchanged HTTPS formula and an independently acquired,
hash-verified download cache; it is not a quarantine or public-delivery attestation.
Upgrade retains the previous runtime, including after ordinary newest-keg removal.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import pwd
import re
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, NoReturn, cast

HOMEBREW_REVISION = "570982948a8a194f0f42f43f4a5bce2d1c9f64cb"
LOCK_SHA256 = "f035ac6a147c5823444965beda36b66e545fc1f1600605159ca6d4f686acc418"
GEMFILE_SHA256 = "4c1281838e5dd97b903c060dd7f920c99cdf2eee7cd0549d35dafe6f01334b31"
PUBLIC_KEY_SHA256 = "ef2d2c9e0219d485df9f07fff7b037feadc36c93085be9ffefb1390f31a3de1d"
RUBY_VERSION = "4.0.7"
RUBY_ABI = "4.0.0"
GEM_VERSIONS = {
    "bindata": "3.0.0",
    "concurrent-ruby": "1.3.8",
    "drb": "2.2.3",
    "elftools": "2.2.0",
    "logger": "1.7.0",
    "minitest": "6.0.6",
    "patchelf": "1.7.0",
    "plist": "3.7.2",
    "prism": "1.9.0",
    "ruby-macho": "7.0.0",
    "sorbet-runtime": "0.6.13497",
}
TAP = "local/polaris-release-acceptance"
FORMULA = f"{TAP}/polaris"
MAX_FILE = 1_000_000_000
MAX_GEM = 50_000_000
MAX_LOG = 8_000_000
POLICIES = {
    "HOMEBREW_ALLOWED_TAPS", "HOMEBREW_FORBIDDEN_TAPS", "HOMEBREW_FORBIDDEN_FORMULAE",
    "HOMEBREW_FORBIDDEN_LICENSES", "HOMEBREW_FORBID_PACKAGES_FROM_PATHS",
    "HOMEBREW_DISABLE_LOAD_FORMULA", "HOMEBREW_VERIFY_ATTESTATIONS",
}
HOST_PATHS = {"HOMEBREW_PREFIX", "HOMEBREW_CELLAR", "HOMEBREW_REPOSITORY"}
DIRECTORIES = (
    "home", "config", "cache", "logs", "tmp", "results", "downloads",
    "stages", "fixture", "empty-git-template",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def safe_path(path: Path) -> Path:
    require(path.is_absolute() and ".." not in path.parts
            and not any(char in str(path) for char in "\0\r\n"), "Use an absolute, unambiguous path.")
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            "Refusing a source/destination symlink.")
    return path


def private_directory(path: Path) -> Path:
    safe_path(path)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0, "Workspace directories must be private and owned.")
    return path


def system_temporary_directory() -> Path:
    result = subprocess.run(
        ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        capture_output=True, text=True, timeout=5, check=True,
    )
    path = Path(result.stdout.strip())
    require(path.is_absolute(), "The OS did not supply an absolute temporary directory.")
    return private_directory(path.resolve(strict=True))


def has_git_ancestor(path: Path) -> bool:
    return any(os.path.lexists(parent / ".git") for parent in (path, *path.parents))


def directory_identity(path: Path) -> dict[str, Any]:
    info = private_directory(path).stat()
    require(stat.S_IMODE(info.st_mode) == 0o700, "Test temp must retain mode 0700.")
    return {"path": str(path), "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode),
            "device": info.st_dev, "inode": info.st_ino}


def file_pin(path: Path, *, limit: int = MAX_FILE) -> dict[str, Any]:
    safe_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                "Expected a bounded regular file.")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "File changed during inspection.")
    return {"sha256": digest, "bytes": before.st_size, "mode": stat.S_IMODE(before.st_mode)}


def verify_pin(path: Path, expected: str, *, limit: int = MAX_FILE) -> dict[str, Any]:
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "An exact SHA256 is required.")
    observed = file_pin(path, limit=limit)
    require(observed["sha256"] == expected, "Input does not match its approved SHA256.")
    return observed


@contextmanager
def download_deadline(seconds: float = 60) -> Iterator[None]:
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            "An existing alarm prevents bounded prerequisite download.")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(*_args: Any) -> NoReturn:
        raise TimeoutError("Prerequisite download exceeded its time bound.")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def write_new(path: Path, content: bytes) -> None:
    safe_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def write_json(path: Path, value: Any) -> None:
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def read_json(path: Path) -> Any:
    file_pin(path, limit=8_000_000)
    return json.loads(path.read_bytes())


def locked_gems(content: bytes, *, expected_hash: str = LOCK_SHA256) -> list[dict[str, str]]:
    require(hashlib.sha256(content).hexdigest() == expected_hash, "Homebrew lockfile changed.")
    text = content.decode()
    require("  remote: https://rubygems.org/\n" in text, "Unexpected gem source.")
    pins = {
        (match[1], match[2]): match[3]
        for match in re.finditer(r"^  ([\w-]+) \(([^)]+)\) sha256=([a-f0-9]{64})$", text, re.M)
    }
    result = []
    for name, version in sorted(GEM_VERSIONS.items()):
        require(f"    {name} ({version})\n" in text and (name, version) in pins,
                "The required locked gem graph is incomplete.")
        filename = f"{name}-{version}.gem"
        result.append({"name": name, "version": version, "filename": filename,
                       "sha256": pins[name, version],
                       "url": f"https://rubygems.org/downloads/{filename}"})
    return result


def tree_inventory(root: Path) -> dict[str, Any]:
    """Hash regular files without following links; permit only contained runtime links."""
    safe_path(root)
    require(root.is_dir(), "Inventory root must exist.")
    inventory = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(folder) / name
            info = path.lstat()
            relative = str(path.relative_to(root))
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                require(path.resolve(strict=True).is_relative_to(root),
                        "Runtime link escapes its inventory root.")
                inventory[relative] = {"link": target, "mode": stat.S_IMODE(info.st_mode)}
            elif stat.S_ISDIR(info.st_mode):
                inventory[relative] = {"directory": True, "mode": stat.S_IMODE(info.st_mode)}
            else:
                inventory[relative] = file_pin(path)
    return inventory


def ensure_unconfined() -> None:
    require(platform.system() == "Darwin" and platform.machine() == "arm64",
            "Native acceptance requires an Apple Silicon Mac.")
    check = ctypes.CDLL(None).sandbox_check
    check.restype = ctypes.c_int
    check.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    require(check(os.getpid(), None, 0) == 0,
            "Already sandboxed; do not bypass Homebrew's or the analyzer's sandbox.")


def process_table() -> dict[int, tuple[int, str]]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,lstart="], env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        capture_output=True, text=True, timeout=5, check=True,
    )
    table = {}
    for line in result.stdout.splitlines():
        pieces = line.split(None, 2)
        if len(pieces) == 3:
            table[int(pieces[0])] = (int(pieces[1]), pieces[2])
    return table


def track_descendants(pid: int, known: dict[int, tuple[int, str]]) -> None:
    current = process_table()
    if pid in current and pid not in known:
        known[pid] = current[pid]
    changed = True
    while changed:
        changed = False
        for child, identity in current.items():
            parent = identity[0]
            if (child not in known and parent in known and parent in current
                    and current[parent][1] == known[parent][1]):
                known[child] = identity
                changed = True


def stop_process(process: subprocess.Popen[bytes], known: dict[int, tuple[int, str]]) -> None:
    track_descendants(process.pid, known)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        current = process_table()
        for pid, identity in known.items():
            if pid in current and current[pid][1] == identity[1]:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        time.sleep(0.2)
    process.wait(timeout=10)


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = safe_path(root)
        self.prefix = root / "prefix"
        self.library = self.prefix / "Library/Homebrew"
        self.ruby_root = self.library / f"vendor/portable-ruby/{RUBY_VERSION}"
        self.ruby = self.ruby_root / "bin/ruby"
        self.brew = self.prefix / "bin/brew"
        self.tap_formula = self.prefix / f"Library/Taps/{TAP.replace('/', '/homebrew-')}/Formula/polaris.rb"

    def check(self) -> None:
        private_directory(self.root)
        marker = read_json(self.root / "workspace.json")
        external_temp = marker.pop("externalTestTemp", None)
        require(marker == {"format": "polaris.homebrew-workspace/1",
                           "root": str(self.root), "prefix": str(self.prefix),
                           "uid": os.getuid(), "homebrew_revision": HOMEBREW_REVISION},
                "Workspace marker or expected prefix does not match.")
        if external_temp is not None:
            self.verify_external_temp(external_temp)
        for relative in ("", "bin", "Cellar", "opt", "var", "var/homebrew", "var/homebrew/linked",
                         "Library", "Library/Homebrew",
                         "Library/Taps", "Library/Taps/local"):
            safe_path(self.prefix / relative)
        for name in DIRECTORIES:
            private_directory(self.root / name)

    def verify_external_temp(self, record: dict[str, Any]) -> Path:
        path = safe_path(Path(record["identity"]["path"]))
        require(path.parent == system_temporary_directory()
                and re.fullmatch(r"polaris-homebrew-test-[a-z0-9_]+", path.name) is not None
                and not has_git_ancestor(path), "External test temp must remain outside Git checkouts.")
        require(record["identity"] == directory_identity(path), "External test temp identity changed.")
        marker = path / ".polaris-homebrew-test-workspace.json"
        verify_pin(marker, record["markerSha256"], limit=8_000)
        require(read_json(marker) == {"format": "polaris.homebrew-test-temp/1",
                                     "workspace": str(self.root), "prefix": str(self.prefix),
                                     "identity": record["identity"]},
                "External test temp belongs to another workspace.")
        return path

    def isolate_test_temp(self) -> None:
        ensure_unconfined()
        self.check()
        marker_path = self.root / "workspace.json"
        old_pin = file_pin(marker_path)
        marker = read_json(marker_path)
        require("externalTestTemp" not in marker, "An external test temp is already bound.")
        parent = system_temporary_directory()
        require(not has_git_ancestor(parent), "The system temporary directory is inside a Git checkout.")
        path = Path(tempfile.mkdtemp(prefix="polaris-homebrew-test-", dir=parent))
        identity = directory_identity(path)
        ownership = path / ".polaris-homebrew-test-workspace.json"
        write_json(ownership, {"format": "polaris.homebrew-test-temp/1",
                              "workspace": str(self.root), "prefix": str(self.prefix),
                              "identity": identity})
        marker["externalTestTemp"] = {"identity": identity,
                                     "markerSha256": file_pin(ownership)["sha256"]}
        stamp = time.time_ns()
        write_json(self.root / f"test-temp-binding-{stamp}.json", {
            "previousMarker": read_json(marker_path), "newMarker": marker,
            "reason": "Keep Homebrew test fixtures outside enclosing source repositories.",
            "changedEnvironmentKeys": ["HOMEBREW_TEMP", "TMPDIR"],
            "freshMkdtemp": True, "customPrefixMechanicsOnly": True,
        })
        pending = self.root / f"workspace-next-{stamp}.json"
        write_json(pending, marker)
        require(file_pin(marker_path) == old_pin, "Workspace marker changed while binding test temp.")
        pending.replace(marker_path)
        self.check()

    def environment(self) -> dict[str, str]:
        self.check()
        require(os.getuid() != 0, "Root execution is forbidden.")
        require(not {key for key in os.environ if key.startswith("HOMEBREW_")
                     and key not in POLICIES | HOST_PATHS}, "Review inherited Homebrew settings first.")
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        policies = [Path("/etc/homebrew/brew.env"), Path("/opt/homebrew/etc/homebrew/brew.env"),
                    home / ".homebrew/brew.env"]
        if os.environ.get("XDG_CONFIG_HOME"):
            policies.append(Path(os.environ["XDG_CONFIG_HOME"]) / "homebrew/brew.env")
        require(not any(path.exists() for path in policies),
                "A host brew.env policy must be reviewed, not silently omitted.")
        user = pwd.getpwuid(os.getuid()).pw_name
        env = {
            "HOME": str(self.root / "home"), "USER": user, "LOGNAME": user, "SHELL": "/bin/sh",
            "PATH": f"{self.prefix}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "TERM": "dumb", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
            "TMPDIR": str(self.root / "tmp"), "TMP": str(self.root / "tmp"),
            "TEMP": str(self.root / "tmp"),
            "XDG_CONFIG_HOME": str(self.root / "config"), "XDG_CACHE_HOME": str(self.root / "cache"),
            "XDG_DATA_HOME": str(self.root / "data"), "XDG_STATE_HOME": str(self.root / "state"),
            "HOMEBREW_CACHE": str(self.root / "cache/homebrew"),
            "HOMEBREW_LOGS": str(self.root / "logs/homebrew"),
            "HOMEBREW_TEMP": str(self.root / "tmp"),
            "HOMEBREW_BUNDLE_USER_CACHE": str(self.root / "cache/bundle"),
            "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1",
            "HOMEBREW_NO_INSTALL_CLEANUP": "1", "HOMEBREW_NO_AUTOREMOVE": "1",
            "HOMEBREW_NO_GITHUB_API": "1", "HOMEBREW_NO_BOOTSNAP": "1", "HOMEBREW_NO_EMOJI": "1",
            "HOMEBREW_CURL_RETRIES": "0", "HOMEBREW_CURLRC": str(self.root / "curlrc"),
            "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_CONFIG_GLOBAL": str(self.root / "gitconfig"),
            "GIT_TEMPLATE_DIR": str(self.root / "empty-git-template"),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            "UV_OFFLINE": "1", "UV_NO_CONFIG": "1", "UV_PYTHON_DOWNLOADS": "never",
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "BUNDLE_DISABLE_VERSION_CHECK": "true", "BUNDLE_RETRY": "0", "BUNDLE_TIMEOUT": "5",
        }
        external_temp = read_json(self.root / "workspace.json").get("externalTestTemp")
        if external_temp is not None:
            temporary = self.verify_external_temp(external_temp)
            env.update({"HOMEBREW_TEMP": str(temporary), "TMPDIR": str(temporary)})
        env.update({key: value for key, value in os.environ.items() if key in POLICIES})
        return env

    def run(self, label: str, command: list[str], *, timeout: float = 120,
            accepted: tuple[int, ...] = (0,), env: dict[str, str] | None = None,
            cwd: Path | None = None) -> tuple[str, Path]:
        self.check()
        require(re.fullmatch(r"[a-z0-9-]+", label) is not None, "Invalid evidence label.")
        directory = self.root / "results" / f"{time.time_ns()}-{label}"
        directory.mkdir(mode=0o700)
        started = time.monotonic()
        process = subprocess.Popen(
            command, env=self.environment() if env is None else env, cwd=cwd or self.root,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        known: dict[int, tuple[int, str]] = {}
        selector = selectors.DefaultSelector()
        require(process.stdout is not None and process.stderr is not None, "Missing process pipes.")
        streams = {}
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            assert pipe is not None
            os.set_blocking(pipe.fileno(), False)
            streams[name] = (directory / f"{name}.log").open("xb")
            selector.register(pipe, selectors.EVENT_READ, name)
        total = 0
        snapshot = 0.0
        error = None
        try:
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now >= snapshot:
                    track_descendants(process.pid, known)
                    snapshot = now + 0.25
                require(now - started < timeout, "Command exceeded its time bound.")
                for key, _ in selector.select(timeout=0.05):
                    pipe = cast(BinaryIO, key.fileobj)
                    chunk = os.read(pipe.fileno(), 65536)
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        continue
                    total += len(chunk)
                    require(total <= MAX_LOG, "Command exceeded its output bound.")
                    streams[key.data].write(chunk)
            process.wait(timeout=5)
        except BaseException as exc:
            error = type(exc).__name__
            stop_process(process, known)
            raise
        finally:
            selector.close()
            for stream in streams.values():
                stream.close()
            write_json(directory / "command.json", {
                "command": command, "cwd": str(cwd or self.root), "returncode": process.returncode,
                "seconds": round(time.monotonic() - started, 3), "error": error,
                "customPrefixMechanicsOnly": True,
            })
        print(json.dumps({"phase": label, "returncode": process.returncode, "evidence": str(directory)}))
        require(process.returncode in accepted, "Command failed; inspect its captured evidence.")
        return (directory / "stdout.log").read_text(errors="replace"), directory

    def brew_run(self, label: str, *args: str, timeout: float = 120) -> tuple[str, Path]:
        self.verify_homebrew()
        return self.run(label, [str(self.brew), *args], timeout=timeout)

    def verify_homebrew(self) -> None:
        self.check()
        safe_path(self.brew)
        safe_path(self.prefix / ".git")
        require((self.prefix / ".git").is_dir(), "An independent Homebrew repository is required.")
        environment = self.environment()
        environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                            "GIT_NO_LAZY_FETCH": "1"})
        git = ["/usr/bin/git", "--no-pager", "-c", "core.fsmonitor=false", "-C", str(self.prefix)]
        revision = subprocess.run([*git, "rev-parse", "HEAD"], env=environment,
                                  capture_output=True, text=True, timeout=15, check=True)
        require(revision.stdout.strip() == HOMEBREW_REVISION, "Isolated Homebrew revision changed.")
        subprocess.run([*git, "diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--"],
                       env=environment, capture_output=True, timeout=15, check=True)
        verify_pin(self.library / "Gemfile.lock", LOCK_SHA256)
        verify_pin(self.library / "Gemfile", GEMFILE_SHA256)
        verify_pin(self.library / "api/homebrew-1.pem", PUBLIC_KEY_SHA256)
        current = self.library / "vendor/portable-ruby/current"
        require(current.is_symlink() and os.readlink(current) == RUBY_VERSION,
                "Portable Ruby current must be the owned relative version link.")
        require(current.resolve() == self.ruby_root and self.ruby.is_file(),
                "Portable Ruby escaped the isolated prefix.")
        require(not (self.prefix / ".git/objects/info/alternates").exists(),
                "Shared Git alternates are forbidden.")
        inputs = self.root / "prerequisite-inputs.json"
        if inputs.exists():
            envelope = read_json(inputs)["apiEnvelope"]
            copy = Path(envelope["copy"])
            require(copy.parent == self.root / "cache/homebrew/api/internal",
                    "Signed metadata copy escaped its cache.")
            verify_pin(copy, envelope["sha256"], limit=100_000_000)

    def init(self, source: Path, envelope: Path, envelope_sha256: str) -> None:
        ensure_unconfined()
        safe_path(source)
        require(source.is_dir() and not self.root.exists()
                and not self.root.is_relative_to(source) and not source.is_relative_to(self.root),
                "Initialization requires a new workspace separate from its trusted source.")
        private_directory(self.root.parent)
        source_library = source / "Library/Homebrew"
        verify_pin(source_library / "Gemfile.lock", LOCK_SHA256)
        verify_pin(source_library / "Gemfile", GEMFILE_SHA256)
        verify_pin(source_library / "api/homebrew-1.pem", PUBLIC_KEY_SHA256)
        envelope_pin = verify_pin(envelope, envelope_sha256, limit=100_000_000)
        require(re.fullmatch(r"packages\.arm64_[a-z0-9]+\.jws\.json", envelope.name) is not None,
                "Use the official signed Apple Silicon packages envelope.")
        require(not (source / ".git/objects/info/alternates").exists(), "Source uses shared Git objects.")
        ruby_source = source_library / f"vendor/portable-ruby/{RUBY_VERSION}"
        ruby_inventory = tree_inventory(ruby_source)
        require(not any("link" in item for item in ruby_inventory.values()),
                "Portable Ruby copy must not traverse source links.")
        self.root.mkdir(mode=0o700)
        for name in DIRECTORIES:
            (self.root / name).mkdir(mode=0o700)
        write_json(self.root / "workspace.json", {
            "format": "polaris.homebrew-workspace/1", "root": str(self.root),
            "prefix": str(self.prefix), "uid": os.getuid(), "homebrew_revision": HOMEBREW_REVISION,
        })
        write_new(self.root / "curlrc", b'proto = "=file"\nproto-redir = "=file"\n')
        write_new(self.root / "gitconfig", b"[protocol]\n\tallow = never\n[protocol \"file\"]\n\tallow = always\n[credential]\n\thelper =\n[core]\n\thooksPath = /dev/null\n\tfsmonitor = false\n")
        output, _ = self.run("source-revision", ["/usr/bin/git", "-C", str(source), "--no-pager",
                                                 "rev-parse", "HEAD"])
        require(output.strip() == HOMEBREW_REVISION, "Trusted Homebrew revision changed.")
        self.run("source-clean", ["/usr/bin/git", "-c", "core.fsmonitor=false", "-C", str(source),
                                  "--no-pager", "diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--"])
        self.run("clone-homebrew", ["/usr/bin/git", "--no-pager", "clone", "--no-local", "--no-hardlinks",
                                    f"--template={self.root / 'empty-git-template'}", str(source), str(self.prefix)],
                 timeout=300)
        output, _ = self.run("isolated-revision", ["/usr/bin/git", "-C", str(self.prefix),
                                                   "--no-pager", "rev-parse", "HEAD"])
        require(output.strip() == HOMEBREW_REVISION, "Copied Homebrew revision does not match.")
        shutil.copytree(ruby_source, self.ruby_root, symlinks=False)
        require(tree_inventory(self.ruby_root) == ruby_inventory, "Portable Ruby copy changed.")
        (self.ruby_root.parent / "current").symlink_to(RUBY_VERSION)
        cache = self.root / "cache/homebrew/api/internal"
        cache.mkdir(mode=0o700, parents=True)
        write_new(cache / envelope.name, envelope.read_bytes())
        verify_pin(cache / envelope.name, envelope_sha256)
        write_json(self.root / "prerequisite-inputs.json", {
            "source": str(source), "homebrewRevision": HOMEBREW_REVISION,
            "lockSha256": LOCK_SHA256, "portableRuby": RUBY_VERSION,
            "rubyInventory": ruby_inventory, "apiEnvelope": {"source": str(envelope),
                "copy": str(cache / envelope.name), **envelope_pin},
            "metadataMode": "normal-api-with-signed-isolated-cache",
            "previousMetadataMode": "no-api",
        })
        self.verify_homebrew()

    def gems(self) -> list[dict[str, str]]:
        self.verify_homebrew()
        return locked_gems((self.library / "Gemfile.lock").read_bytes())

    def fetch_gems(self) -> None:
        pins = self.gems()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        for pin in pins:
            target = self.root / "downloads" / pin["filename"]
            if target.exists() or target.is_symlink():
                verify_pin(target, pin["sha256"], limit=MAX_GEM)
                continue
            request = urllib.request.Request(pin["url"], headers={"User-Agent": "Polaris-release-prerequisites/1"})
            with download_deadline(), opener.open(request, timeout=30) as response:
                require(response.status == 200 and response.geturl() == pin["url"],
                        "Prerequisite download redirected or failed.")
                content = response.read(MAX_GEM + 1)
            require(0 < len(content) <= MAX_GEM
                    and hashlib.sha256(content).hexdigest() == pin["sha256"],
                    "Official gem archive does not match the frozen lock.")
            write_new(target, content)
            print(json.dumps({"downloaded": pin["filename"], "sha256": pin["sha256"]}))
        record = self.root / "gems-verified.json"
        if not record.exists():
            write_json(record, {"format": "polaris.homebrew-gem-inputs/1",
                                "lockSha256": LOCK_SHA256, "gems": pins})

    def provision(self) -> None:
        ensure_unconfined()
        pins = self.gems()
        cache = self.library / "vendor/cache"
        safe_path(cache)
        cache.mkdir(mode=0o700, exist_ok=True)
        for pin in pins:
            source = self.root / "downloads" / pin["filename"]
            verify_pin(source, pin["sha256"], limit=MAX_GEM)
            target = cache / pin["filename"]
            if not target.exists():
                write_new(target, source.read_bytes())
            verify_pin(target, pin["sha256"], limit=MAX_GEM)
        env = self.environment()
        gem_home = self.library / f"vendor/bundle/ruby/{RUBY_ABI}"
        env.update({
            "PATH": f"{self.ruby_root}/bin:{env['PATH']}", "GEM_HOME": str(gem_home),
            "GEM_PATH": str(gem_home), "GEM_SPEC_CACHE": str(self.root / "cache/gem-spec"),
            "BUNDLE_GEMFILE": str(self.library / "Gemfile"),
            "BUNDLE_WITH": "formula_test", "BUNDLE_FROZEN": "true",
            "BUNDLE_PATH": str(self.library / "vendor/bundle"),
            "BUNDLE_USER_CACHE": str(self.root / "cache/bundle"),
            "BUNDLE_DISABLE_SHARED_GEMS": "true",
        })
        network_denial = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"]
        self.run("bundle-install-local", [*network_denial, str(self.ruby),
                                           str(self.ruby_root / "bin/bundle"), "install", "--local"],
                 timeout=600, env=env, cwd=self.library)
        self.verify_homebrew()
        self.run("normal-homebrew-gem-setup", [*network_denial, str(self.brew),
                                               "install-bundler-gems", "--add-groups=formula_test"],
                 timeout=180)
        self.verify_gems()
        self.verify_paths()
        output, metadata_evidence = self.brew_run(
            "signed-api-verification", "ruby", "-e",
            'require "json"; require "api"; puts JSON.generate({'
            '"mode" => Homebrew::EnvConfig.no_install_from_api? ? "no-api" : "normal-api",'
            '"formula_count" => Homebrew::API::Internal.formula_names.length,'
            '"core_head" => Homebrew::API::Internal.formula_tap_git_head})',
        )
        metadata = json.loads(output)
        require(metadata["mode"] == "normal-api" and metadata["formula_count"] > 1000,
                "Normal signed API metadata was not loaded.")
        write_json(self.root / f"provisioned-{time.time_ns()}.json", {
            "gems": pins, "normalHomebrewGemSetupPassed": True,
            "api": metadata, "apiEvidence": str(metadata_evidence),
            "metadataModeChangedFromNoAPI": True, "prerequisiteNetworkDeniedBySandbox": True,
        })

    def verify_gems(self) -> None:
        for pin in self.gems():
            home = self.library / f"vendor/bundle/ruby/{RUBY_ABI}"
            verify_pin(home / "cache" / pin["filename"], pin["sha256"], limit=MAX_GEM)
            file_pin(home / "specifications" / f"{pin['name']}-{pin['version']}.gemspec")
            require((home / "gems" / f"{pin['name']}-{pin['version']}" / "lib").is_dir(),
                    "A required installed gem is incomplete.")
        groups = self.library / "vendor/bundle/ruby/.homebrew_gem_groups"
        require(groups.read_text().splitlines() == ["formula_test"],
                "Unexpected optional gem groups were installed.")

    def verify_paths(self) -> None:
        for flag, path in (("--prefix", self.prefix), ("--cellar", self.prefix / "Cellar"),
                           ("--repository", self.prefix), ("--cache", self.root / "cache/homebrew"),
                           ("--caskroom", self.prefix / "Caskroom")):
            output, _ = self.brew_run(flag[2:], flag)
            require(Path(output.strip()) == path, "Effective Homebrew path escaped isolation.")
        output, _ = self.brew_run(
            "policy-check", "ruby", "-e",
            'require "json"; require "sandbox"; require "trust"; puts JSON.generate({'
            '"ruby" => RbConfig.ruby, "home" => ENV.fetch("HOME"),'
            '"trust" => Homebrew::Trust.trust_file.to_s,'
            '"path_policy" => Homebrew::EnvConfig.forbid_packages_from_paths?,'
            '"trust_required" => !Homebrew::EnvConfig.no_require_tap_trust?,'
            '"sandbox" => Sandbox.available?, "nested" => Sandbox.nested_sandbox?})',
        )
        policy = json.loads(output)
        require(all(Path(policy[key]).resolve().is_relative_to(self.root)
                    for key in ("ruby", "home", "trust")), "Runtime or trust store escaped isolation.")
        require(policy["path_policy"] and policy["trust_required"] and policy["sandbox"]
                and not policy["nested"], "Normal Homebrew safety policy is unavailable.")

    def no_keg(self) -> None:
        require(not os.path.lexists(self.prefix / "Cellar/polaris")
                and self.links_removed(),
                "An isolated keg or command link is still present.")

    def fetch_candidate(self, formula: Path, formula_sha256: str, archive_sha256: str, *,
                        approved_https_url: str, metadata_sha256: str) -> Path:
        self.check()
        self.environment()
        definition = inspect_formula(formula, formula_sha256, archive_sha256,
                                     approved_https_url=approved_https_url, metadata_sha256=metadata_sha256)
        require(definition["mode"] == "https-origin", "Only explicit HTTPS candidates may be acquired.")
        directory = self.root / "downloads" / f"https-{time.time_ns()}"
        directory.mkdir(mode=0o700)
        partial = directory / "archive.partial"
        archive = directory / definition["archive_name"]
        receipt: dict[str, Any] = {
            "format": "polaris.homebrew-https-acquisition/1", "definition": definition, "passed": False,
            "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tlsVerificationRequired": True, "redirectsAllowed": False, "proxiesAllowed": False,
            "quarantineVerified": False, "publicationPerformed": False,
        }
        started = time.monotonic()
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context),
            )
            request = urllib.request.Request(approved_https_url, headers={
                "User-Agent": "Polaris-release-acceptance/1", "Accept-Encoding": "identity",
            })
            with download_deadline(180), opener.open(request, timeout=30) as response:
                require(response.status == 200 and response.geturl() == approved_https_url,
                        "Candidate acquisition redirected or failed.")
                length = response.headers.get("Content-Length")
                require(length is None or length == str(definition["archive_bytes"]),
                        "HTTPS Content-Length differs from its pin.")
                require(response.headers.get("Content-Encoding", "identity") == "identity",
                        "HTTPS content encoding must not transform the archive.")
                descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                total, digest = 0, hashlib.sha256()
                with os.fdopen(descriptor, "wb") as stream:
                    while True:
                        chunk = response.read(min(1_048_576, definition["archive_bytes"] + 1 - total))
                        if not chunk:
                            break
                        total += len(chunk)
                        require(total <= definition["archive_bytes"], "HTTPS archive exceeded its pinned byte bound.")
                        digest.update(chunk)
                        stream.write(chunk)
                require(total == definition["archive_bytes"] and digest.hexdigest() == archive_sha256,
                        "HTTPS archive differs from its pinned size or SHA256.")
            verify_pin(partial, archive_sha256)
            partial.rename(archive)
            candidate = inspect_candidate(formula, formula_sha256, archive_sha256,
                                          approved_https_url=approved_https_url,
                                          metadata_sha256=metadata_sha256, archive=archive)
            require({key: candidate[key] for key in definition} == definition,
                    "Candidate metadata changed during acquisition.")
            receipt.update({"passed": True, "status": 200, "artifact": file_pin(archive)})
        except BaseException as exc:
            receipt["error"] = type(exc).__name__
            raise
        finally:
            receipt["seconds"] = round(time.monotonic() - started, 3)
            write_json(directory / "acquisition.json", receipt)
        print(json.dumps({"httpsReceipt": str(directory / "acquisition.json"),
                          "sha256": file_pin(directory / "acquisition.json")["sha256"]}))
        return directory / "acquisition.json"

    def acquired_candidate(self, receipt_path: Path, definition: dict[str, Any]) -> dict[str, Any]:
        self.check()
        safe_path(receipt_path)
        require(receipt_path.name == "acquisition.json"
                and receipt_path.parent.parent == self.root / "downloads"
                and re.fullmatch(r"https-[0-9]+", receipt_path.parent.name) is not None,
                "HTTPS receipt must belong to this workspace's acquisition directory.")
        private_directory(receipt_path.parent)
        receipt = read_json(receipt_path)
        require(receipt["format"] == "polaris.homebrew-https-acquisition/1" and receipt["passed"] is True
                and receipt["definition"] == definition and receipt["status"] == 200
                and receipt["tlsVerificationRequired"] is True and receipt["redirectsAllowed"] is False
                and receipt["proxiesAllowed"] is False and "error" not in receipt,
                "HTTPS receipt is unsuccessful or belongs to another candidate.")
        archive = receipt_path.parent / definition["archive_name"]
        candidate = inspect_candidate(Path(definition["formula"]), definition["formula_sha256"],
                                      definition["archive_sha256"], approved_https_url=definition["artifact_url"],
                                      metadata_sha256=definition["metadata_sha256"], archive=archive)
        require(file_pin(archive) == receipt["artifact"], "Acquired HTTPS archive changed.")
        return {**candidate, "https_receipt": str(receipt_path),
                "https_receipt_sha256": file_pin(receipt_path)["sha256"]}

    def https_cache(self, candidate: dict[str, Any], *, populate: bool = False) -> None:
        if candidate["mode"] != "https-origin":
            return
        self.check()
        require(safe_path(self.root / "curlrc").read_bytes() == b'proto = "=file"\nproto-redir = "=file"\n',
                "Homebrew transport policy must remain file-only.")
        cache = safe_path(self.root / "cache/homebrew/downloads")
        if populate:
            cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        token = hashlib.sha256(candidate["artifact_url"].encode()).hexdigest()
        target = cache / f"{token}--{candidate['archive_name']}"
        matches = list(cache.glob(f"{token}--*"))
        require(not matches or matches == [target], "Ambiguous preexisting Homebrew download cache.")
        if populate and not os.path.lexists(target):
            source = safe_path(Path(candidate["archive"]))
            verify_pin(source, candidate["archive_sha256"])
            pending = cache / f".candidate-{time.time_ns()}.partial"
            descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
                remaining = candidate["archive_bytes"]
                while remaining:
                    chunk = incoming.read(min(1_048_576, remaining))
                    require(bool(chunk), "Acquired archive was truncated while caching.")
                    outgoing.write(chunk)
                    remaining -= len(chunk)
                require(not incoming.read(1), "Acquired archive grew while caching.")
            verify_pin(pending, candidate["archive_sha256"])
            pending.rename(target)
        observed = verify_pin(target, candidate["archive_sha256"])
        require(observed["bytes"] == candidate["archive_bytes"], "Homebrew cache size changed.")
        if populate:
            output, evidence = self.brew_run("https-cache-binding", "--cache", "--formula", FORMULA)
            require(output.strip() == str(target), "Homebrew selected a different download cache.")
            write_json(Path(candidate["stage"]) / "https-cache.json", {
                "archive": str(target), **observed, "url": candidate["artifact_url"],
                "formulaUnmodified": True, "homebrewTransport": "file-only", "evidence": str(evidence),
                "quarantineVerified": False, "publicDeliveryVerified": False,
            })

    def stage(self, formula: Path, formula_sha256: str, archive_sha256: str, *,
              approved_https_url: str | None = None, metadata_sha256: str | None = None,
              https_receipt: Path | None = None, upgrading: bool = False) -> None:
        self.verify_homebrew()
        self.verify_gems()
        definition = inspect_formula(formula, formula_sha256, archive_sha256,
                                     approved_https_url=approved_https_url, metadata_sha256=metadata_sha256)
        if definition["mode"] == "https-origin":
            require(https_receipt is not None, "HTTPS staging requires a separate successful acquisition.")
            assert https_receipt is not None
            candidate = self.acquired_candidate(https_receipt, definition)
        else:
            require(https_receipt is None, "Local candidates cannot claim HTTPS acquisition.")
            candidate = inspect_candidate(formula, formula_sha256, archive_sha256,
                                          metadata_sha256=metadata_sha256)
        previous = None
        if upgrading:
            previous = self.staged()
            require("upgradeFrom" not in previous, "Use a fresh workspace for another upgrade pair.")
            require(version_tuple(candidate["version"]) > version_tuple(previous["version"]),
                    "Upgrade requires a strictly newer candidate version.")
            self.owned_keg(previous)
            require(self.installed_versions() == [previous["version"]],
                    "Upgrade requires exactly the authenticated previous keg.")
        else:
            self.no_keg()
        if not self.tap_formula.parent.parent.exists():
            self.brew_run("tap-new", "tap-new", "--no-git", TAP)
        stage = self.root / "stages" / f"{time.time_ns()}-{formula_sha256[:12]}"
        stage.mkdir(mode=0o700)
        candidate["stage"] = str(stage)
        if previous is not None:
            snapshot = stage / "previous-runtime.json"
            write_json(snapshot, self.runtime_snapshot(previous))
            candidate["upgradeFrom"] = {"candidate": previous, "snapshotSha256": file_pin(snapshot)["sha256"]}
        write_json(stage / "candidate.json", candidate)
        if self.tap_formula.exists():
            old = self.staged()
            self.tap_formula.rename(Path(old["stage"]) / f"retired-tap-formula-{time.time_ns()}.rb")
        write_new(self.tap_formula, formula.read_bytes())
        self.brew_run("trust-formula", "trust", "--formula", FORMULA)
        self.https_cache(candidate, populate=True)
        pending = self.root / f"state-{time.time_ns()}.json"
        write_json(pending, candidate)
        current = self.root / "staged.json"
        if current.exists():
            file_pin(current)
        pending.replace(current)
        self.staged()
        self.fixture(create=not (self.root / "preservation.json").exists())

    def reinspect_candidate(self, candidate: dict[str, Any]) -> None:
        https = candidate["mode"] == "https-origin"
        definition = inspect_formula(Path(candidate["formula"]), candidate["formula_sha256"],
                                     candidate["archive_sha256"],
                                     approved_https_url=candidate["artifact_url"] if https else None,
                                     metadata_sha256=candidate["metadata_sha256"])
        if https:
            receipt = Path(candidate["https_receipt"])
            verify_pin(receipt, candidate["https_receipt_sha256"], limit=8_000_000)
            observed = self.acquired_candidate(receipt, definition)
        else:
            observed = inspect_candidate(Path(candidate["formula"]), candidate["formula_sha256"],
                                         candidate["archive_sha256"], metadata_sha256=candidate["metadata_sha256"])
        require(all(candidate[key] == value for key, value in observed.items()), "Staged candidate changed.")

    def staged(self) -> dict[str, Any]:
        self.check()
        candidate: dict[str, Any] = read_json(self.root / "staged.json")
        stage = safe_path(Path(candidate["stage"]))
        require(stage.parent == self.root / "stages", "Candidate stage escaped its workspace.")
        require(read_json(stage / "candidate.json") == candidate, "Candidate state differs from its frozen stage.")
        self.reinspect_candidate(candidate)
        verify_pin(self.tap_formula, candidate["formula_sha256"])
        self.https_cache(candidate)
        return candidate

    def links_removed(self) -> bool:
        return not any(os.path.lexists(self.prefix / relative) for relative in (
            "bin/polaris", "bin/theo", "opt/polaris", "var/homebrew/linked/polaris",
        ))

    def installed_versions(self) -> list[str]:
        rack = safe_path(self.prefix / "Cellar/polaris")
        if not rack.exists():
            return []
        versions = []
        for path in rack.iterdir():
            safe_path(path)
            require(path.is_dir(), "Unexpected entry in the owned Polaris rack.")
            version_tuple(path.name)
            versions.append(path.name)
        return sorted(versions, key=version_tuple)

    def owned_keg(self, candidate: dict[str, Any], *, linked: bool = True) -> Path:
        version_tuple(candidate["version"])
        keg = safe_path(self.prefix / "Cellar/polaris" / candidate["version"])
        require(keg.is_dir(), "Expected the authenticated installed candidate keg.")
        verify_pin(keg / ".brew/polaris.rb", candidate["formula_sha256"], limit=1_000_000)
        verify_pin(keg / "libexec/manifest.json", candidate["manifest_sha256"], limit=8_000_000)
        receipt = read_json(keg / "libexec/install-receipt.json")
        require(receipt["manager"] == "homebrew" and receipt["status"] == "installed"
                and receipt["version"] == candidate["version"] and receipt["release"] == candidate["release"]
                and receipt["manifest_sha256"] == candidate["manifest_sha256"]
                and receipt["packageValidated"] is True, "Installed candidate ownership differs from its pins.")
        for name in ("polaris", "theo"):
            file_pin(keg / "bin" / name, limit=1_000_000)
        if linked:
            targets = {"bin/polaris": keg / "bin/polaris", "bin/theo": keg / "bin/theo",
                       "opt/polaris": keg, "var/homebrew/linked/polaris": keg}
            for relative, target in targets.items():
                path = self.prefix / relative
                safe_path(path.parent)
                require(path.is_symlink() and path.resolve(strict=True) == target,
                        "An unrelated command or keg link collides with the owned candidate; never force linking.")
        return keg

    def runtime_snapshot(self, candidate: dict[str, Any]) -> dict[str, Any]:
        keg = self.owned_keg(candidate, linked=False)
        return {"runtime": tree_inventory(keg / "libexec"),
                "launchers": {name: file_pin(keg / "bin" / name) for name in ("polaris", "theo")}}

    def retained_previous(self, candidate: dict[str, Any]) -> int | None:
        if "upgradeFrom" not in candidate:
            return None
        record = candidate["upgradeFrom"]
        previous = record["candidate"]
        require("upgradeFrom" not in previous
                and version_tuple(previous["version"]) < version_tuple(candidate["version"]),
                "Upgrade source must be an earlier independently staged candidate.")
        self.reinspect_candidate(previous)
        snapshot = safe_path(Path(candidate["stage"]) / "previous-runtime.json")
        verify_pin(snapshot, record["snapshotSha256"], limit=8_000_000)
        observed = self.runtime_snapshot(previous)
        require(observed == read_json(snapshot), "Previous runtime or launchers changed during upgrade acceptance.")
        return len(observed["runtime"])

    def upgrade(self, candidate: dict[str, Any]) -> None:
        require("upgradeFrom" in candidate, "Genuine upgrade requires an explicitly staged previous candidate.")
        stage = Path(candidate["stage"])
        previous = candidate["upgradeFrom"]["candidate"]
        result: dict[str, Any] = {"phase": "upgrade", "passed": False, "candidate": candidate}
        try:
            self.retained_previous(candidate)
            self.owned_keg(previous)
            require(self.installed_versions() == [previous["version"]],
                    "Upgrade requires exactly one prior keg and no candidate keg.")
            logs = self.root / "logs/homebrew/polaris"
            if logs.is_dir():
                safe_path(logs)
                shutil.copytree(logs, stage / f"build-logs-before-upgrade-{time.time_ns()}")
            _, evidence = self.brew_run("genuine-brew-upgrade", "upgrade", "--formula", FORMULA, timeout=600)
            self.owned_keg(candidate)
            require(self.installed_versions() == [previous["version"], candidate["version"]],
                    "Genuine upgrade must install the new version and retain the previous keg.")
            self.fixture()
            write_json(stage / f"runtime-{time.time_ns()}.json",
                       tree_inventory(self.prefix / "Cellar/polaris" / candidate["version"] / "libexec"))
            result.update({"passed": True, "genuineBrewUpgradePassed": True, "evidence": str(evidence)})
        except BaseException as exc:
            result["error"] = type(exc).__name__
            raise
        finally:
            preserved = False
            try:
                result["previousRuntimeEntries"] = self.retained_previous(candidate)
                preserved = True
            except (OSError, ValueError, KeyError, TypeError) as exc:
                result["preservationError"] = type(exc).__name__
            result.update({"previousRuntimeUnchanged": preserved, "passed": result["passed"] and preserved})
            result["genuineBrewUpgradePassed"] = result["passed"]
            write_json(stage / f"upgrade-{time.time_ns()}.json", result)
            require(preserved, "Previous runtime preservation failed; retain all evidence.")

    def fixture(self, *, create: bool = False) -> None:
        root = self.root / "fixture"
        contents = {
            "app.py": b'import os\n\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n',
            "app.js": b'const cp = require("child_process");\nfunction ping(req) { cp.exec(req.query.command); }\n',
            "unrelated-preservation.fixture": b"Preserve this unrelated fixture.\n",
        }
        for name, content in contents.items():
            path = root / name
            safe_path(path)
            if create:
                write_new(path, content)
            require(path.read_bytes() == content, "Synthetic preservation fixture changed.")
        sentinel = self.root / "home/unrelated-preservation.fixture"
        safe_path(sentinel)
        if create:
            write_new(sentinel, contents["unrelated-preservation.fixture"])
        require(sentinel.read_bytes() == contents["unrelated-preservation.fixture"],
                "Unrelated home fixture changed.")
        if create:
            self.run("fixture-init", ["/usr/bin/git", "--no-pager", "init", "--initial-branch=acceptance",
                                      f"--template={self.root / 'empty-git-template'}", str(root)])
            self.run("fixture-add", ["/usr/bin/git", "-C", str(root), "--no-pager",
                                     "add", "--", "app.py", "app.js"])
            write_json(self.root / "preservation.json", {
                str(path.relative_to(self.root)): file_pin(path)
                for path in [*(root / name for name in contents), sentinel]
            })
        for relative, expected in read_json(self.root / "preservation.json").items():
            path = safe_path(self.root / relative)
            require(path.is_relative_to(self.root) and file_pin(path) == expected,
                    "An unrelated fixture was removed or changed; never recreate it.")
        require((root / ".git").is_dir(), "Fixture repository was removed.")
        safe_path(root / ".git")
        require(not (root / ".git/refs/heads/acceptance").exists(), "Fixture must not contain commits.")

    def review(self, candidate: dict[str, Any]) -> dict[str, Any]:
        self.fixture()
        manifest_path = self.owned_keg(candidate) / "libexec/manifest.json"
        semgrep_identity = expected_semgrep(manifest_path, candidate)
        for name in ("theo", "polaris"):
            executable_path = self.prefix / "bin" / name
            require(executable_path.is_symlink()
                    and executable_path.resolve().is_relative_to(self.prefix / "Cellar/polaris"),
                    "Installed command escaped its keg.")
            output, _ = self.run(f"{name}-version", [str(executable_path), "--version"])
            require(re.search(rf"(?<![0-9.]){re.escape(candidate['version'])}(?![0-9.])", output) is not None,
                    "Wrong installed version.")
        executable = str(self.prefix / "bin/polaris")
        output, _ = self.run("capabilities", [executable, "workflow", "capabilities"])
        capabilities = json.loads(output)
        analyzer = [item for item in capabilities["analyzers"] if item["analyzer_id"] == "semgrep-ce"]
        require(len(analyzer) == 1 and analyzer[0]["availability"] == "available"
                and analyzer[0]["version"] == semgrep_identity["runtimeVersion"]
                and analyzer[0]["distribution_version"] == semgrep_identity["distributionVersion"]
                and analyzer[0]["identity_digest"] == "sha256:" + semgrep_identity["contractSha256"],
                "Real Semgrep identity and runtime probe did not pass.")
        output, evidence = self.run(
            "review", [executable, "workflow", "review", "--root", str(self.root / "fixture"),
                       "--files", "app.py", "app.js", "--format", "json"], timeout=180, accepted=(1,),
        )
        report = json.loads(output)
        validate_review(report)
        return {"evidence": str(evidence), "fresh": True, "complete": True, "filesAnalyzed": 2,
                "findings": len(report["review"]["findings"]), "semgrep": semgrep_identity}

    def lifecycle(self, phase: str) -> None:
        ensure_unconfined()
        self.verify_homebrew()
        self.verify_gems()
        candidate = self.staged()
        stage = Path(candidate["stage"])
        keg = self.prefix / "Cellar/polaris" / candidate["version"]
        self.fixture()
        if phase != "upgrade":
            self.retained_previous(candidate)
        if phase in ("install", "reinstall"):
            if phase == "install":
                self.no_keg()
            else:
                self.owned_keg(candidate)
                logs = self.root / "logs/homebrew/polaris"
                if logs.is_dir():
                    shutil.copytree(logs, stage / f"build-logs-before-reinstall-{time.time_ns()}")
            self.brew_run(phase, phase, "--formula", FORMULA, timeout=300)
            self.owned_keg(candidate)
            write_json(stage / f"runtime-{time.time_ns()}.json", tree_inventory(keg / "libexec"))
        elif phase == "upgrade":
            self.upgrade(candidate)
        elif phase in ("test", "review"):
            before = tree_inventory(keg / "libexec")
            result: dict[str, Any] = {"passed": False, "phase": phase}
            try:
                if phase == "test":
                    _, evidence = self.brew_run("genuine-brew-test", "test", FORMULA, timeout=360)
                    result.update({"evidence": str(evidence), "genuineBrewTestPassed": True})
                else:
                    result.update(self.review(candidate))
                result["passed"] = True
            finally:
                after = tree_inventory(keg / "libexec")
                result.update({"runtimeInventoryUnchanged": before == after, "runtimeEntries": len(after),
                               "candidate": candidate})
                result["passed"] = result["passed"] and before == after
                if "upgradeFrom" in candidate:
                    try:
                        result["previousRuntimeEntries"] = self.retained_previous(candidate)
                        result["previousRuntimeUnchanged"] = True
                    except (OSError, ValueError, KeyError, TypeError):
                        result.update({"passed": False, "previousRuntimeUnchanged": False})
                write_json(stage / f"{phase}-{time.time_ns()}.json", result)
                require(before == after, "Installed runtime changed during acceptance.")
                require(result.get("previousRuntimeUnchanged", True), "Previous runtime changed during acceptance.")
        elif phase == "uninstall":
            self.owned_keg(candidate)
            _, evidence = self.brew_run("uninstall", "uninstall", "--formula", FORMULA, timeout=180)
            require(not os.path.lexists(keg) and self.links_removed(), "Candidate keg or links remain installed.")
            previous_entries = self.retained_previous(candidate)
            if previous_entries is not None:
                require(self.installed_versions() == [candidate["upgradeFrom"]["candidate"]["version"]],
                        "Ordinary uninstall must retain only the previous authenticated keg.")
            else:
                self.no_keg()
            self.fixture()
            write_json(stage / f"uninstall-{time.time_ns()}.json", {
                "returncode": 0, "kegAndLinksRemoved": True, "preservationFixturesUnchanged": True,
                "allKegsRemoved": previous_entries is None,
                "previousRuntimeRetainedUnchanged": previous_entries is not None,
                "previousRuntimeEntries": previous_entries,
                "evidence": str(evidence), "candidate": candidate,
                "metadataMode": "normal-api-with-signed-isolated-cache",
                "customPrefixMechanicsOnly": True, "defaultPrefixVerified": False,
                "cleanAccountVerified": False, "secondMacVerified": False,
            })
        else:
            raise ValueError("Unknown lifecycle phase.")
        self.retained_previous(candidate)
        self.staged()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> NoReturn:
        raise ValueError("Download redirects are forbidden.")


def version_tuple(value: str) -> tuple[int, ...]:
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is not None, "Invalid candidate version.")
    return tuple(int(part) for part in value.split("."))


def exact_https_url(value: str, release: str, archive_name: str) -> str:
    try:
        url = urllib.parse.urlsplit(value)
        require(value.isascii() and not any(char.isspace() or ord(char) < 33 for char in value)
                and "\\" not in value and url.scheme == "https" and url.hostname is not None
                and url.username is None and url.password is None and not url.query and not url.fragment
                and re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", url.netloc) is not None
                and (url.port is None or 0 < url.port <= 65535) and url.geturl() == value
                and url.path == f"/releases/{release}/{archive_name}",
                "Use the exact credential-free approved HTTPS artifact URL.")
    except ValueError:
        raise ValueError("Use the exact credential-free approved HTTPS artifact URL.") from None
    return value


def inspect_formula(formula: Path, formula_sha256: str, archive_sha256: str, *,
                    approved_https_url: str | None = None,
                    metadata_sha256: str | None = None) -> dict[str, Any]:
    formula_pin = verify_pin(formula, formula_sha256, limit=1_000_000)
    require(formula.name == "polaris.rb", "Expected the generated Polaris formula.")
    metadata_path = formula.parent / "homebrew.json"
    metadata_pin = file_pin(metadata_path, limit=1_000_000)
    if metadata_sha256 is not None:
        verify_pin(metadata_path, metadata_sha256, limit=1_000_000)
    metadata = read_json(metadata_path)
    require(metadata["format"] == "polaris.homebrew-release/1"
            and metadata["mode"] in ("local-file", "https-origin") and metadata["availability"] == "unpublished"
            and metadata["publicationPerformed"] is False and metadata["platform"] == "macos-arm64",
            "Expected an explicitly pinned generated Homebrew candidate.")
    version = metadata["version"]
    require(isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
            "Invalid candidate version.")
    release = metadata["release"]
    require(isinstance(release, str)
            and re.fullmatch(rf"theo-{re.escape(version)}-macos-arm64-r[1-9][0-9]*", release) is not None,
            "Invalid immutable candidate identity.")
    artifact = metadata["artifact"]
    require(artifact["name"] == f"{release}-homebrew.tar.gz", "Archive name escaped its release.")
    require(re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is not None
            and artifact["sha256"] == archive_sha256 and type(artifact["bytes"]) is int
            and 0 < artifact["bytes"] <= MAX_FILE, "Candidate archive metadata does not match.")
    url = artifact["url"]
    if metadata["mode"] == "https-origin":
        require(approved_https_url is not None and metadata_sha256 is not None,
                "HTTPS requires explicit URL approval and a metadata SHA256.")
        assert approved_https_url is not None
        require(url == exact_https_url(approved_https_url, release, artifact["name"]),
                "HTTPS artifact URL differs from the exact approval.")
    else:
        require(approved_https_url is None and url == (formula.parent / artifact["name"]).as_uri(),
                "Local candidate URL does not match its archive.")
    require(metadata["formula"]["sha256"] == formula_sha256
            and metadata["formula"]["bytes"] == formula_pin["bytes"],
            "Candidate formula metadata does not match.")
    manifest_sha256 = metadata["manifest"]["sha256"]
    require(re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is not None,
            "Manifest requires an exact digest.")
    text = formula.read_text()
    lines = text.splitlines()
    require("@@" not in text and all(lines.count(line) == 1 for line in (
        f"  url {json.dumps(url)}", f'  sha256 "{archive_sha256}"', f'  version "{version}"',
        f'  THEO_RELEASE = "{release}".freeze',
        f'  THEO_MANIFEST_SHA256 = "{manifest_sha256}".freeze',
    )) and "deny_network_access!" in text, "Formula declarations do not match the approved candidate.")
    require(file_pin(metadata_path, limit=1_000_000) == metadata_pin
            and file_pin(formula, limit=1_000_000) == formula_pin, "Candidate changed during inspection.")
    return {"formula": str(formula), "formula_sha256": formula_sha256, "archive_name": artifact["name"],
            "archive_sha256": archive_sha256, "archive_bytes": artifact["bytes"], "artifact_url": url,
            "manifest_sha256": manifest_sha256, "version": version, "release": release,
            "metadata_sha256": metadata_pin["sha256"], "mode": metadata["mode"]}


def inspect_candidate(formula: Path, formula_sha256: str, archive_sha256: str, *,
                      approved_https_url: str | None = None, metadata_sha256: str | None = None,
                      archive: Path | None = None) -> dict[str, Any]:
    candidate = inspect_formula(formula, formula_sha256, archive_sha256,
                                approved_https_url=approved_https_url, metadata_sha256=metadata_sha256)
    if candidate["mode"] == "local-file":
        require(archive is None, "Local candidate archives cannot be substituted.")
        archive = formula.parent / candidate["archive_name"]
    else:
        require(archive is not None, "HTTPS requires independently acquired candidate bytes.")
    assert archive is not None
    observed = verify_pin(archive, archive_sha256)
    require(observed["bytes"] == candidate["archive_bytes"], "Candidate archive size does not match.")
    return {**candidate, "archive": str(archive)}


def expected_semgrep(manifest_path: Path, candidate: dict[str, Any]) -> dict[str, str]:
    pin = verify_pin(manifest_path, candidate["manifest_sha256"], limit=8_000_000)
    manifest = read_json(manifest_path)
    require(manifest["format"] == "polaris.theo-bundle/1" and manifest["version"] == candidate["version"]
            and manifest["id"] == candidate["release"] and manifest["platform"] == "macos-arm64",
            "Installed manifest differs from the pinned candidate.")
    # Old receipts remain historical; new acceptance requires the current graph.
    spec = importlib.util.spec_from_file_location(
        "acceptance_analyzer_identity", Path(__file__).resolve().parents[1]
        / "src/polaris/review/analyzers/identity.py",
    )
    assert spec and spec.loader
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    identity.validate_manifest(manifest)
    require(manifest["analyzerIdentity"] == identity.manifest_identity()
            and file_pin(manifest_path, limit=8_000_000) == pin,
            "Pinned manifest does not identify the exact downstream Semgrep graph.")
    return cast(dict[str, str], manifest["analyzerIdentity"])


def validate_review(report: dict[str, Any]) -> None:
    require(report["format"] == "polaris.workflow/0.1.0" and report["status"] == "complete"
            and report["snapshot"]["fresh"] is True, "Expected a fresh, complete workflow review.")
    coverage = report["review"]["coverage"]
    require(coverage["complete"] is True and coverage["files_analyzed"] == 2
            and {item["path"] for item in report["changes"]} == {"app.py", "app.js"},
            "Review was empty or omitted a fixture file.")
    for name in ("app.py", "app.js"):
        require(any(item["path"] == name and item["check_id"] == "command_injection"
                    and item["status"] == "checked" for item in coverage["entries"]),
                "Command-injection coverage is missing.")
        require(any(item["path"] == name and item["check_id"] == "command_injection"
                    and item["result"] == "flagged" for item in report["review"]["findings"]),
                "Expected nonempty command-injection findings are missing.")


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("Invalid verifier arguments; use --help and do not supply credentials.")


def main() -> None:
    os.umask(0o077)
    parser = Parser(description=__doc__)
    parser.add_argument("phase", choices=("init", "fetch-gems", "provision", "isolate-test-temp",
                                         "fetch-candidate", "stage", "stage-upgrade", "install", "upgrade",
                                         "test", "review", "reinstall", "uninstall"))
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--homebrew-source", type=Path)
    parser.add_argument("--api-envelope", type=Path)
    parser.add_argument("--api-sha256")
    parser.add_argument("--formula", type=Path)
    parser.add_argument("--formula-sha256")
    parser.add_argument("--archive-sha256")
    parser.add_argument("--metadata-sha256")
    parser.add_argument("--approved-https-url")
    parser.add_argument("--https-receipt", type=Path)
    try:
        args = parser.parse_args()
        workspace = Workspace(args.workspace)
        if args.phase == "init":
            require(args.homebrew_source is not None and args.api_envelope is not None
                    and args.api_sha256 is not None, "Initialization requires pinned trusted inputs.")
            workspace.init(args.homebrew_source, args.api_envelope, args.api_sha256)
        elif args.phase == "fetch-gems":
            workspace.fetch_gems()
        elif args.phase == "provision":
            workspace.provision()
        elif args.phase == "isolate-test-temp":
            workspace.isolate_test_temp()
        elif args.phase in ("stage", "stage-upgrade", "fetch-candidate"):
            require(args.formula is not None and args.formula_sha256 is not None
                    and args.archive_sha256 is not None, "Staging requires explicit candidate pins.")
            if args.phase == "fetch-candidate":
                require(args.approved_https_url is not None and args.metadata_sha256 is not None
                        and args.https_receipt is None, "Acquisition requires explicit HTTPS URL and metadata pins.")
                workspace.fetch_candidate(args.formula, args.formula_sha256, args.archive_sha256,
                                          approved_https_url=args.approved_https_url,
                                          metadata_sha256=args.metadata_sha256)
            else:
                workspace.stage(args.formula, args.formula_sha256, args.archive_sha256,
                                approved_https_url=args.approved_https_url, metadata_sha256=args.metadata_sha256,
                                https_receipt=args.https_receipt, upgrading=args.phase == "stage-upgrade")
        else:
            workspace.lifecycle(args.phase)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit("Homebrew verification blocked/failed; inspect private evidence and input pins.") from None
    print(json.dumps({"phase": args.phase, "passed": True, "customPrefixMechanicsOnly": True}))


if __name__ == "__main__":
    main()

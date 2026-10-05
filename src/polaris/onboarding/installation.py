"""Inspect this interpreter's package installation, never a project-selected receipt."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from polaris import __version__
from polaris.integrations._safe import atomic_write, no_symlinks, read_bytes, trusted_executable
from polaris.onboarding import MINIMUM_MACOS, RELEASE_IDS
from polaris.onboarding.errors import OnboardingProblem
from polaris.review.analyzers.identity import validate_manifest


def _owned(path: Path, *, private: bool = False, root_owned: bool = False) -> None:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or info.st_uid not in ({0, os.getuid()} if root_owned else {os.getuid()})
            or info.st_mode & (0o077 if private else 0o022)):
        raise OnboardingProblem("invalid_installation", "An installed package path has unsafe ownership or permissions.")


def _json(path: Path, *, limit: int = 2_000_000) -> dict[str, Any]:
    raw = read_bytes(path, limit=limit)
    if raw is None:
        raise OnboardingProblem("invalid_installation", "An installation receipt is missing. Reinstall through its original package manager.")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OnboardingProblem("invalid_installation", "An installation receipt is invalid.")
    return value


def managed_installation() -> dict[str, Any]:
    # The already-running interpreter selects its package, never a project or an
    # environment-variable override. Package-manager opt links resolve to the real keg.
    application = Path(sys.prefix).resolve()
    root = application.parent
    receipt_path = root / "install-receipt.json"
    raw = read_bytes(receipt_path, limit=16_384)
    if raw is None:
        return {"status": "unmanaged", "version": __version__, "manager": "python"}
    receipt = json.loads(raw)
    if (not isinstance(receipt, dict) or application.name != "app"
            or not Path(__file__).resolve().is_relative_to(application)
            or receipt.get("format") != "polaris.theo-install/2"
            or receipt.get("release") not in RELEASE_IDS or receipt.get("version") != __version__
            or receipt.get("platform") != "macos-arm64" or receipt.get("status") != "installed"
            or receipt.get("packageValidated") is not True
            or not re.fullmatch(r"[a-f0-9]{64}", str(receipt.get("manifest_sha256", "")))):
        raise OnboardingProblem("invalid_installation", "This interpreter's completion receipt is invalid. Reinstall the matching package.")
    manager = receipt.get("manager")
    if manager == "standalone":
        prefix = root.parent.parent
        if (root.name != receipt["release"] or root.parent.name != "releases"
                or prefix == Path(prefix.anchor)
                or _json(prefix / "owner.json") != {"format": "polaris.theo-prefix/1", "uid": os.getuid()}):
            raise OnboardingProblem("invalid_installation", "The standalone installation ownership does not match.")
        for path in (prefix, root.parent, root, receipt_path, prefix / "owner.json"):
            _owned(path, private=True)
    elif manager == "homebrew":
        keg = root.parent
        if (root.name != "libexec" or not re.fullmatch(re.escape(__version__) + r"(?:_[0-9]+)?", keg.name)
                or keg.parent.name != "polaris" or keg.parent.parent.name != "Cellar"):
            raise OnboardingProblem("invalid_installation", "The Homebrew receipt is outside the matching Polaris keg.")
        for path in (keg.parent.parent, keg.parent, keg, root, receipt_path):
            _owned(path, root_owned=True)
        prefix = keg
    else:
        raise OnboardingProblem("invalid_installation", "The installation package manager is not recognized.")
    no_symlinks(root)
    _owned(application, root_owned=manager == "homebrew")
    manifest_raw = read_bytes(root / "manifest.json", limit=2_000_000)
    if manifest_raw is None or hashlib.sha256(manifest_raw).hexdigest() != receipt["manifest_sha256"]:
        raise OnboardingProblem("invalid_installation", "The installed manifest does not match its completion receipt.")
    _owned(root / "manifest.json", root_owned=manager == "homebrew")
    manifest = json.loads(manifest_raw)
    if (not isinstance(manifest, dict) or manifest.get("format") != "polaris.theo-bundle/1"
            or manifest.get("id") != receipt["release"] or manifest.get("version") != __version__
            or manifest.get("platform") != "macos-arm64"
            or manifest.get("minimumMacOS") != MINIMUM_MACOS):
        raise OnboardingProblem("invalid_installation", "The installed manifest has an incompatible release identity.")
    try:
        validate_manifest(manifest)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise OnboardingProblem(
            "invalid_installation", "The installed analyzer identity does not match this application.",
        ) from None
    return {
        "status": "managed", "manager": manager, "version": __version__, "release": receipt["release"],
        "root": str(root), "prefix": str(prefix), "manifest_sha256": receipt["manifest_sha256"],
        "package_validated": True, "analyzer_install_check": receipt.get("analyzerRuntime", "not_checked"),
        "minimum_macos": MINIMUM_MACOS,
        "host_verified": False,
    }


def analyzer() -> Path | None:
    installation = managed_installation()
    if installation["status"] != "managed":
        return None
    root = Path(installation["root"])
    executable = root / "analyzer" / "bin" / "semgrep"
    for path in (root / "analyzer", executable.parent, executable):
        _owned(path, root_owned=installation["manager"] == "homebrew")
    return trusted_executable(executable)


def tree_inventory(root: Path) -> dict[str, dict[str, Any]]:
    """Fingerprint a bounded owned release without traversing directory symlinks."""
    root = no_symlinks(root)
    result: dict[str, dict[str, Any]] = {}
    for base, directories, files in os.walk(root, followlinks=False):
        # Mutable installer scratch and quarantined interruptions are retained, not adopted
        # as removable files. No package code or analyzer is ever selected from these paths.
        retained = {"installer-home", "tmp", "uv-cache"} if Path(base) == root else set()
        directories[:] = [name for name in directories
                          if name not in retained and not name.startswith(".interrupted-")]
        for name in sorted([*directories, *files]):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            if relative == "uninstall-files.json" or name in retained or name.startswith(".interrupted-"):
                continue
            if len(result) >= 100_000:
                raise OnboardingProblem("installation_changed", "The installation inventory exceeds its bound.")
            info = path.lstat()
            if info.st_uid != os.getuid() or not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
                raise OnboardingProblem("installation_changed", "An installed path has changed ownership or permissions.")
            if stat.S_ISLNK(info.st_mode):
                if not path.resolve().is_relative_to(root) or not path.resolve().exists():
                    raise OnboardingProblem("installation_changed", "An installed link escapes its release.")
                result[relative] = {"kind": "link", "target": os.readlink(path)}
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
            elif stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    if os.fstat(stream.fileno()) != info:
                        raise OnboardingProblem("installation_changed", "An installed file changed during its inventory.")
                    for chunk in iter(lambda: stream.read(1_048_576), b""):
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
                if (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
                ):
                    raise OnboardingProblem("installation_changed", "An installed file changed during its inventory.")
                result[relative] = {
                    "kind": "file", "sha256": digest.hexdigest(),
                    "bytes": info.st_size, "mode": stat.S_IMODE(info.st_mode),
                }
            else:
                raise OnboardingProblem("installation_changed", "An installation contains a special file.")
    return result


def seal_uninstall_inventory() -> None:
    """Called once by the verified installer, after validating the new runtime."""
    installation = managed_installation()
    if installation["status"] != "managed" or installation["manager"] != "standalone":
        raise OnboardingProblem("invalid_installation", "Only a new standalone runtime can seal removal metadata.")
    root = Path(installation["root"])
    path = root / "uninstall-files.json"
    if path.exists() or path.is_symlink():
        raise OnboardingProblem("installation_changed", "Existing removal metadata is never regenerated.")
    value = {"format": "polaris.theo-removal/1", "release": installation["release"],
             "files": tree_inventory(root)}
    atomic_write(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode(),
                 expected=None, check_expected=True)

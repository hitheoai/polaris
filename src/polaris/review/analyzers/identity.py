"""Analyzer identity, separate from its upstream executable version.

Managed assembly binds wheel bytes separately; runtime probing verifies installed
metadata without importing/executing analyzer packages. This is not a hostile-code
sandbox, a full installed-payload integrity check, or security-risk acceptance.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import sys
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

RUNTIME_VERSION = "1.178.0"
DISTRIBUTION_VERSION = "1.178.0+theovex.1"
# The fixed PATH folders the analyzer runs with. On merged-/usr systems (most Linux distributions)
# /bin is a system link to /usr/bin, so each is checked once, at its real location.
SYSTEM_FOLDERS: tuple[Path, ...] = (Path("/usr/bin"), Path("/bin"))
CONTRACT_SHA256 = "d47d50c73ed61f8f62cdeaf48497a52c063c429aa22b37ddfd25f105ae8f975d"
DERIVATIVE_SHA256 = "16605a0435e87dc05020049e99869670d1209599e115819b38364c73ab23dcd9"


def qualified_platform() -> bool:
    # Retaining the Linux sandbox implementation does not qualify a Linux graph.
    return sys.platform == "darwin" and platform.machine() == "arm64"


def _directory(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Analyzer identity requires an absolute non-link installation.")
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read(path: Path, limit: int = 2_000_000) -> bytes:
    parent = _directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("Analyzer metadata is not a bounded regular file.")
            content = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        if (len(content) != before.st_size or any(
            getattr(before, field) != getattr(item, field) for item in (after, current) for field in fields
        )):
            raise ValueError("Analyzer metadata changed during inspection.")
        return content
    finally:
        os.close(parent)


def contract() -> dict[str, Any]:
    content = _read(Path(__file__).absolute().with_name("analyzer-contract.json"))
    if hashlib.sha256(content).hexdigest() != CONTRACT_SHA256:
        raise ValueError("Analyzer contract differs from its reviewed binding.")
    value: dict[str, Any] = json.loads(content)
    return value


def manifest_identity() -> dict[str, str]:
    value = contract()
    return {
        "format": "polaris.analyzer-identity/1", "platform": value["platform"],
        "runtimeVersion": RUNTIME_VERSION, "distributionVersion": DISTRIBUTION_VERSION,
        "upstreamWheelSha256": value["upstreamWheelSha256"],
        "derivativeWheelSha256": DERIVATIVE_SHA256,
        "derivationRecipeSha256": value["derivationRecipeSha256"],
        "contractSha256": CONTRACT_SHA256,
    }


def validate_manifest(manifest: dict[str, Any]) -> None:
    expected = contract()
    environments = manifest.get("environments", {})
    app = environments.get("app", {})
    if (manifest.get("analyzerIdentity") != manifest_identity()
            or environments.get("analyzer") != {
                name: item["version"] for name, item in expected["packages"].items()
            }
            or manifest.get("runtimes", {}).get("python", {}).get("version") != expected["pythonVersion"]
            or "semgrep" in app or app.get("mcp") != "2.2.0" or app.get("tomlkit") != "0.13.3"):
        raise ValueError("Manifest must retain the exact separate app/MCP and analyzer identities.")


def installed_identity(executable: str) -> dict[str, str]:
    """Require the exact isolated graph and metadata; reject duplicates and upstream CE."""
    path = Path(executable)
    if path.name != "semgrep" or path.parent.name != "bin":
        raise ValueError("The qualified analyzer must use its isolated installation entry point.")
    _read(path, 32_768)
    root = path.parent.parent
    configuration = _read(root / "pyvenv.cfg", 16_384).decode("utf-8").splitlines()
    values: dict[str, str] = {}
    for line in configuration:
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in values:
            raise ValueError("Analyzer environment configuration is ambiguous.")
        values[key] = value
    expected = contract()
    versions = [values[key] for key in ("version", "version_info") if key in values]
    if (values.get("include-system-site-packages") != "false"
            or versions != [expected["pythonVersion"]]
            or values.get("implementation", "CPython") != "CPython"):
        raise ValueError("Analyzer interpreter or site isolation differs from the qualified graph.")
    site = root / "lib" / "python3.11" / "site-packages"
    # Upstream's ordinary CE RPC can prefer Pro independently of --oss-only.
    # Cover packaged resources, our fixed PATH and the venv interpreter's folder.
    # This exclusion is not a general installed-payload integrity guarantee.
    folders = [site / "semgrep" / "bin", root / "bin"]
    for system in SYSTEM_FOLDERS:
        real = Path(os.path.realpath(system))
        if real not in folders:
            folders.append(real)
    for folder in folders:
        try:
            descriptor = _directory(folder)
        except FileNotFoundError:
            continue
        try:
            try:
                os.stat("semgrep-core-proprietary", dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("A proprietary analyzer core is outside the managed CE contract.")
        finally:
            os.close(descriptor)
    descriptor = _directory(site)
    directories: set[str] = set()
    deadline = time.monotonic() + 5
    try:
        with os.scandir(descriptor) as iterator:
            for count, entry in enumerate(iterator):
                if count >= 5_000 or time.monotonic() >= deadline:
                    raise ValueError("Analyzer metadata inventory exceeded its bound.")
                if entry.name.endswith(".egg-info"):
                    raise ValueError("Legacy or duplicate analyzer metadata is not qualified.")
                if entry.name.endswith(".dist-info"):
                    if not entry.is_dir(follow_symlinks=False):
                        raise ValueError("Analyzer metadata directory is not a regular directory.")
                    directories.add(entry.name)
    finally:
        os.close(descriptor)
    packages = expected["packages"]
    if directories != {item["metadataDirectory"] for item in packages.values()}:
        raise ValueError("Installed analyzer graph is missing, unexpected, or duplicated.")
    for name, item in packages.items():
        if time.monotonic() >= deadline:
            raise ValueError("Analyzer metadata inspection exceeded its time bound.")
        directory = site / item["metadataDirectory"]
        metadata = _read(directory / "METADATA")
        wheel = _read(directory / "WHEEL")
        if (hashlib.sha256(metadata).hexdigest() != item["metadataSha256"]
                or hashlib.sha256(wheel).hexdigest() != item["wheelMetadataSha256"]):
            raise ValueError("Installed analyzer metadata differs from its inspected wheel.")
        headers = BytesParser(policy=policy.default).parsebytes(metadata)
        names, versions = headers.get_all("Name", []), headers.get_all("Version", [])
        if len(names) != 1 or len(versions) != 1:
            raise ValueError("Installed analyzer identity is ambiguous.")
        if re.sub(r"[-_.]+", "-", str(names[0])).lower() != name or str(versions[0]) != item["version"]:
            raise ValueError("Installed analyzer identity differs from the qualified graph.")
    return manifest_identity()

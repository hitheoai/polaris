"""Shared managed-analyzer assembly validation; never resolve, install or execute wheels."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def identity() -> Any:
    return _load("managed_analyzer_identity", ROOT / "src/polaris/review/analyzers/identity.py")


def qualifier() -> Any:
    return _load("managed_analyzer_wheel_inspector", ROOT / "scripts/qualify_analyzer_dependencies.py")


def requirements_line(name: str, version: str, digest: str, *, component: str) -> str:
    extra = "[mcp]" if name == "theovex-polaris" else "[crypto]" if component == "analyzer" and name == "pyjwt" else ""
    return f"{name}{extra}=={version} --hash=sha256:{digest}"


def validate_manifest(manifest: dict[str, Any]) -> None:
    identity().validate_manifest(manifest)


def validate_wheel(
    content: bytes, *, signed_members: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    inspected: dict[str, Any] = qualifier().inspect_bytes(content)
    pin = identity().contract()["packages"].get(inspected["name"])
    if (pin is None or inspected["version"] != pin["version"]
            or inspected["metadataDirectory"] != pin["metadataDirectory"]):
        raise ValueError("Unqualified analyzer distribution.")
    if inspected["sha256"] == pin["sha256"] and inspected["bytes"] == pin["bytes"]:
        return inspected
    if signed_members is None or not pin["nativeMembers"]:
        raise ValueError("Analyzer wheel differs from its inspected artifact.")
    # The signed r2 may change only the recorded native members and RECORD, with
    # explicit original->signed member bindings. A version label is never enough.
    remaining = []
    for name, item in sorted(inspected["members"].items()):
        if name == pin["metadataDirectory"] + "/RECORD":
            continue
        if name in pin["nativeMembers"]:
            original = pin["nativeMembers"][name]
            transformed = signed_members.get(original["sha256"], {})
            if any(item[key] != transformed.get(key) for key in ("sha256", "bytes")):
                raise ValueError("Signed analyzer member lacks its exact transformation binding.")
        else:
            remaining.append([name, item["sha256"], item["bytes"]])
    if (not set(pin["nativeMembers"]) <= inspected["members"].keys()
            or hashlib.sha256(json.dumps(remaining, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
            != pin["unchangedMembersSha256"]):
        raise ValueError("Signing changed or omitted non-native analyzer payload.")
    return inspected


def validate_wheelhouse(directory: Path) -> tuple[list[Path], dict[str, str]]:
    inspection = qualifier()
    inspection.no_links(directory)
    expected = identity().contract()["packages"]
    files = list(directory.iterdir())
    if len(files) != len(expected) or {path.name for path in files} != {pin["filename"] for pin in expected.values()}:
        raise ValueError("Analyzer wheelhouse must contain the entire exact inspected graph.")
    versions = {}
    for path in sorted(files):
        content = inspection.read_regular(path, inspection.MAX_ARCHIVE_BYTES)
        item = validate_wheel(content)
        if expected[item["name"]]["filename"] != path.name or item["name"] in versions:
            raise ValueError("Analyzer wheel filename or unique identity is inconsistent.")
        versions[item["name"]] = item["version"]
    return sorted(files), versions

"""Build and verify preparation-only third-party source/notice packets.

Both managed delivery formats may embed the same directory and pin the returned
manifestSha256. No networking, archive extraction, installation, signing or
approval occurs here. A valid packet proves its listed bytes and references, not
that declared sources correspond to every compiled member or satisfy a license.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SPEC_FORMAT = "polaris.source-packet-spec/1"
PACKET_FORMAT = "polaris.source-packet/1"
MANIFEST_NAME = "source-packet.json"
MAX_FILES = 20_000
MAX_SUBJECTS = 4_000
MAX_FILE_BYTES = 128_000_000
MAX_TOTAL_BYTES = 800_000_000
MAX_MANIFEST_BYTES = 16_000_000
MAX_PATH_PARTS = 32
ROLES = frozenset({"source", "notice", "recipe", "patch", "evidence"})
KINDS = frozenset({"python", "native", "runtime", "vendor", "cargo-declaration", "opam-declaration"})
NATIVE_EVIDENCE = ("native-corresponding-source", "compiled-membership", "build-provenance", "relink-materials")
EVIDENCE_ROLES = {
    "native-corresponding-source": "source", "compiled-membership": "evidence",
    "build-provenance": "evidence", "relink-materials": "source",
    "derivative-recipe": "recipe", "derivative-patch": "patch",
    "covered-source-mapping": "evidence",
}


class SourcePacketError(ValueError):
    """An input or packet does not meet the preparation-only packet contract."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _keys(value: Any, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SourcePacketError(f"Invalid {description} fields.")
    return value


def _text(value: Any, description: str, maximum: int = 1000) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(part in value for part in ("/Users/", "/home/", "/private/", "file://"))):
        raise SourcePacketError(f"Invalid or private {description}.")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SourcePacketError("A lowercase SHA256 binding is required.")
    return value


def _path(value: Any) -> str:
    value = _text(value, "relative path", 1024)
    parts = value.split("/")
    if (len(parts) > MAX_PATH_PARTS
            or any(part in ("", ".", "..") or not re.fullmatch(r"[A-Za-z0-9_.+@=-]+", part)
                   for part in parts)):
        raise SourcePacketError("Paths must be canonical recipient-relative ASCII paths.")
    if any(part.casefold() in {"semgrep-rules", "registry-rules", ".semgrep-rule-cache"}
           for part in parts):
        raise SourcePacketError("Registry rule redistribution is outside the allowlist.")
    return value


def _paths_disjoint(paths: list[str]) -> None:
    files: set[str] = set()
    names: dict[str, str] = {}
    for path in paths:
        if path.casefold() in files:
            raise SourcePacketError("Duplicate or case-colliding packet file.")
        files.add(path.casefold())
        parts = path.split("/")
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            key = prefix.casefold()
            if key in names and names[key] != prefix:
                raise SourcePacketError("Case-colliding packet directory.")
            names[key] = prefix
    for path in paths:
        parts = path.split("/")
        if any("/".join(parts[:count]).casefold() in files for count in range(1, len(parts))):
            raise SourcePacketError("Conflicting packet file and directory.")


@contextmanager
def _directory(path: Path) -> Iterator[int]:
    """Anchor every absolute path component with O_NOFOLLOW directory handles."""
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise SourcePacketError("Parent path components are not permitted.")
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _parent(root: int, path: str, *, create: bool = False) -> Iterator[tuple[int, str]]:
    parts = _path(path).split("/")
    descriptor = os.dup(root)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_nlink,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_at(root: int, path: str, limit: int) -> tuple[bytes, int]:
    with _parent(root, path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > limit):
            raise SourcePacketError("A bounded, unlinked regular file is required.")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if _identity(opened) != _identity(before):
                raise SourcePacketError("Input changed before reading.")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (_identity(before) != _identity(after) or _identity(before) != _identity(current)
                or len(data) != before.st_size or len(data) > limit):
            raise SourcePacketError("Input changed while reading or exceeded its bound.")
    return data, stat.S_IMODE(before.st_mode)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def _json(data: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SourcePacketError("Duplicate JSON object key.")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise SourcePacketError("A JSON object is required.")
    return value


def _files(value: Any, *, specification: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 0 < len(value) <= MAX_FILES:
        raise SourcePacketError("A nonempty bounded file allowlist is required.")
    result = []
    total = 0
    for row in value:
        fields = {"path", "sha256", "bytes", "mode", "role"} | ({"source"} if specification else set())
        _keys(row, fields, "file")
        item = dict(row)
        item["path"] = _path(row["path"])
        if item["path"].casefold() == MANIFEST_NAME:
            raise SourcePacketError("The manifest filename is reserved.")
        if specification:
            item["source"] = _path(row["source"])
        _digest(row["sha256"])
        if (type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_FILE_BYTES
                or type(row["mode"]) is not int or row["mode"] not in (0o644, 0o755)
                or row["role"] not in ROLES):
            raise SourcePacketError("Invalid file size, mode or role.")
        total += row["bytes"]
        result.append(item)
    if total > MAX_TOTAL_BYTES:
        raise SourcePacketError("Packet exceeds its aggregate byte bound.")
    _paths_disjoint([MANIFEST_NAME] + [row["path"] for row in result])
    return sorted(result, key=lambda row: row["path"])


def _subjects(value: Any, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 0 < len(value) <= MAX_SUBJECTS:
        raise SourcePacketError("A nonempty bounded subject inventory is required.")
    roles = {row["path"]: row["role"] for row in files}
    identifiers: set[str] = set()
    result = []

    def references(values: Any, role: str) -> list[str]:
        if not isinstance(values, list) or len(values) > MAX_FILES:
            raise SourcePacketError("Invalid packet references.")
        paths = [_path(path) for path in values]
        if len(set(paths)) != len(paths) or any(roles.get(path) != role for path in paths):
            raise SourcePacketError("A reference is missing, duplicate or has the wrong role.")
        return sorted(paths)

    for row in value:
        _keys(row, {"id", "name", "version", "kind", "artifactSha256", "derivative",
                    "licenseDeclarations", "sourcePaths", "noticePaths", "evidence"}, "subject")
        identifier = _text(row["id"], "subject identifier", 200)
        if (not re.fullmatch(r"[A-Za-z0-9_.+@=-]+", identifier)
                or identifier.casefold() in identifiers):
            raise SourcePacketError("Invalid or duplicate subject identifier.")
        identifiers.add(identifier.casefold())
        if row["kind"] not in KINDS or type(row["derivative"]) is not bool:
            raise SourcePacketError("Invalid subject kind or derivative flag.")
        _text(row["name"], "subject name", 200)
        _text(row["version"], "subject version", 200)
        _digest(row["artifactSha256"])
        if row["name"].casefold() == "semgrep" and "+" in row["version"] and not row["derivative"]:
            raise SourcePacketError("A downstream Semgrep identity requires derivative evidence.")
        declarations = row["licenseDeclarations"]
        if not isinstance(declarations, list) or not 0 < len(declarations) <= 100:
            raise SourcePacketError("Original license declarations must be retained.")
        for declaration in declarations:
            _keys(declaration, {"expression", "path"}, "license declaration")
            _text(declaration["expression"], "original license expression", 500)
            if roles.get(_path(declaration["path"])) not in {"source", "notice", "evidence"}:
                raise SourcePacketError("License declaration lacks an included supporting file.")
        evidence = row["evidence"]
        if not isinstance(evidence, dict) or set(evidence) - EVIDENCE_ROLES.keys():
            raise SourcePacketError("Unsupported evidence category.")
        item = dict(row)
        item["sourcePaths"] = references(row["sourcePaths"], "source")
        item["noticePaths"] = references(row["noticePaths"], "notice")
        item["evidence"] = {
            key: references(paths, EVIDENCE_ROLES[key]) for key, paths in sorted(evidence.items())
        }
        result.append(item)
    return sorted(result, key=lambda row: row["id"])


def _unresolved(value: Any, subjects: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_SUBJECTS * 10:
        raise SourcePacketError("Unresolved facts must be a bounded list.")
    identifiers = {row["id"] for row in subjects} | {"packet"}
    result = []
    for row in value:
        _keys(row, {"subject", "category", "detail"}, "unresolved fact")
        if row["subject"] not in identifiers:
            raise SourcePacketError("An unresolved fact references an unknown subject.")
        result.append({key: _text(row[key], f"unresolved {key}") for key in row})
    serialized = [_json_bytes(row) for row in result]
    if len(set(serialized)) != len(serialized):
        raise SourcePacketError("Duplicate unresolved fact.")
    return sorted(result, key=lambda row: (row["subject"], row["category"], row["detail"]))


def _missing(subjects: list[dict[str, Any]], unresolved: list[dict[str, str]]) -> list[dict[str, str]]:
    missing = list(unresolved)
    for subject in subjects:
        requirements = {
            "corresponding-source": subject["sourcePaths"],
            "license-notice": subject["noticePaths"],
        }
        if subject["kind"] in {"native", "runtime"}:
            requirements.update({key: subject["evidence"].get(key, []) for key in NATIVE_EVIDENCE})
        if subject["derivative"]:
            requirements.update({key: subject["evidence"].get(key, []) for key in
                                 ("derivative-recipe", "derivative-patch")})
        if subject["name"].casefold() == "certifi":
            requirements["covered-source-mapping"] = subject["evidence"].get("covered-source-mapping", [])
        for category, paths in requirements.items():
            if not paths:
                missing.append({
                    "subject": subject["id"], "category": category,
                    "detail": "No included digest-bound file supplies this evidence.",
                })
    missing.append({
        "subject": "packet", "category": "independent-compliance-determination",
        "detail": "File integrity is not a legal determination or validation of native source/build/relink completeness; separate review is required.",
    })
    return sorted(missing, key=lambda row: (row["subject"], row["category"], row["detail"]))


def _manifest(specification: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _keys(specification, {"format", "files", "subjects", "unresolved"}, "specification")
    if specification["format"] != SPEC_FORMAT:
        raise SourcePacketError("Unsupported source packet specification.")
    files = _files(specification["files"], specification=True)
    subjects = _subjects(specification["subjects"], files)
    unresolved = _unresolved(specification["unresolved"], subjects)
    manifest = {
        "format": PACKET_FORMAT, "preparationOnly": True,
        "complianceComplete": False, "releaseQualified": False,
        "files": [{key: value for key, value in row.items() if key != "source"} for row in files],
        "subjects": subjects, "unresolved": unresolved, "missingEvidence": _missing(subjects, unresolved),
    }
    if len(_json_bytes(manifest)) > MAX_MANIFEST_BYTES:
        raise SourcePacketError("Manifest exceeds its byte bound.")
    return manifest, files


def _inventory(root: int) -> dict[str, tuple[str, int, int]]:
    """No-follow, bounded traversal; never open a FIFO, socket, device or link."""
    result: dict[str, tuple[str, int, int]] = {}
    entries = 0
    total = 0

    def walk(descriptor: int, prefix: str) -> None:
        nonlocal entries, total
        before = os.fstat(descriptor)
        with os.scandir(descriptor) as children:
            for child in children:
                entries += 1
                if entries > (MAX_FILES + 1) * MAX_PATH_PARTS:
                    raise SourcePacketError("Packet traversal exceeds its entry bound.")
                path = _path(prefix + child.name)
                info = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    nested = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=descriptor)
                    try:
                        if _identity(os.fstat(nested)) != _identity(info):
                            raise SourcePacketError("Packet directory changed during traversal.")
                        walk(nested, path + "/")
                    finally:
                        os.close(nested)
                    result[path] = ("directory", 0, 0)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    limit = MAX_MANIFEST_BYTES if path == MANIFEST_NAME else MAX_FILE_BYTES
                    if info.st_size > limit:
                        raise SourcePacketError("Packet file exceeds its byte bound.")
                    total += info.st_size
                    if total > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES:
                        raise SourcePacketError("Packet exceeds its aggregate byte bound.")
                    result[path] = ("file", info.st_size, stat.S_IMODE(info.st_mode))
                else:
                    raise SourcePacketError("Packet contains a link or special file.")
        if _identity(before) != _identity(os.fstat(descriptor)):
            raise SourcePacketError("Packet directory changed during traversal.")

    walk(root, "")
    return result


def _validate_at(root: int, expected_manifest_sha256: str) -> dict[str, Any]:
    raw, mode = _read_at(root, MANIFEST_NAME, MAX_MANIFEST_BYTES)
    if _sha256(raw) != _digest(expected_manifest_sha256) or mode != 0o644:
        raise SourcePacketError("Manifest digest or mode mismatch.")
    manifest = _json(raw)
    _keys(manifest, {"format", "preparationOnly", "complianceComplete", "releaseQualified",
                     "files", "subjects", "unresolved", "missingEvidence"}, "manifest")
    if (manifest["format"] != PACKET_FORMAT or manifest["preparationOnly"] is not True
            or manifest["complianceComplete"] is not False or manifest["releaseQualified"] is not False):
        raise SourcePacketError("Preparation packets cannot claim compliance or release qualification.")
    files = _files(manifest["files"], specification=False)
    subjects = _subjects(manifest["subjects"], files)
    unresolved = _unresolved(manifest["unresolved"], subjects)
    missing = _missing(subjects, unresolved)
    if manifest["missingEvidence"] != missing:
        raise SourcePacketError("Manifest omits or changes required missing-evidence facts.")
    expected = {MANIFEST_NAME: ("file", len(raw), 0o644)}
    for row in files:
        expected[row["path"]] = ("file", row["bytes"], row["mode"])
        parts = row["path"].split("/")
        for count in range(1, len(parts)):
            expected["/".join(parts[:count])] = ("directory", 0, 0)
    before = _inventory(root)
    if before != expected:
        raise SourcePacketError("Actual packet inventory differs from the exact allowlist.")
    for row in files:
        data, observed_mode = _read_at(root, row["path"], row["bytes"])
        if (_sha256(data) != row["sha256"] or len(data) != row["bytes"]
                or observed_mode != row["mode"]):
            raise SourcePacketError("An included file differs from its digest, size or mode.")
    if _inventory(root) != before:
        raise SourcePacketError("Packet inventory changed during validation.")
    return {
        "format": "polaris.source-packet-validation/1",
        "manifestSha256": expected_manifest_sha256,
        "includedInventory": files, "includedFiles": len(files),
        "includedBytes": sum(row["bytes"] for row in files),
        "artifactBindings": sorted({row["artifactSha256"] for row in subjects}),
        "integrityVerified": True, "preparationOnly": True,
        "complianceComplete": False, "releaseQualified": False, "missingEvidence": missing,
    }


def validate_source_packet(
    packet_root: Path, *, expected_manifest_sha256: str, require_compliance_complete: bool = False,
) -> dict[str, Any]:
    """Verify actual recipient bytes; a digest alone is not publisher trust."""
    with _directory(packet_root) as root:
        result = _validate_at(root, expected_manifest_sha256)
    if require_compliance_complete:
        raise SourcePacketError("Compliance-complete claim refused: independent source/build/relink/legal review remains required.")
    return result


def _write_at(root: int, path: str, data: bytes, mode: int) -> None:
    with _parent(root, path, create=True) as (parent, name):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             mode, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)


def build_source_packet(
    input_root: Path, specification: dict[str, Any], output: Path,
) -> dict[str, Any]:
    """Preflight all allowlisted input bytes before creating any output.

    Output must not exist, and its parent must exist. Source paths are relative
    to input_root and are never copied into the recipient manifest. A later I/O
    failure can leave this call's partial directory, but invalid input cannot.
    """
    manifest, files = _manifest(specification)
    payloads = []
    with _directory(input_root) as root:
        for row in files:
            data, mode = _read_at(root, row["source"], row["bytes"])
            if (_sha256(data) != row["sha256"] or len(data) != row["bytes"] or mode != row["mode"]):
                raise SourcePacketError("Allowlisted input differs from its digest, size or mode.")
            payloads.append(data)
    raw = _json_bytes(manifest)
    with _directory(output.absolute().parent) as parent:
        name = output.name
        if name in {"", ".", ".."} or "/" in name:
            raise SourcePacketError("Invalid output directory.")
        os.mkdir(name, 0o755, dir_fd=parent)
        root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            for row, data in zip(files, payloads, strict=True):
                _write_at(root, row["path"], data, row["mode"])
            _write_at(root, MANIFEST_NAME, raw, 0o644)
            return _validate_at(root, _sha256(raw))
        finally:
            os.close(root)


def advisory_alias_groups(records: list[dict[str, Any]]) -> list[list[str]]:
    """Group transitive advisory aliases; never deduplicate away subject scope."""
    if len(records) > 20_000:
        raise SourcePacketError("Advisory list exceeds its bound.")
    groups: list[set[str]] = []
    for record in records:
        identifier = _text(record.get("id"), "advisory ID", 200)
        aliases = record.get("aliases", [])
        if not isinstance(aliases, list) or len(aliases) > 100:
            raise SourcePacketError("Invalid advisory aliases.")
        group = {identifier} | {_text(alias, "advisory alias", 200) for alias in aliases}
        separated = []
        for previous in groups:
            if group & previous:
                group |= previous
            else:
                separated.append(previous)
        groups = separated + [group]
    return sorted(sorted(group) for group in groups)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    build = commands.add_parser("build")
    build.add_argument("--input-root", type=Path, required=True)
    build.add_argument("--spec", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--packet", type=Path, required=True)
    validate.add_argument("--manifest-sha256", required=True)
    validate.add_argument("--require-compliance-complete", action="store_true")
    args = parser.parse_args()
    try:
        if args.operation == "build":
            with _directory(args.spec.absolute().parent) as parent:
                raw, _ = _read_at(parent, args.spec.name, MAX_MANIFEST_BYTES)
            result = build_source_packet(args.input_root, _json(raw), args.output)
        else:
            result = validate_source_packet(
                args.packet, expected_manifest_sha256=args.manifest_sha256,
                require_compliance_complete=args.require_compliance_complete,
            )
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise SystemExit("Source packet refused: invalid, changed, missing or incomplete evidence.") from None
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()

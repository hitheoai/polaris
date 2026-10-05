"""Inspect wheels and derive the approved PRIVATE Semgrep dependency experiment.

No networking, installation, subprocess execution, signing or release qualification.
The derive command accepts only the approved upstream wheel; tests use synthetic data.
"""

from __future__ import annotations

import argparse
import base64
import csv
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import unicodedata
import zipfile
import zlib
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

UPSTREAM_VERSION = "1.178.0"
LOCAL_VERSION = "1.178.0+theovex.1"
UPSTREAM_SHA256 = "33eb20066093799ab5fb9c4d3722e891d2bfb89218a145762a1f4397642b9ad2"
UPSTREAM_BYTES = 50_025_933
WHEEL_SUFFIX = (
    "cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314"
    "-none-macosx_11_0_arm64.whl"
)
UPSTREAM_REQUIREMENT = "pyjwt[crypto]~=2.13.0"
LOCAL_REQUIREMENT = "pyjwt[crypto]~=2.15.0"
UPSTREAM_REQUIREMENTS = (
    "attrs>=21.3", "boltons~=21.0", "click-option-group~=0.5", "click~=8.4.2",
    "colorama~=0.4.0", "exceptiongroup~=1.2.0", "glom>=23.3", "jsonschema~=4.25.1",
    "mcp==1.29.0", "opentelemetry-api~=1.37.0", "opentelemetry-sdk~=1.37.0",
    "opentelemetry-exporter-otlp-proto-http~=1.37.0",
    "opentelemetry-instrumentation-requests~=0.58b0",
    "opentelemetry-instrumentation-threading~=0.58b0", "packaging>=21.0",
    "peewee~=3.14", UPSTREAM_REQUIREMENT, "requests~=2.22", "rich>=13.5.2",
    "ruamel.yaml>=0.18.15", "ruamel.yaml.clib==0.2.15", "semantic-version~=2.10.0",
    "tomli~=2.4.0", "typing-extensions~=4.2", "urllib3~=2.0", "wcmatch~=8.3",
    'pywin32==311; sys_platform == "win32"',
)
MAX_ARCHIVE_BYTES = 128_000_000
MAX_EXPANDED_BYTES = 500_000_000
MAX_MEMBERS = 20_000
MAX_METADATA_BYTES = 2_000_000
MAX_RECORD_BYTES = 8_000_000


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()

def path_key(name: str) -> str:
    """Conservatively reject case/Unicode aliases on the macOS trial target."""
    return unicodedata.normalize("NFD", name.rstrip("/")).casefold()


def installed_name(name: str, stem: str) -> str:
    """The fixed CPython/macOS venv uses one site-packages for purelib/platlib."""
    prefix = stem + ".data/"
    if name.startswith(prefix):
        parts = name.removeprefix(prefix).split("/", 1)
        if len(parts) != 2 or parts[0] not in ("purelib", "platlib") or not parts[1]:
            raise ValueError("Unsupported wheel installation scheme for this private target.")
        return parts[1]
    if name == stem + ".data":
        raise ValueError("Unsupported wheel installation scheme for this private target.")
    return name


def validate_install_destinations(names: list[str]) -> None:
    keys = {path_key(name) for name in names}
    if len(keys) != len(names):
        raise ValueError("Wheel installation destinations collide.")
    for name in names:
        if any(path_key(str(parent)) in keys for parent in PurePosixPath(name).parents):
            raise ValueError("Wheel installation destinations have conflicting ancestors.")


def no_links(path: Path) -> Path:
    path = path.absolute()
    if ".." in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("Paths must not traverse symlinks or parent components.")
    return path


def read_regular(path: Path, limit: int) -> bytes:
    path = no_links(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Input must be a bounded regular file.")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeds its byte bound.")
    return data


def archive_name(name: str) -> None:
    if (not name or len(name) > 1024 or name.startswith("/") or "\\" in name or ":" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))):
        raise ValueError("Unsafe wheel member path.")


def headers(data: bytes) -> Message:
    if len(data) > MAX_METADATA_BYTES or b"\x00" in data:
        raise ValueError("Excessive or malformed metadata.")
    data.decode("utf-8")
    result = BytesParser(policy=policy.default).parsebytes(data)
    if result.defects:
        raise ValueError("Malformed metadata headers.")
    return result


def singleton(message: Message, key: str) -> str:
    values = message.get_all(key, [])
    if len(values) != 1 or not str(values[0]).strip():
        raise ValueError(f"Missing or ambiguous {key} metadata.")
    return str(values[0])


def inspect_bytes(data: bytes) -> dict[str, Any]:
    """Validate bounded ZIP paths, identities and every mandatory RECORD binding."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Wheel exceeds its archive byte bound.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if (not entries or len(entries) > MAX_MEMBERS or len(names) != len(set(names))
                or len({path_key(name) for name in names}) != len(names)):
            raise ValueError("Wheel has excessive, duplicate or case-colliding members.")
        if sum(entry.file_size for entry in entries) > MAX_EXPANDED_BYTES:
            raise ValueError("Wheel exceeds its expanded byte bound.")
        files = {entry.filename for entry in entries if not entry.is_dir()}
        file_keys = {path_key(name) for name in files}
        for entry in entries:
            archive_name(entry.filename)
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if (entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or kind not in ((0, stat.S_IFDIR) if entry.is_dir() else (0, stat.S_IFREG))
                    or entry.is_dir() and entry.file_size != 0
                    or entry.external_attr >> 16 & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)):
                raise ValueError("Wheel has an unsupported, encrypted or special member.")
            if any(path_key(str(parent)) in file_keys for parent in PurePosixPath(entry.filename).parents):
                raise ValueError("Wheel has conflicting file and directory paths.")
        if any(name.endswith(("/RECORD.jws", "/RECORD.p7s")) for name in names):
            raise ValueError("Signed-wheel metadata requires separate handling; no signature is inherited.")
        roots = {name.split("/")[0] for name in names if name.split("/")[0].endswith(".dist-info")}
        if len(roots) != 1:
            raise ValueError("Wheel requires one unambiguous distribution metadata directory.")
        root = roots.pop()
        metadata_name, wheel_name, record_name = (root + "/" + part for part in ("METADATA", "WHEEL", "RECORD"))
        if not {metadata_name, wheel_name, record_name}.issubset(files):
            raise ValueError("Wheel lacks required metadata or RECORD.")
        for name, limit in ((metadata_name, MAX_METADATA_BYTES), (wheel_name, MAX_METADATA_BYTES),
                            (record_name, MAX_RECORD_BYTES)):
            if archive.getinfo(name).file_size > limit:
                raise ValueError("Wheel metadata exceeds its byte bound.")
        metadata = headers(archive.read(metadata_name))
        wheel = headers(archive.read(wheel_name))
        name, version = singleton(metadata, "Name"), singleton(metadata, "Version")
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!]*", version)):
            raise ValueError("Invalid distribution identity.")
        stem = root.removesuffix(".dist-info")
        distribution, separator, directory_version = stem.rpartition("-")
        if not separator or normalized(distribution) != normalized(name) or directory_version != version:
            raise ValueError("Metadata directory and distribution identity disagree.")
        data_roots = {path.split("/")[0] for path in names if path.split("/")[0].endswith(".data")}
        if data_roots - {stem + ".data"}:
            raise ValueError("Wheel data directory and distribution identity disagree.")
        validate_install_destinations([installed_name(path, stem) for path in files])
        if (singleton(wheel, "Wheel-Version") != "1.0"
                or singleton(wheel, "Root-Is-Purelib") not in ("true", "false")):
            raise ValueError("Unsupported wheel format.")
        tags = [str(value) for value in wheel.get_all("Tag", [])]
        if not tags or len(set(tags)) != len(tags) or any(
            not re.fullmatch(r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+", tag) for tag in tags
        ):
            raise ValueError("Invalid or ambiguous wheel tags.")
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"), newline=""), strict=True))
        if any(len(row) != 3 for row in rows) or len(rows) != len(files):
            raise ValueError("RECORD does not cover every wheel file exactly once.")
        records = {row[0]: row[1:] for row in rows}
        if len(records) != len(rows) or set(records) != files or records.get(record_name) != ["", ""]:
            raise ValueError("RECORD has missing, duplicate or unexpected members.")
        members: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if entry.is_dir():
                continue
            digest = hashlib.sha256()
            count = 0
            with archive.open(entry) as stream:
                for chunk in iter(lambda: stream.read(1_048_576), b""):
                    count += len(chunk)
                    if count > entry.file_size:
                        raise ValueError("Expanded member exceeds its declared size.")
                    digest.update(chunk)
            if count != entry.file_size:
                raise ValueError("Expanded member size differs.")
            if entry.filename != record_name:
                expected = ["sha256=" + base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode(), str(count)]
                if records[entry.filename] != expected:
                    raise ValueError("RECORD hash or size mismatch.")
            members[entry.filename] = {
                "sha256": digest.hexdigest(), "bytes": count,
                "mode": stat.S_IMODE(entry.external_attr >> 16),
            }
        return {
            "sha256": sha256(data), "bytes": len(data),
            "name": normalized(name), "version": version, "metadataDirectory": root,
            "requiresDist": [str(value) for value in metadata.get_all("Requires-Dist", [])],
            "requiresPython": metadata.get("Requires-Python"), "tags": tags,
            "members": members,
        }


def inspect_wheel(path: Path) -> dict[str, Any]:
    return inspect_bytes(read_regular(path, MAX_ARCHIVE_BYTES))


def replace_header(data: bytes, key: str, before: str, after: str) -> bytes:
    """Change an exact, unfolded header once; never rewrite the description body."""
    if b"\r" in data:
        raise ValueError("Unexpected metadata line endings.")
    header, separator, body = data.partition(b"\n\n")
    old = f"{key}: {before}".encode()
    lines = header.split(b"\n")
    if not separator or lines.count(old) != 1:
        raise ValueError("The exact approved metadata header is missing or ambiguous.")
    return b"\n".join(f"{key}: {after}".encode() if line == old else line for line in lines) + separator + body


def mapped_name(name: str) -> str:
    for suffix in (".dist-info/", ".data/"):
        prefix = f"semgrep-{UPSTREAM_VERSION}{suffix}"
        if name.startswith(prefix):
            return f"semgrep-{LOCAL_VERSION}{suffix}" + name.removeprefix(prefix)
    raise ValueError("Unexpected upstream archive layout.")


def write_member(archive: zipfile.ZipFile, name: str, mode: int, content: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, content, compresslevel=9)


def derive(source: Path, output: Path) -> dict[str, Any]:
    """Only the approved immutable input may enter this metadata-only transformation."""
    raw = read_regular(source, MAX_ARCHIVE_BYTES)
    if len(raw) != UPSTREAM_BYTES or sha256(raw) != UPSTREAM_SHA256:
        raise ValueError("Upstream wheel does not match the approved size and SHA-256.")
    before = inspect_bytes(raw)
    if (before["name"] != "semgrep" or before["version"] != UPSTREAM_VERSION
            or sorted(before["requiresDist"]) != sorted(UPSTREAM_REQUIREMENTS)
            or "cp311-none-macosx_11_0_arm64" not in before["tags"]):
        raise ValueError("Upstream identity, tags or requirements differ from the approved contract.")
    output = no_links(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    wheel_path = output / f"semgrep-{LOCAL_VERSION}-{WHEEL_SUFFIX}"
    old_root = before["metadataDirectory"]
    new_root = f"semgrep-{LOCAL_VERSION}.dist-info"
    records = []
    changes = {}
    expected_mutable: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as original, wheel_path.open("xb") as stream:
        expected_mutable[old_root + "/METADATA"] = replace_header(
            replace_header(original.read(old_root + "/METADATA"), "Version", UPSTREAM_VERSION, LOCAL_VERSION),
            "Requires-Dist", UPSTREAM_REQUIREMENT, LOCAL_REQUIREMENT,
        )
        expected_mutable[old_root + "/WHEEL"] = replace_header(
            original.read(old_root + "/WHEEL"), "Generator", "setuptools (84.0.0)",
            "polaris-private-analyzer-qualification/1",
        )
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, item in sorted(before["members"].items()):
                if name == old_root + "/RECORD":
                    continue
                destination = mapped_name(name)
                changed = expected_mutable.get(name)
                if changed is not None:
                    content = original.read(name)
                    changes[name] = "".join(difflib.unified_diff(
                        content.decode().splitlines(keepends=True), changed.decode().splitlines(keepends=True),
                        fromfile=name, tofile=destination,
                    ))
                    write_member(archive, destination, item["mode"], changed)
                    digest, size = hashlib.sha256(changed).digest(), len(changed)
                else:
                    info = zipfile.ZipInfo(destination, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | item["mode"]) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with original.open(name) as input_stream, archive.open(info, "w") as target:
                        shutil.copyfileobj(input_stream, target, length=1_048_576)
                    digest, size = bytes.fromhex(item["sha256"]), item["bytes"]
                records.append([destination, "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode(), str(size)])
            record_path = new_root + "/RECORD"
            records.append([record_path, "", ""])
            content_stream = io.StringIO(newline="")
            csv.writer(content_stream, lineterminator="\n").writerows(sorted(records))
            expected_mutable[old_root + "/RECORD"] = content_stream.getvalue().encode()
            write_member(archive, record_path, before["members"][old_root + "/RECORD"]["mode"],
                         expected_mutable[old_root + "/RECORD"])
    after = inspect_wheel(wheel_path)
    allowed = {old_root + "/" + name for name in ("METADATA", "WHEEL", "RECORD")}
    mapping = []
    for name, item in before["members"].items():
        destination = mapped_name(name)
        observed = after["members"][destination]
        if observed["mode"] != item["mode"] or name not in allowed and observed != item:
            raise ValueError("An unapproved payload member or its permissions changed.")
        if name in allowed and (
            observed["sha256"] != sha256(expected_mutable[name])
            or observed["bytes"] != len(expected_mutable[name])
        ):
            raise ValueError("Mutable metadata differs from the exact approved bytes.")
        mapping.append({
            "upstreamPath": name, "derivedPath": destination,
            "upstream": item, "derived": observed, "contentUnchanged": item == observed,
        })
    if (set(after["members"]) != {mapped_name(name) for name in before["members"]}
            or after["version"] != LOCAL_VERSION or after["name"] != "semgrep"
            or sorted(after["requiresDist"]) != sorted(
                LOCAL_REQUIREMENT if value == UPSTREAM_REQUIREMENT else value for value in UPSTREAM_REQUIREMENTS
            ) or after["tags"] != before["tags"]):
        raise ValueError("Derived wheel differs from the exact approved transformation.")
    patch = "".join(changes.values()).encode()
    with (output / "metadata.patch").open("xb") as target:
        target.write(patch)
    recipe = {
        "format": "polaris.private-analyzer-derivative/1",
        "upstream": {"name": source.name, "sha256": before["sha256"], "bytes": before["bytes"],
                     "version": UPSTREAM_VERSION},
        "derived": {"name": wheel_path.name, "sha256": after["sha256"], "bytes": after["bytes"],
                    "version": LOCAL_VERSION},
        "tool": {
            "sha256": sha256(read_regular(Path(__file__), MAX_METADATA_BYTES)),
            "python": sys.version, "zlib": zlib.ZLIB_RUNTIME_VERSION,
            "archiveTimestamp": [1980, 1, 1, 0, 0, 0],
        },
        "metadataPatch": {"sha256": sha256(patch), "bytes": len(patch)},
        "members": mapping,
        "allowedContentChanges": sorted(allowed),
        "implementationNativeLicenseBytesUnchanged": True,
        "upstreamAttestationsInherited": False,
        "runtimeCompatibilityTested": False,
        "releaseQualified": False,
        "productionPackagingChanged": False,
    }
    with (output / "recipe.json").open("x") as target:
        json.dump(recipe, target, sort_keys=True, indent=2)
        target.write("\n")
    return recipe


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("wheel", type=Path)
    build = subparsers.add_parser("derive")
    build.add_argument("wheel", type=Path)
    build.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect_wheel(args.wheel) if args.operation == "inspect" else derive(args.wheel, args.output)
    except (OSError, ValueError, UnicodeError, csv.Error, zipfile.BadZipFile, KeyError) as exc:
        raise SystemExit(f"Private analyzer trial did not complete: {exc}") from None
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()

"""Inspect macOS release bytes without executing or extracting their native code."""

from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import io
import json
import re
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any

MAX_NATIVE = 250_000_000
THIN = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}
FAT = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
       b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
MAGIC = {*THIN, *FAT, b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}
CPUS = {0x0100000C: "arm64", 0x01000007: "x86_64"}


@functools.lru_cache
def packaging() -> Any:
    path = Path(__file__).with_name("build_homebrew_formula.py")
    spec = importlib.util.spec_from_file_location("native_archive_validation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def version(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){1,2}", value):
        raise ValueError("Invalid bounded macOS version.")
    parts = tuple(map(int, value.split(".")))
    return (parts[0], parts[1], parts[2] if len(parts) == 3 else 0)


def packed_version(value: int) -> str:
    return f"{value >> 16}.{value >> 8 & 255}.{value & 255}"


def thin(content: bytes) -> dict[str, Any]:
    endian = THIN.get(content[:4])
    if endian is None or len(content) < 32:
        raise ValueError("Native code requires a complete 64-bit Mach-O header.")
    _, cpu, subtype, kind, count, size, _, _ = struct.unpack_from(endian + "8I", content)
    if (cpu not in CPUS or kind not in (2, 6, 8) or count > 4096
            or size > 1_048_576 or 32 + size > len(content)):
        raise ValueError("Unsupported or excessive Mach-O header.")
    if cpu == 0x0100000C and subtype & 0xFFFFFF not in (0, 1):
        raise ValueError("An arm64e-only binary does not establish generic Apple Silicon compatibility.")
    minimum, signed, cursor = None, False, 32
    for _ in range(count):
        if cursor + 8 > 32 + size:
            raise ValueError("Truncated native load command.")
        command, length = struct.unpack_from(endian + "2I", content, cursor)
        if length < 8 or length % 4 or cursor + length > 32 + size:
            raise ValueError("Invalid native load-command boundary.")
        if command == 0x32:
            if length < 24:
                raise ValueError("Truncated native build-version command.")
            platform, value, _, tools = struct.unpack_from(endian + "4I", content, cursor + 8)
            if platform != 1 or length != 24 + tools * 8 or minimum is not None:
                raise ValueError("Native code must declare an unambiguous macOS deployment target.")
            minimum = packed_version(value)
        elif command == 0x24:
            if length != 16 or minimum is not None:
                raise ValueError("Ambiguous native minimum-version command.")
            minimum = packed_version(struct.unpack_from(endian + "I", content, cursor + 8)[0])
        elif command == 0x1D:
            if length != 16 or signed:
                raise ValueError("Invalid native code-signature command.")
            offset, amount = struct.unpack_from(endian + "2I", content, cursor + 8)
            if offset < 32 + size or not amount or offset + amount > len(content):
                raise ValueError("Invalid native code-signature boundary.")
            signed = True
        cursor += length
    if cursor != 32 + size or minimum is None or version(minimum) == (0, 0, 0):
        raise ValueError("Native deployment target is missing or malformed.")
    return {"architecture": CPUS[cpu], "cpuSubtype": subtype, "minimumMacOS": minimum,
            "fileType": {2: "executable", 6: "library", 8: "bundle"}[kind],
            "signatureCommandPresent": signed}


def macho(content: bytes) -> list[dict[str, Any]] | None:
    """Header/signature presence is not signature trust or execution qualification."""
    magic = content[:4]
    if magic not in MAGIC:
        return None
    if len(content) > MAX_NATIVE:
        raise ValueError("Native file exceeds its byte bound.")
    if magic not in FAT:
        return [thin(content)]
    endian, wide = FAT[magic]
    if len(content) < 8:
        raise ValueError("Truncated universal Mach-O header.")
    count = struct.unpack_from(endian + "I", content, 4)[0]
    stride = 32 if wide else 20
    end = 8 + count * stride
    if not 1 <= count <= 8 or end > len(content):
        raise ValueError("Invalid universal Mach-O architecture count.")
    slices = []
    ranges: list[tuple[int, int]] = []
    seen: set[int] = set()
    for index in range(count):
        fields = struct.unpack_from(endian + ("IIQQII" if wide else "IIIII"),
                                    content, 8 + index * stride)
        cpu, subtype, offset, amount, alignment = fields[:5]
        if (alignment > 30 or offset < end or not amount or offset % (1 << alignment)
                or offset + amount > len(content) or cpu in seen
                or wide and fields[5] != 0
                or any(offset < stop and offset + amount > start for start, stop in ranges)):
            raise ValueError("Invalid or overlapping universal Mach-O slice.")
        entry = thin(content[offset:offset + amount])
        if CPUS.get(cpu) != entry["architecture"] or subtype != entry["cpuSubtype"]:
            raise ValueError("Universal architecture table differs from its native slice.")
        ranges.append((offset, offset + amount))
        seen.add(cpu)
        slices.append(entry)
    return sorted(slices, key=lambda entry: entry["architecture"])


def native_record(content: bytes, container: str, path: str, minimum: str) -> dict[str, Any] | None:
    slices = macho(content)
    if slices is None:
        return None
    selected = [entry for entry in slices if entry["architecture"] == "arm64"]
    if not selected:
        raise ValueError("Every distributed native file must support Apple Silicon.")
    if any(version(entry["minimumMacOS"]) > version(minimum) for entry in selected):
        raise ValueError("A native file requires a newer macOS than the declared release minimum.")
    return {"container": container, "path": path, "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "slices": slices}


def wheel_records(content: bytes, container: str, minimum: str) -> list[dict[str, Any]]:
    helper = packaging()
    helper.wheel_identity(content)
    result = []
    with zipfile.ZipFile(io.BytesIO(content)) as wheel:
        for member in wheel.infolist():
            if member.is_dir():
                continue
            with wheel.open(member) as stream:
                prefix = stream.read(4)
                if prefix not in MAGIC:
                    continue
                if member.file_size > MAX_NATIVE:
                    raise ValueError("Native wheel member exceeds its byte bound.")
                data = prefix + stream.read(MAX_NATIVE + 1)
            record = native_record(data, container, member.filename, minimum)
            if record:
                result.append(record)
    return result


def tar_records(path: Path, root: str, minimum: str) -> list[dict[str, Any]]:
    helper = packaging()
    members = helper.inspect_tar(path, {root}, links=True)
    result = []
    with tarfile.open(path, "r:gz") as archive:
        for member in members:
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            assert stream
            with stream:
                prefix = stream.read(4)
                if prefix not in MAGIC:
                    continue
                if member.size > MAX_NATIVE:
                    raise ValueError("Native runtime member exceeds its byte bound.")
                data = prefix + stream.read(MAX_NATIVE + 1)
            record = native_record(data, path.name, member.name, minimum)
            if record:
                result.append(record)
    return result


def inventory(bundle: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    helper = packaging()
    minimum = manifest.get("minimumMacOS")
    if not isinstance(minimum, str):
        raise ValueError("A declared minimum macOS version is required.")
    version(minimum)
    files, inputs = [], {}
    for component, root in (("python", "python"), ("uv", "uv-aarch64-apple-darwin")):
        pin = manifest["runtimes"][component]
        if helper.archive_name(pin["name"]) != Path(pin["name"]).name:
            raise ValueError("Runtime artifact name must be a basename.")
        path = bundle / pin["name"]
        inputs[path.name] = helper.verify(path, pin)
        found = tar_records(path, root, minimum)
        if not found:
            raise ValueError("Runtime archive has no validated native code.")
        files.extend(found)
    payload = bundle / "payload.tar.gz"
    inputs[payload.name] = helper.verify(payload, manifest["payload"])
    members = helper.inspect_tar(payload, {"app", "analyzer"})
    with tarfile.open(payload, "r:gz") as archive:
        for member in members:
            if not member.isfile() or not member.name.endswith(".whl"):
                continue
            if member.size > MAX_NATIVE:
                raise ValueError("Wheel exceeds its byte bound.")
            stream = archive.extractfile(member)
            assert stream
            with stream:
                files.extend(wheel_records(stream.read(MAX_NATIVE + 1),
                                           "payload.tar.gz/" + member.name, minimum))
    files.sort(key=lambda entry: (entry["container"], entry["path"]))
    required = max(version(item["minimumMacOS"]) for record in files
                   for item in record["slices"] if item["architecture"] == "arm64")
    for name, pin in inputs.items():
        helper.verify(bundle / name, pin)
    return {"format": "polaris.native-inventory/1", "inputs": inputs, "files": files,
            "nativeFileOccurrences": len(files), "architecturesRequired": ["arm64"],
            "declaredMinimumMacOS": minimum, "requiredMinimumMacOS": ".".join(map(str, required)),
            "minimumOSExecutionTested": False, "signaturesVerified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    helper = packaging()
    try:
        bundle, output = map(helper.regular_path, (arguments.bundle_dir, arguments.output))
        manifest = json.loads(helper.read(bundle / "manifest.json"))
        result = inventory(bundle, manifest)
        with output.open("xb") as stream:
            stream.write(helper.json_bytes(result))
    except (OSError, ValueError, KeyError, TypeError, struct.error, tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit("Native inventory refused unsafe, incompatible or changed inputs.") from None
    print(json.dumps({"nativeFileOccurrences": result["nativeFileOccurrences"],
                      "requiredMinimumMacOS": result["requiredMinimumMacOS"],
                      "executionTested": False, "output": str(output)}))


if __name__ == "__main__":
    main()

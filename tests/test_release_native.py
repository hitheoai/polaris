"""Synthetic Mach-O headers are data only; no fixture native code is executed."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_test", ROOT / "scripts/release_native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def binary(*, minimum=0x000F0000, cpu=0x0100000C, subtype=0, kind=2, platform=1):
    command = struct.pack("<6I", 0x32, 24, platform, minimum, 0x000F0500, 0)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, kind, 1, len(command), 0, 0) + command


def universal(first, second):
    offset = 64
    return (struct.pack(">2I", 0xCAFEBABE, 2)
            + struct.pack(">5I", 0x0100000C, 0, offset, len(first), 0)
            + struct.pack(">5I", 0x01000007, 0, offset + len(first), len(second), 0)
            + b"\0" * 16 + first + second)


def test_native_floor_is_from_load_commands_not_wheel_tags():
    report = native.native_record(binary(), "macosx_11_0_arm64.whl", "semgrep-core", "15.0")
    assert report["slices"][0]["minimumMacOS"] == "15.0.0"
    assert report["slices"][0]["signatureCommandPresent"] is False
    with pytest.raises(ValueError, match="newer macOS"):
        native.native_record(binary(), "macosx_11_0_arm64.whl", "semgrep-core", "11.0")


@pytest.mark.parametrize("data", [b"", b"# shell fixture\n", b"plain data"])
def test_non_native_files_are_not_executed_or_misclassified(data):
    assert native.macho(data) is None


@pytest.mark.parametrize("changes", [
    {"platform": 2}, {"subtype": 2}, {"cpu": 12}, {"kind": 1}, {"minimum": 0},
])
def test_incompatible_headers_fail_closed(changes):
    with pytest.raises(ValueError):
        native.macho(binary(**changes))


def test_x86_only_file_is_not_apple_silicon_compatible():
    with pytest.raises(ValueError, match="Apple Silicon"):
        native.native_record(binary(cpu=0x01000007), "fixture", "binary", "15.0")


def test_universal_files_require_consistent_nonoverlapping_architecture_tables():
    arm, intel = binary(), binary(cpu=0x01000007)
    data = universal(arm, intel)
    report = native.native_record(data, "fixture", "binary", "15.0")
    assert len(report["slices"]) == 2
    overlap = bytearray(data)
    struct.pack_into(">I", overlap, 36, 64)
    with pytest.raises(ValueError, match="overlapping"):
        native.macho(bytes(overlap))
    with pytest.raises(ValueError, match="differs"):
        native.macho(universal(intel, arm))


@pytest.mark.parametrize("cut", [4, 8, 31, 32, 39, 55])
def test_truncated_macho_never_passes(cut):
    with pytest.raises(ValueError):
        native.macho(binary()[:cut])


def test_duplicate_or_out_of_bounds_load_commands_never_pass():
    original = binary()
    duplicated = bytearray(original[:32] + original[32:] * 2)
    struct.pack_into("<2I", duplicated, 16, 2, 48)
    with pytest.raises(ValueError, match="unambiguous"):
        native.macho(bytes(duplicated))
    oversized = bytearray(original)
    struct.pack_into("<I", oversized, 36, 4096)
    with pytest.raises(ValueError, match="boundary"):
        native.macho(bytes(oversized))


def test_actual_supported_floor_remains_distinct_from_execution_evidence():
    assert native.version("15.0") == (15, 0, 0)
    assert native.version("26.6.1") == (26, 6, 1)
    for value in ("", "15", "15.0.0.0", "015.0", "15.0\n"):
        with pytest.raises(ValueError):
            native.version(value)

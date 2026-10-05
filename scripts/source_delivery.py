"""Recipient-relative source packet archives; integrity is not compliance approval."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import os
import stat
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_NAME = "third-party-sources.tar.gz"
ARCHIVE_ROOT = "third-party-sources"


def qualifier() -> Any:
    specification = importlib.util.spec_from_file_location(
        "source_packet_delivery", ROOT / "scripts/qualify_source_provenance.py",
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def artifact(path: Path) -> dict[str, Any]:
    module = qualifier()
    with module._directory(path.absolute().parent) as parent:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 < before.st_size <= 900_000_000):
                raise ValueError("Source archive must be a bounded unlinked regular file.")
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if module._identity(before) != module._identity(after) or module._identity(before) != module._identity(current):
            raise ValueError("Source archive changed during inspection.")
    return {"name": path.name, "sha256": digest, "bytes": before.st_size}


def build_archive(packet_root: Path, expected_manifest_sha256: str, output: Path) -> dict[str, Any]:
    module = qualifier()
    report = module.validate_source_packet(packet_root, expected_manifest_sha256=expected_manifest_sha256)
    if output.name != ARCHIVE_NAME:
        raise ValueError("Source archive requires its fixed recipient filename.")
    files = {row["path"]: row for row in report["includedInventory"]}
    with module._directory(packet_root) as source, module._directory(output.absolute().parent) as parent:
        raw_manifest, mode = module._read_at(source, module.MANIFEST_NAME, module.MAX_MANIFEST_BYTES)
        files[module.MANIFEST_NAME] = {
            "bytes": len(raw_manifest), "mode": mode, "sha256": expected_manifest_sha256,
        }
        descriptor = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                import io

                for name, pin in sorted(files.items()):
                    content, mode = module._read_at(source, name, pin["bytes"])
                    if (len(content) != pin["bytes"] or mode != pin["mode"]
                            or hashlib.sha256(content).hexdigest() != pin["sha256"]):
                        raise ValueError("Source packet changed during archiving.")
                    member = tarfile.TarInfo(f"{ARCHIVE_ROOT}/{name}")
                    member.size, member.mode = len(content), mode
                    archive.addfile(member, io.BytesIO(content))
    if module.validate_source_packet(packet_root, expected_manifest_sha256=expected_manifest_sha256) != report:
        raise ValueError("Source packet changed during archiving.")
    pin = {**artifact(output), "manifestSha256": expected_manifest_sha256,
           "preparationOnly": True, "complianceComplete": False, "releaseQualified": False}
    validate_archive(output, pin)
    return pin


def validate_archive(
    path: Path, pin: dict[str, Any], *, required_artifacts: set[str] | None = None,
    require_compliance_complete: bool = False,
) -> dict[str, Any]:
    module = qualifier()
    before = artifact(path)
    if (pin.get("name") != ARCHIVE_NAME or before != {key: pin.get(key) for key in before}
            or pin.get("preparationOnly") is not True or pin.get("complianceComplete") is not False
            or pin.get("releaseQualified") is not False):
        raise ValueError("Source archive does not match its preparation-only manifest binding.")
    module._digest(pin.get("manifestSha256"))
    deadline = time.monotonic() + 120
    # Preflight the whole bounded archive before writing any member. Nothing from
    # this packet is imported or executed, including build recipes and patches.
    with tarfile.open(path, "r:gz") as archive:
        members: dict[str, tarfile.TarInfo] = {}
        total = 0
        for member in archive:
            name = module._path(member.name)
            total += member.size
            if (name.split("/")[0] != ARCHIVE_ROOT or name in members
                    or len(members) >= 30_000 or total > module.MAX_TOTAL_BYTES + module.MAX_MANIFEST_BYTES
                    or member.size < 0 or member.size > module.MAX_FILE_BYTES
                    or not (member.isfile() or member.isdir())
                    or member.mode not in (0o644, 0o755) or time.monotonic() >= deadline):
                raise ValueError("Source archive contains unsafe, duplicate or excessive entries.")
            members[name] = member
        file_names = {name for name, member in members.items() if member.isfile()}
        module._paths_disjoint(sorted(file_names))
        if any(any(parent.as_posix() in file_names for parent in Path(name).parents) for name in members):
            raise ValueError("Source archive has a file/directory ancestor collision.")
        with tempfile.TemporaryDirectory(prefix="polaris-source-packet-") as temporary:
            root = Path(temporary).resolve()
            for name, member in members.items():
                if time.monotonic() >= deadline:
                    raise ValueError("Source archive exceeded its extraction time bound.")
                target = root / name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                assert stream is not None
                with stream, target.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        content = stream.read(min(1_048_576, remaining))
                        if not content or time.monotonic() >= deadline:
                            raise ValueError("Source archive is truncated or exceeded its extraction bound.")
                        output.write(content)
                        remaining -= len(content)
                    os.fchmod(output.fileno(), member.mode)
            report = module.validate_source_packet(
                root / ARCHIVE_ROOT, expected_manifest_sha256=pin["manifestSha256"],
                require_compliance_complete=require_compliance_complete,
            )
    if required_artifacts and not required_artifacts <= set(report["artifactBindings"]):
        raise ValueError("Source packet does not bind the required delivered artifacts.")
    if artifact(path) != before:
        raise ValueError("Source archive changed during validation.")
    return dict(report)

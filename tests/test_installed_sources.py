"""Recipient packet integrity is checked again even after interrupted installation."""

from __future__ import annotations

import hashlib
import os

import pytest
from test_source_provenance import packet_input, provenance

from polaris.onboarding.sources import verify_installed_sources


@pytest.fixture
def packet(tmp_path):
    inputs, specification = packet_input(tmp_path)
    root = tmp_path / "packet"
    report = provenance.build_source_packet(inputs, specification, root)
    return root, {
        "manifestSha256": report["manifestSha256"],
        "preparationOnly": True, "complianceComplete": False, "releaseQualified": False,
    }, report


def test_exact_recipient_bytes_retain_the_preparation_only_limit(packet):
    root, binding, report = packet
    checked = verify_installed_sources(root, binding)
    assert checked["includedFiles"] == report["includedFiles"]
    assert checked["includedBytes"] == report["includedBytes"]
    assert checked["integrityVerified"] is True
    assert checked["complianceComplete"] is checked["releaseQualified"] is False


@pytest.mark.parametrize("mutation", [
    "bytes", "mode", "missing", "extra-file", "extra-directory", "link", "hardlink", "fifo", "manifest",
])
def test_manifest_digest_alone_cannot_bless_changed_installed_sources(packet, mutation):
    root, binding, report = packet
    target = root / report["includedInventory"][0]["path"]
    manifest = root / "source-packet.json"
    original = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if mutation == "bytes":
        target.write_bytes(b"changed")
    elif mutation == "mode":
        target.chmod(0o600)
    elif mutation == "missing":
        target.unlink()
    elif mutation == "extra-file":
        (root / "unlisted").write_bytes(b"unlisted")
    elif mutation == "extra-directory":
        (root / "unlisted").mkdir()
    elif mutation == "link":
        target.unlink()
        target.symlink_to(root / "missing")
    elif mutation == "hardlink":
        (root / "alias").hardlink_to(target)
    elif mutation == "fifo":
        target.unlink()
        os.mkfifo(target)
    else:
        manifest.write_bytes(manifest.read_bytes() + b"\n")
    if mutation != "manifest":
        assert hashlib.sha256(manifest.read_bytes()).hexdigest() == original == binding["manifestSha256"]
    with pytest.raises((OSError, ValueError)):
        verify_installed_sources(root, binding)

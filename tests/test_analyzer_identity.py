"""Synthetic installed metadata only; no fixture interpreter or analyzer is executed."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import pytest

from polaris.review.analyzers import identity


@pytest.fixture
def installed(tmp_path, monkeypatch):
    pinned = copy.deepcopy(identity.contract())
    root = tmp_path / "analyzer"
    (root / "bin").mkdir(parents=True)
    executable = root / "bin" / "semgrep"
    executable.write_text("# Inert entry point, never executed.\n")
    (root / "pyvenv.cfg").write_text(
        "implementation = CPython\nversion_info = 3.11.16\ninclude-system-site-packages = false\n",
    )
    site = root / "lib/python3.11/site-packages"
    site.mkdir(parents=True)
    for name, pin in pinned["packages"].items():
        folder = site / pin["metadataDirectory"]
        folder.mkdir()
        metadata = f"Metadata-Version: 2.4\nName: {name}\nVersion: {pin['version']}\n".encode()
        wheel = b"Wheel-Version: 1.0\nTag: py3-none-any\n"
        for label, value in (("METADATA", metadata), ("WHEEL", wheel)):
            (folder / label).write_bytes(value)
        pin["metadataSha256"] = hashlib.sha256(metadata).hexdigest()
        pin["wheelMetadataSha256"] = hashlib.sha256(wheel).hexdigest()
    monkeypatch.setattr(identity, "contract", lambda: copy.deepcopy(pinned))
    return executable, site, pinned


def test_shared_contract_matches_full_managed_graph_and_hash_lock():
    contract = identity.contract()
    assert len(contract["packages"]) == 67
    assert contract["packages"]["semgrep"]["version"] == identity.DISTRIBUTION_VERSION
    assert contract["packages"]["semgrep"]["sha256"] == identity.DERIVATIVE_SHA256
    assert contract["packages"]["mcp"]["version"] == "1.29.0"
    assert contract["packages"]["setuptools"]["version"] == "83.0.0"
    root = Path(__file__).resolve().parents[1]
    expected = []
    for name, pin in contract["packages"].items():
        extra = "[" + ",".join(pin["extras"]) + "]" if pin["extras"] else ""
        expected.append(f"{name}{extra}=={pin['version']} --hash=sha256:{pin['sha256']}")
    assert (root / "packaging/installer/analyzer-requirements.txt").read_text() == "\n".join(sorted(expected)) + "\n"
    assert contract["distributionVersion"] != contract["runtimeVersion"]


def test_linked_system_folders_are_checked_at_their_real_location(installed, tmp_path, monkeypatch):
    # Merged-/usr systems link /bin to /usr/bin: the link is followed once, never skipped.
    executable, _, _ = installed
    real = tmp_path / "usr-bin"
    real.mkdir()
    linked = tmp_path / "bin-link"
    linked.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(identity, "SYSTEM_FOLDERS", (real, linked))
    assert identity.installed_identity(str(executable))["runtimeVersion"] == "1.178.0"
    (real / "semgrep-core-proprietary").write_text("")
    with pytest.raises(ValueError, match="proprietary"):
        identity.installed_identity(str(executable))


def test_exact_installed_metadata_reports_separate_identities(installed):
    executable, _, _ = installed
    result = identity.installed_identity(str(executable))
    assert result["distributionVersion"] == "1.178.0+theovex.1"
    assert result["runtimeVersion"] == "1.178.0"
    assert result["contractSha256"] == identity.CONTRACT_SHA256


@pytest.mark.parametrize("mutation", [
    "missing", "duplicate", "unexpected", "upstream", "renamed-upstream",
    "wheel-metadata", "link", "fifo", "legacy-egg",
])
def test_wrong_or_ambiguous_graph_never_passes(installed, mutation):
    executable, site, pinned = installed
    folder = site / pinned["packages"]["semgrep"]["metadataDirectory"]
    metadata = folder / "METADATA"
    if mutation == "missing":
        metadata.unlink()
    elif mutation == "duplicate":
        (site / "semgrep-1.178.0.dist-info").mkdir()
    elif mutation == "unexpected":
        (site / "unqualified_plugin-1.dist-info").mkdir()
    elif mutation == "upstream":
        metadata.write_text(metadata.read_text().replace("1.178.0+theovex.1", "1.178.0"))
    elif mutation == "renamed-upstream":
        metadata.write_text(metadata.read_text() + "Requires-Dist: pyjwt[crypto]~=2.13.0\n")
    elif mutation == "wheel-metadata":
        (folder / "WHEEL").write_text("changed")
    elif mutation in ("link", "fifo"):
        metadata.unlink()
        if mutation == "link":
            metadata.symlink_to(folder / "WHEEL")
        else:
            os.mkfifo(metadata)
    else:
        (site / "semgrep.egg-info").write_text("legacy identity")
    with pytest.raises((OSError, ValueError)):
        identity.installed_identity(str(executable))


@pytest.mark.parametrize("config", [
    "version_info = 3.11.14\ninclude-system-site-packages = false\n",
    "version_info = 3.11.16\ninclude-system-site-packages = true\n",
    "version_info = 3.11.16\ninclude-system-site-packages = false\nversion = 3.11.16\n",
    "version_info = 3.11.16\nversion_info = 3.11.16\ninclude-system-site-packages = false\n",
])
def test_interpreter_and_isolation_are_pinned(installed, config):
    executable, _, _ = installed
    (executable.parent.parent / "pyvenv.cfg").write_text(config)
    with pytest.raises(ValueError):
        identity.installed_identity(str(executable))


def test_contract_tampering_is_refused(monkeypatch):
    monkeypatch.setattr(identity, "_read", lambda path, *args: b"{}")
    with pytest.raises(ValueError, match="binding"):
        identity.contract()


@pytest.mark.parametrize("location", ["packaged", "interpreter"])
@pytest.mark.parametrize("kind", ["file", "dangling-link", "fifo"])
def test_ce_identity_rejects_proprietary_core_candidates_without_opening_them(installed, location, kind):
    executable, site, _ = installed
    folder = site / "semgrep/bin" if location == "packaged" else executable.parent
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "semgrep-core-proprietary"
    if kind == "file":
        path.write_bytes(b"Inert fixture; never executed.")
    elif kind == "dangling-link":
        path.symlink_to(folder / "absent")
    else:
        os.mkfifo(path)
    with pytest.raises(ValueError, match="proprietary"):
        identity.installed_identity(str(executable))

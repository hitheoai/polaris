"""Synthetic source packets only: no network, upstream execution or approvals."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "source_provenance_test", ROOT / "scripts/qualify_source_provenance.py",
)
assert SPEC is not None and SPEC.loader is not None
provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance)


def packet_input(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    files = []
    contents = [
        ("source.py", "sources/component/source.py", b"synthetic source\n", "source"),
        ("LICENSE", "notices/component/LICENSE", b"synthetic notice\n", "notice"),
        ("recipe.json", "derivation/recipe.json", b'{"synthetic": true}\n', "recipe"),
        ("metadata.patch", "derivation/metadata.patch", b"-old\n+new\n", "patch"),
        ("mapping.json", "evidence/mapping.json", b'{"synthetic": true}\n', "evidence"),
    ]
    for source, path, data, role in contents:
        (root / source).write_bytes(data)
        (root / source).chmod(0o644)
        files.append({
            "source": source, "path": path, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "mode": 0o644, "role": role,
        })
    return root, {
        "format": provenance.SPEC_FORMAT, "files": files,
        "subjects": [{
            "id": "semgrep-derivative", "name": "semgrep", "version": "1.178.0+theovex.1",
            "kind": "native", "artifactSha256": "a" * 64, "derivative": True,
            "licenseDeclarations": [
                {"expression": "LGPL-2.1-only", "path": "sources/component/source.py"},
                {"expression": "LGPL-2.1-or-later", "path": "notices/component/LICENSE"},
            ],
            "sourcePaths": ["sources/component/source.py"],
            "noticePaths": ["notices/component/LICENSE"],
            "evidence": {
                "derivative-recipe": ["derivation/recipe.json"],
                "derivative-patch": ["derivation/metadata.patch"],
            },
        }],
        "unresolved": [{
            "subject": "semgrep-derivative", "category": "upstream-link-map",
            "detail": "Exact compiled membership has not been established.",
        }],
    }


def build(tmp_path):
    root, specification = packet_input(tmp_path)
    output = tmp_path / "third-party-sources"
    report = provenance.build_source_packet(root, specification, output)
    return root, specification, output, report


def validate(output, report, **kwargs):
    return provenance.validate_source_packet(
        output, expected_manifest_sha256=report["manifestSha256"], **kwargs,
    )


def rewrite_manifest(output, mutate):
    path = output / provenance.MANIFEST_NAME
    data = json.loads(path.read_bytes())
    mutate(data)
    raw = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_same_packet_validates_at_both_recipient_locations(tmp_path):
    _, specification, packet, report = build(tmp_path)
    for destination in (tmp_path / "standalone/third-party-sources",
                        tmp_path / "homebrew/share/theo/third-party-sources"):
        shutil.copytree(packet, destination)
        assert validate(destination, report) == report
    assert report["integrityVerified"]
    assert not report["complianceComplete"] and not report["releaseQualified"]
    assert report["includedFiles"] == 5
    assert len(report["includedInventory"]) == 5
    assert report["artifactBindings"] == ["a" * 64]
    manifest = json.loads((packet / provenance.MANIFEST_NAME).read_bytes())
    assert manifest["subjects"][0]["licenseDeclarations"] == specification["subjects"][0]["licenseDeclarations"]
    assert all("source" not in item for item in manifest["files"])
    assert str(tmp_path) not in (packet / provenance.MANIFEST_NAME).read_text()
    assert {item["category"] for item in report["missingEvidence"]} >= {
        "native-corresponding-source", "compiled-membership", "build-provenance",
        "relink-materials", "independent-compliance-determination",
    }


def test_build_is_deterministic_and_does_not_copy_unlisted_inputs(tmp_path):
    root, specification, packet, first = build(tmp_path)
    (root / "not-allowlisted").write_text("do not copy")
    second = provenance.build_source_packet(root, specification, tmp_path / "second")
    assert second == first
    assert not (packet / "not-allowlisted").exists()


@pytest.mark.parametrize("path", [
    "", ".", "..", "../escape", "/absolute", "a/../b", "a//b", "a/./b", "a\\b",
    "C:outside", "a\nb", "a\0b", "a%2fb", "é/name", "e\u0301/name", "a/" * 40 + "b",
    "sources/semgrep-rules/rule.yaml", "sources/registry-rules/rule.yaml",
])
@pytest.mark.parametrize("field", ["source", "path"])
def test_bad_allowlist_paths_create_no_output(tmp_path, path, field):
    root, specification = packet_input(tmp_path)
    specification["files"][0][field] = path
    output = tmp_path / "output"
    with pytest.raises((ValueError, OSError)):
        provenance.build_source_packet(root, specification, output)
    assert not output.exists()


@pytest.mark.parametrize("target", [
    "sources/component/source.py", "sources/component/SOURCE.py",
    "Sources/elsewhere.txt", "sources/component", "source-packet.json",
    "SOURCE-PACKET.JSON", "source-packet.json/child",
])
def test_duplicates_and_ancestor_collisions_create_no_output(tmp_path, target):
    root, specification = packet_input(tmp_path)
    extra = dict(specification["files"][0], path=target)
    specification["files"].append(extra)
    with pytest.raises(ValueError):
        provenance.build_source_packet(root, specification, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("change", ["digest", "size", "mode", "removed", "empty-graph"])
def test_invalid_input_bytes_create_no_output(tmp_path, change):
    root, specification = packet_input(tmp_path)
    if change == "digest":
        (root / "source.py").write_bytes(b"tampered source!\n")
    elif change == "size":
        specification["files"][0]["bytes"] += 1
    elif change == "mode":
        (root / "source.py").chmod(0o600)
    elif change == "removed":
        (root / "source.py").unlink()
    else:
        specification["subjects"] = []
    with pytest.raises((ValueError, OSError)):
        provenance.build_source_packet(root, specification, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("change", ["file", "directory", "symlink", "fifo", "socket", "hardlink", "remove", "mode", "bytes"])
def test_validator_checks_actual_included_inventory(tmp_path, change):
    _, _, packet, report = build(tmp_path)
    victim = packet / "sources/component/source.py"
    sock = None
    if change == "file":
        (packet / "extra").write_text("unlisted")
    elif change == "directory":
        (packet / "extra").mkdir()
    elif change == "symlink":
        (packet / "extra").symlink_to(victim)
    elif change == "fifo":
        os.mkfifo(packet / "extra")
    elif change == "socket":
        sock = socket.socket(socket.AF_UNIX)
        # macOS socket paths are short; keep the socket relative to the cwd.
        original = Path.cwd()
        try:
            os.chdir(packet)
            sock.bind("extra")
        finally:
            os.chdir(original)
    elif change == "hardlink":
        os.link(victim, packet / "extra")
    elif change == "remove":
        victim.unlink()
    elif change == "mode":
        victim.chmod(0o755)
    else:
        victim.write_bytes(b"synthetic other!\n")
    try:
        with pytest.raises((ValueError, OSError)):
            validate(packet, report)
    finally:
        if sock is not None:
            sock.close()


def test_fifo_input_is_rejected_without_opening_it(tmp_path, monkeypatch):
    root, specification = packet_input(tmp_path)
    (root / "source.py").unlink()
    os.mkfifo(root / "source.py")
    original = os.open

    def no_fifo_open(path, flags, *args, **kwargs):
        assert path != "source.py", "a FIFO must never be opened"
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(provenance.os, "open", no_fifo_open)
    with pytest.raises(ValueError, match="regular"):
        provenance.build_source_packet(root, specification, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("location", ["input-file", "input-root", "input-parent", "output-parent"])
def test_symlink_inputs_and_parent_components_are_refused(tmp_path, location):
    root, specification = packet_input(tmp_path)
    output = tmp_path / "output"
    if location == "input-file":
        target = root / "source.py"
        target.rename(root / "real-source")
        target.symlink_to("real-source")
    elif location == "input-root":
        link = tmp_path / "link"
        link.symlink_to(root, target_is_directory=True)
        root = link
    elif location == "input-parent":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        root = link / "input"
    else:
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        output = link / "output"
    with pytest.raises((ValueError, OSError)):
        provenance.build_source_packet(root, specification, output)
    assert not (tmp_path / "output").exists()


def test_existing_outputs_are_never_overwritten(tmp_path):
    root, specification, packet, report = build(tmp_path)
    with pytest.raises(FileExistsError):
        provenance.build_source_packet(root, specification, packet)
    assert validate(packet, report) == report


@pytest.mark.parametrize("reference", ["/private/source", "../missing", "sources/missing", "derivation/recipe.json"])
def test_malformed_or_wrong_role_source_references_are_refused(tmp_path, reference):
    root, specification = packet_input(tmp_path)
    specification["subjects"][0]["sourcePaths"] = [reference]
    with pytest.raises(ValueError):
        provenance.build_source_packet(root, specification, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("field", ["complianceComplete", "releaseQualified", "preparationOnly"])
def test_even_repinned_manifest_cannot_issue_approval(tmp_path, field):
    _, _, packet, _ = build(tmp_path)
    digest = rewrite_manifest(packet, lambda doc: doc.update({field: field != "preparationOnly"}))
    with pytest.raises(ValueError, match="cannot claim"):
        provenance.validate_source_packet(packet, expected_manifest_sha256=digest)


def test_missing_evidence_cannot_be_silently_deleted(tmp_path):
    _, _, packet, _ = build(tmp_path)
    digest = rewrite_manifest(packet, lambda doc: doc.update(missingEvidence=[]))
    with pytest.raises(ValueError, match="missing-evidence"):
        provenance.validate_source_packet(packet, expected_manifest_sha256=digest)


def test_complete_looking_references_are_still_not_a_legal_determination(tmp_path):
    root, specification = packet_input(tmp_path)
    subject = specification["subjects"][0]
    subject["evidence"].update({
        "native-corresponding-source": subject["sourcePaths"],
        "compiled-membership": ["evidence/mapping.json"],
        "build-provenance": ["evidence/mapping.json"],
        "relink-materials": subject["sourcePaths"],
    })
    specification["unresolved"] = []
    packet = tmp_path / "packet"
    report = provenance.build_source_packet(root, specification, packet)
    assert not report["complianceComplete"]
    with pytest.raises(ValueError, match="Compliance-complete claim refused"):
        validate(packet, report, require_compliance_complete=True)


def test_missing_source_recipe_patch_and_certifi_mapping_remain_visible(tmp_path):
    root, specification = packet_input(tmp_path)
    subject = specification["subjects"][0]
    subject["sourcePaths"] = []
    subject["evidence"] = {}
    certifi = copy.deepcopy(subject)
    certifi.update(id="certifi", name="certifi", version="2026.7.22", kind="python", derivative=False)
    specification["subjects"].append(certifi)
    report = provenance.build_source_packet(root, specification, tmp_path / "packet")
    categories = {row["category"] for row in report["missingEvidence"]}
    assert categories >= {"corresponding-source", "derivative-recipe", "derivative-patch", "covered-source-mapping"}


@pytest.mark.parametrize("bound,value", [
    ("MAX_FILES", 2), ("MAX_FILE_BYTES", 1), ("MAX_TOTAL_BYTES", 1),
    ("MAX_MANIFEST_BYTES", 1), ("MAX_SUBJECTS", 0),
])
def test_bounds_fail_before_output(tmp_path, monkeypatch, bound, value):
    root, specification = packet_input(tmp_path)
    monkeypatch.setattr(provenance, bound, value)
    with pytest.raises(ValueError):
        provenance.build_source_packet(root, specification, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_replaced_input_race_is_detected_before_output(tmp_path, monkeypatch):
    root, specification = packet_input(tmp_path)
    original = os.open
    changed = False

    def replace_before_open(path, flags, *args, **kwargs):
        nonlocal changed
        if path == "source.py" and not changed:
            changed = True
            (root / "source.py").rename(root / "previous")
            (root / "source.py").write_bytes((root / "previous").read_bytes())
            (root / "source.py").chmod(0o644)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(provenance.os, "open", replace_before_open)
    with pytest.raises(ValueError, match="changed"):
        provenance.build_source_packet(root, specification, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_manifest_pin_and_duplicate_json_keys_are_checked(tmp_path):
    _, _, packet, report = build(tmp_path)
    with pytest.raises(ValueError, match="digest"):
        provenance.validate_source_packet(packet, expected_manifest_sha256="0" * 64)
    manifest = packet / provenance.MANIFEST_NAME
    raw = manifest.read_bytes().replace(b'{\n', b'{"format":"duplicate",\n', 1)
    manifest.write_bytes(raw)
    with pytest.raises(ValueError, match="Duplicate JSON"):
        provenance.validate_source_packet(packet, expected_manifest_sha256=hashlib.sha256(raw).hexdigest())
    assert not report["complianceComplete"]


def test_aliases_join_transitively_without_mutating_subject_records():
    records = [
        {"id": "GHSA-one", "aliases": ["CVE-one"], "subject": "application"},
        {"id": "RUSTSEC-one", "aliases": ["CVE-two"], "subject": "cargo"},
        {"id": "CVE-two", "aliases": ["CVE-one"], "subject": "native"},
        {"id": "GHSA-separate", "aliases": [], "subject": "analyzer"},
    ]
    original = copy.deepcopy(records)
    assert provenance.advisory_alias_groups(records) == [
        ["CVE-one", "CVE-two", "GHSA-one", "RUSTSEC-one"], ["GHSA-separate"],
    ]
    assert records == original

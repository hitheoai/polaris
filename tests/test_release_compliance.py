"""Data-only fixtures: no package imports, installers, fetched code or network."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import socket
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compliance_test_builder", ROOT / "scripts/build_release_compliance.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def tar_content(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, content in entries:
            item = tarfile.TarInfo(name)
            item.mode = 0o644
            if isinstance(content, tuple):
                item.type, item.linkname = content
                archive.addfile(item)
            else:
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
    return result.getvalue()


def wheel_content(name, version, extras=None, *, license_text=b"Original fixture notice\n",
                  metadata_extra="", record=True):
    dist = f"{name.replace('-', '_')}-{version}.dist-info"
    entries = {
        f"{dist}/METADATA": (f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
                            "License-Expression: MIT\n" + metadata_extra).encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
        f"{name.replace('-', '_')}/__init__.py": b"raise AssertionError('package code must never execute')\n",
        **(extras or {}),
    }
    if license_text is not None:
        entries[f"{dist}/licenses/LICENSE"] = license_text
    if record:
        stream = io.StringIO()
        writer = csv.writer(stream, lineterminator="\n")
        for path, content in entries.items():
            encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
            writer.writerow([path, "sha256=" + encoded, len(content)])
        writer.writerow([f"{dist}/RECORD", "", ""])
        entries[f"{dist}/RECORD"] = stream.getvalue().encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as wheel:
        for path, content in entries.items():
            wheel.writestr(path, content)
    return out.getvalue()


def seal(bundle, manifest):
    (bundle / "manifest.json").write_bytes(builder.json_bytes(manifest))
    (bundle / "install-theo.sh").write_bytes(
        b"# NOT EXECUTABLE: synthetic fixture only\nMANIFEST_SHA256='"
        + builder.sha((bundle / "manifest.json").read_bytes()).encode() + b"'\n",
    )
    bootstrap = {k: manifest[k] for k in ("id", "version", "platform")}
    bootstrap["bootstrap"] = builder.pin((bundle / "install-theo.sh").read_bytes(), "install-theo.sh")
    (bundle / "bootstrap.json").write_bytes(builder.json_bytes(bootstrap))


def make_bundle(tmp_path, *, version="0.3.2"):
    bundle = tmp_path / "candidate"
    bundle.mkdir()
    packages = {"app": {"theovex-polaris": version, "shared": "1.0"},
                "analyzer": {"semgrep": "1.136.0", "shared": "1.0"}}
    payload = []
    for env, pins in packages.items():
        requirements = []
        for name, pinned in pins.items():
            wheel = wheel_content(name, pinned)
            filename = f"{name.replace('-', '_')}-{pinned}-py3-none-any.whl"
            payload.append((f"{env}/wheels/{filename}", wheel))
            requirements.append(f"{name}=={pinned} --hash=sha256:{builder.sha(wheel)}")
        payload.append((f"{env}/requirements.txt", ("\n".join(requirements) + "\n").encode()))
    (bundle / "payload.tar.gz").write_bytes(tar_content(payload))
    runtime = tar_content([
        ("python/bin/python3.11", bytes.fromhex("cffaedfe") + b"\0" * 60),
        ("python/bin/python3", (tarfile.SYMTYPE, "python3.11")),
        ("python/lib/LICENSE.txt", b"Original CPython fixture terms\n"),
        ("python/lib/site-packages/pip-24.0.dist-info/METADATA", b"Name: pip\nVersion: 24.0\n"),
        ("python/lib/site-packages/pip-24.0.dist-info/LICENSE", b"Original pip fixture terms\n"),
        ("python/lib/site-packages/pip/_vendor/vendor.txt", b"vendored==2.0\nunresolved>=1.0\n"),
        ("python/lib/ensurepip/_bundled/pip-23.0-py3-none-any.whl", wheel_content("pip", "23.0")),
    ])
    uv = tar_content([("uv/uv", bytes.fromhex("cffaedfe") + b"\0" * 60)])
    (bundle / "python.tar.gz").write_bytes(runtime)
    (bundle / "uv.tar.gz").write_bytes(uv)
    manifest = {
        "format": "polaris.theo-bundle/1", "id": f"theo-{version}-macos-arm64-r1",
        "version": version, "platform": "macos-arm64", "minimumMacOS": "15.0", "modelIncluded": False,
        "payload": builder.pin((bundle / "payload.tar.gz").read_bytes(), "payload.tar.gz"),
        "runtimes": {"python": {**builder.pin(runtime, "python.tar.gz"), "version": "3.11.16"},
                     "uv": {**builder.pin(uv, "uv.tar.gz"), "version": "0.12.20"}},
        "environments": packages,
    }
    seal(bundle, manifest)
    return bundle, manifest


@pytest.fixture
def candidate(tmp_path):
    return make_bundle(tmp_path)


def fingerprint(root):
    return {str(p.relative_to(root)): builder.sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}


def build(candidate, output, **kwargs):
    return builder.build(bundle_dir=candidate[0], output=output, **kwargs)


def supplement(tmp_path, subject, *, kind="license", content=b"Exact upstream fixture license\n",
               status="retrieved", **extra):
    folder = tmp_path / "supplements"
    folder.mkdir()
    record = {"id": "reviewed-evidence", "kind": kind, "subject": subject,
              "url": "https://raw.githubusercontent.com/official/project/0123456789/LICENSE",
              "revision": "0123456789", "retrievedAt": "2026-09-30T00:00:00Z", "status": status, **extra}
    if status == "retrieved":
        (folder / "evidence.txt").write_bytes(content)
        record.update(file="evidence.txt", bytes=len(content), sha256=builder.sha(content))
    (folder / "evidence.json").write_bytes(builder.json_bytes({
        "format": "polaris.compliance-evidence/1", "records": [record],
    }))
    return folder, record


def test_deterministic_outputs_original_notices_and_no_execution(candidate, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("no networking or subprocesses during offline assembly")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    before = fingerprint(candidate[0])
    result = build(candidate, tmp_path / "first")
    assert result["inventoryComplete"] and result["complete"] is False
    build(candidate, tmp_path / "second")
    assert fingerprint(tmp_path / "first") == fingerprint(tmp_path / "second")
    assert fingerprint(candidate[0]) == before
    inventory = json.loads((tmp_path / "first/inventory.json").read_bytes())
    assert inventory["counts"]["outerWheels"] == 4
    assert inventory["counts"]["outerNameVersionPairs"] == 3
    assert inventory["counts"]["componentsByKind"]["installed-distribution"] == 1
    assert inventory["counts"]["componentsByKind"]["ensurepip-wheel"] == 1
    assert inventory["counts"]["componentsByKind"]["vendored-declaration"] == 1
    assert inventory["counts"]["nativeFilesByFormat"]["Mach-O"] == 2
    assert b"Original fixture notice\n" in (tmp_path / "first/THIRD_PARTY_NOTICES.txt").read_bytes()
    assert {"native_build_provenance_unresolved", "corresponding_source_review_required",
            "advisory_coverage_unknown", "vendor_versions_unresolved"} <= {x["code"] for x in result["unresolved"]}
    for path in (tmp_path / "first").rglob("*"):
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize("version", ["0.3.2", "0.4.0", "1.2.3rc1", "9.2.7"])
def test_public_package_version_is_not_hardcoded(tmp_path, version):
    candidate = make_bundle(tmp_path, version=version)
    report = build(candidate, tmp_path / "output")
    assert report["release"]["version"] == version


def test_sbom_references_are_complete_and_declarations_are_not_compiled_proof(candidate, tmp_path):
    build(candidate, tmp_path / "out")
    doc = json.loads((tmp_path / "out/sbom.cdx.json").read_bytes())
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert "serialNumber" not in doc and "timestamp" not in doc["metadata"]
    refs = {item["bom-ref"] for item in doc["components"]}
    assert len(refs) == len(doc["components"])
    assert all(item["ref"] in refs and set(item["dependsOn"]) <= refs for item in doc["dependencies"])


def test_matching_notice_closes_only_missing_text_not_native_provenance(candidate, tmp_path):
    record = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": record["version"], "sha256": record["sha256"]}
    folder, _ = supplement(tmp_path, subject)
    report = build(candidate, tmp_path / "out", supplements=folder)
    inv = json.loads((tmp_path / "out/inventory.json").read_bytes())
    uv = next(c for c in inv["components"] if c["kind"] == "runtime" and c["name"] == "uv")
    codes = {p["code"] for p in report["unresolved"] if p["component"] == uv["id"]}
    assert "license_text_missing" not in codes
    assert "runtime_dependency_closure_unverified" in codes
    assert report["complete"] is False


def test_cargo_lock_is_inventory_not_claim_of_compilation(candidate, tmp_path):
    runtime = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": runtime["version"], "sha256": runtime["sha256"]}
    lock = b'version = 3\n[[package]]\nname = "crate_fixture"\nversion = "1.0.0"\n'
    folder, _ = supplement(tmp_path, subject, kind="dependency-lock", format="cargo-lock", content=lock)
    report = build(candidate, tmp_path / "out", supplements=folder)
    inv = json.loads((tmp_path / "out/inventory.json").read_bytes())
    crate = next(c for c in inv["components"] if c["kind"] == "cargo-declaration")
    assert crate["compiledIntoArtifact"] == "unverified" and crate["declarationOnly"]
    assert crate["name"] == "crate_fixture" and crate["hashScope"] == "declaration"
    assert any(x["component"] == crate["id"] and x["code"] == "declared_dependency_closure_unverified"
               for x in report["unresolved"])


def test_unavailable_advisories_are_not_clean_results(candidate, tmp_path):
    runtime = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": runtime["version"], "sha256": runtime["sha256"]}
    folder, _ = supplement(tmp_path, subject, kind="advisory", status="unavailable",
                           reason="official API unavailable")
    report = build(candidate, tmp_path / "out", supplements=folder)
    assert report["complete"] is False
    assert any(x["code"] == "advisory_coverage_unknown" for x in report["unresolved"])


@pytest.mark.parametrize("path", [
    "../escape", "/absolute", "root/../escape", "root//file", "./root/file",
    "root\\escape", "C:/escape", "root/\x00file", "root/\nfile", "e\u0301/file",
])
def test_unsafe_archive_paths_are_refused(path):
    with pytest.raises(ValueError):
        builder.archive_entries(tar_content([(path, b"x")]))


@pytest.mark.parametrize("paths", [
    [("root/one", b"x"), ("root/one", b"y")],
    [("root/One", b"x"), ("root/one", b"y")],
    [("root/parent", b"x"), ("root/parent/child", b"y")],
    [("root/PARENT", b"x"), ("root/parent/child", b"y")],
    [("root/implicit/one", b"x"), ("ROOT/implicit/two", b"y")],
    [("root/link", (tarfile.SYMTYPE, "../../escape"))],
    [("root/link", (tarfile.SYMTYPE, "missing"))],
    [("root/link", (tarfile.SYMTYPE, "other")), ("root/other", (tarfile.SYMTYPE, "link"))],
    [("root/link", (tarfile.SYMTYPE, "target")), ("root/link/child", b"x"), ("root/target", b"y")],
])
def test_ambiguous_links_and_collisions_are_refused(paths):
    with pytest.raises(ValueError):
        builder.archive_entries(tar_content(paths))


def test_valid_runtime_link_is_recorded_not_extracted():
    entries = builder.archive_entries(tar_content([
        ("python/bin/python3.11", b"data"), ("python/bin/python3", (tarfile.SYMTYPE, "python3.11")),
    ]))
    assert entries[1] == ("python/bin/python3", None, "python/bin/python3.11")


@pytest.mark.parametrize("kind", [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_special_tar_members_are_refused(kind):
    with pytest.raises(ValueError, match="Special"):
        builder.archive_entries(tar_content([("root/device", (kind, ""))]))


def test_wheel_symlink_refused():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        item = zipfile.ZipInfo("link")
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(item, "elsewhere")
    with pytest.raises(ValueError, match="linked"):
        builder.archive_entries(out.getvalue(), wheel=True)


@pytest.mark.parametrize("constant,value", [("MAX_FILE", 3), ("MAX_EXPANDED", 3), ("MAX_MEMBERS", 0)])
def test_expansion_and_count_limits_are_checked_before_read(monkeypatch, constant, value):
    data = tar_content([("root/data", b"long-content")])
    monkeypatch.setattr(builder, constant, value)
    with pytest.raises(ValueError, match="bound"):
        builder.archive_entries(data)


@pytest.mark.parametrize("bad", [
    b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
])
def test_noncanonical_json_rejected(bad):
    with pytest.raises(ValueError):
        builder.parse_json(bad)


@pytest.mark.parametrize("metadata_extra", ["Name: alternate\n", "Version: 9.9\n", "License-Expression: Apache-2.0\n"])
def test_ambiguous_wheel_metadata_refused(metadata_extra):
    content = wheel_content("example", "1.0", metadata_extra=metadata_extra)
    with pytest.raises(ValueError, match="Ambiguous"):
        builder.Inventory().wheel(content, "example-1.0-py3-none-any.whl", "wheel")


def test_wheel_filename_and_missing_record_refused():
    with pytest.raises(ValueError, match="filename"):
        builder.Inventory().wheel(wheel_content("example", "1.0"), "wrong-1.0-py3-none-any.whl", "wheel")
    with pytest.raises(ValueError, match="RECORD"):
        builder.Inventory().wheel(wheel_content("example", "1.0", record=False), "example-1.0-py3-none-any.whl", "wheel")


def test_tampered_record_refused():
    original = wheel_content("example", "1.0")
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original)) as source, zipfile.ZipFile(out, "w") as target:
        for name in source.namelist():
            target.writestr(name, b"changed" if name.endswith("__init__.py") else source.read(name))
    with pytest.raises(ValueError, match="RECORD"):
        builder.Inventory().wheel(out.getvalue(), "example-1.0-py3-none-any.whl", "wheel")


@pytest.mark.parametrize("filename", ["payload.tar.gz", "python.tar.gz", "uv.tar.gz", "install-theo.sh"])
def test_tampered_bundle_creates_no_output(candidate, tmp_path, filename):
    (candidate[0] / filename).write_bytes((candidate[0] / filename).read_bytes() + b"changed")
    with pytest.raises(ValueError, match="mismatch"):
        build(candidate, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_resealed_identity_and_environment_mismatch_refused(candidate, tmp_path):
    candidate[1]["environments"]["app"]["shared"] = "9.0"
    seal(*candidate)
    with pytest.raises(ValueError, match="inventory mismatch"):
        build(candidate, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_existing_and_overlapping_output_are_not_modified(candidate, tmp_path):
    folder = tmp_path / "existing"
    folder.mkdir()
    (folder / "sentinel").write_bytes(b"keep")
    before = fingerprint(folder)
    with pytest.raises(ValueError, match="new"):
        build(candidate, folder)
    assert fingerprint(folder) == before
    with pytest.raises(ValueError, match="overlap"):
        build(candidate, candidate[0] / "new")


def test_symlinked_inputs_or_output_parent_refused(candidate, tmp_path):
    link = tmp_path / "linked"
    link.symlink_to(candidate[0], target_is_directory=True)
    with pytest.raises(ValueError, match="canonical"):
        builder.build(bundle_dir=link, output=tmp_path / "out")
    parent = tmp_path / "linked-parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="canonical"):
        build(candidate, parent / "out")


@pytest.mark.parametrize("mutation", ["sha256", "version", "path", "url", "unavailable-bytes", "unknown-field"])
def test_supplement_tampering_and_unsafe_claims_are_refused(candidate, tmp_path, mutation):
    runtime = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": runtime["version"], "sha256": runtime["sha256"]}
    folder, record = supplement(tmp_path, subject)
    if mutation == "sha256":
        record["sha256"] = "0" * 64
    elif mutation == "version":
        record["subject"]["version"] = "99.0"
    elif mutation == "path":
        record["file"] = "../secret"
    elif mutation == "url":
        record["url"] = "https://user:private@example.invalid/license"
    elif mutation == "unavailable-bytes":
        record["status"] = "unavailable"
    else:
        record["legalApproved"] = True
    (folder / "evidence.json").write_bytes(builder.json_bytes({
        "format": "polaris.compliance-evidence/1", "records": [record],
    }))
    with pytest.raises(ValueError):
        build(candidate, tmp_path / "out", supplements=folder)
    assert not (tmp_path / "out").exists()


def test_generic_source_url_never_closes_copyleft_obligation(candidate, tmp_path):
    data, manifest = builder.load_bundle(candidate[0])
    inv = builder.collect_bundle(data, manifest)
    semgrep = next(c for c in inv.components if c["name"] == "semgrep")
    subject = {k: semgrep[k] for k in ("name", "version", "sha256")}
    folder, _ = supplement(tmp_path, subject, kind="source", content=b"incomplete source fragment\n")
    report = build(candidate, tmp_path / "out", supplements=folder)
    assert any(x["code"] == "corresponding_source_review_required" for x in report["unresolved"])
    assert report["complete"] is False


def test_input_change_during_inventory_is_refused(candidate, tmp_path, monkeypatch):
    original = builder.obligations
    def mutate(*args, **kwargs):
        (candidate[0] / "install-theo.sh").write_bytes(b"changed during operation")
        return original(*args, **kwargs)
    monkeypatch.setattr(builder, "obligations", mutate)
    with pytest.raises(ValueError, match="changed during"):
        build(candidate, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_cli_returns_distinct_incomplete_and_invalid_status(candidate, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["compliance", "--bundle-dir", str(candidate[0]), "--output", str(tmp_path / "out")])
    assert builder.main() == 2
    assert json.loads(capsys.readouterr().out)["complete"] is False
    monkeypatch.setattr("sys.argv", ["compliance", "--bundle-dir", str(candidate[0]), "--output", str(tmp_path / "out")])
    assert builder.main() == 1
    assert "rejected" in capsys.readouterr().out


@pytest.mark.parametrize("url", [
    "http://example.invalid/license", "https://user:private@example.invalid/license",
    "https://example.invalid/license?token=private", "https://example.invalid/license#fragment",
    "https://example.invalid:8443/license", "https://example.invalid/\nfile",
])
def test_unsafe_evidence_urls_do_not_echo_secrets(url):
    with pytest.raises(ValueError) as error:
        builder.https_url(url)
    assert "private" not in str(error.value)


def test_runtime_link_to_implicit_directory_is_valid():
    entries = builder.archive_entries(tar_content([
        ("python/lib/actual/member", b"data"), ("python/lib/link", (tarfile.SYMTYPE, "actual")),
    ]))
    assert entries[1] == ("python/lib/link", None, "python/lib/actual")


@pytest.mark.parametrize("findings,pagination,status", [
    ([], "", "queried-no-matches"),
    ([{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-09-29T00:00:00Z"}], "", "findings-require-review"),
    ([], "next-public-page", "pagination-incomplete"),
])
def test_advisory_results_bind_raw_query_response_and_never_clear(candidate, tmp_path, findings, pagination, status):
    component = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": component["version"], "sha256": component["sha256"], "ecosystem": "PyPI"}
    query = builder.json_bytes({"queries": [{"package": {"name": "uv", "ecosystem": "PyPI"},
                                            "version": component["version"]}]})
    response = builder.json_bytes({"results": [{"vulns": findings, "next_page_token": pagination}]})
    folder, _ = supplement(tmp_path, subject, kind="advisory", content=response,
                           url="https://api.osv.dev/v1/querybatch", format="osv-querybatch",
                           requestFile="request.json", requestSha256=builder.sha(query), queryIndex=0,
                           review="query-recorded-not-triaged")
    (folder / "request.json").write_bytes(query)
    report = build(candidate, tmp_path / "out", supplements=folder)
    result = report["advisoryResults"][0]
    assert result["status"] == status and not result["vulnerabilityFreeClaim"]
    assert result["advisoryIds"] == sorted(f["id"] for f in findings)
    assert result["responseSha256"] == builder.sha(response)
    assert (tmp_path / f"out/evidence/{builder.sha(query)}.data").read_bytes() == query
    assert not report["complete"]
    assert any(x["code"] == "advisory_triage_required" for x in report["unresolved"])


@pytest.mark.parametrize("mutation", ["query-version", "query-name", "query-ecosystem", "count", "index",
                                    "request-hash", "findings-shape", "result-error", "unknown-format", "host"])
def test_bad_advisory_binding_is_rejected(candidate, tmp_path, mutation):
    component = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": component["version"], "sha256": component["sha256"]}
    query = {"queries": [{"package": {"name": "uv", "ecosystem": "PyPI"}, "version": component["version"]}]}
    response = {"results": [{}]}
    if mutation == "query-version":
        query["queries"][0]["version"] = "999.0"
    if mutation == "query-name":
        query["queries"][0]["package"]["name"] = "wrong"
    if mutation == "query-ecosystem":
        query["queries"][0]["package"]["ecosystem"] = "crates.io"
    if mutation == "count":
        response["results"] = []
    if mutation == "findings-shape":
        response["results"] = [{"vulns": "not-a-list"}]
    if mutation == "result-error":
        response["results"] = [{"error": "upstream unavailable"}]
    raw = builder.json_bytes(query)
    folder, _ = supplement(
        tmp_path, subject, kind="advisory", content=builder.json_bytes(response),
        url="https://example.invalid/query" if mutation == "host" else "https://api.osv.dev/v1/querybatch",
        format="invented" if mutation == "unknown-format" else "osv-querybatch",
        requestFile="request.json", requestSha256="0" * 64 if mutation == "request-hash" else builder.sha(raw),
        queryIndex=5 if mutation == "index" else 0,
    )
    (folder / "request.json").write_bytes(raw)
    with pytest.raises(ValueError):
        build(candidate, tmp_path / "out", supplements=folder)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("version", ["0.12.20", "999.0"])
def test_pypi_advisory_version_binding(candidate, tmp_path, version):
    component = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": component["version"], "sha256": component["sha256"]}
    content = builder.json_bytes({"info": {"name": "uv", "version": version}, "vulnerabilities": []})
    folder, _ = supplement(tmp_path, subject, kind="advisory", content=content,
                           url=f"https://pypi.org/pypi/uv/{version}/json", format="pypi-version-json")
    if version != component["version"]:
        with pytest.raises(ValueError, match="subject mismatch"):
            build(candidate, tmp_path / "out", supplements=folder)
    else:
        report = build(candidate, tmp_path / "out", supplements=folder)
        assert report["advisoryResults"][0]["status"] == "queried-no-matches"
        assert not report["complete"]


def test_metadata_hash_is_not_a_claim_to_hash_an_installed_package_tree(candidate, tmp_path):
    build(candidate, tmp_path / "out")
    document = json.loads((tmp_path / "out/sbom.cdx.json").read_bytes())
    for component in document["components"]:
        properties = {p["name"]: p["value"] for p in component["properties"]}
        assert "polaris:evidence-sha256" in properties
        if properties["polaris:hash-scope"] in ("metadata", "declaration"):
            assert "hashes" not in component
        else:
            assert component["hashes"][0]["content"] == properties["polaris:evidence-sha256"]


def test_invalid_calendar_acquisition_time_is_refused(candidate, tmp_path):
    component = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": component["version"], "sha256": component["sha256"]}
    folder, _ = supplement(tmp_path, subject, retrievedAt="2026-99-31T00:00:00Z")
    with pytest.raises(ValueError):
        build(candidate, tmp_path / "out", supplements=folder)


def test_duplicate_components_are_refused():
    inventory = builder.Inventory()
    inventory.component("cargo-declaration", "a", b"declaration", name="crate_fixture", version="1.0")
    with pytest.raises(ValueError, match="Duplicate"):
        inventory.component("cargo-declaration", "a", b"declaration", name="crate_fixture", version="1.0")


def test_source_license_conflict_is_never_silently_resolved():
    inventory = builder.Inventory()
    inventory.component("wheel", "semgrep.whl", b"data", name="semgrep", version="1.136.0",
                        details={"declaredLicense": "LGPL-2.1-or-later"})
    policy = json.loads(builder.POLICY.read_bytes())
    findings = builder.obligations(inventory, [], policy)
    assert any(f["code"] == "source_license_declaration_conflict" for f in findings)


def test_first_party_package_is_not_marked_missing_external_advisories():
    inventory = builder.Inventory()
    item = inventory.component("wheel", "first-party.whl", b"data", name="theovex-polaris", version="0.3.2")
    builder.Inventory.notice(inventory, item, "LICENSE", b"Original first-party terms")
    policy = json.loads(builder.POLICY.read_bytes())
    assert not builder.obligations(inventory, [], policy)


@pytest.mark.parametrize("status", ["unknown", "unavailable"])
def test_generic_incomplete_evidence_is_an_explicit_report_blocker(candidate, tmp_path, status):
    runtime = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": runtime["version"], "sha256": runtime["sha256"]}
    folder, record = supplement(tmp_path, subject, kind="build-metadata", status=status,
                                reason="Exact originating build process has not been established.")
    report = build(candidate, tmp_path / "out", supplements=folder)
    findings = [r for r in report["unresolved"] if r["code"] == "supplement_evidence_unresolved"]
    assert len(findings) == 1
    assert record["id"] in findings[0]["detail"] and status in findings[0]["detail"]
    assert not report["complete"]


def test_pure_assembly_is_replayable_without_creating_files(candidate, tmp_path):
    before = fingerprint(tmp_path)
    outputs = builder.assemble(bundle_dir=candidate[0])
    assert fingerprint(tmp_path) == before
    report = json.loads(outputs["compliance-report.json"])
    assert report["format"] == "polaris.release-compliance/2" and report["stage"] == "observations"
    assert report["original"] == report["unresolved"] and report["resolved"] == []
    assert not report["readyForSigning"] and not report["complete"]
    builder.write_outputs(tmp_path / "written", outputs)
    assert {name: builder.sha(content) for name, content in outputs.items()} == fingerprint(tmp_path / "written")


def test_nested_supplement_inputs_are_preserved_for_replay(candidate, tmp_path):
    runtime = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": runtime["version"], "sha256": runtime["sha256"]}
    folder, record = supplement(tmp_path, subject)
    nested = folder / "raw/nested"
    nested.mkdir(parents=True)
    (folder / record["file"]).rename(nested / "license.txt")
    record["file"] = "raw/nested/license.txt"
    manifest = builder.json_bytes({"format": "polaris.compliance-evidence/1", "records": [record]})
    (folder / "evidence.json").write_bytes(manifest)
    build(candidate, tmp_path / "out", supplements=folder)
    assert (tmp_path / "out/inputs/supplements/evidence.json").read_bytes() == manifest
    assert (tmp_path / "out/inputs/supplements/raw/nested/license.txt").read_bytes() == b"Exact upstream fixture license\n"
    assert all(stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
               for path in (tmp_path / "out").rglob("*"))


@pytest.mark.parametrize("outputs", [
    {"../outside": b"x"}, {"a": b"x", "a/b": b"y"}, {"A/one": b"x", "a/two": b"y"},
])
def test_output_names_are_validated_before_creating_a_directory(tmp_path, outputs):
    output = tmp_path / "out"
    with pytest.raises(ValueError):
        builder.write_outputs(output, outputs)
    assert not output.exists()

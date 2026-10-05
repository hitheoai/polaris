"""Signing/notary fixtures never use credentials, sign code or submit to Apple."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from compliance_resolution_fixtures import synthetic_compliance
from test_homebrew_packaging import builder, tar_bytes
from test_homebrew_packaging import candidate as candidate
from test_release_native import binary

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("macos_release_test", ROOT / "scripts/macos_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.fixture(autouse=True)
def no_apple_tools(monkeypatch):
    monkeypatch.setattr(release, "tool", lambda *a, **kw: pytest.fail("An Apple tool was invoked."))


@pytest.fixture
def binding(candidate, monkeypatch, tmp_path):
    monkeypatch.setattr(release, "helpers", lambda: builder)
    inputs, manifest, *_ = candidate
    _, pins, _ = builder.inspect_bundle(inputs["bundle_dir"])
    directory = tmp_path.resolve() / "compliance"
    directory.mkdir()
    for name, data in {"inventory.json": b"{}", "sbom.cdx.json": b"{}",
                       "THIRD_PARTY_NOTICES.txt": b"Fixture notices, not legal approval."}.items():
        (directory / name).write_bytes(data)
    files = [builder.artifact(path) for path in sorted(directory.iterdir())]
    report = {
        "format": "polaris.release-compliance/1",
        "release": {key: manifest[key] for key in ("id", "version", "platform")},
        "inputArtifacts": list(pins.values()), "inventoryComplete": True, "complete": False,
        "inventorySha256": builder.artifact(directory / "inventory.json")["sha256"],
        "files": files, "unresolved": [{"code": "source_closure_missing"}],
    }
    (directory / "compliance-report.json").write_bytes(builder.json_bytes(report))
    return inputs["bundle_dir"], manifest, pins, directory, report


def test_credential_free_preflight_keeps_incomplete_evidence_blocked(binding):
    bundle, _, _, directory, _ = binding
    report = release.preflight(bundle, directory, ROOT / "packaging/macos-publisher.example.json")
    assert report["readyToSign"] is False and report["blockers"]
    assert report["unresolvedComplianceCount"] == 1
    assert report["credentialsUsed"] is report["signingPerformed"] is report["notarizationSubmitted"] is False


def test_complete_inventory_is_not_complete_compliance(binding):
    _, manifest, pins, directory, _ = binding
    report = release.compliance(directory, pins, manifest)
    assert report["inventoryComplete"] is True and report["complete"] is False
    with pytest.raises(ValueError, match="Unresolved"):
        release.compliance(directory, pins, manifest, complete=True)


def test_historical_complete_report_cannot_authorize_new_signing(binding):
    bundle, manifest, pins, directory, report = binding
    report.update(complete=True, unresolved=[])
    (directory / "compliance-report.json").write_bytes(builder.json_bytes(report))
    assert release.compliance(directory, pins, manifest)["complete"] is True
    with pytest.raises(ValueError, match="Historical"):
        release.compliance(
            directory, pins, manifest, complete=True, bundle_dir=bundle,
            authorization=valid_config()["complianceAuthorization"],
        )


@pytest.mark.parametrize("mutation", ["missing-input", "changed-input", "duplicate-input", "extra-output",
                                     "missing-output", "changed-output", "inventory-pin", "wrong-release"])
def test_compliance_requires_exact_input_and_output_bindings(binding, mutation):
    _, manifest, pins, directory, report = binding
    if mutation == "missing-input":
        report["inputArtifacts"].pop()
    elif mutation == "changed-input":
        report["inputArtifacts"][0] = {**report["inputArtifacts"][0], "sha256": "0" * 64}
    elif mutation == "duplicate-input":
        report["inputArtifacts"].append(report["inputArtifacts"][0])
    elif mutation == "extra-output":
        (directory / "unreviewed").write_bytes(b"unreviewed")
    elif mutation == "missing-output":
        (directory / "THIRD_PARTY_NOTICES.txt").unlink()
    elif mutation == "changed-output":
        (directory / "THIRD_PARTY_NOTICES.txt").write_bytes(b"changed")
    elif mutation == "inventory-pin":
        report["inventorySha256"] = "0" * 64
    else:
        report["release"] = {**report["release"], "version": "999"}
    (directory / "compliance-report.json").write_bytes(builder.json_bytes(report))
    with pytest.raises(ValueError):
        release.compliance(directory, pins, manifest)


def test_staging_exposes_all_unique_native_bytes_without_signing_or_mutating_inputs(binding, tmp_path):
    bundle, manifest, pins, _, _ = binding
    output = tmp_path.resolve() / "stage"
    result = release.stage(bundle, output)
    expected = {item["sha256"] for item in manifest["nativeCompatibility"]["files"]}
    assert set(result["targets"]) == expected
    assert result["release"] != result["sourceRelease"]
    assert result["signingPerformed"] is result["notarizationSubmitted"] is False
    for key, target in result["targets"].items():
        assert builder.artifact(output / target["path"])["sha256"] == key
    assert {name: builder.artifact(bundle / name) for name in pins} == pins
    with pytest.raises(ValueError, match="new"):
        release.stage(bundle, output)
    with pytest.raises(ValueError, match="outside"):
        release.stage(bundle, bundle / "unsafe-output")


def test_approval_is_required_before_any_files_tools_or_credentials(tmp_path):
    absent = tmp_path / "absent"
    output = tmp_path / "must-not-exist"
    with pytest.raises(ValueError, match="approve-signing"):
        release.sign(absent, absent, absent, output)
    with pytest.raises(ValueError, match="approve-submit"):
        release.notarize_payload(absent, absent, output)
    with pytest.raises(ValueError, match="approvals"):
        release.dmg(absent, absent, absent, absent, output)
    assert not output.exists()


def valid_config():
    return {"format": "polaris.macos-publisher/2", "approved": True,
            "publisherRepository": "fixture-publisher/cli", "downloadOrigin": "https://downloads.fixture.test",
            "sourceRevision": "a" * 40, "complianceReportSha256": "b" * 64,
            "certificateSha1": "C" * 40, "teamId": "ABCDE12345", "identifierPrefix": "com.fixture.cli",
            "legalApproval": "Synthetic test decision, not an actual legal approval.",
            "sourceBundleDirectory": "/synthetic-source-bundle",
            "complianceAuthorization": {"path": "/synthetic-owner-authorization.json", "sha256": "d" * 64},
            "notaryKeychainProfile": "fixture-existing-profile"}


@pytest.mark.parametrize("field,value", [
    ("approved", False), ("certificateSha1", "-"), ("certificateSha1", "0" * 40),
    ("teamId", "wrong"), ("identifierPrefix", "unsafe;command"),
    ("publisherRepository", "owner/repository"), ("downloadOrigin", "https://example.com"),
    ("downloadOrigin", "https://user:synthetic-secret@fixture.test"), ("sourceRevision", "0" * 40),
    ("complianceReportSha256", None), ("legalApproval", ""),
    ("format", "polaris.macos-publisher/1"), ("sourceBundleDirectory", "relative/bundle"),
    ("complianceAuthorization", None),
    ("complianceAuthorization", {"path": "relative/authorization", "sha256": "d" * 64}),
    ("complianceAuthorization", {"path": "/fixture-authorization", "sha256": "wrong"}),
])
def test_distribution_configuration_rejects_placeholders_and_unapproved_values(tmp_path, field, value):
    config = {**valid_config(), field: value}
    path = tmp_path.resolve() / "publisher.json"
    path.write_bytes(builder.json_bytes(config))
    with pytest.raises(ValueError) as error:
        release.configuration(path)
    assert "synthetic-secret" not in str(error.value)


def make_wheel(*, native=True, detached=False):
    directory = "fixture-1.0.dist-info"
    files = {
        directory + "/METADATA": b"Metadata-Version: 2.3\nName: fixture\nVersion: 1.0\n",
        directory + "/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
        "fixture/module.py": b"# Fixture data only.\n",
    }
    if native:
        files["fixture/library.so"] = binary(kind=6)
    rows = io.StringIO(newline="")
    writer = csv.writer(rows, lineterminator="\n")
    for name, data in files.items():
        writer.writerow((name, release.record_hash(data), len(data)))
    writer.writerow((directory + "/RECORD", "", ""))
    files[directory + "/RECORD"] = rows.getvalue().encode()
    if detached:
        files[directory + "/RECORD.jws"] = b"Old detached-signature fixture."
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return result.getvalue(), files


def test_signing_derivatives_regenerate_record_but_preserve_upstream_wheel_bytes():
    content, original = make_wheel(detached=True)
    key = hashlib.sha256(original["fixture/library.so"]).hexdigest()
    replacement = original["fixture/library.so"] + b"synthetic changed signature bytes"
    changed = release.transform_wheel(content, {key: replacement})
    assert changed != content
    record, observed, _ = release.wheel_record(changed)
    assert observed["fixture/library.so"] == replacement
    assert observed["fixture/module.py"] == original["fixture/module.py"]
    assert record + ".jws" not in observed
    assert release.wheel_record(content)[1] == original
    assert release.transform_wheel(content, {key: replacement}) == changed


def test_unchanged_pure_wheels_retain_their_exact_upstream_hash():
    content, _ = make_wheel(native=False)
    assert release.transform_wheel(content, {}) == content


def test_missing_native_coverage_or_corrupt_record_never_becomes_a_signed_derivative():
    content, _ = make_wheel()
    with pytest.raises(ValueError, match="coverage"):
        release.transform_wheel(content, {})
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(content)) as original, zipfile.ZipFile(output, "w") as changed:
        for name in original.namelist():
            changed.writestr(name, b"changed" if name.endswith("module.py") else original.read(name))
    with pytest.raises(ValueError, match="RECORD content"):
        release.transform_wheel(output.getvalue(), {})


@pytest.mark.parametrize("mutation", ["status", "log-status", "id", "hash", "coverage"])
def test_notary_acceptance_requires_exact_submission_digest_and_every_native_cdhash(mutation):
    submission = {"id": "12345678-1234-1234-1234-123456789abc", "status": "Accepted"}
    pin = {"sha256": "a" * 64}
    log = {"jobId": submission["id"], "status": "Accepted", "sha256": pin["sha256"],
           "ticketContents": [{"cdhash": "b" * 40}, {"cdhash": "c" * 40}]}
    release.validate_notary(submission, log, pin, {"b" * 40, "c" * 40})
    if mutation == "status":
        submission["status"] = "Invalid"
    elif mutation == "log-status":
        log["status"] = "In Progress"
    elif mutation == "id":
        log["jobId"] = "different"
    elif mutation == "hash":
        log["sha256"] = "0" * 64
    else:
        log["ticketContents"].pop()
    with pytest.raises(ValueError):
        release.validate_notary(submission, log, pin, {"b" * 40, "c" * 40})


@pytest.mark.parametrize("missing", [None, "team", "timestamp", "runtime", "cdhash", "entitlements"])
def test_signature_verification_checks_identity_timestamp_runtime_and_no_blanket_entitlements(
    tmp_path, monkeypatch, missing,
):
    config = valid_config()
    path = tmp_path.resolve() / "native"
    path.write_bytes(binary())
    observed = []

    def fake_tool(command, **kwargs):
        observed.append(command)
        if "--verify" in command:
            assert "--strict" in command and "--all-architectures" in command
            assert config["certificateSha1"] in command[command.index("--test-requirement") + 1]
            return "", ""
        if "--entitlements" in command:
            if missing == "entitlements":
                return '<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>', ""
            return "", ""
        lines = ["Authority=Developer ID Application: Fixture (ABCDE12345)",
                 "TeamIdentifier=" + ("WRONG12345" if missing == "team" else config["teamId"])]
        if missing != "timestamp":
            lines.append("Timestamp=fixture")
        if missing != "runtime":
            lines.append("CodeDirectory flags=0x10000(runtime)")
        if missing != "cdhash":
            lines.append("CDHash=" + "b" * 40)
        return "", "\n".join(lines)

    monkeypatch.setattr(release, "tool", fake_tool)
    if missing is None:
        result = release.verify_signature(path, config)
        assert result["developerIdVerified"] is True
    else:
        with pytest.raises(ValueError):
            release.verify_signature(path, config)
    assert observed
    assert all("--deep" not in command and "--sign" not in command for command in observed)


def test_cli_rejects_secret_like_unknown_arguments_without_echoing_them():
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/macos_release.py"),
                             "sign", "--unknown=synthetic-do-not-echo"],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "synthetic-do-not-echo" not in result.stdout + result.stderr


@pytest.fixture
def signing_case(candidate, tmp_path, monkeypatch):
    """Real repacking with explicitly simulated OS tools and independent source approval."""
    inputs, manifest, source_files, payload = candidate
    bundle = inputs["bundle_dir"]
    payload["app/wheels/theovex_polaris-0.3.3-py3-none-any.whl"] = payload.pop(
        "app/wheels/theovex-polaris-0.3.3-py3-none-any.whl",
    )
    tar_bytes(bundle / "payload.tar.gz", payload)
    manifest["payload"] = builder.artifact(bundle / "payload.tar.gz")
    manifest["nativeCompatibility"] = builder.native_inventory(bundle, manifest)
    (bundle / "manifest.json").write_bytes(builder.json_bytes(manifest))
    modules = {name: release.script(name) for name in (
        "build_public_wheel", "build_theo_release", "release_native", "analyzer_delivery", "source_delivery",
    )}
    source_validator = modules["source_delivery"].validate_archive

    def simulated_source_approval(path, pin, *, require_compliance_complete=False, **kwargs):
        # Test-only simulation: actual packet integrity still runs. The production
        # preparation validator can never approve compliance (tested separately).
        return source_validator(path, pin, **kwargs)

    monkeypatch.setattr(modules["source_delivery"], "validate_archive", simulated_source_approval)
    monkeypatch.setattr(release, "script", lambda name: modules[name])
    monkeypatch.setattr(release, "helpers", lambda: builder)
    monkeypatch.setattr(release, "ROOT", builder.ROOT)
    for name in ("install-theo.sh", "bootstrap.json"):
        (bundle / name).unlink()
    modules["build_theo_release"].render_bootstrap(bundle, manifest)
    for name, data in source_files.items():
        relative = name.removeprefix("theovex_polaris-0.3.3/")
        if relative.startswith("src/polaris/"):
            path = builder.ROOT / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    _, pins, _ = builder.inspect_bundle(bundle)
    compliance = tmp_path.resolve() / "complete-fixture-compliance"
    evaluated = synthetic_compliance(bundle, compliance)
    modules["release_compliance_resolution"] = evaluated["resolver"]
    config = {
        **valid_config(),
        "complianceReportSha256": builder.artifact(compliance / "compliance-report.json")["sha256"],
        "sourceBundleDirectory": str(bundle),
        "complianceAuthorization": {
            "path": str(evaluated["authorization_path"]), "sha256": evaluated["authorization_sha256"],
        },
    }
    config_path = tmp_path.resolve() / "publisher-fixture.json"
    config_path.write_bytes(builder.json_bytes(config))
    calls = []

    def fake_tool(command, **kwargs):
        calls.append(command)
        if command[0] == "/usr/bin/git":
            return (config["sourceRevision"] + "\n", "") if "rev-parse" in command else ("", "")
        if command[0] == "/usr/bin/security":
            return f'  1) {config["certificateSha1"]} "Developer ID Application: Fixture ({config["teamId"]})"\n', ""
        if command[:3] == ["/usr/bin/xcrun", "stapler", "validate"]:
            return "", ""
        assert command[0] == "/usr/bin/codesign", command
        path = Path(command[-1])
        if "--sign" in command:
            assert "--timestamp" in command and "--deep" not in command
            path.write_bytes(path.read_bytes() + b"\nSYNTHETIC-TEST-SIGNATURE")
            return "", ""
        assert path.read_bytes().endswith(b"\nSYNTHETIC-TEST-SIGNATURE")
        if "--verify" in command or "--entitlements" in command:
            return "", ""
        return "", (
            f"Authority=Developer ID Application: Fixture ({config['teamId']})\n"
            f"TeamIdentifier={config['teamId']}\nTimestamp=synthetic-fixture\n"
            f"CodeDirectory flags=0x10000(runtime)\nCDHash={builder.artifact(path)['sha256'][:40]}\n"
        )

    monkeypatch.setattr(release, "tool", fake_tool)
    monkeypatch.setattr(release.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(release.platform, "machine", lambda: "arm64")
    stage = tmp_path.resolve() / "stage"
    release.stage(bundle, stage)
    return {
        "bundle": bundle, "manifest": manifest, "pins": pins, "stage": stage,
        "compliance": compliance, "config": config, "config_path": config_path,
        "output": tmp_path.resolve() / "signed-fixture", "source": inputs["source_archive"],
        "payload": payload, "calls": calls, "evaluated": evaluated,
        "source_delivery": modules["source_delivery"], "source_validator": source_validator,
    }


def sign_fixture(case):
    return release.sign(case["stage"], case["compliance"], case["config_path"], case["output"], approved=True)


def test_full_synthetic_signing_preserves_inputs_and_binds_every_derivative(signing_case):
    case = signing_case
    result = sign_fixture(case)
    signed = Path(result["bundle"])
    manifest, pins, _ = builder.inspect_bundle(signed)
    assert manifest["id"] == builder.SIGNED_RELEASE_ID != case["manifest"]["id"]
    assert len(pins) == 9 and result["notarized"] is False
    assert {name: builder.artifact(case["bundle"] / name) for name in case["pins"]} == case["pins"]
    for component in ("python", "uv"):
        assert manifest["runtimes"][component]["upstream"] == case["manifest"]["runtimes"][component]
    assert manifest["payload"]["sha256"] != case["manifest"]["payload"]["sha256"]
    with tarfile.open(signed / "payload.tar.gz", "r:gz") as archive:
        for member in archive:
            if member.name.endswith(".whl"):
                release.wheel_record(archive.extractfile(member).read())
    verified = release.verify_signed(signed, case["config"])
    assert verified["signaturesVerified"] and verified["bundle"] == pins
    assert len(verified["nativeSignatures"]) == len({
        item["sha256"] for item in manifest["nativeCompatibility"]["files"]
    })
    signing = [command for command in case["calls"] if "--sign" in command]
    assert len(signing) == 2
    assert "--options" not in signing[0] and "--options" in signing[1]
    assert not any("notarytool" in command for command in case["calls"])
    report = json.loads((signed / "signing-report.json").read_bytes())
    assert report["complianceAuthorizationSha256"] == case["config"]["complianceAuthorization"]["sha256"]
    assert report["complianceLedgerSha256"] == case["evaluated"]["report"]["ledgerSha256"]

def test_real_preparation_source_gate_blocks_before_any_signing_tool(signing_case, monkeypatch):
    case = signing_case
    monkeypatch.setattr(case["source_delivery"], "validate_archive", case["source_validator"])
    with pytest.raises(ValueError, match="Compliance-complete"):
        sign_fixture(case)
    assert not case["output"].exists()
    assert not case["calls"]


@pytest.mark.parametrize("mutation", ["stale-input", "missing-target", "target-path", "target-bytes",
                                     "incomplete-compliance", "source-file", "omitted-source", "installer",
                                     "changed-authority", "resealed-compliance", "wrong-original-bundle"])
def test_signing_refuses_stale_unbound_or_incomplete_inputs_before_identity_use(signing_case, mutation):
    case = signing_case
    prepared = json.loads((case["stage"] / "stage.json").read_bytes())
    target = next(iter(prepared["targets"].values()))
    if mutation == "stale-input":
        prepared["inputs"]["payload.tar.gz"]["sha256"] = "0" * 64
    elif mutation == "missing-target":
        prepared["targets"].pop(next(iter(prepared["targets"])))
    elif mutation == "target-path":
        target["path"] = "../outside"
    elif mutation == "target-bytes":
        (case["stage"] / target["path"]).write_bytes(b"altered")
    elif mutation == "incomplete-compliance":
        path = case["compliance"] / "compliance-report.json"
        report = json.loads(path.read_bytes())
        report["complete"] = False
        path.write_bytes(builder.json_bytes(report))
    elif mutation == "changed-authority":
        path = case["evaluated"]["authorization_path"]
        path.write_bytes(path.read_bytes() + b"\n")
    elif mutation == "resealed-compliance":
        path = case["compliance"] / "compliance-report.json"
        report = json.loads(path.read_bytes())
        report["technicalComplete"] = False
        path.write_bytes(builder.json_bytes(report))
        case["config"]["complianceReportSha256"] = builder.artifact(path)["sha256"]
        case["config_path"].write_bytes(builder.json_bytes(case["config"]))
    elif mutation == "wrong-original-bundle":
        case["config"]["sourceBundleDirectory"] = str(case["bundle"].parent)
        case["config_path"].write_bytes(builder.json_bytes(case["config"]))
    elif mutation == "source-file":
        (builder.ROOT / "src/polaris/cli.py").write_bytes(b"altered")
    elif mutation == "omitted-source":
        (builder.ROOT / "src/polaris/review/extra.py").write_bytes(b"extra")
    else:
        path = case["bundle"] / "install-theo.sh"
        path.write_bytes(path.read_bytes() + b"\n# Unapproved bootstrap change.\n")
        control = json.loads((case["bundle"] / "bootstrap.json").read_bytes())
        control["bootstrap"].update({key: builder.artifact(path)[key] for key in ("bytes", "sha256")})
        (case["bundle"] / "bootstrap.json").write_bytes(builder.json_bytes(control))
    (case["stage"] / "stage.json").write_bytes(builder.json_bytes(prepared))
    with pytest.raises(ValueError):
        sign_fixture(case)
    assert not case["output"].exists()
    assert not case["calls"]


def test_approved_source_handles_empty_markers_and_requires_complete_public_tree(signing_case):
    _, _, package = builder.inspect_bundle(signing_case["bundle"])
    assert (builder.ROOT / "src/polaris/py.typed").stat().st_size == 0
    release.source_package(package)
    del package["py.typed"]
    with pytest.raises(ValueError, match="complete public wheel"):
        release.source_package(package)


def test_bootstrap_cannot_be_replaced_and_merely_rehashed(signing_case):
    bundle = signing_case["bundle"]
    release.verify_installer(bundle, signing_case["manifest"])
    path = bundle / "install-theo.sh"
    path.write_bytes(path.read_bytes() + b"\n# Unapproved replacement.\n")
    with pytest.raises(ValueError, match="approved installer"):
        release.verify_installer(bundle, signing_case["manifest"])


def test_shipped_compliance_cannot_be_replaced_and_merely_rehashed(signing_case):
    case = signing_case
    signed = Path(sign_fixture(case)["bundle"])
    report = json.loads((signed / "signing-report.json").read_bytes())
    release.verify_shipped_compliance(signed, report, case["config"])
    path = case["compliance"] / "THIRD_PARTY_NOTICES.txt"
    path.write_bytes(b"Altered legal notices.")
    (signed / "compliance.tar.gz").unlink()
    report["complianceFiles"] = release.archive_tree(case["compliance"], signed / "compliance.tar.gz")
    with pytest.raises(ValueError, match="file binding"):
        release.verify_shipped_compliance(signed, report, case["config"])


def test_shipped_compliance_rechecks_external_authorization(signing_case):
    case = signing_case
    signed = Path(sign_fixture(case)["bundle"])
    report = json.loads((signed / "signing-report.json").read_bytes())
    authority = case["evaluated"]["authorization_path"]
    authority.write_bytes(authority.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="independently approved digest"):
        release.verify_shipped_compliance(signed, report, case["config"])


def test_shipped_compliance_requires_retained_exact_original_bundle(signing_case):
    case = signing_case
    signed = Path(sign_fixture(case)["bundle"])
    report = json.loads((signed / "signing-report.json").read_bytes())
    (case["bundle"] / "install-theo.sh").write_bytes(b"Different unsigned source artifact.")
    with pytest.raises(ValueError):
        release.verify_shipped_compliance(signed, report, case["config"])

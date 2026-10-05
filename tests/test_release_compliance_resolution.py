"""Offline closure protocol: all owner decisions and raw evidence here are synthetic."""

from __future__ import annotations

import copy
import datetime
import json
import os
import socket
import subprocess

import jsonschema
import pytest
import test_homebrew_packaging as packaging_fixtures
from compliance_resolution_fixtures import (
    ROOT,
    collector,
    evaluate_synthetic,
    reseal_synthetic,
    resolver,
    synthetic_compliance,
    synthetic_resolution_inputs,
    verify_synthetic,
)
from test_homebrew_packaging import seal_bundle, tar_bytes
from test_release_compliance import candidate as candidate
from test_release_compliance import fingerprint, seal, supplement, tar_content

NOW = datetime.datetime(2026, 9, 30, 12, tzinfo=datetime.UTC)
packaging_candidate = packaging_fixtures.candidate


@pytest.fixture
def case(candidate, tmp_path):
    return synthetic_resolution_inputs(candidate[0], tmp_path / "decisions-input", now=NOW)


def prune_decisions(case, keep):
    case["ledger"]["decisions"] = [decision for decision in case["ledger"]["decisions"] if keep(decision)]
    used = {value for decision in case["ledger"]["decisions"] for value in decision["evidenceSha256s"]}
    retained = []
    for record in case["ledger"]["evidence"]:
        if record["sha256"] in used:
            retained.append(record)
        else:
            (case["evidence_dir"] / record["file"]).unlink()
    case["ledger"]["evidence"] = retained
    scopes = {value for record in retained for value in record["fileScopeSha256s"]}
    case["ledger"]["fileScopes"] = {key: value for key, value in case["ledger"]["fileScopes"].items() if key in scopes}
    reseal_synthetic(case)


def with_advisory(candidate, tmp_path, *, acquired="2026-09-30T00:00:00Z", matches=True):
    runtime = candidate[1]["runtimes"]["uv"]
    subject = {"name": "uv", "version": runtime["version"], "sha256": runtime["sha256"], "ecosystem": "PyPI"}
    request = collector.json_bytes({"queries": [{"package": {"name": "uv", "ecosystem": "PyPI"},
                                                "version": runtime["version"]}]})
    response = collector.json_bytes({"results": [{"vulns": [{"id": "GHSA-synthetic-fixture"}] if matches else []}]})
    folder, _ = supplement(
        tmp_path, subject, kind="advisory", content=response, url="https://api.osv.dev/v1/querybatch",
        format="osv-querybatch", requestFile="request.json", requestSha256=collector.sha(request),
        queryIndex=0, review="query-recorded-not-triaged", retrievedAt=acquired,
    )
    (folder / "request.json").write_bytes(request)
    return synthetic_resolution_inputs(candidate[0], tmp_path / "advisory-input", now=NOW, supplements=folder)


def test_full_review_is_replayed_not_trusted_and_is_deterministic(case, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline resolution must not execute programs or use the network.")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    before = fingerprint(case["bundle_dir"])
    observations = fingerprint(case["observations_dir"])
    first = evaluate_synthetic(case, tmp_path / "first")
    assert first["format"] == "polaris.release-compliance/2" and first["stage"] == "evaluated"
    assert first["complete"] and first["technicalComplete"] and first["legalAuthorized"] and first["securityAuthorized"]
    assert first["readyForSigning"] and first["unresolved"] == []
    assert len(first["original"]) == len(first["resolved"]) > 0
    assert not first["vulnerabilityFreeClaim"] and not first["trustedCIBuildProvenance"]
    assert first["localEvidenceOnly"] and first["sourceObligationsRemainApplicable"]
    assert verify_synthetic(case, tmp_path / "first") == first
    assert evaluate_synthetic(case, tmp_path / "second") == first
    assert fingerprint(tmp_path / "first") == fingerprint(tmp_path / "second")
    assert fingerprint(case["bundle_dir"]) == before and fingerprint(case["observations_dir"]) == observations
    assert all("OWNER" not in name for name in fingerprint(tmp_path / "first"))


def test_schema_and_runtime_fixture_contract_agree(case):
    schema = json.loads((ROOT / "packaging/compliance/resolution.schema.json").read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    validator.validate(case["ledger"])
    validator.validate(case["authorization"])


def test_template_is_empty_and_cannot_imply_approval(case):
    template = case["template"]
    assert template["targets"] and template["availableFileScopes"]
    fresh = resolver.decision_template(bundle_dir=case["bundle_dir"], observations_dir=case["observations_dir"])
    assert fresh["ledger"]["decisions"] == fresh["ledger"]["evidence"] == []
    assert fresh["ledger"]["fileScopes"] == {}
    raw = json.loads((case["observations_dir"] / "compliance-report.json").read_bytes())
    assert not raw["complete"] and not raw["readyForSigning"]


def test_missing_legal_decisions_do_not_collapse_technical_and_security_status(case, tmp_path):
    prune_decisions(case, lambda decision: decision["domain"] != "legal")
    report = evaluate_synthetic(case, tmp_path / "partial")
    assert report["technicalComplete"] and report["securityAuthorized"]
    assert not report["legalAuthorized"] and not report["complete"] and report["unresolved"]
    assert all(item["missingDomains"] == ["legal"] for item in report["unresolved"])
    with pytest.raises(ValueError, match="Unresolved"):
        verify_synthetic(case, tmp_path / "partial")


@pytest.mark.parametrize("field", [
    "inventorySha256", "policySha256", "toolManifestSha256",
    "observationReportSha256", "observationSetSha256",
])
def test_stale_binding_even_with_owner_digest_is_rejected(case, tmp_path, field):
    case["ledger"]["binding"][field] = "0" * 64
    reseal_synthetic(case)
    with pytest.raises(ValueError, match="binding"):
        evaluate_synthetic(case, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


@pytest.mark.parametrize("mutation", [
    "release", "missing-input", "changed-input", "extra-input", "unknown-field", "global",
    "duplicate-id", "conflicting-decision", "subject-hash", "subject-scope", "subject-occurrence",
    "unknown-obligation", "unknown-domain", "wrong-scope", "omitted-provider", "extra-advisory",
    "empty-evidence", "missing-evidence", "wrong-purpose", "rationale", "unapproved-reviewer",
    "future-review", "expired-review", "stale-review", "invalid-date", "future-evidence",
    "technical-exception", "legal-exception", "partial-files", "missing-file-scope",
    "partial-evidence-coverage", "duplicate-evidence", "evidence-path", "evidence-bytes",
])
def test_tampered_or_blanket_decisions_fail_closed_before_output(case, tmp_path, mutation):
    ledger = case["ledger"]
    decision = ledger["decisions"][0]
    if mutation == "release":
        ledger["binding"]["release"]["version"] = "wrong"
    elif mutation == "missing-input":
        ledger["binding"]["inputArtifacts"].pop()
    elif mutation == "changed-input":
        ledger["binding"]["inputArtifacts"][0]["sha256"] = "f" * 64
    elif mutation == "extra-input":
        ledger["binding"]["inputArtifacts"].append(copy.deepcopy(ledger["binding"]["inputArtifacts"][0]))
    elif mutation == "unknown-field":
        ledger["approved"] = True
    elif mutation == "global":
        decision["observationId"] = "*"
    elif mutation == "duplicate-id":
        ledger["decisions"].append(copy.deepcopy(decision))
    elif mutation == "conflicting-decision":
        duplicate = copy.deepcopy(decision)
        duplicate["id"] = "another-decision"
        ledger["decisions"].append(duplicate)
    elif mutation == "subject-hash":
        decision["subject"] = {**decision["subject"], "sha256": "f" * 64}
    elif mutation == "subject-scope":
        decision["subject"] = {**decision["subject"], "hashScope": "invented"}
    elif mutation == "subject-occurrence":
        decision["subject"] = {**decision["subject"], "location": "another-occurrence"}
    elif mutation == "unknown-obligation":
        decision["obligationCode"] = "approve-all"
    elif mutation == "unknown-domain":
        decision["domain"] = "owner"
    elif mutation == "wrong-scope":
        decision["scopeSha256"] = "f" * 64
    elif mutation == "omitted-provider":
        decision["sourceEvidenceIds"] = ["invented-provider"]
    elif mutation == "extra-advisory":
        decision["advisoryIds"] = ["GHSA-not-observed"]
    elif mutation == "empty-evidence":
        decision["evidenceSha256s"] = []
    elif mutation == "missing-evidence":
        decision["evidenceSha256s"] = ["f" * 64]
    elif mutation == "wrong-purpose":
        ref = decision["evidenceSha256s"][0]
        next(entry for entry in ledger["evidence"] if entry["sha256"] == ref)["kind"] = "review-analysis"
    elif mutation == "rationale":
        decision["rationale"] = "  "
    elif mutation == "unapproved-reviewer":
        decision["reviewer"] = "self-declared-approver"
    elif mutation == "future-review":
        decision["reviewedAt"] = "2026-10-01T00:00:00Z"
    elif mutation == "expired-review":
        decision["expiresAt"] = "2026-09-30T11:00:00Z"
    elif mutation == "stale-review":
        decision["reviewedAt"] = "2025-09-30T00:00:00Z"
    elif mutation == "invalid-date":
        decision["reviewedAt"] = "2026-99-30T00:00:00Z"
    elif mutation == "future-evidence":
        ledger["evidence"][0]["retrievedAt"] = "2026-10-01T00:00:00Z"
    elif mutation in ("technical-exception", "legal-exception"):
        domain = mutation.split("-")[0]
        next(entry for entry in ledger["decisions"] if entry["domain"] == domain)["outcome"] = "accepted-risk"
    elif mutation == "partial-files":
        next(iter(ledger["fileScopes"].values())).pop()
    elif mutation == "missing-file-scope":
        ledger["fileScopes"].pop(decision["scopeSha256"])
    elif mutation == "partial-evidence-coverage":
        ledger["evidence"][0]["fileScopeSha256s"] = []
    elif mutation == "duplicate-evidence":
        ledger["evidence"].append(copy.deepcopy(ledger["evidence"][0]))
    elif mutation == "evidence-path":
        ledger["evidence"][0]["file"] = "../outside"
    elif mutation == "evidence-bytes":
        ledger["evidence"][0]["bytes"] += 1
    reseal_synthetic(case)
    with pytest.raises(ValueError):
        evaluate_synthetic(case, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


@pytest.mark.parametrize("mutation", [
    "wrong-owner-sha", "wrong-ledger", "capability", "expired", "future", "blanket-capability",
    "no-freshness", "boolean-freshness", "unknown-field",
])
def test_authorization_is_not_just_an_approved_field_or_reviewer_name(case, tmp_path, mutation):
    auth = case["authorization"]
    if mutation == "capability":
        auth["authorizedReviewers"]["synthetic-legal"] = ["security"]
    elif mutation == "expired":
        auth["expiresAt"] = "2026-09-30T00:00:00Z"
    elif mutation == "future":
        auth["approvedAt"] = "2026-10-01T00:00:00Z"
    elif mutation == "blanket-capability":
        auth["authorizedReviewers"]["synthetic-legal"] = ["*"]
    elif mutation == "no-freshness":
        del auth["maxAdvisoryAgeSeconds"]
    elif mutation == "boolean-freshness":
        auth["maxAdvisoryAgeSeconds"] = True
    elif mutation == "unknown-field":
        auth["approved"] = True
    reseal_synthetic(case)
    if mutation == "wrong-owner-sha":
        case["authorization_sha256"] = "f" * 64
    elif mutation == "wrong-ledger":
        case["ledger_path"].write_bytes(case["ledger_path"].read_bytes() + b"\n")
    with pytest.raises(ValueError):
        evaluate_synthetic(case, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


def test_known_advisory_risk_is_retained_as_exception_not_erased(candidate, tmp_path):
    case = with_advisory(candidate, tmp_path)
    report = evaluate_synthetic(case, tmp_path / "reviewed")
    assert report["complete"] and report["riskAccepted"] and not report["vulnerabilityFreeClaim"]
    assert any("GHSA-synthetic-fixture" in row["advisoryIds"] for row in report["riskAccepted"])
    assert all(row["findingStillRecorded"] for row in report["riskAccepted"])
    assert any(row["status"] == "authorized-risk-exception" for row in report["resolved"])
    verify_synthetic(case, tmp_path / "reviewed")


def test_existing_matches_cannot_be_relabelled_no_matches(candidate, tmp_path):
    case = with_advisory(candidate, tmp_path)
    decision = next(row for row in case["ledger"]["decisions"] if row["domain"] == "security" and row["advisoryIds"])
    decision["outcome"] = "reviewed-no-matches"
    reseal_synthetic(case)
    with pytest.raises(ValueError, match="cannot be declared absent"):
        evaluate_synthetic(case, tmp_path / "blocked")


def test_new_prose_does_not_refresh_old_advisory_queries(candidate, tmp_path):
    case = with_advisory(candidate, tmp_path, acquired="2026-09-01T00:00:00Z", matches=False)
    with pytest.raises(ValueError, match="Recorded advisory queries are stale"):
        evaluate_synthetic(case, tmp_path / "blocked")


def test_verification_uses_current_clock_not_saved_success(case, tmp_path):
    evaluate_synthetic(case, tmp_path / "out")
    with pytest.raises(ValueError, match="stale"):
        verify_synthetic(case, tmp_path / "out", now=NOW + datetime.timedelta(hours=25))


@pytest.mark.parametrize("mutation", ["booleans", "original", "ledger", "evidence", "inventory", "policy", "tools", "extra"])
def test_resealed_evaluated_output_cannot_substitute_for_replay(case, tmp_path, mutation):
    output = tmp_path / "out"
    evaluate_synthetic(case, output)
    report_path = output / "compliance-report.json"
    report = json.loads(report_path.read_bytes())
    if mutation == "booleans":
        report["legalAuthorized"] = False
    elif mutation == "original":
        report["original"].pop()
    elif mutation == "ledger":
        path = output / "decisions/ledger.json"
        value = json.loads(path.read_bytes())
        value["decisions"][0]["rationale"] = "Attacker rewrote the alleged reviewer rationale."
        path.write_bytes(collector.json_bytes(value))
    elif mutation == "evidence":
        path = next((output / "decisions/evidence").iterdir())
        path.write_bytes(b"Attacker controlled evidence.")
    elif mutation == "inventory":
        for path in (output / "inventory.json", output / "observations/inventory.json"):
            value = json.loads(path.read_bytes())
            value["components"] = [entry for entry in value["components"] if entry["kind"] != "native-file"]
            path.write_bytes(collector.json_bytes(value))
    elif mutation in ("policy", "tools"):
        name = "policy.json" if mutation == "policy" else "tool-manifest.json"
        path = output / "observations/inputs" / name
        path.write_bytes(b"{}\n")
    else:
        (output / "unlisted").write_bytes(b"Extra evidence.")
    report["files"] = [collector.pin(path.read_bytes(), path.relative_to(output).as_posix())
                       for path in sorted(output.rglob("*")) if path.is_file() and path != report_path]
    report_path.write_bytes(collector.json_bytes(report))
    with pytest.raises(ValueError):
        verify_synthetic(case, output)


def test_factory_supports_signing_harness_with_canonical_wheel_names(packaging_candidate, tmp_path):
    inputs, manifest, _, payload = packaging_candidate
    version = manifest["environments"]["app"]["theovex-polaris"]
    original = f"app/wheels/theovex-polaris-{version}-py3-none-any.whl"
    canonical = f"app/wheels/theovex_polaris-{version}-py3-none-any.whl"
    payload[canonical] = payload.pop(original)
    bundle = inputs["bundle_dir"]
    tar_bytes(bundle / "payload.tar.gz", payload)
    manifest["payload"] = collector.pin((bundle / "payload.tar.gz").read_bytes(), "payload.tar.gz")
    seal_bundle(bundle, manifest)
    fixture = synthetic_compliance(bundle, tmp_path / "signing-fixture")
    assert fixture["report"]["complete"] and fixture["report"]["readyForSigning"]


def test_authority_inside_evaluated_tree_is_not_a_trust_root(case, tmp_path):
    output = tmp_path / "out"
    evaluate_synthetic(case, output)
    embedded = output / "OWNER.json"
    embedded.write_bytes(case["authorization_path"].read_bytes())
    case["authorization_path"] = embedded
    with pytest.raises(ValueError, match="outside evaluated evidence"):
        verify_synthetic(case, output)


def test_linked_owner_file_is_not_independent(case, tmp_path):
    linked = tmp_path / "linked-authority.json"
    os.link(case["authorization_path"], linked)
    case["authorization_path"] = linked
    with pytest.raises(ValueError, match="not independent"):
        evaluate_synthetic(case, tmp_path / "blocked")


def test_historical_complete_report_still_cannot_authorize(case, tmp_path):
    output = tmp_path / "legacy"
    output.mkdir()
    (output / "compliance-report.json").write_bytes(collector.json_bytes({
        "format": "polaris.release-compliance/1", "complete": True, "inventoryComplete": True, "unresolved": [],
    }))
    with pytest.raises(ValueError, match="Historical"):
        verify_synthetic(case, output)


def test_native_scope_includes_pe_and_static_archives_not_just_macho(candidate, tmp_path):
    pe = bytearray(b"MZ" + b"\0" * 62)
    pe[60:64] = (64).to_bytes(4, "little")
    pe.extend(b"PE\0\0")
    old = collector.archive_entries((candidate[0] / "uv.tar.gz").read_bytes())
    content = tar_content([(name, data) for name, data, _ in old]
                          + [("uv/windows-launcher.exe", bytes(pe)), ("uv/stubs.a", b"!<arch>\n")])
    (candidate[0] / "uv.tar.gz").write_bytes(content)
    candidate[1]["runtimes"]["uv"].update(collector.pin(content, "uv.tar.gz"))
    seal(*candidate)
    case = synthetic_resolution_inputs(candidate[0], tmp_path / "native-input", now=NOW)
    targets = [target for target in case["template"]["targets"] if target["subject"]["kind"] == "native-file"]
    assert len(targets) == 4
    assert any(target["subject"]["name"].endswith(".exe") for target in targets)
    assert any(target["subject"]["name"].endswith(".a") for target in targets)
    prune_decisions(case, lambda row: not row["subject"]["name"].endswith(".exe"))
    report = evaluate_synthetic(case, tmp_path / "partial-native")
    assert not report["complete"] and not report["technicalComplete"]
    with pytest.raises(ValueError, match="Unresolved"):
        verify_synthetic(case, tmp_path / "partial-native")


def test_metadata_occurrence_coverage_includes_parent_files_not_only_metadata(case):
    target = next(row for row in case["template"]["targets"] if row["subject"]["hashScope"] == "metadata")
    files = case["ledger"]["fileScopes"][target["scopeSha256"]]
    assert len(files) > 1 and any(row["kind"] == "link" for row in files)
    assert target["subject"]["sha256"] != target["scopeSha256"]


def test_inputs_and_existing_outputs_are_never_replaced(case, tmp_path):
    output = tmp_path / "out"
    evaluate_synthetic(case, output)
    before = fingerprint(output)
    with pytest.raises(ValueError, match="new"):
        evaluate_synthetic(case, output)
    assert fingerprint(output) == before
    with pytest.raises(ValueError, match="overlaps"):
        evaluate_synthetic(case, case["bundle_dir"] / "new")


def test_symlinked_evidence_is_not_followed(case, tmp_path):
    entry = case["ledger"]["evidence"][0]
    path = case["evidence_dir"] / entry["file"]
    original = tmp_path / "original"
    original.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(original)
    with pytest.raises(ValueError, match="Unsafe"):
        evaluate_synthetic(case, tmp_path / "blocked")


def test_input_mutation_during_review_is_rejected_without_output(case, tmp_path, monkeypatch):
    original = resolver._assess
    def altered(*args, **kwargs):
        report = original(*args, **kwargs)
        (case["bundle_dir"] / "install-theo.sh").write_bytes(b"Changed while evaluating.")
        return report
    monkeypatch.setattr(resolver, "_assess", altered)
    with pytest.raises(ValueError):
        evaluate_synthetic(case, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


def test_inventory_sized_json_is_supported_but_remains_bounded(monkeypatch):
    raw = b'{"value":"' + b"x" * (4 * 1024 * 1024) + b'"}'
    assert len(resolver.document(raw)["value"]) == 4 * 1024 * 1024
    monkeypatch.setattr(resolver, "MAX_DOCUMENT", 1024)
    with pytest.raises(ValueError, match="bound"):
        resolver.document(raw)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_duplicate_and_nonfinite_resolution_json_is_refused(raw):
    with pytest.raises(ValueError):
        resolver.document(raw)


def test_json_equivalence_is_type_exact():
    assert not resolver.same({"bytes": True}, {"bytes": 1})
    assert not resolver.same({"bytes": 1.0}, {"bytes": 1})


def test_reusable_signing_factory_runs_real_verifier(candidate, tmp_path):
    fixture = synthetic_compliance(candidate[0], tmp_path / "synthetic-compliance", now=NOW)
    assert fixture["report"]["readyForSigning"]
    assert fixture["authorization_path"].is_file()
    assert fixture["resolver"].verify_for_signing(
        bundle_dir=candidate[0], compliance_dir=fixture["compliance_dir"],
        authorization_path=fixture["authorization_path"], authorization_sha256=fixture["authorization_sha256"], now=NOW,
    )["ledgerSha256"] == fixture["report"]["ledgerSha256"]


def test_synthetic_factory_refuses_outside_pytest(candidate, tmp_path, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(ValueError, match="pytest"):
        synthetic_compliance(candidate[0], tmp_path / "never-created")
    assert not (tmp_path / "never-created").exists()


def test_cli_template_remains_unapproved_and_unknown_arguments_do_not_echo(case, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["resolution", "template", "--bundle-dir", str(case["bundle_dir"]),
                                    "--observations-dir", str(case["observations_dir"])])
    assert resolver.main() == 2
    assert json.loads(capsys.readouterr().out)["ledger"]["decisions"] == []
    monkeypatch.setattr("sys.argv", ["resolution", "--unknown=synthetic-private-value"])
    assert resolver.main() == 1
    captured = capsys.readouterr()
    assert "synthetic-private-value" not in captured.out + captured.err


def test_cli_evaluate_and_verify_use_real_current_authorization(candidate, tmp_path, monkeypatch, capsys):
    case = synthetic_resolution_inputs(candidate[0], tmp_path / "cli-input")
    output = tmp_path / "cli-output"
    common = ["--bundle-dir", str(case["bundle_dir"]), "--authorization", str(case["authorization_path"]),
              "--authorization-sha256", case["authorization_sha256"]]
    monkeypatch.setattr("sys.argv", [
        "resolution", "evaluate", *common, "--observations-dir", str(case["observations_dir"]),
        "--ledger", str(case["ledger_path"]), "--evidence-dir", str(case["evidence_dir"]), "--output", str(output),
    ])
    assert resolver.main() == 0
    assert json.loads(capsys.readouterr().out)["complete"] is True
    monkeypatch.setattr("sys.argv", ["resolution", "verify", *common, "--compliance-dir", str(output)])
    assert resolver.main() == 0
    assert json.loads(capsys.readouterr().out)["ledgerSha256"] == case["authorization"]["ledgerSha256"]


def test_policy_change_during_evaluation_is_detected(case, tmp_path, monkeypatch):
    policy = tmp_path / "different-policy.json"
    policy.write_bytes(collector.POLICY.read_bytes() + b"\n")
    original = resolver._assess
    def altered(*args, **kwargs):
        report = original(*args, **kwargs)
        monkeypatch.setattr(collector, "POLICY", policy)
        return report
    monkeypatch.setattr(resolver, "_assess", altered)
    with pytest.raises(ValueError, match="policy changed"):
        evaluate_synthetic(case, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


def test_tool_change_during_evaluation_is_detected(case, tmp_path, monkeypatch):
    original = resolver._assess
    def altered(*args, **kwargs):
        report = original(*args, **kwargs)
        monkeypatch.setattr(collector, "TOOL_FILES", collector.TOOL_FILES[:1])
        return report
    monkeypatch.setattr(resolver, "_assess", altered)
    with pytest.raises(ValueError, match="tooling changed"):
        evaluate_synthetic(case, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


def test_embedded_raw_query_cannot_be_modified_then_resealed(candidate, tmp_path):
    case = with_advisory(candidate, tmp_path)
    output = tmp_path / "out"
    evaluate_synthetic(case, output)
    embedded = output / "observations/inputs/supplements/request.json"
    embedded.write_bytes(b'{"queries":[]}\n')
    report_path = output / "compliance-report.json"
    report = json.loads(report_path.read_bytes())
    report["files"] = [collector.pin(path.read_bytes(), path.relative_to(output).as_posix())
                       for path in sorted(output.rglob("*")) if path.is_file() and path != report_path]
    report_path.write_bytes(collector.json_bytes(report))
    with pytest.raises(ValueError):
        verify_synthetic(case, output)


def test_missing_original_bundle_is_not_replaced_by_inventory_claims(case, tmp_path):
    output = tmp_path / "out"
    evaluate_synthetic(case, output)
    case["bundle_dir"] = tmp_path / "absent-originals"
    with pytest.raises(ValueError):
        verify_synthetic(case, output)

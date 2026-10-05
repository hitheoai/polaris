"""Synthetic observations only; no real release, hardware or legal approval is asserted."""

from __future__ import annotations

import copy
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_homebrew_packaging import builder

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "acceptance_collection_test", ROOT / "scripts/collect_release_acceptance.py",
)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture_host():
    return {
        "system": "Darwin", "machine": "arm64", "macos": "26.6", "hostId": "d" * 64,
        "identityKind": "hostname-sha256-not-hardware-attestation",
    }


def write_observation(report, gate, directory, *, config=None):
    """A test-only factory, never a source of actual release evidence."""
    directory.mkdir(parents=True)
    stdout, stderr, decision = (directory / name for name in ("stdout.log", "stderr.log", "decision.json"))
    stdout.write_bytes(b"SYNTHETIC FIXTURE ONLY, NOT AN OBSERVED COMMAND RESULT.\n")
    stderr.write_bytes(b"")
    decision.write_bytes(b'{"syntheticFixtureOnly":true,"notAnApproval":true}\n')
    details = {
        "source_tests": {"passed": 1, "failed": 0},
        "standalone_lifecycle": {"upgradeVerified": True, "collisionRefused": True, "conservativeRemoval": True},
        "homebrew_lifecycle": {"upgradeVerified": True, "sandboxEnabled": True, "forcedLinking": False},
        "minimum_macos_15": {},
        "clean_account": {"newAccount": True, "defaultPrefix": "/opt/homebrew"},
        "second_apple_silicon_mac": {"physicallyDistinctMac": True},
        "quarantined_download": {"anonymousHttps": True, "redirects": 0, "quarantinePreserved": True},
        "native_editor_invocation": {
            "editorName": "Synthetic fixture, not an editor", "editorVersion": "0.0-fixture",
            "capabilitiesObserved": True, "reviewWorkflowObserved": True,
        },
        "license_source_advisory_approval": {
            "decisionSha256": builder.artifact(decision)["sha256"],
            "complianceReportSha256": (config or {}).get("complianceReportSha256", "e" * 64),
        },
        "publisher_origin_ownership": {
            "decisionSha256": builder.artifact(decision)["sha256"],
            "publisherRepository": (config or {}).get("publisherRepository", "fixture-publisher/cli"),
            "downloadOrigin": (config or {}).get("downloadOrigin", "https://downloads.fixture.test"),
        },
    }[gate]
    host = copy.deepcopy(report["baselineHost"])
    if gate == "minimum_macos_15":
        host["macos"] = "15.7"
    if gate == "second_apple_silicon_mac":
        host["hostId"] = "f" * 64
    now = datetime.now(UTC).isoformat()
    record = {
        "format": collector.OBSERVATION_FORMAT, "gate": gate, "release": report["release"],
        "artifactSetSha256": report["artifactSetSha256"], "status": "passed",
        "observer": "SYNTHETIC TEST FIXTURE ONLY", "observedAt": now,
        "source": copy.deepcopy(report["source"]), "host": host, "details": details,
        "evidence": [builder.artifact(decision)] if gate in collector.DECISION_GATES else [],
        "commands": [] if gate in collector.DECISION_GATES else [{
            "argv": ["/synthetic-fixture-not-executed", gate], "cwd": "/synthetic-fixture",
            "startedAt": now, "finishedAt": now, "returncode": 0, "expectedReturncode": 0,
            "stdout": builder.artifact(stdout), "stderr": builder.artifact(stderr, allow_empty=True),
        }],
    }
    path = directory / "observation.json"
    path.write_bytes(builder.json_bytes(record))
    return path


def external_fixture_approval(directory):
    return {
        "reportSha256": builder.artifact(directory / "acceptance.json")["sha256"],
        "reviewer": "SYNTHETIC TEST OWNER, NOT A REAL APPROVAL",
        "reviewedAt": datetime.now(UTC).isoformat(),
    }


@pytest.fixture
def template(tmp_path):
    root = tmp_path.resolve()
    artifact = root / "synthetic-artifact"
    artifact.write_bytes(b"Unsigned synthetic fixture, not a release artifact.\n")
    artifacts = {"releases/fixture/synthetic-artifact": builder.artifact(artifact)}
    source = {"revision": "a" * 40, "tree": "b" * 40, "dirty": False}
    directory = root / "template"
    report = collector.create_template(artifacts, source, fixture_host(), directory, helper=builder)
    return directory, report


def test_template_preserves_all_unrun_gates_and_cannot_authorize_publication(template):
    directory, report = template
    assert set(report["gates"]) == collector.GATES
    assert all(gate == {"status": "not_run"} for gate in report["gates"].values())
    assert report["publicationAuthorized"] is report["trustedCIEvidence"] is False
    assert collector.verify_report(directory, report["artifacts"], helper=builder) == report
    with pytest.raises(ValueError, match="Unrun"):
        collector.verify_report(directory, report["artifacts"], helper=builder, require_complete=True,
                                approval=external_fixture_approval(directory))


def test_collection_is_append_only_and_never_executes_recorded_commands(template, tmp_path, monkeypatch):
    directory, report = template
    monkeypatch.setattr(collector.subprocess, "run", lambda *a, **kw: pytest.fail("An observation was executed."))
    old = (directory / "acceptance.json").read_bytes()
    path = write_observation(report, "source_tests", tmp_path.resolve() / "incoming")
    output = tmp_path.resolve() / "collected"
    result = collector.collect(directory, [path], output, helper=builder)
    assert (directory / "acceptance.json").read_bytes() == old
    assert result["gates"]["source_tests"]["status"] == "passed"
    assert result["gates"]["minimum_macos_15"] == {"status": "not_run"}
    assert result["publicationAuthorized"] is False and "approved" not in result
    assert collector.verify_report(output, report["artifacts"], helper=builder) == result
    with pytest.raises(ValueError, match="Duplicate"):
        collector.collect(output, [path], tmp_path.resolve() / "replacement", helper=builder)
    assert not (tmp_path / "replacement").exists()


def test_all_observations_still_require_independently_supplied_digest_approval(template, tmp_path):
    directory, report = template
    paths = [write_observation(report, name, tmp_path.resolve() / "incoming" / name)
             for name in sorted(collector.GATES)]
    output = tmp_path.resolve() / "all-collected"
    collector.collect(directory, paths, output, helper=builder)
    with pytest.raises(ValueError, match="Independent"):
        collector.verify_report(output, report["artifacts"], helper=builder, require_complete=True)
    approval = external_fixture_approval(output)
    result = collector.verify_report(output, report["artifacts"], helper=builder, require_complete=True,
                                     approval=approval, source_revision=report["source"]["revision"])
    assert result["publicationAuthorized"] is False
    with pytest.raises(ValueError, match="Independent"):
        collector.verify_report(output, report["artifacts"], helper=builder, require_complete=True,
                                approval={**approval, "reportSha256": "0" * 64})
    with pytest.raises(ValueError, match="source revision"):
        collector.verify_report(output, report["artifacts"], helper=builder, require_complete=True,
                                approval=approval, source_revision="0" * 40)


@pytest.mark.parametrize("mutation", [
    "wrong-release", "wrong-artifacts", "wrong-source", "dirty-source", "missing-command",
    "unexpected-exit", "missing-log", "changed-log", "escaping-log", "absolute-log", "log-symlink",
    "duplicate-json-key", "unknown-gate", "unapproved-claim", "future-time", "reversed-times",
    "before-freeze", "non-utc-time", "invalid-size", "boolean-exit", "relative-command",
    "nonfinite-json", "unhashable-gate", "no-successful-command",
])
def test_unbound_stale_and_unsafe_observations_fail_before_output(template, tmp_path, mutation):
    directory, report = template
    path = write_observation(report, "source_tests", tmp_path.resolve() / "incoming")
    record = json.loads(path.read_bytes())
    command = record["commands"][0]
    if mutation == "wrong-release":
        record["release"] = builder.RELEASE_ID
    elif mutation == "wrong-artifacts":
        record["artifactSetSha256"] = "0" * 64
    elif mutation == "wrong-source":
        record["source"]["revision"] = "0" * 40
    elif mutation == "dirty-source":
        record["source"]["dirty"] = True
    elif mutation == "missing-command":
        record["commands"] = []
    elif mutation == "unexpected-exit":
        command["returncode"] = 1
    elif mutation in ("missing-log", "changed-log", "log-symlink"):
        log = path.parent / "stdout.log"
        if mutation == "changed-log":
            log.write_bytes(b"changed")
        else:
            log.unlink()
            if mutation == "log-symlink":
                log.symlink_to(path.parent / "decision.json")
    elif mutation in ("escaping-log", "absolute-log"):
        command["stdout"]["name"] = "../stdout.log" if mutation == "escaping-log" else "/stdout.log"
    elif mutation == "unknown-gate":
        record["gate"] = "all_checks_complete"
    elif mutation == "unapproved-claim":
        record["approved"] = True
    elif mutation == "future-time":
        record["observedAt"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif mutation == "reversed-times":
        command["finishedAt"] = report["createdAt"]
    elif mutation == "before-freeze":
        command["startedAt"] = "2020-01-01T00:00:00Z"
    elif mutation == "non-utc-time":
        record["observedAt"] = "2026-01-01T00:00:00"
    elif mutation == "invalid-size":
        command["stdout"]["bytes"] = True
    elif mutation == "boolean-exit":
        command["returncode"] = False
    elif mutation == "relative-command":
        command["argv"][0] = "polaris"
    elif mutation == "nonfinite-json":
        record["details"]["invalid"] = float("nan")
    elif mutation == "unhashable-gate":
        record["gate"] = []
    elif mutation == "no-successful-command":
        command["returncode"] = command["expectedReturncode"] = 2
    path.write_bytes(builder.json_bytes(record))
    if mutation == "duplicate-json-key":
        path.write_bytes(path.read_bytes().replace(b'"status": "passed"', b'"status": "failed", "status": "passed"'))
    output = tmp_path.resolve() / "must-not-exist"
    with pytest.raises((ValueError, OSError)):
        collector.collect(directory, [path], output, helper=builder)
    assert not output.exists()


@pytest.mark.parametrize("gate,mutation", [
    ("minimum_macos_15", "newer-host"), ("second_apple_silicon_mac", "same-host"),
    ("homebrew_lifecycle", "no-upgrade"), ("homebrew_lifecycle", "force-linked"),
    ("clean_account", "custom-prefix"), ("quarantined_download", "redirected"),
    ("native_editor_invocation", "missing-editor"), ("source_tests", "failed-tests"),
    ("license_source_advisory_approval", "missing-decision"),
])
def test_scope_claims_cannot_substitute_for_required_gates(template, tmp_path, gate, mutation):
    directory, report = template
    path = write_observation(report, gate, tmp_path.resolve() / "incoming")
    record = json.loads(path.read_bytes())
    if mutation == "newer-host":
        record["host"]["macos"] = "26.6"
    elif mutation == "same-host":
        record["host"]["hostId"] = report["baselineHost"]["hostId"]
    elif mutation == "no-upgrade":
        record["details"]["upgradeVerified"] = False
    elif mutation == "force-linked":
        record["details"]["forcedLinking"] = True
    elif mutation == "custom-prefix":
        record["details"]["defaultPrefix"] = "/private/test-prefix"
    elif mutation == "redirected":
        record["details"]["redirects"] = 1
    elif mutation == "missing-editor":
        del record["details"]["editorName"]
    elif mutation == "failed-tests":
        record["details"]["failed"] = 1
    else:
        record["details"]["decisionSha256"] = "0" * 64
    path.write_bytes(builder.json_bytes(record))
    with pytest.raises(ValueError):
        collector.collect(directory, [path], tmp_path.resolve() / "blocked", helper=builder)


def test_failed_observation_is_retained_without_becoming_a_pass(template, tmp_path):
    directory, report = template
    path = write_observation(report, "source_tests", tmp_path.resolve() / "incoming")
    record = json.loads(path.read_bytes())
    record["status"] = "failed"
    record["commands"][0]["returncode"] = 1
    record["details"] = {"passed": 0, "failed": 1}
    path.write_bytes(builder.json_bytes(record))
    result = collector.collect(directory, [path], tmp_path.resolve() / "failed", helper=builder)
    assert result["gates"]["source_tests"]["status"] == "failed"
    assert result["publicationAuthorized"] is False


@pytest.mark.parametrize("mutation", ["changed-log", "extra-file", "symlink-directory", "self-approval", "wrong-format"])
def test_collected_report_revalidates_every_file(template, tmp_path, mutation):
    directory, report = template
    path = write_observation(report, "source_tests", tmp_path.resolve() / "incoming")
    output = tmp_path.resolve() / "collected"
    result = collector.collect(directory, [path], output, helper=builder)
    if mutation == "changed-log":
        (output / "evidence/source_tests/stdout.log").write_bytes(b"changed")
    elif mutation == "extra-file":
        (output / "extra").write_bytes(b"unreviewed")
    elif mutation == "symlink-directory":
        (output / "unexpected-link").symlink_to(path.parent, target_is_directory=True)
    else:
        if mutation == "self-approval":
            result["publicationAuthorized"] = True
        else:
            result["format"] = "polaris.signed-release-acceptance/1"
        (output / "acceptance.json").write_bytes(builder.json_bytes(result))
    with pytest.raises(ValueError):
        collector.verify_report(output, report["artifacts"], helper=builder)


def test_duplicate_gate_in_one_collection_is_not_last_writer_wins(template, tmp_path):
    directory, report = template
    first = write_observation(report, "source_tests", tmp_path.resolve() / "first")
    second = write_observation(report, "source_tests", tmp_path.resolve() / "second")
    with pytest.raises(ValueError, match="Duplicate"):
        collector.collect(directory, [first, second], tmp_path.resolve() / "blocked", helper=builder)


def test_output_must_be_new_outside_inputs(template, tmp_path):
    directory, report = template
    path = write_observation(report, "source_tests", tmp_path.resolve() / "incoming")
    for output in (directory, directory / "nested", path.parent / "nested"):
        with pytest.raises(ValueError, match="new and outside"):
            collector.collect(directory, [path], output, helper=builder)

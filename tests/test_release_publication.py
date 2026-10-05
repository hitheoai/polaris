"""Synthetic local-only publication fixtures; never upload or invoke real Apple tools."""

from __future__ import annotations

import importlib.util
import json
import plistlib
import shutil
import sys
from pathlib import Path

import pytest
from test_homebrew_packaging import builder
from test_homebrew_packaging import candidate as candidate
from test_macos_release import release, sign_fixture
from test_macos_release import signing_case as signing_case
from test_release_acceptance import (
    collector,
    external_fixture_approval,
    fixture_host,
    write_observation,
)

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


publisher = module("prepare_release_publication")


@pytest.fixture
def publication_case(signing_case, tmp_path, monkeypatch):
    case = signing_case
    bundle = Path(sign_fixture(case)["bundle"])
    monkeypatch.setattr(publisher, "release_tool", lambda: release)
    _, pins, _ = builder.inspect_bundle(bundle)
    public = tmp_path.resolve() / "public"
    public.mkdir()
    source = public / case["source"].name
    shutil.copyfile(case["source"], source)
    wheel = public / "theovex_polaris-0.3.3-py3-none-any.whl"
    wheel.write_bytes(next(data for name, data in case["payload"].items() if "/theovex_polaris-" in name))
    brew_dir = tmp_path.resolve() / "homebrew"
    brew = builder.build(bundle_dir=bundle, source_archive=source, output=brew_dir,
                         base_url=case["config"]["downloadOrigin"])
    dmg = tmp_path.resolve() / "dmg"
    dmg.mkdir()
    image = dmg / f"{builder.SIGNED_RELEASE_ID}.dmg"
    image.write_bytes(b"Synthetic DMG fixture, not a disk image.\nSYNTHETIC-TEST-SIGNATURE")
    contents = release.distribution_content(bundle, source, dmg / "content")
    distribution = {
        "format": "polaris.macos-distribution/1", "bundle": pins,
        "stapled": True, "signatureVerified": True, "notarization": {"status": "Accepted"},
        "source": builder.artifact(source), "artifact": builder.artifact(image), "content": contents,
    }
    (dmg / "result.json").write_bytes(builder.json_bytes(distribution))
    fake_tool = release.tool
    calls = []

    def mounted_fixture(command, **kwargs):
        if command[0] != "/usr/bin/hdiutil":
            return fake_tool(command, **kwargs)
        calls.append(command)
        if command[1] == "attach":
            assert all(option in command for option in ("-readonly", "-nobrowse", "-noautoopen"))
            mount = Path(command[command.index("-mountpoint") + 1])
            shutil.copytree(dmg / "content", mount, dirs_exist_ok=True)
            return plistlib.dumps({"system-entities": [{"mount-point": str(mount)}]}).decode(), ""
        assert command[1] == "detach"
        return "", ""

    monkeypatch.setattr(release, "tool", mounted_fixture)
    sources = {f"releases/{builder.SIGNED_RELEASE_ID}/{name}": bundle / name for name in pins}
    sources.update({
        f"releases/{builder.SIGNED_RELEASE_ID}/{image.name}": image,
        f"releases/{builder.SIGNED_RELEASE_ID}/{brew['artifact']['name']}": brew_dir / brew["artifact"]["name"],
        f"releases/{builder.SIGNED_RELEASE_ID}/{source.name}": source,
        f"releases/{builder.SIGNED_RELEASE_ID}/{wheel.name}": wheel,
        "tap/Formula/polaris.rb": brew_dir / "polaris.rb",
    })
    artifacts = {name: builder.artifact(path) for name, path in sources.items()}
    template = tmp_path.resolve() / "acceptance-template"
    source_identity = {"revision": case["config"]["sourceRevision"], "tree": "b" * 40, "dirty": False}
    initial = collector.create_template(artifacts, source_identity, fixture_host(), template, helper=builder)
    observations = [
        write_observation(initial, name, tmp_path.resolve() / "observations" / name, config=case["config"])
        for name in sorted(publisher.GATES)
    ]
    acceptance = tmp_path.resolve() / "acceptance"
    decision = collector.collect(template, observations, acceptance, helper=builder)
    case["config"]["acceptanceApproval"] = external_fixture_approval(acceptance)
    case["config_path"].write_bytes(builder.json_bytes(case["config"]))
    return {
        "arguments": (bundle, dmg, brew_dir, public, acceptance, case["config_path"], tmp_path.resolve() / "kit"),
        "artifacts": artifacts, "decision": decision, "dmg": distribution, "brew": brew,
        "mountCalls": calls, "config": case["config"],
    }


def test_explicit_release_approval_precedes_even_input_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(publisher, "release_tool", lambda: pytest.fail("Inputs were accessed before approval."))
    with pytest.raises(ValueError, match="approve-release"):
        publisher.build(*([tmp_path / "absent"] * 7))


def test_complete_fixture_creates_only_an_unpublished_local_kit(publication_case):
    case = publication_case
    result = publisher.build(*case["arguments"], approved=True)
    output = case["arguments"][-1]
    assert result["publicationPerformed"] is result["trustedCIBuildProvenance"] is False
    assert result["availability"] == "unpublished"
    assert result["anonymousProductionDelivery"] == "not_verified"
    assert result["artifacts"] == case["artifacts"]
    for name, pin in result["artifacts"].items():
        builder.verify(output / name, pin)
    assert (output / "SHA256SUMS").is_file()
    assert [command[1] for command in case["mountCalls"]] == ["attach", "detach"]


@pytest.mark.parametrize("mutation", ["unapproved", "missing-gate", "not-run", "stale-artifacts",
                                     "stale-gate", "changed-evidence", "escaping-evidence", "wrong-release"])
def test_every_acceptance_gate_is_exact_and_hash_bound(publication_case, mutation):
    case = publication_case
    decision = case["decision"]
    directory = case["arguments"][4]
    gate = decision["gates"]["minimum_macos_15"]
    if mutation == "unapproved":
        case["config"]["acceptanceApproval"] = None
    elif mutation == "missing-gate":
        decision["gates"].pop("second_apple_silicon_mac")
    elif mutation == "not-run":
        gate["status"] = "not_run"
    elif mutation == "stale-artifacts":
        decision["artifactSetSha256"] = "0" * 64
    elif mutation == "stale-gate":
        path = directory / gate["observation"]["name"]
        record = json.loads(path.read_bytes())
        record["artifactSetSha256"] = "0" * 64
        path.write_bytes(builder.json_bytes(record))
        gate["observation"].update(builder.artifact(path))
        gate["observation"]["name"] = "evidence/minimum_macos_15/observation.json"
    elif mutation == "changed-evidence":
        (directory / gate["observation"]["name"]).write_bytes(b"changed")
    elif mutation == "escaping-evidence":
        gate["observation"]["name"] = "../outside"
    else:
        decision["release"] = builder.RELEASE_ID
    (directory / "acceptance.json").write_bytes(builder.json_bytes(decision))
    with pytest.raises(ValueError):
        publisher.acceptance(directory, case["artifacts"], helper=builder, config=case["config"])
    assert not case["arguments"][-1].exists()


@pytest.mark.parametrize("mutation", ["formula", "archive", "dmg-content", "dmg-metadata", "wrong-origin",
                                     "unaccepted-notary", "unstapled"])
def test_metadata_cannot_relabel_wrong_distribution_bytes(publication_case, mutation):
    case = publication_case
    _, dmg, homebrew, *_ = case["arguments"]
    if mutation in ("formula", "archive"):
        name = "polaris.rb" if mutation == "formula" else case["brew"]["artifact"]["name"]
        path = homebrew / name
        path.write_bytes(path.read_bytes() + b"\nUnapproved replacement.")
        key = "formula" if mutation == "formula" else "artifact"
        case["brew"][key].update(builder.artifact(path))
        (homebrew / "homebrew.json").write_bytes(builder.json_bytes(case["brew"]))
    elif mutation == "dmg-content":
        path = dmg / "content/README.txt"
        path.write_bytes(b"A different signed distribution.")
    elif mutation == "wrong-origin":
        case["brew"]["artifact"]["url"] = "https://different.test/unapproved"
        (homebrew / "homebrew.json").write_bytes(builder.json_bytes(case["brew"]))
    else:
        if mutation == "dmg-metadata":
            case["dmg"]["content"] = {}
        elif mutation == "unaccepted-notary":
            case["dmg"]["notarization"]["status"] = "Invalid"
        else:
            case["dmg"]["stapled"] = False
        (dmg / "result.json").write_bytes(builder.json_bytes(case["dmg"]))
    with pytest.raises(ValueError):
        publisher.build(*case["arguments"], approved=True)
    assert not case["arguments"][-1].exists()
    if mutation == "dmg-content":
        assert [command[1] for command in case["mountCalls"]] == ["attach", "detach"]


def test_acceptance_cli_freezes_the_exact_publication_inventory(publication_case, tmp_path, monkeypatch, capsys):
    case = publication_case
    bundle, dmg, homebrew, public, *_ = case["arguments"]
    assert collector.inspect_distribution(bundle, dmg, homebrew, public, builder) == case["artifacts"]
    monkeypatch.setattr(collector, "helper_module", lambda: builder)
    monkeypatch.setattr(collector, "source_identity", lambda *a: case["decision"]["source"])
    monkeypatch.setattr(collector, "host_identity", fixture_host)
    output = tmp_path.resolve() / "cli-template"
    arguments = ["collect_release_acceptance.py", "template"]
    for name, value in {
        "bundle-dir": bundle, "dmg-dir": dmg, "homebrew-dir": homebrew, "public-dir": public,
        "source-dir": builder.ROOT, "output": output,
    }.items():
        arguments.extend(("--" + name, str(value)))
    monkeypatch.setattr(sys, "argv", arguments)
    collector.main()
    result = json.loads(capsys.readouterr().out)
    assert result["artifactSetSha256"] == publisher.set_digest(case["artifacts"])
    assert set(result["gates"].values()) == {"not_run"}
    assert result["publicationAuthorized"] is result["observationCommandsExecuted"] is False
    report = collector.verify_report(output, case["artifacts"], helper=builder)
    incoming = write_observation(report, "source_tests", tmp_path.resolve() / "cli-incoming")
    collected = tmp_path.resolve() / "cli-collected"
    monkeypatch.setattr(sys, "argv", [
        "collect_release_acceptance.py", "collect", "--acceptance-dir", str(output),
        "--observation", str(incoming), "--output", str(collected),
    ])
    collector.main()
    result = json.loads(capsys.readouterr().out)
    assert result["gates"]["source_tests"] == "passed"
    assert result["publicationAuthorized"] is result["observationCommandsExecuted"] is False
    collector.verify_report(collected, case["artifacts"], helper=builder)


def test_acceptance_template_cannot_use_unsigned_inputs(signing_case, tmp_path):
    with pytest.raises(ValueError, match="Unsigned"):
        collector.inspect_distribution(
            signing_case["bundle"], tmp_path.resolve(), tmp_path.resolve(), tmp_path.resolve(), builder,
        )


def test_publisher_approval_must_stay_outside_acceptance_evidence(publication_case):
    arguments = list(publication_case["arguments"])
    nested = arguments[4] / "publisher.json"
    shutil.copyfile(arguments[5], nested)
    arguments[5] = nested
    with pytest.raises(ValueError, match="outside"):
        publisher.build(*arguments, approved=True)
    assert not arguments[-1].exists()


@pytest.mark.parametrize("gate,field", [
    ("license_source_advisory_approval", "complianceReportSha256"),
    ("publisher_origin_ownership", "publisherRepository"),
    ("publisher_origin_ownership", "downloadOrigin"),
])
def test_reapproved_acceptance_cannot_name_different_publisher_decisions(publication_case, gate, field):
    case = publication_case
    directory = case["arguments"][4]
    report = case["decision"]
    pin = report["gates"][gate]["observation"]
    path = directory / pin["name"]
    record = json.loads(path.read_bytes())
    record["details"][field] = "different-reviewed-decision"
    path.write_bytes(builder.json_bytes(record))
    pin.update({key: builder.artifact(path)[key] for key in ("sha256", "bytes")})
    (directory / "acceptance.json").write_bytes(builder.json_bytes(report))
    case["config"]["acceptanceApproval"] = external_fixture_approval(directory)
    with pytest.raises(ValueError, match="decisions differ"):
        publisher.acceptance(directory, case["artifacts"], helper=builder, config=case["config"])

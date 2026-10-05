"""Collect local release observations without executing them or authorizing publication.

Templates require the final signed distribution bytes. Observations and their logs are
copied into new immutable snapshots; neither a template nor collection approves a gate.
An owner must separately approve the exact report digest in the private publisher config.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
GATES = frozenset({
    "source_tests", "standalone_lifecycle", "homebrew_lifecycle", "minimum_macos_15",
    "clean_account", "second_apple_silicon_mac", "quarantined_download", "native_editor_invocation",
    "license_source_advisory_approval", "publisher_origin_ownership",
})
DECISION_GATES = frozenset({"license_source_advisory_approval", "publisher_origin_ownership"})
FORMAT = "polaris.signed-release-acceptance/2"
OBSERVATION_FORMAT = "polaris.release-gate-observation/1"
MAX_EVIDENCE_BYTES = 20_000_000
MAX_TOTAL_EVIDENCE = 250_000_000


def helper_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "acceptance_bundle", ROOT / "scripts/build_homebrew_formula.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON fields are not acceptance evidence.")
        value[key] = item
    return value


def read_json(path: Path, helper: Any) -> dict[str, Any]:
    def reject_constant(value: str) -> NoReturn:
        raise ValueError("Non-finite JSON values are not acceptance evidence.")

    value = json.loads(
        helper.read(path, limit=2_000_000),
        object_pairs_hook=unique_object, parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("An acceptance document must be an object.")
    return value


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value,
    ):
        raise ValueError("Evidence needs an explicit UTC timestamp.")
    observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if observed > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("Future observations cannot satisfy acceptance.")
    return observed


def text(value: Any, *, limit: int = 300) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and not any(
        ord(character) < 32 for character in value
    )


def source_identity(directory: Path, helper: Any) -> dict[str, Any]:
    """Read Git identity only; no hooks, shell, user configuration or source execution."""
    directory = helper.regular_path(directory)
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["/usr/bin/git", "--no-pager", "-c", "core.fsmonitor=false", "-C", str(directory),
             *arguments],
            stdin=subprocess.DEVNULL, capture_output=True, env=environment, timeout=30, check=False,
        )
        if result.returncode or len(result.stdout) + len(result.stderr) > 2_000_000:
            raise ValueError("Source identity could not be read within its bound.")
        return result.stdout.decode("utf-8").strip()

    before = git("rev-parse", "--verify", "HEAD")
    tree = git("rev-parse", "--verify", "HEAD^{tree}")
    dirty = bool(git("status", "--porcelain=v1", "--untracked-files=all"))
    if before != git("rev-parse", "--verify", "HEAD"):
        raise ValueError("Source revision changed while collecting its identity.")
    return {"revision": before, "tree": tree, "dirty": dirty}


def host_identity() -> dict[str, str]:
    # A hostname fingerprint is a correlation aid, not a hardware attestation.
    return {
        "system": platform.system(), "machine": platform.machine(), "macos": platform.mac_ver()[0],
        "hostId": hashlib.sha256(platform.node().encode()).hexdigest(),
        "identityKind": "hostname-sha256-not-hardware-attestation",
    }


def validate_source(value: Any) -> None:
    if (not isinstance(value, dict) or set(value) != {"revision", "tree", "dirty"}
            or any(not re.fullmatch(r"[a-f0-9]{40}", str(value.get(key, "")))
                   for key in ("revision", "tree"))
            or type(value["dirty"]) is not bool):
        raise ValueError("Acceptance requires an exact source revision, tree and dirty state.")


def validate_host(value: Any) -> None:
    if (not isinstance(value, dict)
            or set(value) != {"system", "machine", "macos", "hostId", "identityKind"}
            or value.get("system") != "Darwin" or value.get("machine") != "arm64"
            or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", str(value.get("macos", "")))
            or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("hostId", "")))
            or value.get("identityKind") != "hostname-sha256-not-hardware-attestation"):
        raise ValueError("macOS ARM64 host observations and their identity limitations are required.")


def set_digest(artifacts: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        artifacts, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def validate_artifacts(artifacts: Any, helper: Any) -> None:
    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 100:
        raise ValueError("Acceptance requires a bounded, nonempty final artifact set.")
    for name, pin in artifacts.items():
        if not isinstance(name, str):
            raise ValueError("Artifact names must be relative strings.")
        helper.archive_name(name)
        if (not isinstance(pin, dict) or set(pin) != {"name", "bytes", "sha256"}
                or pin["name"] != Path(name).name or type(pin["bytes"]) is not int
                or not 0 < pin["bytes"] <= helper.MAX_ARTIFACT
                or not re.fullmatch(r"[a-f0-9]{64}", str(pin["sha256"]))):
            raise ValueError("Every final artifact must have its exact name, size and hash.")


def distribution_sources(bundle: Path, dmg: Path, homebrew: Path, public: Path,
                         pins: dict[str, Any], helper: Any) -> dict[str, Path]:
    release = helper.SIGNED_RELEASE_ID
    sources = {f"releases/{release}/{name}": bundle / name for name in pins}
    sources.update({
        f"releases/{release}/{release}.dmg": dmg / f"{release}.dmg",
        f"releases/{release}/{release}-homebrew.tar.gz": homebrew / f"{release}-homebrew.tar.gz",
        f"releases/{release}/theovex_polaris-{helper.VERSION}.tar.gz":
            public / f"theovex_polaris-{helper.VERSION}.tar.gz",
        f"releases/{release}/theovex_polaris-{helper.VERSION}-py3-none-any.whl":
            public / f"theovex_polaris-{helper.VERSION}-py3-none-any.whl",
        "tap/Formula/polaris.rb": homebrew / "polaris.rb",
    })
    return sources


def inspect_distribution(bundle: Path, dmg: Path, homebrew: Path, public: Path,
                         helper: Any) -> dict[str, Any]:
    """Hash real final files; signature/notary verification remains the publisher's job."""
    bundle, dmg, homebrew, public = map(helper.regular_path, (bundle, dmg, homebrew, public))
    manifest, pins, package = helper.inspect_bundle(bundle)
    if manifest["id"] != helper.SIGNED_RELEASE_ID:
        raise ValueError("Unsigned or earlier bytes cannot become final signed acceptance.")
    source = public / f"theovex_polaris-{helper.VERSION}.tar.gz"
    wheel = public / f"theovex_polaris-{helper.VERSION}-py3-none-any.whl"
    helper.inspect_source(source, package)
    _, version, wheel_package = helper.wheel_identity(helper.read(wheel, limit=250_000_000))
    if version != helper.VERSION or wheel_package != package:
        raise ValueError("Source and public wheel differ from the signed candidate.")
    distribution = read_json(dmg / "result.json", helper)
    brew = read_json(homebrew / "homebrew.json", helper)
    if (distribution.get("format") != "polaris.macos-distribution/1"
            or distribution.get("bundle") != pins or distribution.get("stapled") is not True
            or distribution.get("signatureVerified") is not True
            or distribution.get("notarization", {}).get("status") != "Accepted"
            or distribution.get("source") != helper.artifact(source)
            or distribution.get("artifact", {}).get("name") != f"{helper.SIGNED_RELEASE_ID}.dmg"
            or brew.get("format") != "polaris.homebrew-release/1"
            or brew.get("release") != helper.SIGNED_RELEASE_ID or brew.get("mode") != "https-origin"
            or brew.get("manifest") != pins["manifest.json"]
            or brew.get("source") != helper.artifact(source)
            or brew.get("artifact", {}).get("name") != f"{helper.SIGNED_RELEASE_ID}-homebrew.tar.gz"):
        raise ValueError("Final distribution receipts are missing, local-only or mismatched.")
    helper.verify(dmg / distribution["artifact"]["name"], distribution["artifact"])
    helper.verify(homebrew / brew["artifact"]["name"], brew["artifact"])
    helper.verify(homebrew / "polaris.rb", brew["formula"])
    sources = distribution_sources(bundle, dmg, homebrew, public, pins, helper)
    artifacts = {name: helper.artifact(path) for name, path in sources.items()}
    validate_artifacts(artifacts, helper)
    return artifacts


def new_directory(path: Path, inputs: tuple[Path, ...], helper: Any) -> Path:
    path = helper.regular_path(path)
    if path.exists() or any(path.is_relative_to(helper.regular_path(item)) for item in inputs):
        raise ValueError("Acceptance output must be new and outside its immutable inputs.")
    path.mkdir(mode=0o700, parents=True)
    return path


def write_report(directory: Path, report: dict[str, Any], helper: Any) -> None:
    path = directory / "acceptance.json"
    with path.open("xb") as stream:
        stream.write(helper.json_bytes(report))
    path.chmod(0o600)


def create_template(artifacts: dict[str, Any], source: dict[str, Any], host: dict[str, Any],
                    output: Path, *, helper: Any, inputs: tuple[Path, ...] = ()) -> dict[str, Any]:
    validate_artifacts(artifacts, helper)
    validate_source(source)
    validate_host(host)
    report = {
        "format": FORMAT, "release": helper.SIGNED_RELEASE_ID, "artifacts": artifacts,
        "artifactSetSha256": set_digest(artifacts), "source": source, "baselineHost": host,
        "createdAt": datetime.now(UTC).isoformat(),
        "gates": {name: {"status": "not_run"} for name in sorted(GATES)},
        "publicationAuthorized": False, "localEvidenceOnly": True, "trustedCIEvidence": False,
    }
    write_report(new_directory(output, inputs, helper), report, helper)
    return report


def evidence_pin(pin: Any, helper: Any) -> str:
    if (not isinstance(pin, dict) or set(pin) != {"name", "bytes", "sha256"}
            or not isinstance(pin["name"], str)
            or not re.fullmatch(r"(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/){0,3}"
                                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", pin["name"])
            or pin["name"] == "observation.json"
            or type(pin["bytes"]) is not int or not 0 <= pin["bytes"] <= MAX_EVIDENCE_BYTES
            or not re.fullmatch(r"[a-f0-9]{64}", str(pin["sha256"]))):
        raise ValueError("Observation evidence needs a bounded relative path, size and SHA256.")
    return str(helper.archive_name(pin["name"]))


def validate_details(gate: str, record: dict[str, Any], report: dict[str, Any]) -> None:
    details = record["details"]
    if record["status"] != "passed":
        return
    flags: dict[str, dict[str, Any]] = {
        "standalone_lifecycle": {"upgradeVerified": True, "collisionRefused": True, "conservativeRemoval": True},
        "homebrew_lifecycle": {"upgradeVerified": True, "sandboxEnabled": True, "forcedLinking": False},
        "clean_account": {"newAccount": True, "defaultPrefix": "/opt/homebrew"},
        "second_apple_silicon_mac": {"physicallyDistinctMac": True},
        "quarantined_download": {"anonymousHttps": True, "redirects": 0, "quarantinePreserved": True},
        "native_editor_invocation": {"capabilitiesObserved": True, "reviewWorkflowObserved": True},
    }
    for key, expected in flags.get(gate, {}).items():
        if type(details.get(key)) is not type(expected) or details[key] != expected:
            raise ValueError("The observed gate does not cover its required acceptance claims.")
    if gate == "minimum_macos_15" and record["host"]["macos"].split(".")[0] != "15":
        raise ValueError("A newer macOS host does not test the minimum macOS 15 gate.")
    if gate == "second_apple_silicon_mac" and record["host"]["hostId"] == report["baselineHost"]["hostId"]:
        raise ValueError("The baseline host cannot be relabeled as the second Mac.")
    if gate == "native_editor_invocation" and not all(
        text(details.get(key)) for key in ("editorName", "editorVersion")
    ):
        raise ValueError("Native-editor acceptance needs the actual editor identity.")
    if gate == "source_tests" and (
        type(details.get("passed")) is not int or details["passed"] <= 0
        or type(details.get("failed")) is not int or details["failed"] != 0
    ):
        raise ValueError("Source-test acceptance needs observed passing and failing counts.")
    if gate in DECISION_GATES and details.get("decisionSha256") not in {
        pin["sha256"] for pin in record["evidence"] if pin["bytes"] > 0
    }:
        raise ValueError("Decision gates require their actual digest-bound decision evidence.")


def observation(path: Path, report: dict[str, Any], helper: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    record = read_json(path, helper)
    fields = {
        "format", "gate", "release", "artifactSetSha256", "status", "observer", "observedAt",
        "source", "host", "commands", "evidence", "details",
    }
    if (set(record) != fields or record["format"] != OBSERVATION_FORMAT
            or not isinstance(record["gate"], str) or record["gate"] not in GATES
            or record["release"] != report["release"]
            or record["artifactSetSha256"] != report["artifactSetSha256"]
            or not isinstance(record["status"], str) or record["status"] not in {"passed", "failed", "blocked"}
            or not text(record["observer"]) or not isinstance(record["details"], dict)
            or not isinstance(record["commands"], list) or len(record["commands"]) > 100
            or not isinstance(record["evidence"], list) or len(record["evidence"]) > 100):
        raise ValueError("Invalid, wrong-release or unbound gate observation.")
    observed_at = timestamp(record["observedAt"])
    if observed_at < timestamp(report["createdAt"]):
        raise ValueError("Gate observations must follow the final artifact-set freeze.")
    validate_source(record["source"])
    validate_host(record["host"])
    if record["source"] != report["source"] or (
        record["status"] == "passed" and record["source"]["dirty"]
    ):
        raise ValueError("Acceptance must use the exact clean source identity.")
    if record["gate"] not in DECISION_GATES and not record["commands"]:
        raise ValueError("An executed gate requires observed commands and their logs.")
    references = list(record["evidence"])
    for command in record["commands"]:
        if (not isinstance(command, dict) or set(command) != {
            "argv", "cwd", "startedAt", "finishedAt", "returncode", "expectedReturncode", "stdout", "stderr",
        } or not isinstance(command["argv"], list) or not 1 <= len(command["argv"]) <= 200
                or not all(text(argument, limit=4000) for argument in command["argv"])
                or not Path(command["argv"][0]).is_absolute()
                or not text(command["cwd"], limit=4000) or not Path(command["cwd"]).is_absolute()
                or type(command["returncode"]) is not int or type(command["expectedReturncode"]) is not int
                or not -255 <= command["returncode"] <= 255
                or not -255 <= command["expectedReturncode"] <= 255):
            raise ValueError("A command observation needs bounded argv, identity, outcome and logs.")
        started, finished = timestamp(command["startedAt"]), timestamp(command["finishedAt"])
        if not timestamp(report["createdAt"]) <= started <= finished <= observed_at:
            raise ValueError("Command timestamps precede the freeze or are inconsistent.")
        if record["status"] == "passed" and command["returncode"] != command["expectedReturncode"]:
            raise ValueError("Unexpected command outcomes cannot satisfy a passed gate.")
        references.extend((command["stdout"], command["stderr"]))
    if (record["status"] == "passed" and record["gate"] not in DECISION_GATES
            and not any(command["returncode"] == 0 for command in record["commands"])):
        raise ValueError("A passed execution gate requires at least one successful command.")
    if not references:
        raise ValueError("A gate without actual evidence cannot satisfy acceptance.")
    pins: dict[str, Any] = {}
    for pin in references:
        name = evidence_pin(pin, helper)
        if name in pins and pin != pins[name]:
            raise ValueError("Conflicting evidence pins are not permitted.")
        pins[name] = pin
    if len(pins) > 200 or sum(pin["bytes"] for pin in pins.values()) > MAX_TOTAL_EVIDENCE:
        raise ValueError("Gate evidence exceeds its bound.")
    for name, pin in pins.items():
        helper.verify(path.parent / name, pin, allow_empty=True)
    validate_details(record["gate"], record, report)
    return record, pins


def verify_report(directory: Path, artifacts: dict[str, Any], *, helper: Any,
                  require_complete: bool = False, approval: dict[str, Any] | None = None,
                  source_revision: str | None = None,
                  publisher: dict[str, Any] | None = None) -> dict[str, Any]:
    directory = helper.regular_path(directory)
    report_pin = helper.artifact(directory / "acceptance.json")
    report = read_json(directory / "acceptance.json", helper)
    helper.verify(directory / "acceptance.json", report_pin)
    validate_artifacts(artifacts, helper)
    if (set(report) != {
        "format", "release", "artifacts", "artifactSetSha256", "source", "baselineHost", "createdAt",
        "gates", "publicationAuthorized", "localEvidenceOnly", "trustedCIEvidence",
    } or report["format"] != FORMAT or report["release"] != helper.SIGNED_RELEASE_ID
            or report["artifacts"] != artifacts or report["artifactSetSha256"] != set_digest(artifacts)
            or report["publicationAuthorized"] is not False or report["localEvidenceOnly"] is not True
            or report["trustedCIEvidence"] is not False
            or not isinstance(report["gates"], dict) or set(report["gates"]) != GATES):
        raise ValueError("An exact final-artifact observation report is required; collection is not approval.")
    timestamp(report["createdAt"])
    validate_source(report["source"])
    validate_host(report["baselineHost"])
    if source_revision is not None and report["source"]["revision"] != source_revision:
        raise ValueError("Acceptance source revision differs from publisher approval.")
    expected_files = {"acceptance.json"}
    observed_times = [timestamp(report["createdAt"])]
    records = {}
    total = 0
    for name, gate in report["gates"].items():
        if not isinstance(gate, dict):
            raise ValueError("Invalid acceptance gate.")
        if gate == {"status": "not_run"} and not require_complete:
            continue
        if (set(gate) != {"status", "observation"} or not isinstance(gate["status"], str)
                or gate["status"] not in {"passed", "failed", "blocked"}):
            raise ValueError("Unrun or invalid acceptance gates block publication.")
        pin = gate["observation"]
        relative = f"evidence/{name}/observation.json"
        if (not isinstance(pin, dict) or set(pin) != {"name", "sha256", "bytes"}
                or pin["name"] != relative):
            raise ValueError("A gate must reference its exact collected observation.")
        helper.verify(directory / relative, pin)
        record, references = observation(directory / relative, report, helper)
        helper.verify(directory / relative, pin)
        if record["gate"] != name or record["status"] != gate["status"]:
            raise ValueError("The gate summary differs from its observation.")
        if require_complete and record["status"] != "passed":
            raise ValueError("Failed or blocked acceptance gates block publication.")
        observed_times.append(timestamp(record["observedAt"]))
        records[name] = record
        expected_files.add(relative)
        expected_files.update(f"evidence/{name}/{item}" for item in references)
        total += sum(item["bytes"] for item in references.values())
    if total > MAX_TOTAL_EVIDENCE:
        raise ValueError("The complete acceptance collection exceeds its evidence bound.")
    actual_files = set()
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in [*directories, *files]:
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Acceptance evidence cannot contain links or special files.")
            actual_files.add(path.relative_to(directory).as_posix())
    if actual_files != expected_files:
        raise ValueError("Acceptance contains missing or unreviewed evidence files.")
    if require_complete:
        if (not isinstance(approval, dict) or set(approval) != {"reportSha256", "reviewer", "reviewedAt"}
                or not text(approval["reviewer"]) or not re.fullmatch(
                    r"[a-f0-9]{64}", str(approval["reportSha256"]),
                ) or report_pin["sha256"] != approval["reportSha256"]
                or timestamp(approval["reviewedAt"]) < max(observed_times)):
            raise ValueError("Independent owner approval of this exact acceptance digest is required.")
        if publisher is not None:
            legal = records["license_source_advisory_approval"]["details"]
            ownership = records["publisher_origin_ownership"]["details"]
            if (legal.get("complianceReportSha256") != publisher["complianceReportSha256"]
                    or ownership.get("publisherRepository") != publisher["publisherRepository"]
                    or ownership.get("downloadOrigin") != publisher["downloadOrigin"]):
                raise ValueError("Acceptance decisions differ from the approved compliance or publisher.")
    helper.verify(directory / "acceptance.json", report_pin)
    return report


def collect(directory: Path, observations: list[Path], output: Path, *, helper: Any) -> dict[str, Any]:
    directory = helper.regular_path(directory)
    initial = read_json(directory / "acceptance.json", helper)
    report = copy.deepcopy(verify_report(directory, initial["artifacts"], helper=helper))
    if not 1 <= len(observations) <= len(GATES):
        raise ValueError("Collection needs a bounded nonempty list of gate observations.")
    initial_pin = helper.artifact(directory / "acceptance.json")
    additions = []
    for path in observations:
        path = helper.regular_path(path)
        pin = helper.artifact(path)
        record, references = observation(path, report, helper)
        name = record["gate"]
        if report["gates"][name] != {"status": "not_run"}:
            raise ValueError("Duplicate or conflicting gate observations require a new template, not replacement.")
        report["gates"][name] = {
            "status": record["status"],
            "observation": {**pin, "name": f"evidence/{name}/observation.json"},
        }
        additions.append((path, pin, record, references))
    output = new_directory(output, (directory, *(path.parent for path in observations)), helper)
    for path in directory.rglob("*"):
        if path.is_file() and path != directory / "acceptance.json":
            target = output / path.relative_to(directory)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    for path, pin, record, references in additions:
        target = output / "evidence" / record["gate"]
        target.mkdir(mode=0o700, parents=True)
        shutil.copyfile(path, target / "observation.json")
        helper.verify(target / "observation.json", pin)
        for name, reference in references.items():
            destination = target / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            helper.verify(path.parent / name, reference, allow_empty=True)
            shutil.copyfile(path.parent / name, destination)
            helper.verify(destination, reference, allow_empty=True)
        helper.verify(path, pin)
    helper.verify(directory / "acceptance.json", initial_pin)
    verify_report(directory, initial["artifacts"], helper=helper)
    write_report(output, report, helper)
    verify_report(output, report["artifacts"], helper=helper)
    return report


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("Invalid acceptance arguments; use --help without secrets or command credentials.")


def main() -> None:
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    template = commands.add_parser("template")
    for name in ("bundle-dir", "dmg-dir", "homebrew-dir", "public-dir", "source-dir", "output"):
        template.add_argument("--" + name, type=Path, required=True)
    record = commands.add_parser("collect")
    record.add_argument("--acceptance-dir", type=Path, required=True)
    record.add_argument("--observation", type=Path, action="append", required=True)
    record.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args()
        os.umask(0o077)
        helper = helper_module()
        if args.command == "template":
            inputs = (args.bundle_dir, args.dmg_dir, args.homebrew_dir, args.public_dir, args.source_dir)
            artifacts = inspect_distribution(*inputs[:4], helper)
            result = create_template(
                artifacts, source_identity(args.source_dir, helper), host_identity(), args.output,
                helper=helper, inputs=inputs,
            )
            if inspect_distribution(*inputs[:4], helper) != artifacts:
                raise ValueError("Distribution bytes changed during acceptance collection.")
        else:
            result = collect(args.acceptance_dir, args.observation, args.output, helper=helper)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit("Acceptance collection refused invalid, stale, conflicting or unsafe observations.") from None
    print(json.dumps({
        "artifactSetSha256": result["artifactSetSha256"],
        "gates": {name: gate["status"] for name, gate in result["gates"].items()},
        "publicationAuthorized": False, "observationCommandsExecuted": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()

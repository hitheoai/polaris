"""Prepare macOS releases offline; signing and Apple submissions require explicit approvals.

All outputs are new private directories. No key is imported/exported, no installer runs,
and no publication is performed. Local receipts are not trusted CI build attestations.
"""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import functools
import gzip
import hashlib
import importlib.util
import io
import json
import os
import platform
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]


@functools.lru_cache
def script(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("macos_" + name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helpers() -> Any:
    return script("build_homebrew_formula")


def write_json(path: Path, value: Any) -> None:
    with path.open("xb") as stream:
        stream.write(helpers().json_bytes(value))
    path.chmod(0o600)


def new_directory(path: Path, *inputs: Path) -> Path:
    path = helpers().regular_path(path)
    if path.exists() or any(path.is_relative_to(helpers().regular_path(item)) for item in inputs):
        raise ValueError("Output must be new and outside every immutable input.")
    path.mkdir(mode=0o700, parents=True)
    return path


def tree(root: Path) -> dict[str, Any]:
    root = helpers().regular_path(root)
    if not root.is_dir():
        raise ValueError("Evidence must be a regular directory.")
    result: dict[str, Any] = {}
    total = 0
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in sorted([*directories, *files]):
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError("Evidence contains a link or special file.")
            if stat.S_ISDIR(info.st_mode):
                continue
            relative = path.relative_to(root).as_posix()
            helpers().archive_name(relative)
            total += info.st_size
            if len(result) >= 30_000 or total > 1_500_000_000:
                raise ValueError("Evidence tree exceeds its bound.")
            result[relative] = helpers().artifact(path)
    return result


def tool(command: list[str], *, timeout: int = 300) -> tuple[str, str]:
    """Only explicit trusted system tools; no shell, ambient loader settings or secret arguments."""
    if command[0] not in ("/usr/bin/codesign", "/usr/bin/security", "/usr/bin/xcrun",
                           "/usr/bin/hdiutil", "/usr/sbin/spctl", "/usr/bin/git"):
        raise ValueError("Release tooling only invokes allowlisted absolute system executables.")
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()), "LANG": "C",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                 env=environment, start_new_session=True)
        try:
            child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise ValueError("Release tool interrupted; no successful result is recorded.") from None
        output.seek(0)
        errors.seek(0)
        stdout, stderr = output.read(2_000_001), errors.read(2_000_001)
    if child.returncode or len(stdout) + len(stderr) > 2_000_000:
        raise ValueError("A release tool failed or exceeded its output bound; no success is claimed.")
    return stdout.decode("utf-8"), stderr.decode("utf-8")


def configuration(path: Path) -> dict[str, Any]:
    value = json.loads(helpers().read(path))
    if (not isinstance(value, dict) or value.get("format") != "polaris.macos-publisher/2"
            or value.get("approved") is not True
            or not re.fullmatch(r"[A-F0-9]{40}", str(value.get("certificateSha1", "")))
            or not re.fullmatch(r"[A-Z0-9]{10}", str(value.get("teamId", "")))
            or not re.fullmatch(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,5}",
                                str(value.get("identifierPrefix", "")))
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}",
                                str(value.get("publisherRepository", "")))
            or not re.fullmatch(r"[a-f0-9]{40}", str(value.get("sourceRevision", "")))
            or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("complianceReportSha256", "")))
            or not isinstance(value.get("legalApproval"), str) or not value["legalApproval"].strip()):
        raise ValueError("An explicitly approved publisher, source revision, identity and legal decision are required.")
    origin = helpers().https_origin(value["downloadOrigin"])
    if (any(word in origin.lower() for word in ("example", "localhost", "placeholder", "replace"))
            or value["publisherRepository"].lower().split("/")[0] in ("owner", "example", "placeholder")
            or value["certificateSha1"] == "0" * 40 or value["sourceRevision"] == "0" * 40):
        raise ValueError("Placeholder publisher configuration cannot authorize distribution.")
    authority = value.get("complianceAuthorization")
    if (not isinstance(authority, dict) or set(authority) != {"path", "sha256"}
            or not isinstance(authority["path"], str) or not Path(authority["path"]).is_absolute()
            or not re.fullmatch(r"[a-f0-9]{64}", str(authority["sha256"]))
            or not isinstance(value.get("sourceBundleDirectory"), str)
            or not Path(value["sourceBundleDirectory"]).is_absolute()):
        raise ValueError("Independent compliance authorization and the retained original bundle are required.")
    helpers().regular_path(Path(authority["path"]))
    helpers().regular_path(Path(value["sourceBundleDirectory"]))
    return value


def requirement(config: dict[str, Any]) -> str:
    return ('anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
            f' and certificate leaf = H"{config["certificateSha1"]}"'
            f' and certificate leaf[subject.OU] = "{config["teamId"]}"')


def verify_signature(path: Path, config: dict[str, Any], *, native: bool = True) -> dict[str, Any]:
    helper = helpers()
    before = helper.artifact(path)
    tool(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
          "--test-requirement", requirement(config), str(path)])
    architectures = script("release_native").macho(helper.read(path, limit=250_000_000)) if native else []
    if native and not architectures:
        raise ValueError("Expected native code is missing.")
    records = []
    for entry in architectures or [{"architecture": None, "fileType": "container"}]:
        command = ["/usr/bin/codesign", "--display", "--verbose=4"]
        if entry["architecture"]:
            command += ["--arch", entry["architecture"]]
        _, information = tool([*command, str(path)])
        if (f"TeamIdentifier={config['teamId']}" not in information.splitlines()
                or not any(line.startswith("Authority=Developer ID Application:") for line in information.splitlines())
                or not any(line.startswith("Timestamp=") for line in information.splitlines())
                or "Signature=adhoc" in information
                or entry["fileType"] == "executable" and "(runtime)" not in information):
            raise ValueError("Expected Developer ID, secure timestamp or hardened runtime is missing.")
        hashes = re.findall(r"^CDHash=([a-f0-9]{40})$", information, re.MULTILINE)
        if native and len(hashes) != 1:
            raise ValueError("An unambiguous code-directory hash is required for notarization coverage.")
        if native:
            entitlement_command = ["/usr/bin/codesign", "--display", "--entitlements", "-"]
            if entry["architecture"]:
                entitlement_command += ["--arch", entry["architecture"]]
            entitlements, _ = tool([*entitlement_command, str(path)])
            if entitlements.strip() and plistlib.loads(entitlements.encode()) != {}:
                raise ValueError("Unreviewed entitlement exceptions are not permitted.")
        records.append({"architecture": entry["architecture"], "cdhash": hashes[0] if hashes else None,
                        "hardenedRuntime": "(runtime)" in information})
    helper.verify(path, before)
    return {"artifact": before, "architectures": records, "developerIdVerified": True,
            "timestampVerified": True, "entitlements": {}}


def identity_available(config: dict[str, Any]) -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("Signing requires a native Apple Silicon macOS host.")
    output, _ = tool(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"])
    expression = (r'^\s*\d+\)\s+' + re.escape(config["certificateSha1"])
                  + r' "Developer ID Application: [^"\n]+ \(' + re.escape(config["teamId"]) + r'\)"\s*$')
    if len(re.findall(expression, output, re.MULTILINE)) != 1:
        raise ValueError("The exact approved Developer ID Application identity is unavailable.")


def clean_source(config: dict[str, Any]) -> None:
    revision, _ = tool(["/usr/bin/git", "--no-pager", "-C", str(ROOT), "rev-parse", "HEAD"])
    status, _ = tool(["/usr/bin/git", "--no-pager", "-C", str(ROOT), "status", "--porcelain=v1",
                      "--untracked-files=all"])
    if revision.strip() != config["sourceRevision"] or status:
        raise ValueError("Final signing requires the exact approved, clean committed source revision.")


def source_package(package: dict[str, str]) -> None:
    """Bind every public file, including empty markers, not just a required subset."""
    root = ROOT / "src/polaris"
    helper = helpers()
    public = script("build_public_wheel")
    observed = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if (relative.parts[0] not in public.PUBLIC or "__pycache__" in relative.parts
                or path.suffix in (".pyc", ".pyo")):
            continue
        helper.regular_path(path)
        if path.is_file():
            observed[relative.as_posix()] = helper.artifact(path, allow_empty=True)["sha256"]
        elif not path.is_dir():
            raise ValueError("Public source contains a special file.")
    if not observed or observed != package:
        raise ValueError("The complete public wheel differs from the approved source checkout.")


def verify_installer(bundle: Path, manifest: dict[str, Any]) -> None:
    """Unsigned scripts must also match the approved builder source, not just their own pins."""
    with tempfile.TemporaryDirectory(prefix="polaris-bootstrap-verification-") as temporary:
        directory = Path(temporary).resolve()
        shutil.copyfile(bundle / "manifest.json", directory / "manifest.json")
        script("build_theo_release").render_bootstrap(directory, manifest)
        for name in ("install-theo.sh", "bootstrap.json"):
            if helpers().artifact(bundle / name) != helpers().artifact(directory / name):
                raise ValueError("The bootstrap differs from the approved installer source.")


def native_bytes(bundle: Path, record: dict[str, Any]) -> bytes:
    container = record["container"]
    if container.startswith("payload.tar.gz/"):
        with tarfile.open(bundle / "payload.tar.gz", "r:gz") as payload:
            member = payload.extractfile(container.removeprefix("payload.tar.gz/"))
            assert member
            with member:
                wheel_bytes = member.read(250_000_001)
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as wheel:
            result = wheel.read(record["path"])
    else:
        with tarfile.open(bundle / container, "r:gz") as archive:
            stream = archive.extractfile(record["path"])
            assert stream
            with stream:
                result = stream.read(250_000_001)
    if len(result) != record["bytes"] or hashlib.sha256(result).hexdigest() != record["sha256"]:
        raise ValueError("Native bytes changed after inventory.")
    return result


def stage(bundle: Path, output: Path) -> dict[str, Any]:
    helper = helpers()
    bundle = helper.regular_path(bundle)
    manifest, pins, _ = helper.inspect_bundle(bundle)
    if manifest["id"] != helper.RELEASE_ID:
        raise ValueError("Signing staging requires the untouched upstream candidate.")
    records = manifest["nativeCompatibility"]["files"]
    output = new_directory(output, bundle)
    targets = {}
    for record in records:
        key = record["sha256"]
        if key in targets:
            continue
        data = native_bytes(bundle, record)
        path = output / "native" / key / "native"
        path.parent.mkdir(mode=0o700, parents=True)
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o700)
        targets[key] = {"path": path.relative_to(output).as_posix(), "artifact": helper.artifact(path),
                        "slices": record["slices"]}
    for name, pin in pins.items():
        helper.verify(bundle / name, pin)
    result = {"format": "polaris.macos-signing-stage/1", "sourceBundle": str(bundle),
              "sourceRelease": manifest["id"], "release": helper.SIGNED_RELEASE_ID, "inputs": pins,
              "targets": targets, "nativeFileOccurrences": len(records), "signingPerformed": False,
              "notarizationSubmitted": False, "publicationPerformed": False, "localEvidenceOnly": True}
    write_json(output / "stage.json", result)
    return result


def record_hash(data: bytes, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm, data).digest()
    return algorithm + "=" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def wheel_record(content: bytes) -> tuple[str, dict[str, bytes], dict[str, int]]:
    helpers().wheel_identity(content)
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        files = {member.filename: archive.read(member) for member in archive.infolist() if not member.is_dir()}
        modes = {member.filename: member.external_attr >> 16 for member in archive.infolist() if not member.is_dir()}
    records = [name for name in files if name.count("/") == 1 and name.endswith(".dist-info/RECORD")]
    if len(records) != 1 or len(files[records[0]]) > 2_000_000:
        raise ValueError("Wheel lacks a bounded, unambiguous RECORD.")
    record = records[0]
    rows = list(csv.reader(io.StringIO(files[record].decode("utf-8"))))
    declared = {}
    for row in rows:
        if len(row) != 3 or row[0] in declared:
            raise ValueError("Invalid or duplicate wheel RECORD row.")
        declared[row[0]] = row[1:]
    exempt = {record + ".jws", record + ".p7s"}
    if set(declared) != set(files) - exempt or declared.get(record) != ["", ""]:
        raise ValueError("Wheel RECORD does not cover exactly the input files.")
    for name, (checksum, size) in declared.items():
        if name == record:
            continue
        algorithm = checksum.split("=", 1)[0]
        if (algorithm not in ("sha256", "sha384", "sha512")
                or checksum != record_hash(files[name], algorithm) or size != str(len(files[name]))):
            raise ValueError("Wheel RECORD content or size differs from the original bytes.")
    return record, files, modes


def transform_wheel(content: bytes, replacements: dict[str, bytes]) -> bytes:
    record, files, modes = wheel_record(content)
    changed = False
    for name, data in list(files.items()):
        if data[:4] not in script("release_native").MAGIC:
            continue
        key = hashlib.sha256(data).hexdigest()
        if key not in replacements:
            raise ValueError("A native wheel member is missing from the signing coverage.")
        files[name] = replacements[key]
        changed = True
    if not changed:
        return content
    for name in (record + ".jws", record + ".p7s"):
        files.pop(name, None)
    rows = io.StringIO(newline="")
    writer = csv.writer(rows, lineterminator="\n")
    for name, data in sorted(files.items()):
        if name != record:
            writer.writerow((name, record_hash(data), len(data)))
    writer.writerow((record, "", ""))
    files[record] = rows.getvalue().encode()
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o755 if modes[name] & 0o111 else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    wheel_record(result.getvalue())
    return result.getvalue()


def transform_tar(source: Path, target: Path, roots: set[str],
                  replacements: dict[str, bytes], *, payload: bool = False) -> None:
    helper = helpers()
    members = helper.inspect_tar(source, roots, links=not payload)
    locks: dict[str, list[str]] = {"app": [], "analyzer": []}
    with tarfile.open(source, "r:gz") as original, target.open("xb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for old in sorted(members, key=lambda item: item.name):
                    if payload and old.name in ("app/requirements.txt", "analyzer/requirements.txt"):
                        continue
                    item = copy.copy(old)
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ""
                    item.pax_headers = {}
                    stream = original.extractfile(old) if old.isfile() else None
                    data = None
                    if stream is not None:
                        with stream:
                            if old.size > 250_000_000:
                                raise ValueError("Archive file exceeds its transformation bound.")
                            data = stream.read(250_000_001)
                        if payload and old.name.endswith(".whl"):
                            data = transform_wheel(data, replacements)
                            name, version, _ = helper.wheel_identity(data)
                            component = old.name.split("/")[0]
                            locks[component].append(script("analyzer_delivery").requirements_line(
                                name, version, hashlib.sha256(data).hexdigest(), component=component,
                            ))
                        elif data[:4] in script("release_native").MAGIC:
                            key = hashlib.sha256(data).hexdigest()
                            if key not in replacements:
                                raise ValueError("A native runtime member is missing from signing coverage.")
                            data = replacements[key]
                        item.size = len(data)
                    archive.addfile(item, io.BytesIO(data) if data is not None else None)
                if payload:
                    for component, lines in locks.items():
                        data = ("\n".join(sorted(lines)) + "\n").encode()
                        item = tarfile.TarInfo(f"{component}/requirements.txt")
                        item.size, item.mode = len(data), 0o600
                        archive.addfile(item, io.BytesIO(data))


def archive_tree(root: Path, destination: Path) -> dict[str, Any]:
    inputs = tree(root)
    with destination.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            for name, pin in sorted(inputs.items()):
                helpers().verify(root / name, pin)
                item = tarfile.TarInfo(f"compliance/{name}")
                item.size, item.mode = pin["bytes"], 0o600
                with (root / name).open("rb") as stream:
                    archive.addfile(item, stream)
    if inputs != tree(root):
        raise ValueError("Compliance evidence changed during packaging.")
    return inputs


def compliance(directory: Path, pins: dict[str, Any], manifest: dict[str, Any], *,
               complete: bool = False, expected_report: str | None = None,
               bundle_dir: Path | None = None,
               authorization: dict[str, Any] | None = None) -> dict[str, Any]:
    helper = helpers()
    actual = tree(directory)
    report_path = directory / "compliance-report.json"
    report = json.loads(helper.read(report_path, limit=20_000_000))
    if (not isinstance(report, dict)
            or report.get("format") not in ("polaris.release-compliance/1", "polaris.release-compliance/2")
            or report.get("release") != {key: manifest[key] for key in ("id", "version", "platform")}
            or report.get("inventoryComplete") is not True):
        raise ValueError("Compliance evidence has an incompatible release or incomplete inventory.")
    inputs = report.get("inputArtifacts", [])
    declared = {item["name"]: item for item in inputs}
    if len(declared) != len(inputs) or declared != pins:
        raise ValueError("Compliance evidence does not bind every exact input bundle artifact.")
    files = report.get("files", [])
    expected = {item["name"]: item for item in files}
    if (len(expected) != len(files) or set(actual) != {*expected, "compliance-report.json"}
            or not {"inventory.json", "sbom.cdx.json", "THIRD_PARTY_NOTICES.txt"} <= set(expected)
            or report.get("inventorySha256") != expected["inventory.json"]["sha256"]):
        raise ValueError("Compliance output set or inventory binding is inconsistent.")
    for name, pin in expected.items():
        helper.archive_name(name)
        helper.verify(directory / name, pin)
    if expected_report is not None and actual["compliance-report.json"]["sha256"] != expected_report:
        raise ValueError("The compliance report is not the exact publisher-approved evidence.")
    if complete and (report.get("complete") is not True or report.get("unresolved") != []):
        raise ValueError("Unresolved license, source, provenance or advisory obligations block signing.")
    if complete:
        if (report.get("format") != "polaris.release-compliance/2" or report.get("stage") != "evaluated"
                or bundle_dir is None or not isinstance(authorization, dict)
                or set(authorization) != {"path", "sha256"}):
            raise ValueError("Historical or unevaluated compliance cannot authorize signing without independent decisions.")
        script("source_delivery").validate_archive(
            bundle_dir / "third-party-sources.tar.gz", manifest["thirdPartySources"],
            required_artifacts={manifest["analyzerIdentity"]["derivativeWheelSha256"]},
            require_compliance_complete=True,
        )
        verified = script("release_compliance_resolution").verify_for_signing(
            bundle_dir=bundle_dir, compliance_dir=directory,
            authorization_path=Path(authorization["path"]), authorization_sha256=authorization["sha256"],
        )
        if verified != report:
            raise ValueError("Replayed compliance differs from the report approved by the publisher.")
    if tree(directory) != actual:
        raise ValueError("Compliance evidence changed during verification.")
    return report


def preflight(bundle: Path, compliance_dir: Path | None, config_path: Path | None) -> dict[str, Any]:
    manifest, pins, _ = helpers().inspect_bundle(bundle)
    blockers, report, config = [], None, None
    source_report = script("source_delivery").validate_archive(
        bundle / "third-party-sources.tar.gz", manifest["thirdPartySources"],
        required_artifacts={manifest["analyzerIdentity"]["derivativeWheelSha256"]},
    )
    if source_report["complianceComplete"] is not True:
        blockers.append("Third-party source packet remains preparation-only; independent source/build/relink/legal review is required.")
    resolution_verified = False
    if compliance_dir is None:
        blockers.append("Missing dependency compliance evidence.")
    else:
        report = compliance(compliance_dir, pins, manifest)
        if report.get("complete") is not True or report.get("unresolved") != []:
            blockers.append("Unresolved dependency compliance obligations.")
    if config_path is None:
        blockers.append("Publisher/signing configuration has not been approved.")
    else:
        try:
            config = configuration(config_path)
        except (ValueError, KeyError, TypeError):
            blockers.append("Publisher/signing configuration has not been approved.")
    if config:
        if compliance_dir is not None:
            try:
                if helpers().regular_path(Path(config["sourceBundleDirectory"])) != helpers().regular_path(bundle):
                    raise ValueError("Publisher configuration selects a different original bundle.")
                compliance(
                    compliance_dir, pins, manifest, complete=True,
                    expected_report=config["complianceReportSha256"],
                    bundle_dir=bundle, authorization=config["complianceAuthorization"],
                )
                resolution_verified = True
            except (ValueError, OSError, KeyError, TypeError):
                blockers.append("Exact independently authorized compliance replay has not passed.")
        for check in (identity_available, clean_source):
            try:
                check(config)
            except ValueError as error:
                blockers.append(str(error))
    else:
        blockers.append("Expected Developer ID identity and committed-source binding are not established.")
    return {"format": "polaris.macos-preflight/1", "release": manifest["id"],
            "signedRelease": helpers().SIGNED_RELEASE_ID, "inputs": pins,
            "nativeCompatibility": manifest["nativeCompatibility"],
            "unresolvedComplianceCount": len(report.get("unresolved", [])) if report else None,
            "complianceResolutionVerified": resolution_verified,
            "readyToSign": not blockers, "blockers": blockers, "credentialsUsed": False,
            "signingPerformed": False, "notarizationSubmitted": False, "publicationPerformed": False,
            "localEvidenceOnly": True, "signedRuntimeAcceptance": "not_run"}


def sign(stage_dir: Path, compliance_dir: Path, config_path: Path, output: Path, *,
         approved: bool = False) -> dict[str, Any]:
    if not approved:
        raise ValueError("Signing requires explicit --approve-signing; preparation does not grant approval.")
    helper = helpers()
    config = configuration(config_path)
    stage_dir, compliance_dir = map(helper.regular_path, (stage_dir, compliance_dir))
    prepared = json.loads(helper.read(stage_dir / "stage.json", limit=20_000_000))
    bundle = helper.regular_path(Path(prepared["sourceBundle"]))
    manifest, pins, package = helper.inspect_bundle(bundle)
    if (prepared.get("format") != "polaris.macos-signing-stage/1"
            or prepared.get("sourceRelease") != helper.RELEASE_ID or manifest["id"] != helper.RELEASE_ID
            or prepared.get("release") != helper.SIGNED_RELEASE_ID or prepared.get("inputs") != pins):
        raise ValueError("Signing stage is stale or belongs to different inputs.")
    if helper.regular_path(Path(config["sourceBundleDirectory"])) != bundle:
        raise ValueError("The staged source differs from the approved retained original bundle.")
    compliance_report = compliance(
        compliance_dir, pins, manifest, complete=True, expected_report=config["complianceReportSha256"],
        bundle_dir=bundle, authorization=config["complianceAuthorization"],
    )
    expected_targets = {record["sha256"] for record in manifest["nativeCompatibility"]["files"]}
    if set(prepared["targets"]) != expected_targets:
        raise ValueError("Signing stage omits native code.")
    for key, target in prepared["targets"].items():
        if target["path"] != f"native/{key}/native":
            raise ValueError("Signing target escapes its content-addressed stage.")
        helper.verify(stage_dir / target["path"], target["artifact"])
        if target["artifact"]["sha256"] != key:
            raise ValueError("Signing target differs from its original native bytes.")
        if script("release_native").macho(helper.read(stage_dir / target["path"], limit=250_000_000)) != target["slices"]:
            raise ValueError("Signing target architecture metadata is stale.")
    source_package(package)
    verify_installer(bundle, manifest)
    clean_source(config)
    identity_available(config)
    output = new_directory(output, bundle, stage_dir, compliance_dir)
    derived = output / "bundle"
    derived.mkdir(mode=0o700)
    replacements, signatures = {}, {}
    ordered = sorted(prepared["targets"].items(),
                     key=lambda pair: (any(item["fileType"] == "executable" for item in pair[1]["slices"]),
                                       -pair[1]["path"].count("/"), pair[0]))
    for key, target in ordered:
        path = output / target["path"]
        path.parent.mkdir(mode=0o700, parents=True)
        shutil.copyfile(stage_dir / target["path"], path)
        path.chmod(0o700)
        command = ["/usr/bin/codesign", "--force", "--sign", config["certificateSha1"], "--timestamp",
                   "--identifier", config["identifierPrefix"] + ".native." + key]
        if any(item["fileType"] == "executable" for item in target["slices"]):
            command += ["--options", "runtime"]
        tool([*command, str(path)])
        signatures[key] = verify_signature(path, config)
        replacements[key] = helper.read(path, limit=250_000_000)
    next_manifest = copy.deepcopy(manifest)
    next_manifest["id"] = helper.SIGNED_RELEASE_ID
    for component, root in (("python", "python"), ("uv", "uv-aarch64-apple-darwin")):
        pin = manifest["runtimes"][component]
        target = derived / f"{component}-developer-id.tar.gz"
        transform_tar(bundle / pin["name"], target, {root}, replacements)
        next_manifest["runtimes"][component] = {
            **helper.artifact(target), "version": pin["version"], "upstream": pin,
            "transformation": "developer-id-signing",
        }
    transform_tar(bundle / "payload.tar.gz", derived / "payload.tar.gz",
                  {"app", "analyzer"}, replacements, payload=True)
    next_manifest["payload"] = helper.artifact(derived / "payload.tar.gz")
    shutil.copyfile(bundle / "third-party-sources.tar.gz", derived / "third-party-sources.tar.gz")
    compliance_files = archive_tree(compliance_dir, derived / "compliance.tar.gz")
    next_manifest["compliance"] = helper.artifact(derived / "compliance.tar.gz")
    native = helper.native_inventory(derived, next_manifest)
    expected_occurrences = Counter(signatures[item["sha256"]]["artifact"]["sha256"]
                                   for item in manifest["nativeCompatibility"]["files"])
    if Counter(item["sha256"] for item in native["files"]) != expected_occurrences:
        raise ValueError("Repackaged native code does not exactly match verified signing coverage.")
    next_manifest["nativeCompatibility"] = native
    artifacts = {path.name: helper.artifact(path) for path in derived.iterdir()}
    report = {"format": "polaris.developer-id-signing/1", "release": helper.SIGNED_RELEASE_ID,
              "sourceRelease": helper.RELEASE_ID, "sourceRevision": config["sourceRevision"],
              "sourceBundle": pins, "artifacts": artifacts, "nativeSignatures": signatures,
              "complianceFiles": compliance_files, "teamId": config["teamId"],
              "complianceAuthorizationSha256": compliance_report["authorizationSha256"],
              "complianceLedgerSha256": compliance_report["ledgerSha256"],
              "certificateSha1": config["certificateSha1"], "signaturesVerified": True,
              "wheelRecordHashesRegenerated": True, "oldDetachedWheelSignaturesRetained": False,
              "notarizationSubmitted": False, "publicationPerformed": False, "localEvidenceOnly": True}
    write_json(derived / "signing-report.json", report)
    next_manifest["signing"] = helper.artifact(derived / "signing-report.json")
    write_json(derived / "manifest.json", next_manifest)
    script("build_theo_release").render_bootstrap(derived, next_manifest)
    _, final_pins, _ = helper.inspect_bundle(derived)
    for name, pin in pins.items():
        helper.verify(bundle / name, pin)
    if tree(compliance_dir) != compliance_files:
        raise ValueError("Compliance evidence changed during signing.")
    compliance(
        compliance_dir, pins, manifest, complete=True, expected_report=config["complianceReportSha256"],
        bundle_dir=bundle, authorization=config["complianceAuthorization"],
    )
    clean_source(config)
    write_json(output / "result.json", {"format": "polaris.macos-signed-result/1",
                                      "bundle": final_pins, "notarized": False,
                                      "signedRuntimeAcceptance": "not_run", "publicationPerformed": False})
    return {"bundle": str(derived), "signaturesVerified": True, "notarized": False}


def expose_native(bundle: Path, manifest: dict[str, Any], output: Path) -> dict[str, Path]:
    paths = {}
    for record in manifest["nativeCompatibility"]["files"]:
        key = record["sha256"]
        if key not in paths:
            path = output / f"{key}.mach-o"
            with path.open("xb") as stream:
                stream.write(native_bytes(bundle, record))
            path.chmod(0o700)
            paths[key] = path
    return paths


def verify_signed(bundle: Path, config: dict[str, Any]) -> dict[str, Any]:
    helper = helpers()
    manifest, pins, package = helper.inspect_bundle(bundle)
    if manifest["id"] != helper.SIGNED_RELEASE_ID:
        raise ValueError("Only the distinct signed derivative can be notarized or distributed.")
    report = json.loads(helper.read(bundle / "signing-report.json", limit=20_000_000))
    if (report["teamId"] != config["teamId"] or report["certificateSha1"] != config["certificateSha1"]
            or report["sourceRevision"] != config["sourceRevision"]
            or report["complianceFiles"]["compliance-report.json"]["sha256"] != config["complianceReportSha256"]
            or report.get("complianceAuthorizationSha256") != config["complianceAuthorization"]["sha256"]):
        raise ValueError("Signed evidence differs from the approved identity, source or compliance decision.")
    clean_source(config)
    source_package(package)
    verify_installer(bundle, manifest)
    verify_shipped_compliance(bundle, report, config)
    verified = {}
    with tempfile.TemporaryDirectory(prefix="polaris-signature-verification-") as temporary:
        paths = expose_native(bundle, manifest, Path(temporary).resolve())
        for key, path in paths.items():
            verified[key] = verify_signature(path, config)
    declared = {value["artifact"]["sha256"]: value for value in report["nativeSignatures"].values()}
    if set(declared) != set(verified):
        raise ValueError("Signing receipt does not cover the current native code.")
    for key, value in verified.items():
        if value["architectures"] != declared[key]["architectures"]:
            raise ValueError("Current code-directory hashes differ from signing evidence.")
    for name, pin in pins.items():
        helper.verify(bundle / name, pin)
    return {"bundle": pins, "nativeSignatures": verified, "signaturesVerified": True}


def verify_shipped_compliance(bundle: Path, signing: dict[str, Any], config: dict[str, Any]) -> None:
    """Replay shipped decisions against retained original inputs, never saved summary flags."""
    helper = helpers()
    helper.inspect_tar(bundle / "compliance.tar.gz", {"compliance"})
    expected = signing["complianceFiles"]
    observed: dict[str, dict[str, Any]] = {}
    with tarfile.open(bundle / "compliance.tar.gz", "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name.removeprefix("compliance/")
            stream = archive.extractfile(member)
            assert stream
            checksum = hashlib.sha256()
            with stream:
                while chunk := stream.read(1_048_576):
                    checksum.update(chunk)
            observed[name] = {"name": Path(name).name, "sha256": checksum.hexdigest(), "bytes": member.size}
        if observed != expected:
            raise ValueError("Shipped compliance differs from the signing evidence.")
        if observed["compliance-report.json"]["bytes"] > 20_000_000:
            raise ValueError("Shipped compliance report exceeds its bound.")
        stream = archive.extractfile("compliance/compliance-report.json")
        assert stream
        with stream:
            report = json.loads(stream.read(20_000_001))
    if (observed["compliance-report.json"]["sha256"] != config["complianceReportSha256"]
            or report.get("format") != "polaris.release-compliance/2" or report.get("stage") != "evaluated"
            or report.get("release") != {"id": helper.RELEASE_ID, "version": helper.VERSION, "platform": helper.PLATFORM}
            or report.get("inventoryComplete") is not True or report.get("complete") is not True
            or report.get("unresolved") != []):
        raise ValueError("Shipped compliance is not the exact complete approved report.")
    inputs = report.get("inputArtifacts", [])
    if len(inputs) != len(signing["sourceBundle"]) or {item["name"]: item for item in inputs} != signing["sourceBundle"]:
        raise ValueError("Shipped compliance does not bind the signing inputs.")
    files = report.get("files", [])
    if (len(files) != len(observed) - 1
            or {item["name"] for item in files} != set(observed) - {"compliance-report.json"}
            or report.get("inventorySha256") != observed["inventory.json"]["sha256"]):
        raise ValueError("Shipped compliance file coverage is incomplete.")
    for item in files:
        actual = observed[item["name"]]
        if any(item[key] != actual[key] for key in ("bytes", "sha256")):
            raise ValueError("Shipped compliance file binding is inconsistent.")
    if (report.get("authorizationSha256") != config["complianceAuthorization"]["sha256"]
            or report.get("ledgerSha256") != signing.get("complianceLedgerSha256")):
        raise ValueError("Shipped decisions differ from the independently approved authorization.")
    original = helper.regular_path(Path(config["sourceBundleDirectory"]))
    original_manifest, original_pins, _ = helper.inspect_bundle(original)
    if original_manifest["id"] != helper.RELEASE_ID or original_pins != signing["sourceBundle"]:
        raise ValueError("The retained original bundle does not match the signing inputs.")
    with tempfile.TemporaryDirectory(prefix="polaris-compliance-replay-") as temporary:
        directory = Path(temporary).resolve() / "evidence"
        directory.mkdir(mode=0o700)
        with tarfile.open(bundle / "compliance.tar.gz", "r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                name = helper.archive_name(member.name.removeprefix("compliance/"))
                destination = directory / name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                assert stream
                with stream, destination.open("xb") as output:
                    shutil.copyfileobj(stream, output, length=1_048_576)
                destination.chmod(0o600)
                helper.verify(destination, observed[name])
        compliance(
            directory, original_pins, original_manifest, complete=True,
            expected_report=config["complianceReportSha256"], bundle_dir=original,
            authorization=config["complianceAuthorization"],
        )


def notary_profile(config: dict[str, Any]) -> str:
    profile = config.get("notaryKeychainProfile")
    if not isinstance(profile, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", profile):
        raise ValueError("Notarization requires a named existing Keychain profile, never a plaintext credential.")
    return profile


def validate_notary(submission: dict[str, Any], log: dict[str, Any], pin: dict[str, Any],
                    cdhashes: set[str]) -> None:
    if (not re.fullmatch(r"[a-f0-9-]{36}", str(submission.get("id", "")))
            or submission.get("status") != "Accepted" or log.get("status") != "Accepted"
            or log.get("jobId") != submission["id"] or log.get("sha256") != pin["sha256"]):
        raise ValueError("Apple did not accept the exact submitted artifact.")
    covered = {item.get("cdhash") for item in log.get("ticketContents", [])}
    if not cdhashes <= covered:
        raise ValueError("Apple's ticket log does not cover every submitted native code-directory hash.")


def submit(archive: Path, config: dict[str, Any], output: Path, cdhashes: set[str]) -> dict[str, Any]:
    helper = helpers()
    pin = helper.artifact(archive)
    profile = notary_profile(config)
    stdout, _ = tool(["/usr/bin/xcrun", "notarytool", "submit", str(archive), "--keychain-profile", profile,
                      "--wait", "--timeout", "30m", "--output-format", "json", "--no-progress"], timeout=2100)
    submission = json.loads(stdout)
    write_json(output / "submission.json", submission)
    if not re.fullmatch(r"[a-f0-9-]{36}", str(submission.get("id", ""))):
        raise ValueError("Apple returned no usable submission ID.")
    log_path = output / "notary-log.json"
    tool(["/usr/bin/xcrun", "notarytool", "log", submission["id"], str(log_path),
          "--keychain-profile", profile, "--output-format", "json"])
    log = json.loads(helper.read(log_path, limit=20_000_000))
    helper.verify(archive, pin)
    validate_notary(submission, log, pin, cdhashes)
    return {"submission": submission, "submittedArtifact": pin, "log": helper.artifact(log_path),
            "coveredCodeDirectoryHashes": sorted(cdhashes), "status": "Accepted"}


def notarize_payload(bundle: Path, config_path: Path, output: Path, *, approved: bool = False) -> dict[str, Any]:
    if not approved:
        raise ValueError("Apple submission requires explicit --approve-submit.")
    config = configuration(config_path)
    notary_profile(config)
    verified = verify_signed(bundle, config)
    output = new_directory(output, bundle)
    native_dir = output / "native"
    native_dir.mkdir(mode=0o700)
    manifest = json.loads(helpers().read(bundle / "manifest.json"))
    paths = expose_native(bundle, manifest, native_dir)
    archive = output / "payload-notarization.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zipped:
        for key, path in sorted(paths.items()):
            zipped.write(path, arcname=f"native/{key}.mach-o")
    cdhashes = {item["cdhash"] for record in verified["nativeSignatures"].values()
               for item in record["architectures"]}
    result = submit(archive, config, output, cdhashes)
    if verify_signed(bundle, config) != verified:
        raise ValueError("Signed bundle changed during notarization.")
    result |= {"format": "polaris.payload-notarization/1", "release": helpers().SIGNED_RELEASE_ID,
               "bundle": verified["bundle"], "payloadCoverageVerified": True,
               "stapled": False, "offlineGatekeeperAcceptance": "not_established", "localEvidenceOnly": True}
    write_json(output / "result.json", result)
    return result


def distribution_content(bundle: Path, source_archive: Path, content: Path) -> dict[str, Any]:
    content.mkdir(mode=0o700)
    shutil.copytree(bundle, content / "release")
    (content / "source").mkdir(mode=0o700)
    shutil.copyfile(source_archive, content / "source" / source_archive.name)
    installer = content / "Install Theo.command"
    with installer.open("x") as stream:
        stream.write('#!/bin/bash\nset -e\nhere=$(cd -- "$(dirname -- "$0")" && /bin/pwd -P)\n'
                     'exec /bin/bash "$here/release/install-theo.sh" --release-dir "$here/release" "$@"\n')
    installer.chmod(0o700)
    with (content / "README.txt").open("x") as stream:
        stream.write("Polaris / Theo CLI for Apple Silicon, macOS 15 or later.\n"
                     "From Terminal: bash '/Volumes/Polaris CLI/Install Theo.command'\n"
                     "The installer does not configure a project, editor, account or shell profile.\n"
                     "Do not remove quarantine or disable macOS security policy to install this release.\n"
                     "Dependency notices and corresponding-source evidence accompany the release.\n")
    return tree(content)


def verify_distribution_contents(image: Path, bundle: Path, source_archive: Path) -> dict[str, Any]:
    """Mount read-only without opening or executing the installer, and compare actual bytes."""
    pin = helpers().artifact(image)
    with tempfile.TemporaryDirectory(prefix="polaris-dmg-verification-") as temporary:
        root = Path(temporary).resolve()
        expected = distribution_content(bundle, source_archive, root / "expected")
        mount = root / "mount"
        mount.mkdir(mode=0o700)
        mounted = False
        try:
            stdout, _ = tool([
                "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-plist",
                "-mountpoint", str(mount), str(image),
            ], timeout=120)
            mounted = True
            attached = plistlib.loads(stdout.encode())
            if [item["mount-point"] for item in attached.get("system-entities", []) if "mount-point" in item] != [str(mount)]:
                raise ValueError("DMG attachment did not use its private verification mountpoint.")
            if tree(mount) != expected:
                raise ValueError("DMG contents do not match the exact approved bundle, source and installer.")
        finally:
            if mounted:
                tool(["/usr/bin/hdiutil", "detach", str(mount)], timeout=120)
    helpers().verify(image, pin)
    return expected


def dmg(bundle: Path, source_archive: Path, payload_evidence: Path, config_path: Path,
        output: Path, *, approve_signing: bool = False, approve_submit: bool = False) -> dict[str, Any]:
    if not approve_signing or not approve_submit:
        raise ValueError("DMG production requires explicit signing and Apple-submission approvals.")
    helper = helpers()
    config = configuration(config_path)
    profile = notary_profile(config)
    verified = verify_signed(bundle, config)
    manifest, _, package = helper.inspect_bundle(bundle)
    helper.inspect_source(source_archive, package)
    payload_evidence = helper.regular_path(payload_evidence)
    payload = json.loads(helper.read(payload_evidence / "result.json", limit=20_000_000))
    if (payload.get("format") != "polaris.payload-notarization/1"
            or payload.get("bundle") != verified["bundle"] or payload.get("payloadCoverageVerified") is not True):
        raise ValueError("Payload-first notarization is missing or belongs to different bundle bytes.")
    helper.verify(payload_evidence / "payload-notarization.zip", payload["submittedArtifact"])
    helper.verify(payload_evidence / "notary-log.json", payload["log"])
    cdhashes = {item["cdhash"] for record in verified["nativeSignatures"].values()
               for item in record["architectures"]}
    validate_notary(payload["submission"], json.loads(helper.read(payload_evidence / "notary-log.json",
                                                                limit=20_000_000)),
                    payload["submittedArtifact"], cdhashes)
    info, _ = tool(["/usr/bin/xcrun", "notarytool", "info", payload["submission"]["id"],
                   "--keychain-profile", profile, "--output-format", "json"])
    if json.loads(info).get("status") != "Accepted":
        raise ValueError("Apple no longer reports the payload submission as accepted.")
    identity_available(config)
    output = new_directory(output, bundle, payload_evidence, source_archive)
    content = output / "content"
    content_pins = distribution_content(bundle, source_archive, content)
    image = output / f"{manifest['id']}.dmg"
    tool(["/usr/bin/hdiutil", "create", "-fs", "HFS+", "-format", "UDZO", "-volname", "Polaris CLI",
          "-srcfolder", str(content), str(image)], timeout=900)
    tool(["/usr/bin/codesign", "--sign", config["certificateSha1"], "--timestamp", str(image)])
    verify_signature(image, config, native=False)
    accepted = submit(image, config, output, set())
    tool(["/usr/bin/xcrun", "stapler", "staple", str(image)])
    tool(["/usr/bin/xcrun", "stapler", "validate", str(image)])
    verify_signature(image, config, native=False)
    tool(["/usr/sbin/spctl", "--assess", "--type", "open", "--context", "context:primary-signature",
          "--verbose=2", str(image)])
    if verify_distribution_contents(image, bundle, source_archive) != content_pins:
        raise ValueError("Final DMG differs from its exact staging contents.")
    if tree(content) != content_pins or verify_signed(bundle, config) != verified:
        raise ValueError("Distribution inputs changed during DMG production.")
    result = {"format": "polaris.macos-distribution/1", "release": manifest["id"],
              "bundle": verified["bundle"], "source": helper.artifact(source_archive),
              "artifact": helper.artifact(image), "notarization": accepted, "stapled": True,
              "signatureVerified": True, "localGatekeeperAssessment": "accepted",
              "payloadNotarization": helper.artifact(payload_evidence / "result.json"),
              "content": content_pins, "publicationPerformed": False, "localEvidenceOnly": True,
              "cleanMacDownloadedAcceptance": "not_run", "signedRuntimeAcceptance": "not_run"}
    write_json(output / "result.json", result)
    return result


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("Invalid release arguments; use --help and never supply secrets.")


def main() -> None:
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name in ("preflight", "stage", "sign", "verify", "notarize-payload", "dmg"):
        command = commands.add_parser(name)
        command.add_argument("--stage" if name == "sign" else "--bundle-dir", type=Path, required=True)
        if name != "stage":
            command.add_argument("--config", type=Path, required=name != "preflight")
        if name in ("preflight", "sign"):
            command.add_argument("--compliance", type=Path, required=name == "sign")
        if name != "verify":
            command.add_argument("--output", type=Path, required=True)
        if name in ("sign", "dmg"):
            command.add_argument("--approve-signing", action="store_true")
        if name in ("notarize-payload", "dmg"):
            command.add_argument("--approve-submit", action="store_true")
        if name == "dmg":
            command.add_argument("--source-archive", type=Path, required=True)
            command.add_argument("--payload-evidence", type=Path, required=True)
    try:
        args = parser.parse_args()
        os.umask(0o077)
        if args.command == "preflight":
            result = preflight(args.bundle_dir, args.compliance, args.config)
            write_json(helpers().regular_path(args.output), result)
        elif args.command == "stage":
            result = stage(args.bundle_dir, args.output)
        elif args.command == "sign":
            result = sign(args.stage, args.compliance, args.config, args.output, approved=args.approve_signing)
        elif args.command == "verify":
            result = verify_signed(args.bundle_dir, configuration(args.config))
        elif args.command == "notarize-payload":
            result = notarize_payload(args.bundle_dir, args.config, args.output, approved=args.approve_submit)
        else:
            result = dmg(args.bundle_dir, args.source_archive, args.payload_evidence, args.config, args.output,
                         approve_signing=args.approve_signing, approve_submit=args.approve_submit)
    except (OSError, ValueError, KeyError, TypeError, plistlib.InvalidFileException,
            tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit("macOS release operation refused: invalid, changed, incomplete or unapproved inputs.") from None
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.command == "preflight" and not result["readyToSign"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()

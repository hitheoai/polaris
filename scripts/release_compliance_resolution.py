"""Resolve immutable compliance observations without treating evidence as authority.

Trust boundary: callers supply an owner-approved authorization-file SHA-256 and
its path OUTSIDE every evaluated tree. That file pins the exact ledger and maps
reviewers to capabilities. Neither an embedded approval nor this module proves
the semantic truth of a review, grants credential use, or is a CI attestation.

Signing consumers must call verify_for_signing against the retained original
six-file bundle, not inspect readyForSigning/complete in a saved report. The
collector is replayed using current pinned tooling and exact embedded supplements.
The /1 historical report schema is never accepted by this entrypoint.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import functools
import importlib.util
import os
import re
import stat
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn, ParamSpec, TypeVar

ROOT = Path(__file__).resolve().parents[1]
MAX_DOCUMENT = 64 * 1024 * 1024
MAX_TREE = 1024 * 1024 * 1024
DOMAINS = frozenset({"technical", "legal", "security"})
EVIDENCE_KINDS = frozenset({
    "build-provenance", "source-manifest", "source-delivery", "original-notice",
    "license-review", "advisory-review", "review-analysis",
})
OUTCOMES = {
    "technical": frozenset({"verified"}),
    "legal": frozenset({"authorized"}),
    "security": frozenset({"reviewed-no-matches", "not-affected", "remediated", "accepted-risk"}),
}
SUBJECT_FIELDS = ("id", "kind", "location", "name", "version", "parent", "sha256", "hashScope")
P = ParamSpec("P")
T = TypeVar("T")


def checked(function: Callable[P, T]) -> Callable[P, T]:
    @functools.wraps(function)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return function(*args, **kwargs)
        except (OSError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError,
                tarfile.TarError, zipfile.BadZipFile, csv.Error) as error:
            raise ValueError("Invalid or incomplete compliance input; verification cannot authorize signing.") from error
    return wrapper


@functools.lru_cache
def collector() -> Any:
    spec = importlib.util.spec_from_file_location(
        "resolution_compliance_collector", ROOT / "scripts/build_release_compliance.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def document(raw: bytes) -> dict[str, Any]:
    value = collector().parse_json(raw, maximum=MAX_DOCUMENT)
    require(isinstance(value, dict), "Expected a JSON object.")
    return value


def fields(value: Any, names: set[str]) -> None:
    require(isinstance(value, dict) and set(value) == names, "Missing or unknown resolution fields.")


def same(left: Any, right: Any) -> bool:
    """JSON type-exact comparison: Python's True == 1 is not an artifact pin match."""
    return collector().json_bytes(left) == collector().json_bytes(right)


def identifier(value: Any) -> None:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", value),
            "Invalid resolution identifier.")


def digest(value: Any) -> None:
    require(isinstance(value, str) and collector().HEX.fullmatch(value), "Invalid SHA-256 digest.")


def identifiers(value: Any) -> None:
    require(isinstance(value, list) and len(value) <= 20_000, "Invalid resolution identifier list.")
    for entry in value:
        identifier(entry)
    require(value == sorted(set(value)), "Resolution lists must be sorted and unique.")


def timestamp(value: Any) -> datetime.datetime:
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z", value),
            "Expected an explicit UTC resolution timestamp.")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() == datetime.timedelta(0), "Resolution timestamp is not UTC.")
    return parsed


def clock(now: datetime.datetime | None) -> datetime.datetime:
    value = now if now is not None else datetime.datetime.now(datetime.UTC)
    require(isinstance(value, datetime.datetime) and value.utcoffset() == datetime.timedelta(0),
            "Verification clock must be timezone-aware UTC.")
    return value


def tree(directory: Path) -> dict[str, bytes]:
    """No extraction, execution, symlinks, special files or unbounded reads."""
    helper = collector()
    directory = helper.canonical(directory)
    require(directory.is_dir(), "Missing evidence directory.")
    result: dict[str, bytes] = {}
    spellings: set[str] = set()
    total = 0
    entries = 0
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in sorted([*directories, *files]):
            path = Path(parent) / name
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "Unsafe evidence-tree entry.")
            relative = helper.member_path(path.relative_to(directory).as_posix())
            require(relative.casefold() not in spellings, "Ambiguous evidence-tree path.")
            spellings.add(relative.casefold())
            entries += 1
            require(entries <= 30_000, "Evidence-tree entry bound exceeded.")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                require(total <= MAX_TREE, "Evidence-tree size bound exceeded.")
                result[relative] = helper.read_regular(path)
    return result


def _unchanged(directory: Path, snapshot: dict[str, bytes]) -> None:
    require(tree(directory) == snapshot, "Evidence changed during verification.")


@checked
def replay_observations(*, bundle_dir: Path, observations_dir: Path) -> dict[str, bytes]:
    helper = collector()
    bundle_dir, observations_dir = map(helper.canonical, (bundle_dir, observations_dir))
    require(not bundle_dir.is_relative_to(observations_dir)
            and not observations_dir.is_relative_to(bundle_dir), "Overlapping observation inputs.")
    actual = tree(observations_dir)
    require("compliance-report.json" in actual, "Missing observation report.")
    report = document(actual["compliance-report.json"])
    require(report.get("format") == "polaris.release-compliance/2"
            and report.get("stage") == "observations", "Only replayable /2 observations may authorize decisions.")
    supplements = observations_dir / "inputs/supplements"
    expected = helper.assemble(bundle_dir=bundle_dir, supplements=supplements if supplements.exists() else None)
    require(actual == expected, "Observation replay differs from actual bundle, evidence, policy or tooling.")
    _unchanged(observations_dir, actual)
    return expected


def _model(outputs: dict[str, bytes]) -> dict[str, Any]:
    """Derive exact occurrence and file coverage; metadata hashes never become tree hashes."""
    helper = collector()
    inventory = document(outputs["inventory.json"])
    report = document(outputs["compliance-report.json"])
    policy = document(outputs["inputs/policy.json"])
    components = {item["id"]: item for item in inventory["components"]}
    file_scopes: dict[str, list[dict[str, Any]]] = {}
    scope_cache: dict[str, str] = {}
    targets = []
    for finding in report["original"]:
        ref = finding["component"]
        if ref in components:
            item = components[ref]
        else:
            matches = [entry for entry in inventory["files"] if entry["location"] == ref]
            require(len(matches) == 1 and matches[0]["kind"] == "file", "Unknown observation occurrence.")
            entry = matches[0]
            item = {**entry, "id": ref, "kind": "vendor-manifest",
                    "name": ref.rsplit("/", 1)[-1], "version": None, "hashScope": "supplied-file"}
        subject = {key: item[key] for key in SUBJECT_FIELDS}
        scope_owner = item["id"]
        if item["hashScope"] in {"metadata", "declaration"} or item["kind"] == "vendor-manifest":
            scope_owner = item["parent"]
        if scope_owner not in scope_cache:
            if item["kind"] == "native-file":
                covered = [entry for entry in inventory["files"] if entry["location"] == item["location"]]
                require(len(covered) == 1 and covered[0].get("sha256") == item["sha256"],
                        "Native file scope is incomplete.")
            else:
                descendants = {scope_owner}
                while True:
                    expanded = descendants | {c["id"] for c in components.values() if c["parent"] in descendants}
                    if expanded == descendants:
                        break
                    descendants = expanded
                covered = [entry for entry in inventory["files"] if entry["parent"] in descendants]
            require(bool(covered), "An observation has no exact file coverage.")
            covered = sorted(covered, key=lambda entry: entry["location"])
            scope_digest = helper.sha(helper.json_bytes(covered))
            file_scopes[scope_digest] = covered
            scope_cache[scope_owner] = scope_digest
        relevant = [record for record in inventory["evidence"]
                    if all(record["subject"].get(key) == item.get(key) for key in ("name", "version", "sha256"))]
        advisory_results = [entry for entry in inventory["advisoryResults"] if ref in entry["components"]]
        evidence_ids = sorted({record["id"] for record in relevant} | set(finding.get("evidence", [])))
        advisory_ids = sorted({identifier for result in advisory_results for identifier in result["advisoryIds"]}
                              | set(finding.get("advisoryIds", [])))
        requirements = policy["resolutionRequirements"].get(finding["code"])
        require(isinstance(requirements, dict) and bool(requirements) and set(requirements) <= DOMAINS,
                "Unknown obligation or authorization domain.")
        require(all(isinstance(kinds, list) and bool(kinds) and set(kinds) <= EVIDENCE_KINDS
                    for kinds in requirements.values()), "Invalid obligation-specific evidence requirements.")
        target = {"original": finding, "subject": subject, "scopeSha256": scope_cache[scope_owner],
                  "sourceEvidenceIds": evidence_ids, "advisoryIds": advisory_ids,
                  "requirements": requirements}
        targets.append({"id": "observation-" + helper.sha(helper.json_bytes(target)), **target})
    require(len({target["id"] for target in targets}) == len(targets), "Duplicate observation.")
    targets.sort(key=lambda target: target["id"])
    return {
        "binding": {"release": report["release"], "inputArtifacts": report["inputArtifacts"],
                    "observationReportSha256": helper.sha(outputs["compliance-report.json"]),
                    "inventorySha256": helper.sha(outputs["inventory.json"]),
                    "policySha256": helper.sha(outputs["inputs/policy.json"]),
                    "toolManifestSha256": helper.sha(outputs["inputs/tool-manifest.json"]),
                    "observationSetSha256": helper.sha(helper.json_bytes(targets))},
        "targets": targets, "fileScopes": file_scopes,
    }


@checked
def decision_template(*, bundle_dir: Path, observations_dir: Path) -> dict[str, Any]:
    """Return nonauthorizing work items and an EMPTY ledger, never invented approvals."""
    model = _model(replay_observations(bundle_dir=bundle_dir, observations_dir=observations_dir))
    return {"targets": model["targets"], "availableFileScopes": model["fileScopes"],
            "ledger": {"format": "polaris.compliance-resolution-ledger/1", "binding": model["binding"],
                       "fileScopes": {}, "evidence": [], "decisions": []}}


def _authorization(path: Path, expected_sha256: str, ledger_raw: bytes, outside: list[Path],
                   now: datetime.datetime) -> tuple[dict[str, Any], bytes]:
    helper = collector()
    path = helper.canonical(path)
    digest(expected_sha256)
    require(all(not path.is_relative_to(helper.canonical(root)) for root in outside),
            "Owner authorization must be independently supplied outside evaluated evidence.")
    require(path.lstat().st_nlink == 1, "Linked owner authorization is not independent.")
    raw = helper.read_regular(path, helper.MAX_METADATA)
    require(helper.sha(raw) == expected_sha256, "Owner authorization does not match its independently approved digest.")
    value = document(raw)
    fields(value, {"format", "ledgerSha256", "authorizedReviewers", "approvedAt", "expiresAt",
                   "maxReviewAgeSeconds", "maxAdvisoryAgeSeconds"})
    require(value["format"] == "polaris.compliance-owner-authorization/1", "Unknown owner authorization schema.")
    require(value["ledgerSha256"] == helper.sha(ledger_raw), "The owner did not approve these exact ledger bytes.")
    approved, expires = timestamp(value["approvedAt"]), timestamp(value["expiresAt"])
    require(approved <= now < expires, "Owner authorization is future-dated or expired.")
    reviewers = value["authorizedReviewers"]
    require(isinstance(reviewers, dict) and 0 < len(reviewers) <= 1000, "Missing authorized-reviewer mapping.")
    for reviewer, domains in reviewers.items():
        identifier(reviewer)
        identifiers(domains)
        require(bool(domains) and set(domains) <= DOMAINS, "Unknown reviewer capability.")
    ages = value["maxReviewAgeSeconds"]
    fields(ages, set(DOMAINS))
    require(all(type(age) is int and 0 < age <= 2**31 - 1
                for age in [*ages.values(), value["maxAdvisoryAgeSeconds"]]),
            "Explicit owner-approved finite freshness limits are required.")
    return value, raw


def _evidence(ledger: dict[str, Any], raw_files: dict[str, bytes], targets: dict[str, Any],
              scopes: dict[str, Any]) -> dict[str, dict[str, Any]]:
    helper = collector()
    require(isinstance(ledger["evidence"], list) and len(ledger["evidence"]) <= 20_000,
            "Invalid decision evidence list.")
    observed: dict[str, dict[str, Any]] = {}
    for entry in ledger["evidence"]:
        fields(entry, {"file", "bytes", "sha256", "kind", "retrievedAt", "observationIds", "fileScopeSha256s"})
        digest(entry["sha256"])
        require(entry["sha256"] not in observed, "Duplicate or conflicting evidence digest.")
        require(isinstance(entry["kind"], str) and entry["kind"] in EVIDENCE_KINDS,
                "Unknown decision evidence purpose.")
        require(entry["file"] == entry["sha256"] + ".data", "Decision evidence must be content-addressed.")
        require(entry["file"] in raw_files, "Missing decision evidence.")
        helper.check_pin(raw_files[entry["file"]], entry)
        require(entry["bytes"] > 0, "Empty decision evidence cannot resolve an obligation.")
        timestamp(entry["retrievedAt"])
        identifiers(entry["observationIds"])
        identifiers(entry["fileScopeSha256s"])
        require(bool(entry["observationIds"]) and set(entry["observationIds"]) <= set(targets),
                "Evidence has unknown or blanket observation coverage.")
        expected_scopes = {targets[ref]["scopeSha256"] for ref in entry["observationIds"]}
        require(set(entry["fileScopeSha256s"]) == expected_scopes and expected_scopes <= set(scopes),
                "Partial or extra decision-evidence file coverage.")
        if entry["kind"] == "original-notice":
            raw = raw_files[entry["file"]]
            require(len(raw) <= helper.MAX_METADATA and b"\0" not in raw, "Invalid original notice attachment.")
            raw.decode("utf-8")
        observed[entry["sha256"]] = entry
    require(set(raw_files) == {entry["file"] for entry in observed.values()},
            "Unlisted decision-evidence files.")
    return observed


def _assess(outputs: dict[str, bytes], ledger_raw: bytes, raw_evidence: dict[str, bytes],
            authority: dict[str, Any], authority_digest: str, now: datetime.datetime,
            evaluated_at: str) -> dict[str, Any]:
    helper = collector()
    model = _model(outputs)
    ledger = document(ledger_raw)
    fields(ledger, {"format", "binding", "fileScopes", "evidence", "decisions"})
    require(ledger["format"] == "polaris.compliance-resolution-ledger/1", "Unknown decision ledger schema.")
    require(same(ledger["binding"], model["binding"]), "Wrong release, inventory, policy, tooling or observation binding.")
    require(isinstance(ledger["fileScopes"], dict) and len(ledger["fileScopes"]) <= 20_000,
            "Missing or excessive explicit file coverage.")
    for scope, files in ledger["fileScopes"].items():
        require(scope in model["fileScopes"] and same(files, model["fileScopes"][scope]),
                "Unknown or partial file scope; include every observed occurrence, including links.")
    targets = {target["id"]: target for target in model["targets"]}
    evidence = _evidence(ledger, raw_evidence, targets, ledger["fileScopes"])
    require(isinstance(ledger["decisions"], list) and len(ledger["decisions"]) <= 60_000,
            "Invalid decision list.")
    approved_at = timestamp(authority["approvedAt"])
    require(approved_at <= timestamp(evaluated_at) <= now, "Evaluation predates approval or is future-dated.")
    inventory = document(outputs["inventory.json"])
    source_records = {entry["id"]: entry for entry in inventory["evidence"]}
    decisions: dict[tuple[str, str], dict[str, Any]] = {}
    decision_ids: set[str] = set()
    used_evidence: set[str] = set()
    used_scopes: set[str] = set()
    for decision in ledger["decisions"]:
        fields(decision, {"id", "observationId", "subject", "obligationCode", "domain", "scopeSha256",
                          "sourceEvidenceIds", "advisoryIds", "evidenceSha256s", "outcome", "rationale",
                          "reviewer", "reviewedAt", "expiresAt"})
        identifier(decision["id"])
        require(decision["id"] not in decision_ids, "Duplicate decision ID.")
        decision_ids.add(decision["id"])
        identifier(decision["observationId"])
        require(decision["observationId"] in targets, "Unknown or blanket decision target.")
        target = targets[decision["observationId"]]
        domain = decision["domain"]
        require(isinstance(domain, str) and domain in target["requirements"], "Unknown decision domain.")
        key = (target["id"], domain)
        require(key not in decisions, "Duplicate or conflicting obligation decision.")
        require(same(decision["subject"], target["subject"])
                and decision["obligationCode"] == target["original"]["code"]
                and decision["scopeSha256"] == target["scopeSha256"]
                and decision["sourceEvidenceIds"] == target["sourceEvidenceIds"]
                and decision["advisoryIds"] == target["advisoryIds"],
                "Decision occurrence, hash scope, obligation, provider or advisory coverage mismatch.")
        require(decision["scopeSha256"] in ledger["fileScopes"], "Missing decision file scope.")
        require(isinstance(decision["outcome"], str) and decision["outcome"] in OUTCOMES[domain],
                "An exception cannot substitute for source closure or legal authorization.")
        if domain == "security" and target["advisoryIds"]:
            require(decision["outcome"] != "reviewed-no-matches", "Recorded advisory matches cannot be declared absent.")
        require(isinstance(decision["rationale"], str) and 20 <= len(decision["rationale"].strip()) <= 20_000,
                "A substantive bounded decision rationale is required.")
        identifier(decision["reviewer"])
        require(domain in authority["authorizedReviewers"].get(decision["reviewer"], []),
                "Reviewer lacks independently authorized capability.")
        reviewed_at, expires = timestamp(decision["reviewedAt"]), timestamp(decision["expiresAt"])
        require(reviewed_at <= approved_at <= now < expires
                and (now - reviewed_at).total_seconds() <= authority["maxReviewAgeSeconds"][domain],
                "Decision is stale, expired, future-dated or postdates owner approval.")
        identifiers(decision["evidenceSha256s"])
        require(bool(decision["evidenceSha256s"]) and set(decision["evidenceSha256s"]) <= set(evidence),
                "Missing exact decision evidence.")
        attached = [evidence[value] for value in decision["evidenceSha256s"]]
        require(set(target["requirements"][domain]) <= {entry["kind"] for entry in attached},
                "Obligation-specific evidence is incomplete.")
        for entry in attached:
            require(target["id"] in entry["observationIds"]
                    and target["scopeSha256"] in entry["fileScopeSha256s"],
                    "Decision evidence does not cover this occurrence and its complete files.")
            retrieved = timestamp(entry["retrievedAt"])
            require(retrieved <= reviewed_at, "Decision predates its supporting evidence.")
            if entry["kind"] == "advisory-review":
                require((now - retrieved).total_seconds() <= authority["maxAdvisoryAgeSeconds"],
                        "Advisory evidence is stale.")
        if domain == "security":
            for ref in target["sourceEvidenceIds"]:
                source = source_records[ref]
                if source["kind"] == "advisory" and source["status"] == "retrieved":
                    acquired = datetime.datetime.fromisoformat(source["retrievedAt"].replace("Z", "+00:00"))
                    require(acquired <= reviewed_at
                            and (now - acquired).total_seconds() <= authority["maxAdvisoryAgeSeconds"],
                            "Recorded advisory queries are stale; recollect observations instead of relabeling them.")
        used_scopes.add(target["scopeSha256"])
        used_evidence.update(decision["evidenceSha256s"])
        decisions[key] = decision
    require(used_evidence == set(evidence), "Unused decision evidence is not an authorization.")
    coverage_scopes = {scope for entry in evidence.values() for scope in entry["fileScopeSha256s"]}
    require(set(ledger["fileScopes"]) == used_scopes | coverage_scopes, "Unknown or unused ledger file scopes.")
    resolved, unresolved, risk_accepted = [], [], []
    domain_complete = {domain: True for domain in DOMAINS}
    for target in model["targets"]:
        missing = sorted(domain for domain in target["requirements"] if (target["id"], domain) not in decisions)
        reviewed = [decisions[(target["id"], domain)] for domain in sorted(target["requirements"])
                    if (target["id"], domain) in decisions]
        for domain in missing:
            domain_complete[domain] = False
        disposition = {"observation": target["id"], "decisions": [decision["id"] for decision in reviewed],
                       "missingDomains": missing}
        if missing:
            unresolved.append(disposition)
        else:
            risks = [decision["id"] for decision in reviewed if decision["outcome"] == "accepted-risk"]
            resolved.append({**disposition, "status": "authorized-risk-exception" if risks else "reviewed",
                             "originalObservationRetained": True})
            if risks:
                risk_accepted.append({"observation": target["id"], "decisions": risks,
                                      "advisoryIds": target["advisoryIds"], "findingStillRecorded": True})
    complete = not unresolved and all(domain_complete.values())
    report = document(outputs["compliance-report.json"])
    return {"format": "polaris.release-compliance/2", "stage": "evaluated",
            "release": model["binding"]["release"], "inputArtifacts": model["binding"]["inputArtifacts"],
            "binding": model["binding"], "inventorySha256": model["binding"]["inventorySha256"],
            "inventoryComplete": True, "complete": complete, "readyForSigning": complete,
            "technicalComplete": domain_complete["technical"], "legalAuthorized": domain_complete["legal"],
            "securityAuthorized": domain_complete["security"], "original": model["targets"],
            "resolved": resolved, "unresolved": unresolved, "riskAccepted": risk_accepted,
            "advisoryResults": report["advisoryResults"], "vulnerabilityFreeClaim": False,
            "sourceObligationsRemainApplicable": True, "ledgerSha256": helper.sha(ledger_raw),
            "authorizationSha256": authority_digest, "evaluatedAt": evaluated_at,
            "localEvidenceOnly": True, "trustedCIBuildProvenance": False,
            "limitations": report["limitations"]}


def _package(outputs: dict[str, bytes], ledger_raw: bytes, evidence: dict[str, bytes],
             report: dict[str, Any]) -> dict[str, bytes]:
    helper = collector()
    result = {"observations/" + name: raw for name, raw in outputs.items()}
    result["decisions/ledger.json"] = ledger_raw
    result.update({"decisions/evidence/" + name: raw for name, raw in evidence.items()})
    # Convenient public surfaces remain byte-for-byte observations, not rewritten conclusions.
    for name in ("inventory.json", "sbom.cdx.json", "THIRD_PARTY_NOTICES.txt"):
        result[name] = outputs[name]
    report = {**report, "files": [helper.pin(raw, name) for name, raw in sorted(result.items())]}
    result["compliance-report.json"] = helper.json_bytes(report)
    return result


def _finish_inputs(bundle_dir: Path, outputs: dict[str, bytes]) -> None:
    helper = collector()
    report = document(outputs["compliance-report.json"])
    data, manifest = helper.load_bundle(bundle_dir)
    require({key: manifest[key] for key in ("id", "version", "platform")} == report["release"]
            and [helper.pin(raw, name) for name, raw in sorted(data.items())] == report["inputArtifacts"],
            "Original bundle changed during verification.")
    require(helper.read_regular(helper.POLICY, helper.MAX_METADATA) == outputs["inputs/policy.json"],
            "Compliance policy changed during verification.")
    current_tools = {"format": "polaris.compliance-tools/1", "files": [
        helper.pin(helper.read_regular(helper.ROOT / name, helper.MAX_METADATA), name)
        for name in sorted(helper.TOOL_FILES)
    ]}
    require(helper.json_bytes(current_tools) == outputs["inputs/tool-manifest.json"],
            "Compliance tooling changed during verification.")


@checked
def evaluate(*, bundle_dir: Path, observations_dir: Path, ledger_path: Path, evidence_dir: Path,
             authorization_path: Path, authorization_sha256: str, output: Path,
             now: datetime.datetime | None = None) -> dict[str, Any]:
    """Write a NEW evaluated tree; partial ledgers remain incomplete, never implicitly approved."""
    helper = collector()
    now = clock(now)
    bundle_dir, observations_dir, ledger_path, evidence_dir, output = map(
        helper.canonical, (bundle_dir, observations_dir, ledger_path, evidence_dir, output),
    )
    require(not output.exists() and output.parent.is_dir(), "Evaluation output must be new.")
    for source in (bundle_dir, observations_dir, ledger_path, evidence_dir, authorization_path):
        source = helper.canonical(source)
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                "Evaluation output overlaps immutable inputs or owner authorization.")
    outputs = replay_observations(bundle_dir=bundle_dir, observations_dir=observations_dir)
    ledger_raw = helper.read_regular(ledger_path, MAX_DOCUMENT)
    evidence = tree(evidence_dir)
    authority, authority_raw = _authorization(authorization_path, authorization_sha256, ledger_raw,
                                             [bundle_dir, observations_dir, evidence_dir, ledger_path, output], now)
    evaluated_at = now.isoformat().replace("+00:00", "Z")
    report = _assess(outputs, ledger_raw, evidence, authority, authorization_sha256, now, evaluated_at)
    result = _package(outputs, ledger_raw, evidence, report)
    _unchanged(observations_dir, outputs)
    _unchanged(evidence_dir, evidence)
    require(helper.read_regular(ledger_path, MAX_DOCUMENT) == ledger_raw
            and helper.read_regular(authorization_path, helper.MAX_METADATA) == authority_raw,
            "Decision or authorization changed during evaluation.")
    _finish_inputs(bundle_dir, outputs)
    helper.write_outputs(output, result)
    return document(result["compliance-report.json"])


@checked
def verify_for_signing(*, bundle_dir: Path, compliance_dir: Path, authorization_path: Path,
                       authorization_sha256: str, now: datetime.datetime | None = None) -> dict[str, Any]:
    """Fail closed by replay, exact owner authorization and CURRENT freshness; no saved boolean is trusted."""
    helper = collector()
    now = clock(now)
    compliance_dir = helper.canonical(compliance_dir)
    actual = tree(compliance_dir)
    require("compliance-report.json" in actual, "Missing evaluated compliance report.")
    saved = document(actual["compliance-report.json"])
    require(saved.get("format") == "polaris.release-compliance/2" and saved.get("stage") == "evaluated",
            "Historical or unevaluated reports cannot authorize signing.")
    outputs = replay_observations(bundle_dir=bundle_dir, observations_dir=compliance_dir / "observations")
    require("decisions/ledger.json" in actual, "Missing independently authorized decision ledger.")
    ledger_raw = actual["decisions/ledger.json"]
    prefix = "decisions/evidence/"
    evidence = {name.removeprefix(prefix): raw for name, raw in actual.items() if name.startswith(prefix)}
    authority, authority_raw = _authorization(authorization_path, authorization_sha256, ledger_raw,
                                             [bundle_dir, compliance_dir], now)
    evaluated_at = saved.get("evaluatedAt")
    timestamp(evaluated_at)
    assert isinstance(evaluated_at, str)
    report = _assess(outputs, ledger_raw, evidence, authority, authorization_sha256, now, evaluated_at)
    expected = _package(outputs, ledger_raw, evidence, report)
    require(actual == expected, "Evaluated report or evidence was altered, omitted or resealed.")
    require(report["readyForSigning"] and report["unresolved"] == [],
            "Unresolved technical, legal or security decisions block signing.")
    _unchanged(compliance_dir, actual)
    require(helper.read_regular(authorization_path, helper.MAX_METADATA) == authority_raw,
            "Owner authorization changed during verification.")
    _finish_inputs(bundle_dir, outputs)
    return document(expected["compliance-report.json"])


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("Invalid resolution arguments; use --help and never supply credentials.")


def main() -> int:
    parser = Parser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser("template", help="Print explicit work items and an empty, unapproved ledger.")
    template.add_argument("--bundle-dir", type=Path, required=True)
    template.add_argument("--observations-dir", type=Path, required=True)
    for name in ("evaluate", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--bundle-dir", type=Path, required=True)
        command.add_argument("--authorization", type=Path, required=True)
        command.add_argument("--authorization-sha256", required=True)
        if name == "verify":
            command.add_argument("--compliance-dir", type=Path, required=True)
        else:
            for field in ("observations-dir", "ledger", "evidence-dir", "output"):
                command.add_argument("--" + field, type=Path, required=True)
    try:
        args = parser.parse_args()
        if args.command == "template":
            result = decision_template(bundle_dir=args.bundle_dir, observations_dir=args.observations_dir)
            print(collector().json_bytes(result).decode(), end="")
            return 2  # Work items are not decisions.
        common = {"bundle_dir": args.bundle_dir, "authorization_path": args.authorization,
                  "authorization_sha256": args.authorization_sha256}
        if args.command == "verify":
            result = verify_for_signing(compliance_dir=args.compliance_dir, **common)
        else:
            result = evaluate(observations_dir=args.observations_dir, ledger_path=args.ledger,
                              evidence_dir=args.evidence_dir, output=args.output, **common)
        print(collector().json_bytes({key: result[key] for key in (
            "complete", "technicalComplete", "legalAuthorized", "securityAuthorized", "ledgerSha256",
        )}).decode(), end="")
        return 0 if result["complete"] else 2
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, RecursionError):
        print("Compliance resolution rejected; no authority can be inferred from the supplied report.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

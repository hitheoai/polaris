"""SYNTHETIC PYTEST FIXTURES ONLY. Never import from release implementation."""

from __future__ import annotations

import datetime
import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "synthetic_compliance_resolver", ROOT / "scripts/release_compliance_resolution.py",
)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)
collector = resolver.collector()


def synthetic_resolution_inputs(bundle_dir, private, *, now=None, supplements=None):
    """Create test-only decisions for tiny nonrunnable bundles; return mutable attack fixtures."""
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise ValueError("Synthetic decisions can only be created during pytest.")
    if sum(path.stat().st_size for path in bundle_dir.iterdir()) > 2 * 1024 * 1024:
        raise ValueError("Synthetic helper refuses real-sized release inputs.")
    data, manifest = collector.load_bundle(bundle_dir)
    inventory = collector.collect_bundle(data, manifest)
    native = [item for item in inventory.components if item["kind"] == "native-file"]
    if not native or any(item["bytes"] > 4096 for item in native):
        raise ValueError("Synthetic helper requires tiny nonrunnable native header fixtures.")
    now = now or datetime.datetime.now(datetime.UTC)
    private.mkdir(mode=0o700)
    observations = private / "observations"
    collector.build(bundle_dir=bundle_dir, output=observations, supplements=supplements)
    template = resolver.decision_template(bundle_dir=bundle_dir, observations_dir=observations)
    ledger = template["ledger"]
    ledger["fileScopes"] = template["availableFileScopes"]
    evidence_dir = private / "decision-evidence"
    evidence_dir.mkdir(mode=0o700)
    acquired = (now - datetime.timedelta(minutes=3)).isoformat().replace("+00:00", "Z")
    reviewed = (now - datetime.timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    approved = (now - datetime.timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    expires = (now + datetime.timedelta(days=2)).isoformat().replace("+00:00", "Z")
    for target in template["targets"]:
        evidence_by_kind = {}
        for kind in sorted({kind for kinds in target["requirements"].values() for kind in kinds}):
            raw = collector.json_bytes({
                "syntheticOnly": True, "notRealApproval": True, "kind": kind,
                "observation": target["id"], "scopeSha256": target["scopeSha256"],
                "purpose": "Exercise validation using tiny fixture bytes, not legal or security evidence.",
            })
            digest = collector.sha(raw)
            filename = digest + ".data"
            (evidence_dir / filename).write_bytes(raw)
            ledger["evidence"].append({
                "file": filename, "sha256": digest, "bytes": len(raw), "kind": kind,
                "retrievedAt": acquired, "observationIds": [target["id"]],
                "fileScopeSha256s": [target["scopeSha256"]],
            })
            evidence_by_kind[kind] = digest
        for domain, kinds in sorted(target["requirements"].items()):
            outcome = {"technical": "verified", "legal": "authorized", "security": "reviewed-no-matches"}[domain]
            if domain == "security" and target["advisoryIds"]:
                outcome = "accepted-risk"
            ledger["decisions"].append({
                "id": f"synthetic-{len(ledger['decisions']):05d}",
                "observationId": target["id"], "subject": target["subject"],
                "obligationCode": target["original"]["code"], "domain": domain,
                "scopeSha256": target["scopeSha256"], "sourceEvidenceIds": target["sourceEvidenceIds"],
                "advisoryIds": target["advisoryIds"],
                "evidenceSha256s": sorted(evidence_by_kind[kind] for kind in kinds),
                "outcome": outcome, "rationale": "SYNTHETIC TEST ONLY: not an actual owner, legal or security decision.",
                "reviewer": "synthetic-" + domain, "reviewedAt": reviewed, "expiresAt": expires,
            })
    authorization = {
        "format": "polaris.compliance-owner-authorization/1",
        "ledgerSha256": collector.sha(collector.json_bytes(ledger)),
        "authorizedReviewers": {"synthetic-" + domain: [domain] for domain in sorted(resolver.DOMAINS)},
        "approvedAt": approved, "expiresAt": expires,
        "maxReviewAgeSeconds": {domain: 86400 for domain in sorted(resolver.DOMAINS)},
        "maxAdvisoryAgeSeconds": 86400,
    }
    case = {
        "bundle_dir": bundle_dir, "observations_dir": observations, "ledger_path": private / "ledger.json",
        "evidence_dir": evidence_dir, "authorization_path": private / "OWNER-SYNTHETIC-ONLY.json",
        "ledger": ledger, "authorization": authorization, "template": template, "now": now,
    }
    reseal_synthetic(case)
    return case


def reseal_synthetic(case):
    """Attack tests may reapprove fixture bytes to test validation beyond digest equality."""
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise ValueError("Synthetic authorizations can only be resealed during pytest.")
    raw = collector.json_bytes(case["ledger"])
    case["ledger_path"].write_bytes(raw)
    case["authorization"]["ledgerSha256"] = collector.sha(raw)
    authority = collector.json_bytes(case["authorization"])
    case["authorization_path"].write_bytes(authority)
    case["authorization_sha256"] = collector.sha(authority)


def evaluate_synthetic(case, output):
    return resolver.evaluate(
        **{key: case[key] for key in ("bundle_dir", "observations_dir", "ledger_path", "evidence_dir",
                                     "authorization_path", "authorization_sha256", "now")},
        output=output,
    )


def verify_synthetic(case, output, *, now=None):
    return resolver.verify_for_signing(
        **{key: case[key] for key in ("bundle_dir", "authorization_path", "authorization_sha256")},
        compliance_dir=output, now=now or case["now"],
    )


def synthetic_compliance(bundle_dir, output, *, now=None):
    """Lead signing tests: real collector/evaluator, independent test authority; NO verifier stub."""
    case = synthetic_resolution_inputs(bundle_dir, output.with_name(output.name + "-fixture-inputs"), now=now)
    report = evaluate_synthetic(case, output)
    verify_synthetic(case, output)
    return {"compliance_dir": output, "report": report, "resolver": resolver,
            "authorization_path": case["authorization_path"], "authorization_sha256": case["authorization_sha256"],
            "case": case}

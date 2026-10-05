"""The review input format: one changed unit -> one `polaris.assessment/0.1.0` request.

Training examples and live reviews both use `build_request`, so the model always learns from
exactly what it later sees. Changing this format requires retraining and a version bump.
"""

from __future__ import annotations

import hashlib
from typing import Any

from polaris.contract import CONTRACT_VERSION
from polaris.jsonio import digest_text
from polaris.registry import BY_ID
from polaris.review.dataflow import ANALYZER_VERSION, FlowFacts

REVIEW_INPUT_FORMAT = "polaris.review-input/0.1.0"
MAX_EVIDENCE_CHARS = 60_000


def _evidence(identifier: str, kind: str, content: str, origin: str, path: str | None = None,
              line: int | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "evidence_id": identifier,
        "kind": kind,
        "origin": origin,
        "revision": "v1",
        "digest": digest_text(content),
        "content": content,
    }
    if path is not None:
        item["location"] = {"path": path[:1024], "start_line": line} if line else {"path": path[:1024]}
    return item


def unit_request_id(path: str, symbol: str, source: str, before: str | None) -> str:
    material = "\0".join((path, symbol, source, before or ""))
    return "review-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def build_request(
    *,
    path: str,
    symbol: str,
    start_line: int,
    source: str,
    before: str | None,
    facts: FlowFacts,
    checks: list[str],
    policy: list[str],
    policy_source: str,
) -> dict[str, Any]:
    """Build the assessment request for one unit. Raises ValueError for oversized units."""
    if len(source) > MAX_EVIDENCE_CHARS or (before is not None and len(before) > MAX_EVIDENCE_CHARS):
        raise ValueError("unit too large")
    evidence = []
    if before is not None:
        evidence.append(_evidence("before", "code_before", before, "repository", path, start_line))
    evidence.append(_evidence("after", "code_after", source, "repository", path, start_line))
    evidence.append(_evidence("flow", "data_flow", facts.render(), ANALYZER_VERSION))
    content = "\n".join(policy)
    return {
        "contract_version": CONTRACT_VERSION,
        "request_id": unit_request_id(path, symbol, source, before),
        "requested_checks": [
            {"check_id": check, "check_revision": BY_ID[check].revision} for check in checks
        ],
        "action": {
            "action_id": "change",
            "kind": "code_change",
            "language": "python",
            "before_refs": ["before"] if before is not None else [],
            "after_refs": ["after"],
        },
        "evidence": evidence,
        "trusted_context": [
            {
                "context_id": "policy-scope",
                "kind": "scope",
                "source": f"{policy_source}-policy",
                "revision": "v1",
                "digest": digest_text(content),
                "content": content,
            }
        ],
    }

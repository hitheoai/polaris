"""Regenerate versioned wire schemas and non-neural conformance examples."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from polaris.contract import CONTRACT_VERSION, schema
from polaris.engine import Assessor
from polaris.fixtures import sample_request

ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
    )


def main() -> None:
    for kind in ("request", "response", "error"):
        write(ROOT / "schemas" / f"{kind}.schema.json", schema(kind))
    request = sample_request()
    write(ROOT / "examples" / "request.json", request)
    missing = copy.deepcopy(request)
    missing["trusted_context"] = []
    write(ROOT / "examples" / "request-missing-context.json", missing)
    unknown = copy.deepcopy(request)
    unknown["requested_checks"] = [{"check_id": "future_check", "check_revision": 1}]
    conflict = copy.deepcopy(request)
    conflict["trusted_context"][0]["conflicts_with"] = ["trusted-scope"]
    invalid = copy.deepcopy(request)
    invalid["evidence"][0]["digest"] = "sha256:" + "0" * 64
    cases = []
    for name, value in (
        ("model-unavailable", request),
        ("missing-context", missing),
        ("unknown-check", unknown),
        ("declared-policy-conflict", conflict),
        ("invalid-digest", invalid),
    ):
        cases.append(
            {
                "name": name,
                "request": value,
                "expected": Assessor().assess_envelope(value).model_dump(mode="json"),
            }
        )
    write(
        ROOT / "schemas" / "conformance.json",
        {
            "contract_version": CONTRACT_VERSION,
            "purpose": "Software conformance only; no model inference or security-quality evidence.",
            "cases": cases,
        },
    )


if __name__ == "__main__":
    main()

import json
from pathlib import Path

import jsonschema
import pytest

from polaris.contract import schema
from polaris.engine import Assessor

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", ["request", "response", "error"])
def test_published_schema_matches_sdk(kind):
    published = json.loads((ROOT / "schemas" / f"{kind}.schema.json").read_text())
    assert published == schema(kind)
    jsonschema.Draft202012Validator.check_schema(published)


def test_published_non_neural_conformance_cases():
    conformance = json.loads((ROOT / "schemas/conformance.json").read_text())
    assert len(conformance["cases"]) == 5
    for case in conformance["cases"]:
        response = Assessor().assess_envelope(case["request"]).model_dump(mode="json")
        assert response == case["expected"]
        jsonschema.validate(
            response, schema("error" if response["kind"] == "error" else "response")
        )

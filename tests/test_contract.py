import copy
import json

import jsonschema
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from polaris.contract import (
    AssessmentRequest,
    CheckRequest,
    EvidenceReference,
    RiskProbabilities,
    parse_request,
    schema,
)
from polaris.engine import Assessor
from polaris.errors import PolarisInputError
from polaris.fixtures import sample_request
from polaris.jsonio import MAX_PAYLOAD_BYTES, digest_text, load_json


def test_valid_request_schema_and_roundtrip(request_data):
    request = parse_request(request_data)
    jsonschema.validate(request.model_dump(mode="json"), schema("request"))
    assert parse_request(request.model_dump_json()) == request
    assert len(request.request_digest) == 71


def test_typed_request_constructor(request_data):
    request_data["requested_checks"] = [CheckRequest(check_id="sql_injection")]
    assert AssessmentRequest(**request_data).requested_checks[0].check_id == "sql_injection"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda x: x.update(unknown=True),
        lambda x: x["evidence"][0].update(digest="sha256:" + "0" * 64),
        lambda x: x["evidence"].append(copy.deepcopy(x["evidence"][0])),
        lambda x: x["action"].update(after_refs=["missing"]),
        lambda x: x["action"].update(after_refs=["before"]),
        lambda x: x["requested_checks"].append(copy.deepcopy(x["requested_checks"][0])),
        lambda x: x["requested_checks"][0].update(check_revision=True),
        lambda x: x["trusted_context"][0].update(trusted=True),
        lambda x: x["trusted_context"][0].update(conflicts_with=["missing"]),
    ],
)
def test_invalid_semantics_are_rejected(request_data, mutation):
    mutation(request_data)
    with pytest.raises(PolarisInputError):
        parse_request(request_data)


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}'])
def test_ambiguous_or_nonfinite_json_rejected(text):
    with pytest.raises(PolarisInputError):
        load_json(text)


def test_payload_and_depth_limits():
    with pytest.raises(PolarisInputError, match="limit"):
        load_json(b" " * (MAX_PAYLOAD_BYTES + 1))
    with pytest.raises(PolarisInputError):
        load_json("[" * 20 + "0" + "]" * 20)


def test_error_never_echoes_payload(request_data):
    request_data["private_field"] = "SYNTHETIC_PRIVATE_MARKER"
    result = Assessor().assess_envelope(json.dumps(request_data))
    assert result.kind == "error"
    assert "SYNTHETIC_PRIVATE_MARKER" not in result.model_dump_json()
    assert "results" not in result.model_dump()
    jsonschema.validate(result.model_dump(mode="json"), schema("error"))


def test_bad_contract_is_separate_error(request_data):
    request_data["contract_version"] = "polaris.assessment/999"
    assert Assessor().assess_envelope(request_data).code == "unsupported_contract"


def test_request_mutations_are_revalidated(request_data):
    request = parse_request(request_data)
    request.evidence.append(request.evidence[0])
    with pytest.raises(PolarisInputError):
        parse_request(request)


@given(st.floats(allow_nan=False, allow_infinity=False, min_value=0.0, max_value=1.0))
def test_probabilities_are_normalized(p):
    assert RiskProbabilities(risk_present=p, risk_absent=1.0 - p).risk_present == p


@pytest.mark.parametrize("p", [float("nan"), float("inf"), -0.1, 1.1])
def test_invalid_probabilities(p):
    with pytest.raises(ValidationError):
        RiskProbabilities(risk_present=p, risk_absent=1.0 - p)


def test_coverage_cannot_claim_supporting_evidence():
    with pytest.raises(ValidationError):
        EvidenceReference(
            evidence_id="e",
            digest=digest_text("x"),
            relation="supporting",
            method="input_coverage",
        )


def test_request_digest_binds_policy_and_action():
    first = sample_request()
    second = copy.deepcopy(first)
    second["trusted_context"][0]["content"] += " Updated policy."
    second["trusted_context"][0]["digest"] = digest_text(second["trusted_context"][0]["content"])
    assert parse_request(first).request_digest != parse_request(second).request_digest

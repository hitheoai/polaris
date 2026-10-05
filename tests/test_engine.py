import jsonschema
import pytest

from polaris.contract import schema
from polaris.engine import Assessor, Logits
from polaris.fixtures import sample_request
from polaris.registry import CHECK_IDS


def test_no_bundle_is_not_fake_safety(request_data):
    response = Assessor().assess_envelope(request_data)
    assert response.kind == "error"
    assert response.code == "model_unavailable"
    assert "results" not in response.model_dump()


def test_unknown_and_unsupported_checks_without_a_model(request_data):
    request_data["requested_checks"] = [
        {"check_id": "unknown", "check_revision": 1},
        {"check_id": "sql_injection", "check_revision": 999},
    ]
    result = Assessor().assess(request_data)
    assert [r.status for r in result.results] == ["unsupported", "unsupported"]
    assert all(r.probabilities is None for r in result.results)
    assert result.runtime.release_status == "not_loaded"


def test_missing_context_is_abstention_not_probability(request_data, backend):
    request_data["trusted_context"] = []
    result = Assessor(backend).assess(request_data)
    assert result.results[0].status == "abstain"
    assert result.results[0].coverage.missing_required_context == ["context:scope"]
    assert result.results[0].probabilities is None
    assert backend.calls == 0


def test_experimental_opt_in_is_required(request_data, backend):
    assert Assessor(backend).assess_envelope(request_data).code == "unqualified_model"


def test_one_forward_pass_and_status_schema(request_data, backend):
    request_data["requested_checks"] = [{"check_id": check} for check in CHECK_IDS]
    response = Assessor(backend, allow_experimental=True).assess(request_data)
    assert backend.calls == 1
    assert len(response.results) == 7
    assert response.results[1].status == "unsupported"
    assert response.results[2].status == "assessed"
    assert all(ref.relation == "considered" for ref in response.results[2].evidence_refs)
    coverage = response.results[2].coverage
    assert coverage.supplied_tokens == coverage.consumed_tokens
    assert not coverage.truncated
    jsonschema.validate(response.model_dump(mode="json"), schema("response"))
    corrupted = response.model_dump(mode="json")
    corrupted["results"][2]["probabilities"] = None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(corrupted, schema("response"))


@pytest.mark.parametrize(
    "logits,reason",
    [
        (Logits(risk=0.0, sufficiency=8.0), "uncertain"),
        (Logits(risk=-8.0, sufficiency=-8.0), "insufficient_context"),
    ],
)
def test_model_abstention(request_data, backend, logits, reason):
    backend.outputs["sql_injection"] = logits
    response = Assessor(backend, allow_experimental=True).assess(request_data)
    assert response.results[0].status == "abstain"
    assert response.results[0].probabilities is None
    assert response.results[0].reason_codes == [reason]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_outputs_fail_atomically(request_data, backend, value):
    backend.outputs["sql_injection"] = Logits(risk=value, sufficiency=8.0)
    response = Assessor(backend, allow_experimental=True).assess_envelope(request_data)
    assert response.kind == "error"
    assert response.code == "non_finite_output"
    assert "results" not in response.model_dump()


def test_stale_calibration_and_overlap_rejected(request_data, backend):
    backend.calibration = backend.calibration.model_copy(
        update={"source_groups": ["tuning-repository"]}
    )
    assert (
        Assessor(backend, allow_experimental=True).assess_envelope(request_data).code
        == "calibration_mismatch"
    )


def test_token_budget_never_truncates(request_data, backend):
    backend.max_tokens = 12
    result = Assessor(backend, allow_experimental=True).assess_envelope(request_data)
    assert result.code == "context_limit"
    assert backend.calls == 0


def test_literal_special_token_cannot_become_a_control_id(backend):
    response = Assessor(backend, allow_experimental=True).assess(sample_request("prompt_injection"))
    assert response.results[0].status == "assessed"
    assert all("[MASK]" not in text for text in backend.tokenizer.texts)
    assert "\\u005b" in backend.tokenizer.texts[-1]


def test_requested_check_set_does_not_change_encoding(request_data, backend):
    assessor = Assessor(backend, allow_experimental=True)
    first = assessor.assess(request_data)
    first_texts = list(backend.tokenizer.texts)
    request_data["requested_checks"].insert(0, {"check_id": "secret_exposure"})
    second = assessor.assess(request_data)
    assert backend.tokenizer.texts[3:] == first_texts
    assert first.results[0].probabilities == second.results[1].probabilities


def test_conflicts_and_omissions(request_data, backend):
    request_data["trusted_context"][0]["conflicts_with"] = ["trusted-scope"]
    result = Assessor(backend).assess(request_data)
    assert result.results[0].reason_codes == ["conflicting_context"]
    request_data["trusted_context"][0]["conflicts_with"] = []
    request_data["known_omissions"] = ["authorization middleware not provided"]
    result = Assessor(backend).assess(request_data)
    assert result.results[0].reason_codes == ["known_omissions"]


def test_timeout_discards_assessment(request_data, backend):
    result = Assessor(backend, allow_experimental=True, timeout_seconds=1e-12).assess_envelope(
        request_data
    )
    assert result.code == "timeout"


def test_changed_calibrator_contents_cannot_reuse_its_version(request_data, backend):
    backend.calibration.heads["sql_injection"] = backend.calibration.heads[
        "sql_injection"
    ].model_copy(update={"temperature": 2.0})
    response = Assessor(backend, allow_experimental=True).assess_envelope(request_data)
    assert response.code == "calibration_mismatch"


def test_tool_payload_is_never_executed(tmp_path, backend):
    target = tmp_path / "must-not-exist"
    request = sample_request("tool_scope")
    request["action"]["tool_name"] = "shell"
    request["action"]["arguments"] = {"command": f"touch {target}"}
    Assessor(backend, allow_experimental=True).assess(request)
    assert not target.exists()

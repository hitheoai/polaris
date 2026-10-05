import math

import pytest
from pydantic import ValidationError

from polaris.calibration import fit_binary_calibration, log_loss, sigmoid
from polaris.data import (
    DatasetRecord,
    Label,
    audit,
    make_splits,
    require_adjudicated,
    validate_splits,
)
from polaris.fixtures import smoke_records


def test_original_fixtures_are_not_gold():
    records = smoke_records()
    assert len(records) == 21
    assert all(record.provenance.review_state == "unreviewed" for record in records)
    with pytest.raises(ValueError, match="adjudicated"):
        require_adjudicated(records)
    report = audit(records, make_splits(records))
    assert report["status"] == "blocked"
    assert "empty_split" in report["blockers"]
    assert report["independent_components"] == 1


def test_splits_are_deterministic_and_keep_pairs_together():
    records = smoke_records()
    first, second = make_splits(records), make_splits(list(reversed(records)))
    assert first.assignments == second.assignments
    assert first.dataset_digest == second.dataset_digest
    validate_splits(records, first)
    assert len(set(first.assignments.values())) == 1


def test_split_tampering_is_detected():
    records = smoke_records()
    manifest = make_splits(records)
    original = manifest.assignments[records[0].record_id]
    manifest.assignments[records[0].record_id] = "test" if original != "test" else "train"
    with pytest.raises(ValueError, match="leakage"):
        validate_splits(records, manifest)


def test_clone_in_separate_repo_is_still_connected():
    record = smoke_records()[0]
    copied = record.model_dump(mode="json")
    copied.update(record_id="copy", repository_family="different-repo", template_families=[])
    second = DatasetRecord.model_validate(copied)
    manifest = make_splits([record, second])
    assert len(set(manifest.components.values())) == 1


def test_unknown_labels_are_not_negative():
    with pytest.raises(ValidationError):
        Label(risk=0, sufficient_context=False)
    with pytest.raises(ValidationError):
        Label(risk=True, sufficient_context=True)


def test_calibration_never_sharpens_separable_data():
    # Perfectly separated, modestly confident logits would "want" a temperature near zero.
    logits = [2.0, 1.5, 3.0, -2.0, -1.0, -2.5]
    labels = [1, 1, 1, 0, 0, 0]
    temperature, bias = fit_binary_calibration(logits, labels)
    assert temperature == pytest.approx(1.0, abs=1e-6)
    assert bias == 0.0


@pytest.mark.parametrize("method", ["temperature", "platt"])
def test_held_out_calibration_improves_overconfident_logits(method):
    logits = [8.0, 8.0, 8.0, -8.0, -8.0, -8.0]
    labels = [1, 1, 0, 0, 0, 1]
    temperature, bias = fit_binary_calibration(logits, labels, method=method)
    assert temperature > 1.0
    assert log_loss(logits, labels, temperature, bias) < log_loss(logits, labels, 1.0, 0.0)


def test_calibration_needs_both_classes():
    with pytest.raises(ValueError):
        fit_binary_calibration([1.0, 1.0], [1, 1])
    assert sigmoid(-1000.0) == 0.0
    assert sigmoid(1000.0) == 1.0
    with pytest.raises(ValueError):
        sigmoid(math.nan)


def test_duplicate_tool_snapshot_cannot_cross_splits_after_identifier_renaming():
    first = next(record for record in smoke_records() if "tool_scope-benign" in record.record_id)
    values = first.model_dump(mode="json")
    values.update(
        record_id="renamed-record", repository_family="renamed-repo", template_families=[]
    )
    values["request"]["request_id"] = "renamed-request"
    values["request"]["action"]["action_id"] = "renamed-action"
    values["request"]["action"]["summary"] = "A different summary is not independent evidence."
    for index, item in enumerate(values["request"]["evidence"]):
        item.update(
            evidence_id=f"renamed-{index}", origin="renamed-source", revision="renamed-revision"
        )
    second = DatasetRecord.model_validate(values)
    manifest = make_splits([first, second])
    assert len(set(manifest.components.values())) == 1
    manifest.assignments[first.record_id] = "train"
    manifest.assignments[second.record_id] = "test"
    with pytest.raises(ValueError, match="leakage"):
        validate_splits([first, second], manifest)

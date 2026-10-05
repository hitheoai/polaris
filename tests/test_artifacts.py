import pytest

from polaris.artifacts import (
    BundleManifest,
    inventory,
    model_digest,
    read_manifest,
    reseal,
    safe_member,
    write_json,
)
from polaris.errors import PolarisRuntimeError
from polaris.jsonio import digest_text
from polaris.registry import CHECK_IDS


@pytest.fixture
def sealed_bundle(tmp_path):
    # Hash/inventory fixtures only: these bytes are not loadable model weights.
    (tmp_path / "encoder").mkdir()
    (tmp_path / "tokenizer").mkdir()
    write_json(tmp_path / "encoder/config.json", {"model_type": "modernbert"})
    write_json(tmp_path / "tokenizer/tokenizer.json", {})
    for name in ("encoder/model.safetensors", "heads.safetensors"):
        (tmp_path / name).write_bytes(b"integrity-test-placeholder")
    for name in ("calibration.json", "profile.json"):
        write_json(tmp_path / name, {})
    files = inventory(tmp_path)
    manifest = BundleManifest(
        model_version="integrity-test",
        base_model="local-smoke-modernbert",
        base_revision="test-only",
        model_digest=model_digest(files),
        tokenizer_version="test-only",
        runtime_variant="test-only",
        head_order=list(CHECK_IDS),
        supported_checks=list(CHECK_IDS),
        training_dataset_digest=digest_text("test-only"),
        training_groups=[],
        files=files,
    )
    reseal(tmp_path, manifest)
    return tmp_path


def test_inventory_and_model_digest(sealed_bundle):
    manifest = read_manifest(sealed_bundle)
    assert manifest.release_status == "experimental"
    assert manifest.model_digest == model_digest(manifest.files)


def test_tampered_weights_are_rejected(sealed_bundle):
    (sealed_bundle / "heads.safetensors").write_bytes(b"changed")
    with pytest.raises(PolarisRuntimeError) as error:
        read_manifest(sealed_bundle)
    assert error.value.code == "artifact_invalid"


def test_extra_file_is_rejected_even_with_safe_extension(sealed_bundle):
    write_json(sealed_bundle / "extra.json", {})
    with pytest.raises(PolarisRuntimeError):
        read_manifest(sealed_bundle)


def test_symlink_is_rejected(sealed_bundle):
    path = sealed_bundle / "alias.json"
    path.symlink_to(sealed_bundle / "calibration.json")
    with pytest.raises(PolarisRuntimeError):
        safe_member(sealed_bundle, "alias.json")


@pytest.mark.parametrize(
    "name",
    [
        "../escape.json",
        "/tmp/escape.json",
        "encoder/../heads.safetensors",
        "./calibration.json",
        "encoder\\config.json",
        "bad.py",
        "",
    ],
)
def test_unsafe_members_are_rejected(sealed_bundle, name):
    with pytest.raises(PolarisRuntimeError):
        safe_member(sealed_bundle, name)


def test_config_must_be_a_non_remote_modernbert_object(sealed_bundle):
    manifest = read_manifest(sealed_bundle)
    (sealed_bundle / "encoder/config.json").write_text("[]", encoding="utf-8")
    reseal(sealed_bundle, manifest)
    with pytest.raises(PolarisRuntimeError) as error:
        read_manifest(sealed_bundle)
    assert error.value.code == "artifact_invalid"


def test_recalibration_preserves_weights_but_drops_release_qualification(sealed_bundle):
    manifest = read_manifest(sealed_bundle)
    write_json(sealed_bundle / "calibration.json", {"changed": True})
    write_json(sealed_bundle / "qualification.json", {"qualification": "pass"})
    updated = reseal(sealed_bundle, manifest.model_copy(update={"release_status": "qualified"}))
    assert updated.model_digest == manifest.model_digest
    assert updated.release_status == "experimental"
    assert updated.files["calibration.json"] != manifest.files["calibration.json"]


def test_sharded_checkpoint_cannot_reference_uninventoried_weights(sealed_bundle):
    manifest = read_manifest(sealed_bundle)
    write_json(
        sealed_bundle / "encoder/model.safetensors.index.json",
        {"weight_map": {"weight": "../../outside.safetensors"}},
    )
    reseal(sealed_bundle, manifest)
    with pytest.raises(PolarisRuntimeError) as error:
        read_manifest(sealed_bundle)
    assert error.value.code == "artifact_invalid"


def test_tokenizer_config_cannot_load_a_file_outside_the_bundle(sealed_bundle):
    manifest = read_manifest(sealed_bundle)
    write_json(
        sealed_bundle / "tokenizer/tokenizer_config.json",
        {
            "tokenizer_class": "PreTrainedTokenizerFast",
            "tokenizer_file": "/outside/tokenizer.json",
        },
    )
    reseal(sealed_bundle, manifest)
    with pytest.raises(PolarisRuntimeError):
        read_manifest(sealed_bundle)

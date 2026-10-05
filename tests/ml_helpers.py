"""Tiny random offline test artifacts; never published or treated as security data."""

import json

from polaris.artifacts import (
    BundleManifest,
    inventory,
    model_digest,
    reseal,
    runtime_tag,
    write_json,
)
from polaris.calibration import (
    CalibrationArtifact,
    CheckOperatingPoint,
    HeadCalibration,
    OperatingProfile,
)
from polaris.contract import parse_request
from polaris.fixtures import sample_request
from polaris.jsonio import digest_json, digest_text
from polaris.registry import CHECK_IDS


def tiny_request(*, longer=False):
    value = sample_request()
    value["action"]["before_refs"] = []
    value["evidence"] = [
        item for item in value["evidence"] if item["evidence_id"] in ("after", "flow")
    ]
    for item in value["evidence"]:
        item["content"] = (
            "db.execute(query)\n" if item["evidence_id"] == "after" else "query is untrusted"
        )
        item["digest"] = digest_text(item["content"])
        item["origin"] = "unit-test"
        item["revision"] = "v1"
    value["trusted_context"] = [
        item for item in value["trusted_context"] if item["kind"] == "scope"
    ]
    context = value["trusted_context"][0]
    context["content"] = "Local maintenance; request input is untrusted."
    context["digest"] = digest_text(context["content"])
    if longer:
        value["action"]["summary"] = "An untrusted summary with extra context. " * 12
    return parse_request(value)


def tiny_config(vocab_size=300):
    from transformers import ModernBertConfig

    return ModernBertConfig(
        vocab_size=vocab_size,
        hidden_size=32,
        intermediate_size=48,
        num_hidden_layers=2,
        num_attention_heads=4,
        max_position_embeddings=2048,
        pad_token_id=0,
        cls_token_id=1,
        sep_token_id=2,
        reference_compile=False,
        _attn_implementation="sdpa",
    )


def make_tiny_bundle(path):
    import torch
    from safetensors.torch import save_file
    from tokenizers import Tokenizer, decoders, models, pre_tokenizers, trainers
    from transformers import ModernBertModel, PreTrainedTokenizerFast

    from polaris.model import ParallelDecisionModel

    path.mkdir()
    torch.manual_seed(17)
    tokenizer = Tokenizer(models.BPE(unk_token="[UNK]"))
    tokenizer.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tokenizer.decoder = decoders.ByteLevel()
    special = ["[PAD]", "[CLS]", "[SEP]", "[UNK]", "[MASK]"]
    tokenizer.train_from_iterator(
        [json.dumps(tiny_request().model_dump(mode="json"))],
        trainers.BpeTrainer(
            vocab_size=512,
            special_tokens=special,
            initial_alphabet=pre_tokenizers.ByteLevel.alphabet(),
            show_progress=False,
        ),
    )
    fast = PreTrainedTokenizerFast(
        tokenizer_object=tokenizer,
        pad_token="[PAD]",
        cls_token="[CLS]",
        sep_token="[SEP]",
        unk_token="[UNK]",
        mask_token="[MASK]",
    )
    encoder = ModernBertModel(tiny_config(len(fast)))
    model = ParallelDecisionModel(encoder, 32)
    with torch.no_grad():
        model.heads["risk"].bias.fill_(8.0)
        model.heads["sufficiency"].bias.fill_(8.0)
    encoder.save_pretrained(path / "encoder", safe_serialization=True)
    fast.save_pretrained(path / "tokenizer")
    save_file(model.heads.state_dict(), str(path / "heads.safetensors"))
    files = inventory(path)
    digest = model_digest(files)
    variant = runtime_tag("cpu")
    calibration = CalibrationArtifact(
        version="unit-test-calibration-not-real",
        model_digest=digest,
        runtime_variant=variant,
        method="temperature",
        fitted=True,
        source_digest=digest_text("unit-test-only"),
        source_groups=["unit-cal"],
        heads={check: HeadCalibration() for check in CHECK_IDS},
    )
    profile = OperatingProfile(
        version="unit-test-profile-not-real",
        model_digest=digest,
        calibration_version=calibration.version,
        tuned=True,
        source_digest=digest_text("unit-test-only"),
        source_groups=["unit-tuning"],
        checks={check: CheckOperatingPoint() for check in CHECK_IDS},
    )
    write_json(path / "calibration.json", calibration.model_dump(mode="json"))
    write_json(path / "profile.json", profile.model_dump(mode="json"))
    manifest = BundleManifest(
        model_version="tiny-random-unit-test",
        base_model="local-smoke-modernbert",
        base_revision="random",
        model_digest=digest,
        runtime_variant=variant,
        head_order=list(CHECK_IDS),
        supported_checks=list(CHECK_IDS),
        training_dataset_digest=digest_text("unit-test-only"),
        training_groups=["unit-train"],
        development_groups=["unit-development"],
        tokenizer_version=digest_json(
            {name: value for name, value in files.items() if name.startswith("tokenizer/")}
        ),
        files=inventory(path),
    )
    reseal(path, manifest)
    return path

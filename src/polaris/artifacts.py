from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, ValidationError, model_validator

from polaris.contract import (
    CONTRACT_VERSION,
    MAX_TOKENS,
    PREPROCESSING_VERSION,
    REGISTRY_VERSION,
    Digest,
    StrictModel,
)
from polaris.errors import PolarisError, PolarisRuntimeError
from polaris.jsonio import digest_json, load_json
from polaris.registry import CHECK_IDS


class BundleManifest(StrictModel):
    format_version: Literal["polaris.bundle/0.1.0"] = "polaris.bundle/0.1.0"
    contract_version: Literal["polaris.assessment/0.1.0"] = CONTRACT_VERSION
    registry_version: Literal["polaris.checks/0.1.0"] = REGISTRY_VERSION
    preprocessing_version: Literal["snapshot-json/0.2.0"] = PREPROCESSING_VERSION
    model_version: str
    base_model: Literal["answerdotai/ModernBERT-base", "local-smoke-modernbert"]
    base_revision: str
    model_digest: Digest
    tokenizer_version: str
    runtime_variant: str
    release_status: Literal["experimental", "qualified"] = "experimental"
    max_input_tokens: Annotated[int, Field(ge=1, le=MAX_TOKENS)] = MAX_TOKENS
    head_order: list[str]
    supported_checks: list[str]
    training_dataset_digest: Digest
    split_manifest_digest: Digest | None = None
    training_groups: list[str]
    development_groups: list[str] = Field(default_factory=list)
    files: dict[str, Digest]

    @model_validator(mode="after")
    def consistent_heads(self) -> Self:
        if tuple(self.head_order) != CHECK_IDS:
            raise ValueError("head order is incompatible with registry")
        if not self.supported_checks or not set(self.supported_checks) <= set(CHECK_IDS):
            raise ValueError("invalid supported checks")
        if len(self.supported_checks) != len(set(self.supported_checks)):
            raise ValueError("duplicate supported check")
        if set(self.training_groups) & set(self.development_groups):
            raise ValueError("training/development overlap")
        return self


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def model_digest(files: dict[str, str]) -> str:
    return digest_json(
        {
            name: digest
            for name, digest in files.items()
            if name.startswith(("encoder/", "tokenizer/")) or name == "heads.safetensors"
        }
    )


def runtime_tag(device: str) -> str:
    try:
        versions = "/".join(
            f"{name}@{importlib.metadata.version(name)}"
            for name in ("torch", "transformers", "tokenizers")
        )
    except importlib.metadata.PackageNotFoundError as exc:
        raise PolarisRuntimeError("model_unavailable") from exc
    return f"{versions}/{platform.system()}-{platform.machine()}/{device}/float32/sdpa"


def safe_member(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        not name
        or relative.is_absolute()
        or ".." in relative.parts
        or "\\" in name
        or str(relative) != name
    ):
        raise PolarisRuntimeError("artifact_invalid")
    path = root.joinpath(*relative.parts)
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise PolarisRuntimeError("artifact_invalid")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise PolarisRuntimeError("artifact_invalid")
    if path.suffix not in (".json", ".txt", ".safetensors"):
        raise PolarisRuntimeError("artifact_invalid")
    return path


def read_manifest(root: Path) -> BundleManifest:
    if root.is_symlink() or not root.is_dir():
        raise PolarisRuntimeError("model_unavailable")
    try:
        manifest_path = safe_member(root, "manifest.json")
        manifest = BundleManifest.model_validate(load_json(manifest_path.read_bytes()))
        required = {
            "encoder/config.json",
            "tokenizer/tokenizer.json",
            "heads.safetensors",
            "calibration.json",
            "profile.json",
        }
        if not required <= manifest.files.keys():
            raise PolarisRuntimeError("artifact_invalid")
        actual = {
            path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
        } - {"manifest.json"}
        if actual != set(manifest.files):
            raise PolarisRuntimeError("artifact_invalid")
        for name, expected in manifest.files.items():
            if file_digest(safe_member(root, name)) != expected:
                raise PolarisRuntimeError("artifact_invalid")
            if name.startswith("encoder/") and name.endswith(".index.json"):
                index = load_json(safe_member(root, name).read_bytes())
                if not isinstance(index, dict) or not isinstance(index.get("weight_map"), dict):
                    raise PolarisRuntimeError("artifact_invalid")
                for shard in index["weight_map"].values():
                    if not isinstance(shard, str) or f"encoder/{shard}" not in manifest.files:
                        raise PolarisRuntimeError("artifact_invalid")
                    safe_member(root, f"encoder/{shard}")
            if name == "tokenizer/tokenizer_config.json":
                tokenizer_config = load_json(safe_member(root, name).read_bytes())
                if (
                    not isinstance(tokenizer_config, dict)
                    or tokenizer_config.get("auto_map")
                    or tokenizer_config.get("tokenizer_class")
                    not in ("PreTrainedTokenizerFast", "BertTokenizerFast")
                    or any(
                        key.endswith("_file") and value is not None
                        for key, value in tokenizer_config.items()
                    )
                ):
                    raise PolarisRuntimeError("artifact_invalid")
        if model_digest(manifest.files) != manifest.model_digest:
            raise PolarisRuntimeError("artifact_invalid")
        config = load_json((root / "encoder/config.json").read_bytes())
        if (
            not isinstance(config, dict)
            or config.get("model_type") != "modernbert"
            or config.get("auto_map")
        ):
            raise PolarisRuntimeError("artifact_invalid")
        if not any(
            name.startswith("encoder/") and name.endswith(".safetensors") for name in actual
        ):
            raise PolarisRuntimeError("artifact_invalid")
        return manifest
    except (OSError, ValueError, ValidationError, PolarisError) as exc:
        if isinstance(exc, PolarisRuntimeError):
            raise
        raise PolarisRuntimeError("artifact_invalid") from exc


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
    )


def inventory(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): file_digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def reseal(root: Path, manifest: BundleManifest) -> BundleManifest:
    files = inventory(root)
    values = manifest.model_dump(mode="json")
    values.update(files=files, model_digest=model_digest(files), release_status="experimental")
    result = BundleManifest.model_validate(values)
    write_json(root / "manifest.json", result.model_dump(mode="json"))
    return result

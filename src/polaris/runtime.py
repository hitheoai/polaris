from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from polaris.artifacts import read_manifest, runtime_tag
from polaris.calibration import CalibrationArtifact, OperatingProfile
from polaris.contract import AssessmentRequest, RuntimeIdentity
from polaris.engine import Logits
from polaris.errors import PolarisError, PolarisRuntimeError
from polaris.jsonio import digest_json, load_json
from polaris.preprocessing import PreparedInput, prepare
from polaris.registry import CHECK_IDS


class LocalBackend:
    def __init__(
        self,
        bundle: Path,
        *,
        device: str = "cpu",
        allow_experimental: bool = False,
        allow_uncalibrated_runtime: bool = False,
    ) -> None:
        self.manifest = read_manifest(bundle)
        if self.manifest.release_status != "qualified" and not allow_experimental:
            raise PolarisRuntimeError("unqualified_model")
        try:
            import torch
            from safetensors.torch import load_file
            from transformers import AutoModel, AutoTokenizer

            from polaris.model import ParallelDecisionModel
        except ImportError as exc:
            raise PolarisRuntimeError("model_unavailable") from exc
        self.torch = torch
        self.device = device
        if device not in ("cpu", "mps", "cuda"):
            raise PolarisRuntimeError("artifact_invalid")
        if device == "mps" and os.environ.get("PYTORCH_ENABLE_MPS_FALLBACK", "0") != "0":
            raise PolarisRuntimeError("artifact_invalid")
        if (device == "mps" and not torch.backends.mps.is_available()) or (
            device == "cuda" and not torch.cuda.is_available()
        ):
            raise PolarisRuntimeError("model_unavailable")
        variant = runtime_tag(device)
        runtime_changed = variant != self.manifest.runtime_variant
        # A different machine is acceptable only if the bundle's self-test passes here.
        self_testable = "selftest.json" in self.manifest.files and allow_experimental
        if runtime_changed and not (allow_experimental and allow_uncalibrated_runtime) and not self_testable:
            raise PolarisRuntimeError("calibration_mismatch")
        self.runtime_verified = False
        self.selftest_result: dict[str, Any] | None = None
        self._lock = threading.RLock()
        try:
            self.calibration = CalibrationArtifact.model_validate(
                load_json((bundle / "calibration.json").read_bytes())
            )
            self.profile = OperatingProfile.model_validate(
                load_json((bundle / "profile.json").read_bytes())
            )
            calibration_digest = digest_json(self.calibration.model_dump(mode="json"))
            profile_digest = digest_json(self.profile.model_dump(mode="json"))
            # A prior pass cannot qualify changed weights, calibration, profile, or runtime.
            if self.manifest.release_status == "qualified" and not runtime_changed:
                try:
                    report = load_json((bundle / "qualification.json").read_bytes())
                    if not isinstance(report, dict) or not isinstance(report.get("runtime"), dict):
                        raise ValueError("invalid qualification report")
                    identity = report["runtime"]
                    if (
                        report.get("model_digest") != self.manifest.model_digest
                        or self.manifest.base_model != "answerdotai/ModernBERT-base"
                        or self.manifest.split_manifest_digest is None
                        or report.get("split_manifest_digest")
                        != self.manifest.split_manifest_digest
                        or report.get("dataset_digest") != self.manifest.training_dataset_digest
                        or report.get("qualification") != "pass"
                        or identity.get("calibration_version") != self.calibration.version
                        or identity.get("calibration_digest") != calibration_digest
                        or identity.get("operating_profile_version") != self.profile.version
                        or identity.get("operating_profile_digest") != profile_digest
                        or identity.get("max_input_tokens") != self.manifest.max_input_tokens
                        or identity.get("runtime_variant") != variant
                        or set(report.get("checks", {})) != set(self.manifest.supported_checks)
                    ):
                        raise ValueError("qualification does not match this artifact")
                except (OSError, ValueError, TypeError, PolarisError) as exc:
                    raise PolarisRuntimeError("unqualified_model") from exc
            fitted_groups = set(self.calibration.source_groups) | set(self.profile.source_groups)
            if fitted_groups & (
                set(self.manifest.training_groups) | set(self.manifest.development_groups)
            ):
                raise PolarisRuntimeError("calibration_mismatch")
            self.tokenizer = AutoTokenizer.from_pretrained(
                str(bundle / "tokenizer"), local_files_only=True, trust_remote_code=False
            )
            if any(
                value is None
                for value in (
                    self.tokenizer.cls_token_id,
                    self.tokenizer.sep_token_id,
                    self.tokenizer.pad_token_id,
                )
            ):
                raise PolarisRuntimeError("artifact_invalid")
            encoder = AutoModel.from_pretrained(
                str(bundle / "encoder"),
                local_files_only=True,
                trust_remote_code=False,
                use_safetensors=True,
                attn_implementation="sdpa",
                reference_compile=False,
                dtype=torch.float32,
            )
            self.model = ParallelDecisionModel(encoder, encoder.config.hidden_size)
            self.model.heads.load_state_dict(
                load_file(str(bundle / "heads.safetensors")), strict=True
            )
            self.model.to(device)
            self.model.eval()
        except PolarisError:
            raise
        except Exception as exc:
            raise PolarisRuntimeError("artifact_invalid") from exc
        self.supported_checks = frozenset(self.manifest.supported_checks)
        if runtime_changed and self_testable and not allow_uncalibrated_runtime:
            from polaris import selftest

            test = selftest.load(bundle)
            if test is None:
                raise PolarisRuntimeError("calibration_mismatch")
            self.selftest_result = selftest.cached_verify(self, test, variant)
            if not self.selftest_result["passed"]:
                raise PolarisRuntimeError("calibration_mismatch")
            self.runtime_verified = True
        self.identity = RuntimeIdentity(
            model_version=self.manifest.model_version,
            model_digest=self.manifest.model_digest,
            tokenizer_version=self.manifest.tokenizer_version,
            calibration_version=self.calibration.version,
            calibration_digest=calibration_digest,
            operating_profile_version=self.profile.version,
            operating_profile_digest=profile_digest,
            max_input_tokens=self.manifest.max_input_tokens,
            runtime_variant=variant,
            release_status="experimental" if runtime_changed else self.manifest.release_status,
        )

    def prepare(self, request: AssessmentRequest) -> PreparedInput:
        return prepare(request, self.tokenizer, self.manifest.max_input_tokens)

    def synchronize(self) -> None:
        if self.device == "mps":
            self.torch.mps.synchronize()
        elif self.device == "cuda":
            self.torch.cuda.synchronize()

    def predict(self, prepared: PreparedInput) -> dict[str, Logits]:
        return self.predict_batch([prepared])[0]

    def predict_batch(self, prepared: list[PreparedInput]) -> list[dict[str, Logits]]:
        if not prepared or len(prepared) > 16:
            raise PolarisRuntimeError("inference_error")
        if any(len(item.input_ids) > self.manifest.max_input_tokens for item in prepared):
            raise PolarisRuntimeError("inference_error")
        with self._lock, self.torch.inference_mode():
            width = max(len(item.input_ids) for item in prepared)
            ids = self.torch.full(
                (len(prepared), width),
                self.tokenizer.pad_token_id,
                dtype=self.torch.long,
                device=self.device,
            )
            mask = self.torch.zeros_like(ids)
            for index, item in enumerate(prepared):
                ids[index, : len(item.input_ids)] = self.torch.tensor(
                    item.input_ids, device=self.device
                )
                mask[index, : len(item.input_ids)] = 1
            output = self.model(ids, mask)
            if any(not self.torch.isfinite(value).all() for value in output.values()):
                raise PolarisRuntimeError("non_finite_output")
            risk, sufficiency = output["risk"].cpu().tolist(), output["sufficiency"].cpu().tolist()
            return [
                {
                    check: Logits(
                        risk=float(risk[row][col]), sufficiency=float(sufficiency[row][col])
                    )
                    for col, check in enumerate(CHECK_IDS)
                }
                for row in range(len(prepared))
            ]

    def memory(self) -> dict[str, Any]:
        result: dict[str, Any] = {"device": self.device}
        if self.device == "mps":
            result.update(
                current_allocated_bytes=self.torch.mps.current_allocated_memory(),
                driver_allocated_bytes=self.torch.mps.driver_allocated_memory(),
                measurement="current_not_peak",
            )
        elif self.device == "cuda":
            result.update(peak_allocated_bytes=self.torch.cuda.max_memory_allocated())
        return result

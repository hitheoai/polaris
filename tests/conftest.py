from __future__ import annotations

import re
import zlib
from typing import Any

import pytest

from polaris.calibration import (
    CalibrationArtifact,
    CheckOperatingPoint,
    HeadCalibration,
    OperatingProfile,
)
from polaris.contract import AssessmentRequest, RuntimeIdentity
from polaris.engine import Logits
from polaris.fixtures import sample_request
from polaris.jsonio import digest_json, digest_text
from polaris.preprocessing import PreparedInput, prepare
from polaris.registry import CHECK_IDS


class TestTokenizer:
    __test__ = False
    all_special_tokens = ["[CLS]", "[SEP]", "[MASK]"]
    all_special_ids = [1, 2, 3]
    cls_token_id = 1
    sep_token_id = 2

    def __init__(self) -> None:
        self.texts: list[str] = []

    def encode(self, text: str, *, add_special_tokens: bool) -> list[int]:
        assert not add_special_tokens
        self.texts.append(text)
        for token, token_id in zip(self.all_special_tokens, self.all_special_ids, strict=True):
            if token in text:
                return [token_id]
        return [4 + zlib.crc32(word.encode()) % 120 for word in re.findall(r"\w+|[^\w\s]", text)]


class FakeBackend:
    """Deterministic test double only; never exposed as a security model."""

    def __init__(self) -> None:
        self.calls = 0
        self.max_tokens = 2048
        self.tokenizer = TestTokenizer()
        self.supported_checks = frozenset(CHECK_IDS)
        self.identity = RuntimeIdentity(
            model_version="test-double",
            model_digest=digest_text("test-weights"),
            tokenizer_version="test-tokenizer",
            calibration_version="test-calibration",
            operating_profile_version="test-profile",
            runtime_variant="test-only",
            release_status="experimental",
        )
        self.calibration = CalibrationArtifact(
            version="test-calibration",
            model_digest=digest_text("test-weights"),
            runtime_variant="test-only",
            method="temperature",
            fitted=True,
            source_digest=digest_text("cal-data"),
            source_groups=["cal-repository"],
            heads={check: HeadCalibration() for check in CHECK_IDS},
        )
        self.profile = OperatingProfile(
            version="test-profile",
            model_digest=digest_text("test-weights"),
            calibration_version="test-calibration",
            tuned=True,
            source_digest=digest_text("tuning-data"),
            source_groups=["tuning-repository"],
            checks={check: CheckOperatingPoint() for check in CHECK_IDS},
        )
        self.identity = self.identity.model_copy(
            update={
                "calibration_digest": digest_json(self.calibration.model_dump(mode="json")),
                "operating_profile_digest": digest_json(self.profile.model_dump(mode="json")),
                "max_input_tokens": self.max_tokens,
            }
        )
        self.outputs = {check: Logits(risk=8.0, sufficiency=8.0) for check in CHECK_IDS}

    def prepare(self, request: AssessmentRequest) -> PreparedInput:
        return prepare(request, self.tokenizer, self.max_tokens)

    def predict(self, prepared: PreparedInput) -> dict[str, Logits]:
        self.calls += 1
        return self.outputs

    def synchronize(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _not_signed_in(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never use a real sign-in: no API key from the environment, credentials in a temp folder."""
    monkeypatch.delenv("POLARIS_API_KEY", raising=False)
    monkeypatch.delenv("POLARIS_API_URL", raising=False)
    path = tmp_path_factory.mktemp("account") / "credentials.json"
    monkeypatch.setattr("polaris.remote.credentials_path", lambda: path)


@pytest.fixture
def request_data() -> dict[str, Any]:
    return sample_request()


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()

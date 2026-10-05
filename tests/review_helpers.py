"""A scripted stand-in model for review tests. It reads markers, not code: never a security model."""

from polaris.calibration import (
    CalibrationArtifact,
    CheckOperatingPoint,
    HeadCalibration,
    OperatingProfile,
)
from polaris.contract import RuntimeIdentity, TokenCoverage
from polaris.engine import Logits
from polaris.errors import PolarisInputError
from polaris.jsonio import digest_json, digest_text
from polaris.preprocessing import PreparedInput
from polaris.registry import CHECK_IDS

# marker -> (risk logit, sufficiency logit)
OUTCOMES = {3: (8.0, 8.0), 2: (0.0, 8.0), 1: (0.0, -8.0), 0: (-8.0, 8.0)}


class ScriptedBackend:
    """RISKY -> flagged, UNSURE -> uncertain, NOCONTEXT -> needs context, TOOLONG -> too long."""

    def __init__(self, supported=("sql_injection", "command_injection")):
        digest = digest_text("scripted-test-model")
        self.calibration = CalibrationArtifact(
            version="test-cal", model_digest=digest, runtime_variant="test", method="temperature",
            fitted=True, source_digest=digest, source_groups=["cal"],
            heads={check: HeadCalibration() for check in CHECK_IDS},
        )
        self.profile = OperatingProfile(
            version="test-profile", model_digest=digest, calibration_version="test-cal", tuned=True,
            source_digest=digest, source_groups=["tune"],
            checks={check: CheckOperatingPoint() for check in CHECK_IDS},
        )
        self.identity = RuntimeIdentity(
            model_version="scripted-test", model_digest=digest, tokenizer_version="scripted",
            calibration_version="test-cal", calibration_digest=digest_json(self.calibration.model_dump(mode="json")),
            operating_profile_version="test-profile",
            operating_profile_digest=digest_json(self.profile.model_dump(mode="json")),
            max_input_tokens=2048, runtime_variant="test", release_status="experimental",
        )
        self.supported_checks = frozenset(supported)
        self.batches = []

    def prepare(self, request):
        after = next(item.content for item in request.evidence if item.kind == "code_after")
        if "TOOLONG" in after:
            raise PolarisInputError("context_limit", request_id=request.request_id)
        marker = 3 if "RISKY" in after else 2 if "UNSURE" in after else 1 if "NOCONTEXT" in after else 0
        size = len(after) // 10 + 1
        return PreparedInput(
            input_ids=tuple([marker] * size),
            coverage=TokenCoverage(action=0, evidence=size, trusted_context=0, framing=0, total=size),
        )

    def predict_batch(self, prepared):
        self.batches.append(len(prepared))
        outputs = []
        for item in prepared:
            risk, sufficiency = OUTCOMES[item.input_ids[0]]
            outputs.append({check: Logits(risk=risk, sufficiency=sufficiency) for check in CHECK_IDS})
        return outputs

    def predict(self, prepared):
        return self.predict_batch([prepared])[0]

    def synchronize(self):
        pass

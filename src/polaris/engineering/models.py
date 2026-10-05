"""Independent, immutable engineering records; not the experimental model contract.

All digests use ``sha256:<lowercase hex>``. Tuples deliberately replace mutable lists.
Use the parse helpers for untrusted JSON; they suppress Pydantic input excerpts.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, Literal, Self, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from polaris.engineering.errors import EngineeringError, ErrorCode
from polaris.engineering.security import relative_path
from polaris.errors import PolarisInputError
from polaris.jsonio import canonical_bytes, digest_json, load_json

SNAPSHOT_FORMAT: Final = "polaris.repair-snapshot/0.1.0"
PROPOSAL_FORMAT: Final = "polaris.proposal/0.1.0"
APPROVAL_FORMAT: Final = "polaris.approval/0.1.0"
VERIFICATION_FORMAT: Final = "polaris.verification/0.1.0"
ACTION_FORMAT: Final = "polaris.action-review/0.1.0"
GENERATION_FORMAT: Final = "polaris.generation/0.1.0"

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:/@-]+$")]
Text = Annotated[str, Field(min_length=1, max_length=4096)]
PathText = Annotated[str, Field(min_length=1, max_length=512)]
ScopedPath = Annotated[PathText, AfterValidator(relative_path)]
Argument = Annotated[str, Field(max_length=4096, pattern=r"^[^\x00\r\n]*$")]
Executable = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\s\x00;&|`$<>]+$")]
Count = Annotated[int, Field(ge=0)]


class EngineeringModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        revalidate_instances="always",
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )

    @field_validator(
        "approved", "authorized", "executed", "policy_changed", "scope_only",
        "transactional", "behavior_proven",
        mode="before", check_fields=False,
    )
    @classmethod
    def literal_booleans_are_strict(cls, value: Any) -> bool:
        # Pydantic's Literal[True/False] otherwise accepts the equal integers 1/0.
        if not isinstance(value, bool):
            raise ValueError("literal boolean required")
        return value


class EngineeringLimits(EngineeringModel):
    max_files: Annotated[int, Field(ge=1, le=64)] = 16
    max_context_files: Annotated[int, Field(ge=0, le=64)] = 16
    max_file_bytes: Annotated[int, Field(ge=1, le=262_144)] = 131_072
    max_total_bytes: Annotated[int, Field(ge=1, le=2_097_152)] = 524_288
    max_edits: Annotated[int, Field(ge=1, le=16)] = 8
    max_patch_bytes: Annotated[int, Field(ge=1, le=262_144)] = 65_536
    max_changed_lines: Annotated[int, Field(ge=1, le=2000)] = 200
    max_approval_seconds: Annotated[int, Field(ge=1, le=3600)] = 300


class ReviewContext(EngineeringModel):
    """Digests supplied through the embedding application's trusted review channel."""

    review_digest: Digest
    policy_digest: Digest
    analyzer_digest: Digest
    capability_digest: Digest


class FindingReference(EngineeringModel):
    finding_id: Identifier
    path: ScopedPath
    evidence_refs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def unique_evidence(self) -> Self:
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("duplicate evidence reference")
        return self


class FileState(EngineeringModel):
    path: ScopedPath
    sha256: Digest
    size_bytes: Annotated[int, Field(ge=0, le=262_144)]
    # Filesystem permissions are only meaningful in worktree snapshots.
    mode: Annotated[int, Field(ge=0, le=0o777)] | None = None


class ReviewedSnapshot(EngineeringModel):
    format: Literal["polaris.repair-snapshot/0.1.0"] = SNAPSHOT_FORMAT
    source_kind: Literal["worktree", "submitted_content"]
    root_digest: Digest | None
    files: Annotated[tuple[FileState, ...], Field(min_length=1, max_length=64)]
    context_files: Annotated[tuple[FileState, ...], Field(max_length=64)] = ()
    context: ReviewContext
    finding_refs: Annotated[tuple[FindingReference, ...], Field(min_length=1, max_length=128)]
    snapshot_digest: Digest

    @model_validator(mode="after")
    def consistent_snapshot(self) -> Self:
        states = (*self.files, *self.context_files)
        paths = [item.path for item in states]
        if len(set(paths)) != len(paths):
            raise ValueError("duplicate source or context path")
        if (self.source_kind == "worktree") != (self.root_digest is not None):
            raise ValueError("invalid workspace binding")
        if any((item.mode is not None) != (self.source_kind == "worktree") for item in states):
            raise ValueError("invalid mode binding")
        refs = [item.finding_id for item in self.finding_refs]
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate finding")
        scope = {item.path for item in self.files}
        if any(item.path not in scope for item in self.finding_refs):
            raise ValueError("finding outside scope")
        if digest_json(self.model_dump(mode="json", exclude={"snapshot_digest"})) != self.snapshot_digest:
            raise ValueError("snapshot digest mismatch")
        return self


class CandidateEdit(EngineeringModel):
    """A host-supplied replacement; creation, deletion, and rename are not supported."""
    path: ScopedPath
    before_sha256: Digest
    replacement: Annotated[str, Field(max_length=262_144, repr=False)]
    finding_refs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def unique_findings(self) -> Self:
        if len(set(self.finding_refs)) != len(self.finding_refs):
            raise ValueError("duplicate finding reference")
        return self


class ProcessAction(EngineeringModel):
    kind: Literal["process"] = "process"
    action_id: Identifier
    executable: Executable
    argv: Annotated[tuple[Argument, ...], Field(max_length=128, repr=False)] = ()
    cwd: PathText = "."
    filesystem_targets: Annotated[tuple[PathText, ...], Field(max_length=64)] = ()
    network_targets: Annotated[tuple[Text, ...], Field(max_length=32)] = ()


class FilesystemAction(EngineeringModel):
    kind: Literal["filesystem"] = "filesystem"
    action_id: Identifier
    operation: Literal["read", "write", "delete"]
    path: PathText


class NetworkAction(EngineeringModel):
    kind: Literal["network"] = "network"
    action_id: Identifier
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
    url: Text = Field(repr=False)


Action = Annotated[ProcessAction | FilesystemAction | NetworkAction, Field(discriminator="kind")]


class ActionRequest(EngineeringModel):
    format: Literal["polaris.action-review/0.1.0"] = ACTION_FORMAT
    action: Action


class PatchProposal(EngineeringModel):
    format: Literal["polaris.proposal/0.1.0"] = PROPOSAL_FORMAT
    snapshot: ReviewedSnapshot
    origin: Literal["host_candidate", "configured_generator"] = "host_candidate"
    edits: Annotated[tuple[CandidateEdit, ...], Field(min_length=1, max_length=16, repr=False)]
    rationale: Text = Field(repr=False)
    verification_commands: Annotated[tuple[ProcessAction, ...], Field(max_length=16)] = ()
    diff: Annotated[str, Field(min_length=1, max_length=262_144, repr=False)]
    changed_lines: Annotated[int, Field(ge=1, le=2000)]
    proposal_digest: Digest

    @model_validator(mode="after")
    def consistent_proposal(self) -> Self:
        paths = [item.path for item in self.edits]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate edit")
        commands = [item.action_id for item in self.verification_commands]
        if len(commands) != len(set(commands)):
            raise ValueError("duplicate verification command")
        states = {item.path: item for item in self.snapshot.files}
        findings = {item.finding_id: item.path for item in self.snapshot.finding_refs}
        for edit in self.edits:
            if edit.path not in states or states[edit.path].sha256 != edit.before_sha256:
                raise ValueError("edit outside snapshot")
            if any(findings.get(ref) != edit.path for ref in edit.finding_refs):
                raise ValueError("finding does not bind edited file")
        if digest_json(self.model_dump(mode="json", exclude={"proposal_digest"})) != self.proposal_digest:
            raise ValueError("proposal digest mismatch")
        return self


class ProposalValidation(EngineeringModel):
    format: Literal["polaris.proposal-validation/0.1.0"] = "polaris.proposal-validation/0.1.0"
    proposal_digest: Digest
    snapshot_digest: Digest
    status: Literal["valid"] = "valid"
    paths: Annotated[tuple[ScopedPath, ...], Field(min_length=1, max_length=16)]
    authorized: Literal[False] = False
    behavioral_tests: Literal["not_run"] = "not_run"


class ProposalApproval(EngineeringModel):
    """The caller must authenticate human approval; possession of this JSON is not authority."""

    format: Literal["polaris.approval/0.1.0"] = APPROVAL_FORMAT
    proposal_digest: Digest
    snapshot_digest: Digest
    approved: Literal[True]
    approved_at_unix: Annotated[int, Field(ge=0)]
    expires_at_unix: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at_unix <= self.approved_at_unix:
            raise ValueError("invalid approval window")
        return self


class AppliedFile(EngineeringModel):
    path: ScopedPath
    before_sha256: Digest
    after_sha256: Digest


class ApplyReceipt(EngineeringModel):
    format: Literal["polaris.apply-receipt/0.1.0"] = "polaris.apply-receipt/0.1.0"
    proposal_digest: Digest
    snapshot_digest: Digest
    status: Literal["applied", "not_applied", "partially_applied"]
    applied_files: Annotated[tuple[AppliedFile, ...], Field(max_length=16)] = ()
    remaining_paths: Annotated[tuple[ScopedPath, ...], Field(max_length=16)] = ()
    error_code: Identifier | None = None
    transactional: Literal[False] = False
    behavioral_tests: Literal["not_run"] = "not_run"

    @model_validator(mode="after")
    def honest_write_status(self) -> Self:
        paths = [item.path for item in self.applied_files]
        if (
            len(paths) != len(set(paths))
            or len(self.remaining_paths) != len(set(self.remaining_paths))
            or set(paths) & set(self.remaining_paths)
        ):
            raise ValueError("ambiguous receipt paths")
        if self.status == "applied":
            if not self.applied_files or self.remaining_paths or self.error_code is not None:
                raise ValueError("invalid complete receipt")
        elif (
            self.error_code is None
            or (self.status == "not_applied" and self.applied_files)
            or (self.status == "partially_applied" and not self.applied_files)
        ):
            raise ValueError("invalid failure receipt")
        return self


class AdditionalFinding(EngineeringModel):
    """A post-edit result not mapped to an original reference; not proof of when it arose."""

    finding_id: Identifier
    path: ScopedPath
    check_id: Identifier
    result: Literal["flagged", "needs_context", "uncertain", "unsupported", "too_large", "error"] = "flagged"


class StaticReviewObservation(EngineeringModel):
    """Source-free observation returned only by a trusted static-review adapter."""

    status: Literal["completed", "partial", "unavailable", "error"]
    review_digest: Digest | None = None
    analyzed_paths: Annotated[tuple[ScopedPath, ...], Field(max_length=64)] = ()
    # The adapter maps findings to the *original* reference IDs, not unstable post-edit IDs.
    remaining_finding_refs: Annotated[tuple[Identifier, ...], Field(max_length=128)] = ()
    additional_findings: Annotated[tuple[AdditionalFinding, ...], Field(max_length=128)] = ()
    unreviewed_paths: Annotated[tuple[ScopedPath, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def valid_coverage(self) -> Self:
        if len(set(self.analyzed_paths)) != len(self.analyzed_paths):
            raise ValueError("duplicate analyzed path")
        if len(set(self.unreviewed_paths)) != len(self.unreviewed_paths):
            raise ValueError("duplicate unreviewed path")
        if set(self.analyzed_paths) & set(self.unreviewed_paths):
            raise ValueError("conflicting coverage")
        if self.status in ("completed", "partial") and self.review_digest is None:
            raise ValueError("missing observed review digest")
        if self.status == "completed" and self.unreviewed_paths:
            raise ValueError("completed review cannot have unreviewed paths")
        if self.status in ("unavailable", "error") and (
            self.analyzed_paths or self.remaining_finding_refs or self.additional_findings
        ):
            raise ValueError("unavailable review cannot claim findings or coverage")
        if len(self.remaining_finding_refs) != len(set(self.remaining_finding_refs)):
            raise ValueError("duplicate remaining finding reference")
        additional_ids = {item.finding_id for item in self.additional_findings}
        if len(additional_ids) != len(self.additional_findings):
            raise ValueError("duplicate additional finding")
        if additional_ids & set(self.remaining_finding_refs):
            raise ValueError("additional finding overlaps an original reference")
        observed_paths = set(self.analyzed_paths) | set(self.unreviewed_paths)
        if any(item.path not in observed_paths for item in self.additional_findings):
            raise ValueError("additional finding lacks explicit path coverage")
        return self


class FindingVerification(EngineeringModel):
    finding_id: Identifier
    status: Literal["still_detected", "no_longer_detected", "not_reviewed"]


class VerificationRecord(EngineeringModel):
    format: Literal["polaris.verification/0.1.0"] = VERIFICATION_FORMAT
    proposal_digest: Digest
    snapshot_digest: Digest
    status: Literal["verified_snapshot", "stale", "error"]
    observed_files: Annotated[tuple[FileState, ...], Field(max_length=64)] = ()
    static_review: StaticReviewObservation
    findings: Annotated[tuple[FindingVerification, ...], Field(max_length=128)] = ()
    behavioral_tests: Literal["not_run"] = "not_run"
    behavioral_reason: Literal["no_approved_isolated_runner"] = "no_approved_isolated_runner"
    behavior_proven: Literal[False] = False
    error_code: Identifier | None = None


class FilesystemGrant(EngineeringModel):
    path: PathText
    operations: Annotated[
        tuple[Literal["read", "write", "delete"], ...], Field(min_length=1, max_length=3)
    ]


class NetworkGrant(EngineeringModel):
    url: Text
    methods: Annotated[
        tuple[Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], ...],
        Field(min_length=1, max_length=6),
    ]


class ProcessGrant(EngineeringModel):
    """Exact argv and declared effects, not a blanket executable allowlist."""

    executable: Executable
    argv: Annotated[tuple[Argument, ...], Field(max_length=128)] = ()
    cwd: PathText = "."
    filesystem_targets: Annotated[tuple[PathText, ...], Field(max_length=64)] = ()
    network_targets: Annotated[tuple[Text, ...], Field(max_length=32)] = ()


class ActionPolicy(EngineeringModel):
    """A trusted application argument. Never load this from repository/model text."""

    policy_id: Identifier
    revision: Identifier
    authority: Literal["application", "user"]
    process_allowlist: Annotated[tuple[ProcessGrant, ...], Field(max_length=64)] = ()
    filesystem_allowlist: Annotated[tuple[FilesystemGrant, ...], Field(max_length=128)] = ()
    network_allowlist: Annotated[tuple[NetworkGrant, ...], Field(max_length=64)] = ()


class ActionReason(EngineeringModel):
    code: Identifier
    message: Text


class ActionReview(EngineeringModel):
    format: Literal["polaris.action-review/0.1.0"] = ACTION_FORMAT
    action_digest: Digest
    policy_digest: Digest | None = None
    status: Literal["within_declared_scope", "out_of_scope", "needs_review"]
    risk: Literal["low", "elevated", "unknown"]
    reasons: Annotated[tuple[ActionReason, ...], Field(min_length=1, max_length=16)]
    safer_alternative: Text | None = None
    authorized: Literal[False] = False
    executed: Literal[False] = False
    policy_changed: Literal[False] = False
    scope_only: Literal[True] = True


ModelT = TypeVar("ModelT", bound=EngineeringModel)
InputValue = EngineeringModel | dict[str, Any] | str | bytes


def parse_model(model: type[ModelT], value: InputValue) -> ModelT:
    """Revalidate even existing instances/model_copy results and bound untrusted JSON."""
    try:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", warnings=False)
        if isinstance(value, dict):
            value = canonical_bytes(value)
        if not isinstance(value, (str, bytes)):
            raise EngineeringError("invalid_input")
        data = load_json(value)
        return model.model_validate_json(canonical_bytes(data))
    except PolarisInputError as exc:
        code: ErrorCode = "payload_limit" if exc.code == "payload_limit" else "invalid_input"
        raise EngineeringError(code) from None
    except (ValidationError, ValueError, TypeError, OverflowError):
        raise EngineeringError("invalid_input") from None


def parse_proposal(value: InputValue) -> PatchProposal:
    return parse_model(PatchProposal, value)


def parse_snapshot(value: InputValue) -> ReviewedSnapshot:
    return parse_model(ReviewedSnapshot, value)


def parse_action(value: InputValue) -> ActionRequest:
    return parse_model(ActionRequest, value)


def schema(kind: str) -> dict[str, Any]:
    from polaris.engineering.generation_models import (
        GenerationReceipt,
        GenerationRequest,
        GenerationResult,
    )
    models: dict[str, type[EngineeringModel]] = {
        "snapshot": ReviewedSnapshot,
        "candidate_edit": CandidateEdit,
        "proposal": PatchProposal,
        "proposal_validation": ProposalValidation,
        "approval": ProposalApproval,
        "apply_receipt": ApplyReceipt,
        "verification": VerificationRecord,
        "action_request": ActionRequest,
        "action_policy": ActionPolicy,
        "action_review": ActionReview,
        "generation_request": GenerationRequest,
        "generation_result": GenerationResult,
        "generation_receipt": GenerationReceipt,
    }
    if kind not in models:
        raise EngineeringError("invalid_input")
    result = models[kind].model_json_schema()
    result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    result["$id"] = f"urn:polaris:engineering:0.1.0:{kind}"
    return result

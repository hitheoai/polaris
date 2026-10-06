"""An AI model as one more source of candidate fixes, behind everything else Polaris checks.

The model is asked for a whole corrected file for one finding. What comes back is untrusted text:
it goes through the same scope lock, in-memory re-review, size limits and secret guard as any other
candidate, and a person approves the exact result before anything is written. Anything the model
adds beyond the corrected file (commands to run, edits to other files) is thrown away.

It only runs for `polaris fix --ai`, with settings from your own `ai.toml`, after you have seen
which files may be sent where. A file is sent only when Polaris has no checked fix of its own for a
problem in it, and only the file with the problem (no other project file, no other findings).
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from pydantic import ValidationError

from polaris.engineering import FindingReference, capture_supplied_snapshot
from polaris.engineering.errors import EngineeringError
from polaris.engineering.generation import OpenAICompatibleGateway
from polaris.engineering.generation_models import GenerationRequest, GenerationSource
from polaris.errors import PolarisInputError
from polaris.jsonio import digest_text
from polaris.refactor.aiconfig import AiSettings
from polaris.refactor.generators import Candidate, Declined, Origin
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import WorkflowFinding, WorkflowReviewConfig
from polaris.workflow.repair import supplied_context
from polaris.workflow.service import WorkspaceReview

LIST_LIMIT = 8


@dataclass(frozen=True)
class Disclosure:
    """What may leave the computer, shown before anything does."""

    host: str
    model: str
    files: tuple[tuple[str, int], ...]  # (path, bytes), at most one entry per file

    @property
    def total_bytes(self) -> int:
        return sum(size for _, size in self.files)


def disclosure_for(review: WorkspaceReview, settings: AiSettings) -> Disclosure | None:
    """Every file with a flagged problem: the most that could be sent. None when nothing is flagged."""
    sizes = {source.path: len((source.after or "").encode("utf-8")) for source in review.sources
             if source.role == "review" and source.after is not None and source.skip is None}
    paths = sorted({item.path for item in review.envelope.review.findings
                    if item.result == "flagged" and item.path in sizes})
    if not paths:
        return None
    return Disclosure(settings.host, settings.model, tuple((path, sizes[path]) for path in paths))


def describe(files: Collection[tuple[str, int]]) -> str:
    """'a.py (12 bytes), b.py (30 bytes) and 2 more', for notes and prompts."""
    ordered = sorted(files)
    shown = [f"{path} ({size:,} bytes)" for path, size in ordered[:LIST_LIMIT]]
    if len(ordered) > LIST_LIMIT:
        shown.append(f"and {len(ordered) - LIST_LIMIT} more")
    return ", ".join(shown)


class AiGenerator:
    origin: Origin = "ai"

    def __init__(
        self, gateway: OpenAICompatibleGateway, review: WorkspaceReview, settings: AiSettings, *,
        approved: Collection[str], config: WorkflowReviewConfig, runtime: AnalysisRuntime,
    ) -> None:
        self._gateway = gateway
        self._review = review
        self._settings = settings
        self._approved = frozenset(approved)
        self._config = config
        self._runtime = runtime
        # path -> bytes, for every file a request was made for (whether or not it was answered).
        self.sent: dict[str, int] = {}

    def _goal(self, finding: WorkflowFinding) -> str:
        return (f"Fix this security finding with the smallest possible change: {finding.title} "
                f"({finding.rule_id}) at line {finding.start_line}. Return exactly one edit, for this "
                "file, whose replacement is the complete corrected file. Change only what the fix "
                "needs and keep everything else identical.")[:4000]

    def _request(self, finding: WorkflowFinding, text: str) -> GenerationRequest:
        reference = FindingReference(
            finding_id=finding.finding_id, path=finding.path,
            evidence_refs=(f"check:{finding.check_id}", finding.evidence_digest))
        snapshot = capture_supplied_snapshot(
            {finding.path: text}, context=supplied_context(self._review.envelope, self._config, self._runtime),
            finding_refs=[reference])
        source = GenerationSource(path=finding.path, sha256=digest_text(text), content=text)
        return GenerationRequest(snapshot=snapshot, goal=self._goal(finding), sources=(source,))

    def __call__(self, finding: WorkflowFinding, text: str) -> Candidate | Declined | None:
        name = self._settings.model[:200]

        def declined(reason: str) -> Declined:
            return Declined("ai", name, reason)

        if finding.path not in self._approved:
            return declined("ai_not_approved_for_this_file")
        if "\r" in text:
            return declined("carriage_returns")  # a fix couldn't be checked, so don't send the file
        try:
            request = self._request(finding, text)
        except EngineeringError as exc:
            return declined(f"ai_{exc.code}")
        except (ValidationError, ValueError, PolarisInputError):
            return declined("ai_invalid_request")
        result = self._gateway.generate(request)
        if result.receipt.attempts:
            self.sent[finding.path] = len(text.encode("utf-8"))
        proposal = result.proposal
        if proposal is None:
            return declined(f"ai_{result.receipt.code}")
        if len(proposal.edits) != 1 or proposal.edits[0].path != finding.path:
            return declined("ai_changed_other_files")
        # Only the corrected file is kept. Verification commands and everything else are dropped.
        return Candidate(finding.path, proposal.edits[0].replacement, "ai", name,
                         ("Suggested by an AI model, then re-checked by Polaris. " + proposal.rationale)[:4000])

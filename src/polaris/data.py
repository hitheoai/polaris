from __future__ import annotations

import ast
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from polaris.contract import AssessmentRequest, Digest, Identifier, StrictModel
from polaris.errors import PolarisInputError
from polaris.jsonio import MAX_PAYLOAD_BYTES, digest_json, digest_text, load_json
from polaris.registry import CHECK_IDS

SPLITS = ("train", "development", "calibration", "tuning", "test")
Split = Literal["train", "development", "calibration", "tuning", "test"]
LICENSE_ALLOWLIST = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "CC-BY-4.0", "CC0-1.0"}


class Label(StrictModel):
    risk: Annotated[int, Field(ge=0, le=1)] | None
    sufficient_context: bool
    critical: bool = False

    @model_validator(mode="after")
    def no_false_negative_for_unknown(self) -> Self:
        if not self.sufficient_context and self.risk is not None:
            raise ValueError("insufficient context must not have a risk target")
        return self


class Provenance(StrictModel):
    source: str
    source_license: str
    annotation_license: str
    rights_reviewed: bool
    review_state: Literal["unreviewed", "reviewed", "adjudicated"]
    reviewers: list[Identifier] = Field(default_factory=list)
    synthetic: bool

    @model_validator(mode="after")
    def reviewers_required(self) -> Self:
        if self.review_state == "adjudicated" and len(set(self.reviewers)) < 2:
            raise ValueError("adjudication requires at least two distinct reviewers")
        return self


class DatasetRecord(StrictModel):
    record_id: Identifier
    repository_family: Identifier
    template_families: list[Identifier] = Field(default_factory=list)
    cves: list[Identifier] = Field(default_factory=list)
    clone_families: list[Identifier] = Field(default_factory=list)
    slice_tags: list[Identifier]
    provenance: Provenance
    request: AssessmentRequest
    labels: dict[str, Label]

    @model_validator(mode="after")
    def supported_labels(self) -> Self:
        requested = {check.check_id for check in self.request.requested_checks}
        if not self.labels or not self.labels.keys() <= set(CHECK_IDS) & requested:
            raise ValueError("labels must identify supported, requested checks")
        return self


class SplitManifest(StrictModel):
    version: Literal["polaris.splits/0.1.0"] = "polaris.splits/0.1.0"
    dataset_digest: Digest
    seed: str
    assignments: dict[str, Split]
    components: dict[str, str]


def read_records(path: Path) -> list[DatasetRecord]:
    records = []
    with path.open("rb") as stream:
        while line := stream.readline(MAX_PAYLOAD_BYTES + 1):
            if len(line) > MAX_PAYLOAD_BYTES:
                raise PolarisInputError("payload_limit")
            if line.strip():
                records.append(DatasetRecord.model_validate(load_json(line)))
    ids = [record.record_id for record in records]
    if not records or len(ids) != len(set(ids)):
        raise ValueError("dataset must be nonempty with unique record identifiers")
    return records


def dataset_digest(records: list[DatasetRecord]) -> str:
    return digest_json(
        [record.model_dump(mode="json") for record in sorted(records, key=lambda r: r.record_id)]
    )


def leakage_keys(record: DatasetRecord) -> set[str]:
    keys = {f"repository:{record.repository_family}"}
    keys.update(f"template:{value}" for value in record.template_families)
    keys.update(f"cve:{value}" for value in record.cves)
    keys.update(f"clone:{value}" for value in record.clone_families)
    action = record.request.action.model_dump(mode="json")
    action.pop("action_id")
    action.pop("summary", None)
    evidence_by_id = {item.evidence_id: item.digest for item in record.request.evidence}
    for field in ("before_refs", "after_refs", "diff_refs"):
        if field in action:
            action[field] = sorted(evidence_by_id[ref] for ref in action[field])
    # Transport IDs and provenance renames cannot separate identical model states.
    keys.add(
        "snapshot:"
        + digest_json(
            {
                "action": action,
                "evidence": sorted((item.kind, item.digest) for item in record.request.evidence),
                "context": sorted(
                    (item.kind, item.digest) for item in record.request.trusted_context
                ),
            }
        )
    )
    for item in record.request.evidence:
        if item.kind not in ("code_before", "code_after") or len(item.content) < 32:
            continue
        keys.add("exact-code:" + item.digest)
        try:
            # Parsing creates an AST only. Submitted code is never imported or run.
            tree = ast.parse(item.content)
            keys.add("ast:" + digest_text(ast.dump(tree, include_attributes=False)))
        except (SyntaxError, ValueError, RecursionError):
            pass
    return keys


def components(records: list[DatasetRecord]) -> dict[str, str]:
    ids = [record.record_id for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate dataset record")
    parent = {record_id: record_id for record_id in ids}

    def root(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    owners: dict[str, str] = {}
    for record in sorted(records, key=lambda r: r.record_id):
        for key in sorted(leakage_keys(record)):
            if key in owners:
                a, b = root(record.record_id), root(owners[key])
                parent[max(a, b)] = min(a, b)
            else:
                owners[key] = record.record_id
    return {record_id: root(record_id) for record_id in ids}


def make_splits(records: list[DatasetRecord], seed: str = "polaris-0.1") -> SplitManifest:
    groups = components(records)
    assignments: dict[str, Split] = {}
    for record_id, group in groups.items():
        value = int(hashlib.sha256(f"{seed}:{group}".encode()).hexdigest()[:16], 16) / 2**64
        split: Split = (
            "train"
            if value < 0.6
            else "development"
            if value < 0.7
            else "calibration"
            if value < 0.8
            else "tuning"
            if value < 0.9
            else "test"
        )
        assignments[record_id] = split
    return SplitManifest(
        dataset_digest=dataset_digest(records),
        seed=seed,
        assignments=assignments,
        components=groups,
    )


def validate_splits(records: list[DatasetRecord], manifest: SplitManifest) -> None:
    expected = {record.record_id for record in records}
    if (
        manifest.dataset_digest != dataset_digest(records)
        or set(manifest.assignments) != expected
        or set(manifest.components) != expected
        or manifest.components != components(records)
    ):
        raise ValueError("split manifest does not match the dataset")
    seen: dict[str, str] = {}
    for record in records:
        for key in leakage_keys(record):
            split = manifest.assignments[record.record_id]
            if key in seen and seen[key] != split:
                raise ValueError(
                    "cross-split repository, template, CVE, clone, or snapshot leakage"
                )
            seen[key] = split


def audit(records: list[DatasetRecord], manifest: SplitManifest | None = None) -> dict[str, Any]:
    blockers = []
    unreviewed = sum(record.provenance.review_state != "adjudicated" for record in records)
    rights = sum(
        not record.provenance.rights_reviewed
        or record.provenance.source_license not in LICENSE_ALLOWLIST
        or record.provenance.annotation_license not in LICENSE_ALLOWLIST
        for record in records
    )
    if unreviewed:
        blockers.append("independent_adjudication_required")
    if rights:
        blockers.append("rights_review_required")
    if len(records) < 2000:
        blockers.append("below_planned_pilot_size")
    group_counts: dict[str, set[str]] = defaultdict(set)
    if manifest is not None:
        validate_splits(records, manifest)
        for record in records:
            group_counts[manifest.assignments[record.record_id]].add(
                manifest.components[record.record_id]
            )
        if any(not group_counts[split] for split in SPLITS):
            blockers.append("empty_split")
    return {
        "dataset_digest": dataset_digest(records),
        "records": len(records),
        "repository_families": len({r.repository_family for r in records}),
        "independent_components": len(set(components(records).values())),
        "unadjudicated_records": unreviewed,
        "rights_unreviewed_or_disallowed_records": rights,
        "synthetic_records": sum(r.provenance.synthetic for r in records),
        "labels": dict(Counter(check for record in records for check in record.labels)),
        "groups_by_split": {split: len(group_counts[split]) for split in SPLITS},
        "status": "blocked" if blockers else "ready_for_experiment",
        "blockers": blockers,
        "qualification": "not_a_security_release",
    }


def require_adjudicated(records: list[DatasetRecord]) -> None:
    if any(
        record.provenance.review_state != "adjudicated"
        or len(set(record.provenance.reviewers)) < 2
        or not record.provenance.rights_reviewed
        or record.provenance.source_license not in LICENSE_ALLOWLIST
        or record.provenance.annotation_license not in LICENSE_ALLOWLIST
        for record in records
    ):
        raise ValueError("independently adjudicated, rights-reviewed data is required")

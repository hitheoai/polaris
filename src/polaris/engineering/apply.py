"""Optional local editing primitive; deliberately not an MCP/API write tool.

Callers authenticate approval and ensure a controlled, quiescent workspace. Individual
replacements are atomic, but multiple files are not a transaction. Detected races or errors
stop further writes; rollback would risk overwriting concurrent work and is not attempted.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from polaris.engineering.errors import EngineeringError, ErrorCode
from polaris.engineering.models import (
    AppliedFile,
    ApplyReceipt,
    CandidateEdit,
    EngineeringLimits,
    InputValue,
    PatchProposal,
    ProposalApproval,
    ReviewContext,
    parse_model,
    parse_proposal,
)
from polaris.engineering.security import guard_output, utf8_bytes
from polaris.engineering.service import (
    check_workspace,
    limits_or_default,
    validate_derived_diff,
)
from polaris.engineering.workspace import Workspace
from polaris.jsonio import digest_bytes


@dataclass
class _Prepared:
    edit: CandidateEdit
    parent: int
    name: str
    temporary: str | None
    descriptor: int
    identity: tuple[int, int]
    mode: int


def _approval(
    proposal: PatchProposal, approval: ProposalApproval | None, limits: EngineeringLimits
) -> None:
    if approval is None:
        raise EngineeringError("approval_required")
    try:
        approval = parse_model(ProposalApproval, approval)
    except EngineeringError:
        raise EngineeringError("approval_required") from None
    if (
        approval.proposal_digest != proposal.proposal_digest
        or approval.snapshot_digest != proposal.snapshot.snapshot_digest
        or approval.approved is not True
    ):
        raise EngineeringError("approval_required")
    now = time.time()
    if (
        not approval.approved_at_unix <= now < approval.expires_at_unix
        or approval.expires_at_unix - approval.approved_at_unix > limits.max_approval_seconds
    ):
        raise EngineeringError("approval_expired")


def _cleanup(prepared: list[_Prepared]) -> bool:
    successful = True
    for item in prepared:
        try:
            if item.temporary is not None:
                info = os.stat(item.temporary, dir_fd=item.parent, follow_symlinks=False)
                if (info.st_dev, info.st_ino) == item.identity:
                    os.unlink(item.temporary, dir_fd=item.parent)
                else:
                    successful = False
        except FileNotFoundError:
            pass
        except OSError:
            successful = False
        finally:
            for descriptor in (item.descriptor, item.parent):
                try:
                    os.close(descriptor)
                except OSError:
                    successful = False
    return successful


def _prepare(
    workspace: Workspace, proposal: PatchProposal, prepared: list[_Prepared]
) -> None:
    modes = {state.path: state.mode for state in proposal.snapshot.files}
    for edit in proposal.edits:
        parent, name = workspace.parent(edit.path)
        temporary = f".polaris-{secrets.token_hex(16)}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            info = os.fstat(descriptor)
            mode = modes[edit.path]
            item = _Prepared(
                edit=edit, parent=parent, name=name, temporary=temporary,
                descriptor=descriptor, identity=(info.st_dev, info.st_ino),
                mode=mode if mode is not None else 0o600,
            )
            prepared.append(item)
            raw = utf8_bytes(edit.replacement)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise EngineeringError("write_failed")
                view = view[count:]
            os.fsync(descriptor)
        except BaseException:
            # Once registered, the outer finally owns descriptor and file cleanup.
            if descriptor is None:
                os.close(parent)
            raise


def _check_temporary(item: _Prepared) -> None:
    if item.temporary is None:
        raise EngineeringError("race_detected")
    info = os.stat(item.temporary, dir_fd=item.parent, follow_symlinks=False)
    opened = os.fstat(item.descriptor)
    if (
        (info.st_dev, info.st_ino) != item.identity
        or (opened.st_dev, opened.st_ino) != item.identity
        or opened.st_nlink != 1
    ):
        raise EngineeringError("race_detected")
    expected = utf8_bytes(item.edit.replacement)
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= len(expected):
        chunk = os.read(item.descriptor, min(65_536, len(expected) + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if content != expected:
        raise EngineeringError("race_detected")


def apply_proposal(
    root: Path,
    proposal: InputValue,
    *,
    approval: ProposalApproval | None,
    context: ReviewContext,
    limits: EngineeringLimits | None = None,
) -> ApplyReceipt:
    """Apply only a freshly validated, explicitly approved exact worktree proposal.

    No source, rationale, diff, command, approval principal, or credentials go in the receipt.
    An embedding application must never infer approval from a risk score or an untrusted
    ``approved: true`` request field. This function itself cannot authenticate a human.
    """
    proposal = parse_proposal(proposal)
    bounds = limits_or_default(limits)
    applied: list[AppliedFile] = []
    prepared: list[_Prepared] = []
    error_code: ErrorCode | None = None
    try:
        guard_output(proposal)
        if proposal.snapshot.source_kind != "worktree":
            raise EngineeringError("worktree_required")
        _approval(proposal, approval, bounds)
        with Workspace(root, max_file_bytes=bounds.max_file_bytes) as workspace:
            sources, _ = check_workspace(
                workspace, proposal.snapshot, context=context, limits=bounds
            )
            validate_derived_diff(
                {path: source.text for path, source in sources.items()}, proposal, bounds
            )
            # Every file, context, digest and approval is checked before even staging bytes.
            _approval(proposal, approval, bounds)
            _prepare(workspace, proposal, prepared)
            # Do not replace file A when file B has become stale during preparation.
            check_workspace(workspace, proposal.snapshot, context=context, limits=bounds)
            replacements: dict[str, str] = {}
            for item in prepared:
                _approval(proposal, approval, bounds)
                check_workspace(
                    workspace, proposal.snapshot, context=context,
                    limits=bounds, replacements=replacements,
                )
                workspace.assert_parent(item.edit.path, item.parent)
                _check_temporary(item)
                os.fchmod(item.descriptor, item.mode)
                os.fsync(item.descriptor)
                if item.temporary is None:
                    raise EngineeringError("race_detected")
                os.replace(
                    item.temporary, item.name, src_dir_fd=item.parent, dst_dir_fd=item.parent
                )
                item.temporary = None
                applied.append(
                    AppliedFile(
                        path=item.edit.path, before_sha256=item.edit.before_sha256,
                        after_sha256=digest_bytes(utf8_bytes(item.edit.replacement)),
                    )
                )
                replacements[item.edit.path] = item.edit.replacement
                os.fsync(item.parent)
                workspace.assert_parent(item.edit.path, item.parent)
            check_workspace(
                workspace, proposal.snapshot, context=context, limits=bounds,
                replacements=replacements,
            )
    except EngineeringError as exc:
        error_code = exc.code
    except OSError:
        error_code = "write_failed"
    finally:
        if not _cleanup(prepared) and error_code is None:
            error_code = "write_failed"
    applied_paths = {item.path for item in applied}
    return ApplyReceipt(
        proposal_digest=proposal.proposal_digest,
        snapshot_digest=proposal.snapshot.snapshot_digest,
        status=(
            "applied" if error_code is None else "partially_applied" if applied else "not_applied"
        ),
        applied_files=tuple(applied),
        remaining_paths=tuple(edit.path for edit in proposal.edits if edit.path not in applied_paths),
        error_code=error_code,
    )

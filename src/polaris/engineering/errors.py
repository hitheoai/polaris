"""Public engineering errors contain fixed messages, never submitted source or credentials."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal[
    "invalid_input",
    "payload_limit",
    "invalid_path",
    "unsafe_file",
    "unreadable_source",
    "source_limit",
    "scope_mismatch",
    "snapshot_mismatch",
    "proposal_mismatch",
    "stale_source",
    "stale_context",
    "secret_detected",
    "no_change",
    "patch_limit",
    "approval_required",
    "approval_expired",
    "worktree_required",
    "unsupported_platform",
    "race_detected",
    "write_failed",
    "review_failed",
]

MESSAGES: dict[ErrorCode, str] = {
    "invalid_input": "The input does not conform to the engineering schema.",
    "payload_limit": "The input exceeds the JSON size or structure limit.",
    "invalid_path": "An exact, normalized, workspace-relative path is required.",
    "unsafe_file": "Symlinks, hard links, special files, and sensitive metadata are unsupported.",
    "unreadable_source": "A required UTF-8 source file could not be read safely.",
    "source_limit": "The supplied source or context exceeds the configured bounds.",
    "scope_mismatch": "The edit or finding is outside the exact caller-established scope.",
    "snapshot_mismatch": "The snapshot digest or workspace binding does not match.",
    "proposal_mismatch": "The exact proposal digest or derived diff does not match.",
    "stale_source": "A reviewed source file has changed; capture and review a new snapshot.",
    "stale_context": "Review, policy, analyzer, capabilities, or context files have changed.",
    "secret_detected": "Potential credentials were detected; no source-bearing output is returned.",
    "no_change": "A candidate contains no change.",
    "patch_limit": "The candidate exceeds the configured edit, byte, or changed-line limit.",
    "approval_required": "Explicit approval of this exact worktree-bound proposal is required.",
    "approval_expired": "The exact-proposal approval is expired or not yet valid.",
    "worktree_required": "Submitted-content snapshots cannot authorize local filesystem edits.",
    "unsupported_platform": "Required no-follow, directory-descriptor operations are unavailable.",
    "race_detected": "The workspace changed during the operation; inspect it before continuing.",
    "write_failed": "A local write failed; inspect the receipt for files already replaced.",
    "review_failed": "The configured static reviewer failed; no successful review is claimed.",
}


class EngineeringError(Exception):
    """A safe boundary error. Do not attach provider or filesystem exception text."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(MESSAGES[code])

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": MESSAGES[self.code]}

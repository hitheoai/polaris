"""Explain typed action scope. No subprocess, network request, policy-file read, or execution."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import unquote, urlsplit

from polaris.engineering.errors import EngineeringError
from polaris.engineering.models import (
    ActionPolicy,
    ActionReason,
    ActionRequest,
    ActionReview,
    FilesystemAction,
    InputValue,
    NetworkAction,
    ProcessAction,
    parse_action,
    parse_model,
)
from polaris.engineering.security import guard_output, relative_path
from polaris.engineering.workspace import Workspace
from polaris.jsonio import digest_json

_SHELLS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
)
_REASONS = {
    "missing_authority": "No application- or user-established action policy was supplied.",
    "invalid_policy": "The configured policy has ambiguous or unsupported scope.",
    "secret_detected": "Potential credentials are present; remove secrets from the proposal.",
    "outside_root": "The action names an absolute, traversing, sensitive, or otherwise unscoped path.",
    "filesystem_not_allowlisted": "The exact file and operation are not in the caller's allowlist.",
    "network_not_allowlisted": "The exact network URL and method are not in the caller's allowlist.",
    "invalid_destination": "The destination has unsupported or ambiguous URL semantics.",
    "insecure_transport": "Non-loopback cleartext network access needs separate review.",
    "ambiguous_shell": "Shell/interpreter command strings are not an assessable argv boundary.",
    "ambiguous_executable": "Use an exact absolute executable identity, not PATH lookup or shell text.",
    "process_not_allowlisted": "The exact executable, argv, cwd, and declared effects are not allowlisted.",
    "undeclared_target": "A visible argv path or network target was not explicitly declared.",
    "filesystem_unverified": "No actual workspace was provided; symlink and filesystem scope is unknown.",
    "unsafe_filesystem": "The actual workspace path is unavailable, aliased, or contains a symlink.",
    "scope_match": "This typed proposal matches the declared scope; this is not execution permission.",
    "process_effects_unknown": "Exact invocation matching does not prove the program's runtime effects.",
}


def scope_url(value: str) -> tuple[str, str, int, str]:
    """A deliberately narrow, exact URL scope. No wildcards, redirects, query or userinfo."""
    try:
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            parsed.scheme not in ("http", "https")
            or host is None
            or not host.isascii()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "%" in parsed.netloc
            or "\\" in value
            or host.endswith(".")
            or parsed.netloc.endswith(":")
        ):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(
                len(label) > 63
                or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label.lower()) is None
                for label in host.split(".")
            ):
                raise ValueError from None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if port < 1:
            raise ValueError
        path = parsed.path or "/"
        decoded = unquote(path)
        if (
            decoded != path
            or not path.startswith("/")
            or "//" in path
            or any(part in (".", "..") for part in path.split("/"))
        ):
            raise ValueError
        return parsed.scheme, host.lower(), port, path
    except (ValueError, UnicodeError):
        raise EngineeringError("invalid_input") from None


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _policy_valid(policy: ActionPolicy) -> bool:
    try:
        paths = [relative_path(grant.path) for grant in policy.filesystem_allowlist]
        urls = [scope_url(grant.url) for grant in policy.network_allowlist]
        if len(set(paths)) != len(paths) or len(set(urls)) != len(urls):
            return False
        for grant in policy.process_allowlist:
            relative_path(grant.cwd, allow_root=True)
            for path in grant.filesystem_targets:
                relative_path(path)
            for url in grant.network_targets:
                scope_url(url)
        guard_output(policy)
        return True
    except EngineeringError:
        return False


def _network_code(url: str, policy: ActionPolicy, method: str | None = None) -> str | None:
    try:
        parsed = scope_url(url)
    except EngineeringError:
        return "invalid_destination"
    if parsed[0] == "http" and not _loopback(parsed[1]):
        return "insecure_transport"
    if not any(
        scope_url(grant.url) == parsed and (method is None or method in grant.methods)
        for grant in policy.network_allowlist
    ):
        return "network_not_allowlisted"
    return None


def _filesystem_code(path: str, policy: ActionPolicy, operation: str | None = None) -> str | None:
    try:
        relative_path(path)
    except EngineeringError:
        return "outside_root"
    if not any(
        path == grant.path and (operation is None or operation in grant.operations)
        for grant in policy.filesystem_allowlist
    ):
        return "filesystem_not_allowlisted"
    return None


def _actual_paths(
    root: Path | None, paths: tuple[str, ...], *, cwd: str | None = None, allow_missing: bool = False
) -> str | None:
    if root is None:
        return "filesystem_unverified"
    try:
        with Workspace(root, max_file_bytes=1) as workspace:
            if cwd is not None:
                descriptor = workspace.directory(cwd)
                os.close(descriptor)
            for path in paths:
                workspace.probe(path, allow_missing=allow_missing)
            workspace.assert_root()
        return None
    except (EngineeringError, OSError):
        return "unsafe_filesystem"


def _process_code(action: ProcessAction, policy: ActionPolicy, root: Path | None) -> str | None:
    if PurePosixPath(action.executable).name.lower() in _SHELLS:
        return "ambiguous_shell"
    if (
        not action.executable.startswith("/")
        or "\\" in action.executable
        or any(part in (".", "..") for part in action.executable.split("/"))
    ):
        return "ambiguous_executable"
    try:
        relative_path(action.cwd, allow_root=True)
    except EngineeringError:
        return "outside_root"
    for path in action.filesystem_targets:
        conflict = _filesystem_code(path, policy)
        if conflict:
            return conflict
    for url in action.network_targets:
        conflict = _network_code(url, policy)
        if conflict:
            return conflict
    for argument in action.argv:
        value = argument.partition("=")[2] if argument.startswith("-") and "=" in argument else argument
        if value.startswith(("http://", "https://")):
            if value not in action.network_targets:
                return "undeclared_target"
        elif value.startswith(("/", "~")) or "\\" in value or ".." in value.split("/"):
            return "outside_root"
        elif "/" in value and not value.startswith("-"):
            try:
                relative_path(value)
            except EngineeringError:
                return "outside_root"
            if value not in action.filesystem_targets:
                return "undeclared_target"
    signature = action.model_dump(mode="json", exclude={"kind", "action_id"})
    if not any(grant.model_dump(mode="json") == signature for grant in policy.process_allowlist):
        return "process_not_allowlisted"
    return _actual_paths(root, action.filesystem_targets, cwd=action.cwd, allow_missing=True)


def review_action(
    action: ActionRequest | ProcessAction | FilesystemAction | NetworkAction | InputValue,
    *,
    policy: ActionPolicy | None,
    root: Path | None = None,
) -> ActionReview:
    """Policy is a trusted argument, never a field in ActionRequest or repository config.

    Bare shell strings, unknown action kinds, and per-request policy fields fail schema
    validation. An exact command allowlist is narrower than merely trusting an executable,
    but still cannot establish arbitrary program effects or grant execution permission.
    """
    if isinstance(action, (ProcessAction, FilesystemAction, NetworkAction)):
        request = parse_action({"action": action.model_dump(mode="json", warnings=False)})
    else:
        request = parse_action(action)
    action_digest = digest_json(request.model_dump(mode="json"))
    policy_digest: str | None = None
    code: str | None
    try:
        guard_output(request)
        code = None
    except EngineeringError:
        code = "secret_detected"
    if code is None:
        if policy is None:
            code = "missing_authority"
        else:
            try:
                policy = parse_model(ActionPolicy, policy)
            except EngineeringError:
                code = "invalid_policy"
            else:
                policy_digest = digest_json(policy.model_dump(mode="json"))
                if not _policy_valid(policy):
                    code = "invalid_policy"
    typed = request.action
    if code is None and policy is not None:
        if isinstance(typed, NetworkAction):
            code = _network_code(typed.url, policy, typed.method)
        elif isinstance(typed, FilesystemAction):
            code = _filesystem_code(typed.path, policy, typed.operation)
            if code is None:
                code = _actual_paths(root, (typed.path,), allow_missing=typed.operation == "write")
        else:
            code = _process_code(typed, policy, root)
    conflicts = {
        "outside_root", "filesystem_not_allowlisted", "network_not_allowlisted",
        "process_not_allowlisted", "secret_detected", "unsafe_filesystem",
    }
    status: Literal["within_declared_scope", "out_of_scope", "needs_review"] = (
        "within_declared_scope" if code is None else "out_of_scope" if code in conflicts else "needs_review"
    )
    reason_codes = [code or "scope_match"]
    if code is None and isinstance(typed, ProcessAction):
        reason_codes.append("process_effects_unknown")
    alternative = None
    if code in {"ambiguous_shell", "ambiguous_executable"}:
        alternative = "Propose an exact executable and separate literal arguments for host review."
    elif code in conflicts:
        alternative = "Narrow the proposal to the existing scope, or ask the user separately to change it."
    return ActionReview(
        action_digest=action_digest, policy_digest=policy_digest, status=status,
        risk="low" if code is None else "elevated" if code in conflicts else "unknown",
        reasons=tuple(ActionReason(code=reason, message=_REASONS[reason]) for reason in reason_codes),
        safer_alternative=alternative,
    )

"""Private Polaris-key activation. Never infer a hosted endpoint or print remote text."""

from __future__ import annotations

import getpass
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from polaris.onboarding.errors import OnboardingProblem

DATA_BOUNDARY = (
    "Hosted classification sends only eligible Python functions with SQL/process calls, "
    "their previous versions, path/line, static notes and policy. Expanded workflow review "
    "stays local static analysis; a key does not add model coverage to it."
)


def endpoint(value: str) -> str:
    """A credential-free origin only; literal loopback HTTP is for local operator validation."""
    from polaris.remote import normalize_api_url
    try:
        return normalize_api_url(value)
    except ValueError as exc:
        raise OnboardingProblem(
            "invalid_api_url",
            "Use a configured credential-free https:// API origin, without a path, query or fragment "
            "(literal loopback HTTP is allowed for local validation).",
        ) from exc


def validate_key(key: str) -> str:
    if not 8 <= len(key) <= 2048 or not key.isascii() or any(
        character.isspace() or not character.isprintable() for character in key
    ):
        raise OnboardingProblem("invalid_key", "That key has an invalid format. Enter the Polaris-issued key privately again.")
    return key


def check_key(api_url: str, key: str) -> dict[str, Any]:
    from polaris.client import PolarisAPIError, PolarisClient

    url = endpoint(api_url)
    validate_key(key)
    try:
        client = PolarisClient(url, api_key=key, timeout=15)
        client.usage()
        model = client.models().model
    except PolarisAPIError as exc:
        if exc.status in (401, 403):
            raise OnboardingProblem("key_rejected", "The configured API did not accept this key. Enter a valid Polaris key privately.", exit_code=1) from None
        if exc.status == 429:
            raise OnboardingProblem("api_busy", "The configured API is rate-limited. Wait briefly and rerun setup; installed files are retained.", exit_code=1) from None
        raise OnboardingProblem("api_unavailable", "The configured Polaris API could not be validated. Check its availability and rerun; no hosted activation was saved.", exit_code=1) from None
    except (ValueError, OSError):
        raise OnboardingProblem("api_invalid", "The endpoint did not return a compatible Polaris response. No hosted activation was saved.", exit_code=1) from None
    if (not model.loaded or model.identity is None
            or not {"sql_injection", "command_injection"} <= set(model.supported_checks)):
        raise OnboardingProblem("model_unavailable", "The API accepted the key but its Polaris model is not ready for the required checks. Rerun when it is ready; no local fallback was selected.", exit_code=1)
    return {"status": "verified", "api_url": url, "auth_verified": True, "model_ready": True}


def activate(api_url: str, *, project: Path | None = None, method: str = "auto",
             timeout: float = 180, notify: Callable[[str], None] | None = None) -> dict[str, Any]:
    from polaris.remote import credentials_path, load_credentials, save_credentials

    url = endpoint(api_url)
    if project is not None and credentials_path().expanduser().absolute().is_relative_to(project):
        raise OnboardingProblem("unsafe_credentials", "Credentials must be stored outside the project. Remove the project-local POLARIS_HOME override before activation.")

    def accept(key: str) -> dict[str, Any]:
        result = check_key(url, key)
        save_credentials(url, key)
        return result

    # The explicit --api-url is consent to this endpoint. An unrelated credential is never sent.
    saved = load_credentials()
    if saved is not None:
        try:
            matches = endpoint(saved.api_url) == url
        except OnboardingProblem:
            matches = False
        if matches:
            try:
                return accept(saved.api_key)
            except OnboardingProblem as exc:
                if exc.code not in ("key_rejected", "invalid_key"):
                    raise
                # A revoked key must not trap the user in a reinstall/retry loop.
                # Keep the old private file until a replacement has actually validated.
    if method == "terminal" or method == "auto" and sys.stdin.isatty():
        if not sys.stdin.isatty():
            raise OnboardingProblem("private_input_required", "No private terminal input is available. Rerun with --auth browser; never put the key in agent chat.")
        try:
            key = getpass.getpass("Polaris API key (hidden): ").strip()
        except EOFError:
            raise OnboardingProblem("private_input_required", "Private key entry was cancelled; rerun setup when ready.") from None
        return accept(key)
    from polaris.onboarding.browser import browser_activation

    return browser_activation(url, accept, timeout=timeout, notify=notify)

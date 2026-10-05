"""`polaris login`, `polaris logout` and `polaris whoami`: use the hosted Polaris model.

The API key is checked with the server before it is saved, and it is never printed. Keys in
POLARIS_API_KEY take precedence over the saved one, which suits CI.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from typing import Any

SENT = ("Reviews now use the hosted model. Only functions with SQL or process calls are sent; everything "
        "else stays on this machine. Use --model-source local to keep a review entirely local.")


def add_account_parsers(commands: Any) -> None:

    login = commands.add_parser(
        "login", help="Sign in to the hosted Polaris model with an API key.",
        description="Checks the key with the Polaris API, then saves it to ~/.polaris/credentials.json "
                    "(readable only by you). In CI, set POLARIS_API_KEY instead.",
    )
    login.add_argument("--api-url", help="Configured Polaris API origin (or $POLARIS_API_URL). No undeployed endpoint is assumed.")
    login.add_argument("--key-stdin", action="store_true",
                       help="Read the API key from standard input instead of prompting (for scripts).")
    commands.add_parser("logout", help="Forget the saved API key.")
    commands.add_parser("whoami", help="Show which Polaris API and key reviews use.")


def _client(url: str, key: str) -> Any:
    from polaris.client import PolarisClient

    return PolarisClient(url, api_key=key, timeout=30)


def _login(args: argparse.Namespace) -> int:
    from polaris.client import PolarisAPIError
    from polaris.onboarding.auth import endpoint
    from polaris.onboarding.errors import OnboardingProblem
    from polaris.remote import load_credentials, save_credentials

    configured = args.api_url or os.environ.get("POLARIS_API_URL")
    if not configured:
        saved = load_credentials()
        configured = saved.api_url if saved is not None and saved.source == "file" else None
    if not configured:
        print("Polaris login: supply your configured --api-url. No public API deployment is assumed.", file=sys.stderr)
        return 2
    try:
        url = endpoint(configured)
    except OnboardingProblem as exc:
        print(f"Polaris login: {exc.message}", file=sys.stderr)
        return 2
    if args.key_stdin:
        key = sys.stdin.readline(2049).strip()
    elif sys.stdin.isatty():
        key = getpass.getpass("Polaris API key (typing is hidden): ").strip()
    else:
        print("Polaris login: no terminal to type the key in. Pipe it in with --key-stdin, or set "
              "POLARIS_API_KEY.", file=sys.stderr)
        return 2
    if not key:
        print("Polaris login: no API key given.", file=sys.stderr)
        return 2
    if len(key) > 2048 or any(character.isspace() for character in key) or not key.isascii() or not key.isprintable():
        print("Polaris login: that doesn't look like an API key (it has spaces or control characters).",
              file=sys.stderr)
        return 2
    try:
        client = _client(url, key)
        usage = client.usage()
        status = client.models().model
    except ValueError:
        print("Polaris login: the endpoint returned an invalid or incompatible response.", file=sys.stderr)
        return 2
    except PolarisAPIError as exc:
        if exc.status == 401:
            print(f"Polaris login: {url} didn't accept that API key. Check it and try again.", file=sys.stderr)
        else:
            print("Polaris login: the configured API is unavailable or rejected the request.", file=sys.stderr)
        return 1
    if not status.loaded or status.identity is None or not status.supported_checks:
        print("Polaris login: the key was accepted but no compatible model is ready. Nothing was saved.", file=sys.stderr)
        return 1
    try:
        path = save_credentials(url, key)
    except (OSError, OnboardingProblem):
        print("Polaris login: couldn't safely save the key; check the private credential directory.", file=sys.stderr)
        return 2
    print(f"Signed in to {url} (key {_safe_label(usage.key_id, key)}). Saved to {path}, readable only by you.")
    print(f"Model: {_safe_label(status.model_version, key)} (loaded).")
    print(SENT)
    if os.environ.get("POLARIS_API_KEY"):
        print("Note: POLARIS_API_KEY is set in this shell and takes precedence over the saved key.")
    return 0


def _logout() -> int:
    from polaris.remote import credentials_path, delete_credentials

    removed = delete_credentials()
    print(f"Signed out: removed {credentials_path()}." if removed else "No saved API key to remove.")
    if os.environ.get("POLARIS_API_KEY"):
        print("POLARIS_API_KEY is still set in this shell, so reviews keep using the hosted model until "
              "you unset it.")
    return 0


def _whoami() -> int:
    from polaris.client import PolarisAPIError
    from polaris.onboarding.auth import endpoint
    from polaris.onboarding.errors import OnboardingProblem
    from polaris.remote import credentials_path, load_credentials

    credentials = load_credentials()
    if credentials is None:
        print("Not signed in. Reviews use a model on this machine if one is installed. Sign in with "
              "`polaris login`, or set POLARIS_API_KEY.")
        return 1
    try:
        url = endpoint(credentials.api_url)
    except OnboardingProblem:
        print("The configured API address is unsafe; run `polaris login --api-url` with your endpoint.", file=sys.stderr)
        return 2
    where = "POLARIS_API_KEY" if credentials.source == "environment" else str(credentials_path())
    print(f"Polaris API: {url}")
    print(f"API key: from {where}")
    try:
        client = _client(credentials.api_url, credentials.api_key)
        usage = client.usage()
        status = client.models().model
    except ValueError:
        print("The endpoint returned an invalid or incompatible response.", file=sys.stderr)
        return 2
    except PolarisAPIError as exc:
        if exc.status == 401:
            print("The API didn't accept this key. Run `polaris login` again.", file=sys.stderr)
        else:
            print("Couldn't check the key: the configured API is unavailable.", file=sys.stderr)
        return 1
    if not status.loaded or status.identity is None:
        print("The key was accepted, but the hosted model is not ready.", file=sys.stderr)
        return 1
    counts = usage.usage
    print(f"Key id: {_safe_label(usage.key_id, credentials.api_key)}")
    print(f"Model: {_safe_label(status.model_version, credentials.api_key)} (loaded).")
    print(f"Since {usage.since}: {counts.requests} requests, {counts.assessments} functions assessed.")
    return 0


def _safe_label(value: Any, key: str) -> str:
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", value) and key not in value:
        return value
    return "verified"


def run(args: argparse.Namespace) -> int:
    if args.command == "login":
        return _login(args)
    if args.command == "logout":
        return _logout()
    return _whoami()

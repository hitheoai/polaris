"""Detect only explicit host signals; installed apps and project files are not evidence."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

from polaris.onboarding import HOSTS
from polaris.onboarding.errors import OnboardingProblem


def candidates(environment: Mapping[str, str]) -> list[str]:
    found: set[str] = set()
    program = environment.get("TERM_PROGRAM", "").lower()
    if program in ("warp", "warpterminal"):
        found.add("warp")
    if program == "cursor" or environment.get("CURSOR_SESSION_ID") or environment.get("CURSOR_TRACE_ID"):
        found.add("cursor")
    if environment.get("CLAUDECODE") == "1" or environment.get("CLAUDE_CODE_ENTRYPOINT"):
        found.add("claude-code")
    if environment.get("CODEX_THREAD_ID") or environment.get("CODEX_SESSION_ID"):
        found.add("codex")
    if program == "windsurf" or environment.get("WINDSURF_SESSION_ID"):
        found.add("windsurf")
    if program == "vscode" and not found & {"cursor", "windsurf"}:
        found.add("vscode")
    return [host for host in HOSTS if host in found]


def choose_host(requested: str) -> str:
    if requested != "auto":
        if requested not in HOSTS:
            raise OnboardingProblem("host_required", "Choose a supported host with --host.")
        return requested
    found = candidates(os.environ)
    if len(found) == 1:
        return found[0]
    if sys.stdin.isatty():
        print("Which coding host should Theo configure?", file=sys.stderr)
        for index, host in enumerate(HOSTS, 1):
            print(f"  {index}. {host}", file=sys.stderr)
        print("Choose one number: ", end="", file=sys.stderr, flush=True)
        selected = sys.stdin.readline(32).strip()
        if selected.isdigit() and 1 <= int(selected) <= len(HOSTS):
            return HOSTS[int(selected) - 1]
    raise OnboardingProblem(
        "host_required",
        "Theo could not identify one host. Rerun with --host "
        "warp|cursor|claude-code|codex|vscode|windsurf; no configuration was changed.",
    )

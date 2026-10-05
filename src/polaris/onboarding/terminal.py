"""Human output is deliberately separate from JSON and MCP stdout."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

WORDMARK = (
    "  ████████  ██   ██  ███████   ██████\n"
    "     ██     ██   ██  ██       ██    ██\n"
    "     ██     ███████  █████    ██    ██\n"
    "     ██     ██   ██  ██       ██    ██\n"
    "     ██     ██   ██  ███████   ██████"
)


class Terminal:
    def __init__(self, *, json_output: bool = False) -> None:
        self.json_output = json_output
        self.interactive = sys.stderr.isatty() and not json_output

    def banner(self) -> None:
        if not self.interactive:
            return
        color = "\033[38;5;81m" if not os.environ.get("NO_COLOR") else ""
        reset = "\033[0m" if color else ""
        print(f"\n{color}{WORDMARK}{reset}\n  Polaris, ready for your next change.\n", file=sys.stderr)

    def stage(self, number: int, label: str) -> None:
        if not self.json_output:
            print(f"  [{number}/3] {label}", file=sys.stderr, flush=True)

    def private_handoff(self, url: str) -> None:
        # This is an expiring loopback session, never an API key or remote authorization URL.
        print("Enter your Polaris key in the private browser window, not in agent chat.\n"
              f"If it did not open: {url}", file=sys.stderr, flush=True)

    def result(self, value: dict[str, Any], lines: list[str]) -> None:
        if self.json_output:
            print(json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True))
        else:
            for line in lines:
                print(line)

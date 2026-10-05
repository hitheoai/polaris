"""Fixtures for the simple view (`polaris check` in a terminal): a clean repository for the all
clear, a stand-in for `run_check` that the tests control, and Pilot helpers.

Repositories use fixed commit dates (see tests/tui_fixtures.py), so every check of them gives the
same result; nothing in them is executed.
"""

from __future__ import annotations

import asyncio
import functools
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from tui_fixtures import git, write

CLEAN_BASE = {
    "package.json": '{ "name": "clean-app", "private": true }\n',
    "lib/math.ts": "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
    "README.md": "# Clean app\n",
}
CLEAN_FEATURE = {
    "lib/math.ts": (
        "export function add(a: number, b: number): number {\n  return a + b;\n}\n\n"
        "export function double(value: number): number {\n  return value * 2;\n}\n"
    ),
    "lib/greeting.py": 'def greet(name: str) -> str:\n    return "Hello, " + name\n',
    "README.md": "# Clean app\n\nSmall helpers.\n",
}
PROGRESS = "Looking at your changes\u2026"


def clean_repository(base: Path) -> Path:
    """One commit on `main`, then uncommitted changes ("your changes") with nothing to report."""
    root = base.resolve() / "clean-app"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(root, CLEAN_BASE)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    write(root, CLEAN_FEATURE)
    return root


class FakeRunner:
    """Stands in for `run_check`: reports progress lines, optionally waits until `release()`,
    then returns `outcome` (a CheckRun) or raises it (an exception)."""

    def __init__(self, outcome: Any, *, lines: Sequence[str] = (PROGRESS,), hold: bool = False) -> None:
        self.outcome = outcome
        self.lines = tuple(lines)
        self.hold = hold
        self.calls = 0
        self.requests: list[Any] = []
        self.gate = threading.Event()

    def release(self) -> None:
        self.gate.set()

    def __call__(self, request: Any, *, progress: Callable[[str], None] | None = None) -> Any:
        self.calls += 1
        self.requests.append(request)
        for line in self.lines:
            if progress is not None:
                progress(line)
        if self.hold:
            self.gate.wait(30)
            self.gate.clear()
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def scenario(test: Any) -> Any:
    """Run an async Pilot scenario as a plain test (no async pytest plugin is needed)."""

    @functools.wraps(test)
    def run(*args: Any, **kwargs: Any) -> None:
        asyncio.run(test(*args, **kwargs))

    return run


async def settle(pilot: Any, app: Any, *, timeout: float = 30.0) -> None:
    """Wait until the app's check has finished and its screen is shown."""
    deadline = time.monotonic() + timeout
    await pilot.pause()
    while app.checking and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    await pilot.pause()
    await pilot.pause()
    assert not app.checking, "the check did not finish"


async def until(pilot: Any, condition: Callable[[], bool], *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
        await pilot.pause()
    assert condition(), "timed out"

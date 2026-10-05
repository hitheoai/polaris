"""Golden screenshots of the simple view (`polaris check` in a terminal): the checking, results,
problem and all-clear screens at 80x24 and 120x40, with and without colour.

As in tests/test_tui_golden.py, the Textual extra is pinned and the SVG export is compared
exactly. After an intended change, review the differences and refresh them:

    POLARIS_TUI_UPDATE_GOLDEN=1 uv run --no-sync pytest -q tests/test_tui_simple_golden.py

Deterministic: fixed commit dates, "checked just now" frozen, no animation, a fixed progress
line, and nothing from the machine (no $EDITOR, no terminal, no network).
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("textual")

from tui_fixtures import sample_repository  # noqa: E402
from tui_simple_fixtures import PROGRESS, FakeRunner, clean_repository, settle, until  # noqa: E402

from polaris.check.runner import CheckRequest, run_check  # noqa: E402
from polaris.tui.simple.app import SimpleApp  # noqa: E402
from polaris.tui.simple.screens import CheckingScreen  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "tui_golden"
UPDATE = os.environ.get("POLARIS_TUI_UPDATE_GOLDEN") == "1"
# screen -> (which check, keys pressed once it shows, whether the check is still running)
SCREENS: dict[str, tuple[str, tuple[str, ...], bool]] = {
    "checking": ("sample", (), True),
    "results": ("sample", (), False),
    "problem": ("sample", ("down", "down", "down", "enter"), False),  # Anyone can use DELETE /api/users...
    "clear": ("clean", (), False),
}


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    base = tmp_path_factory.mktemp("tui-simple-golden")
    sample = sample_repository(base)
    clean = clean_repository(base)
    return {
        "sample": run_check(CheckRequest(root=sample, mode="range", revision_range="main...feature", remember=False)),
        "clean": run_check(CheckRequest(root=clean, remember=False)),
        "request": CheckRequest(root=sample, remember=False),
    }


@pytest.fixture(autouse=True)
def plain_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("VISUAL", "EDITOR", "NO_COLOR", "TEXTUAL", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)


def normalize(svg: str) -> str:
    # Rich derives element ids from a hash of the content; one id per file is enough to compare.
    return re.sub(r"terminal-\d+", "terminal", svg)


def compare(name: str, svg: str, tmp_path: Path) -> None:
    path = GOLDEN / f"{name}.svg"
    actual = normalize(svg)
    if UPDATE:
        GOLDEN.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8")
        return
    assert path.exists(), f"{path.name} is missing: run with POLARIS_TUI_UPDATE_GOLDEN=1 to create it"
    if path.read_text(encoding="utf-8") != actual:
        (tmp_path / path.name).write_text(actual, encoding="utf-8")
        pytest.fail(f"{path.name} changed (new rendering: {tmp_path / path.name}). Review it, then refresh with "
                    "POLARIS_TUI_UPDATE_GOLDEN=1.")


def screenshot(runs: dict[str, Any], screen: str, size: tuple[int, int]) -> str:
    which, keys, running = SCREENS[screen]

    async def run() -> str:
        runner = FakeRunner(runs[which], hold=running)
        app = SimpleApp(runs["request"], animation=False, runner=runner, clock=lambda: 0.0)
        async with app.run_test(size=size) as pilot:
            if running:
                await until(pilot, lambda: isinstance(app.screen, CheckingScreen) and app.progress == PROGRESS)
            else:
                await settle(pilot, app)
            for key in keys:
                await pilot.press(key)
                await pilot.pause()
            await pilot.pause()
            svg = app.export_screenshot(simplify=True)
            runner.release()
            await settle(pilot, app)
            return svg

    return asyncio.run(run())


@pytest.mark.parametrize("size", [(80, 24), (120, 40)], ids=["80x24", "120x40"])
@pytest.mark.parametrize("no_color", [False, True], ids=["color", "nocolor"])
@pytest.mark.parametrize("screen", list(SCREENS))
def test_simple_screens(runs, screen, no_color, size, monkeypatch, tmp_path):
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    name = f"simple-{screen}-{size[0]}x{size[1]}" + ("-nocolor" if no_color else "")
    compare(name, screenshot(runs, screen, size), tmp_path)

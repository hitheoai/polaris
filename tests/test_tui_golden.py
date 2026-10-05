"""Golden screenshots of `polaris tui`: Textual's SVG export of the main screens, normalized.

Textual minor releases have changed rendering (8.2's ANSI themes), so the extra is pinned and these
screens are compared exactly. After an intended change, review the differences and refresh them:

    POLARIS_TUI_UPDATE_GOLDEN=1 uv run --no-sync pytest -q tests/test_tui_golden.py

The sample review is deterministic (fixed commit dates, a fixed elapsed time), and nothing here
depends on the machine: no $EDITOR, no terminal, no network.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("textual")

from tui_fixtures import fixed, live_data, sample_repository, sarif_file, saved_copy  # noqa: E402

from polaris.tui.app import Options, PolarisApp  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "tui_golden"
UPDATE = os.environ.get("POLARIS_TUI_UPDATE_GOLDEN") == "1"


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    base = tmp_path_factory.mktemp("tui-golden")
    root = sample_repository(base)
    sarif = str(sarif_file(base))
    data = live_data(root, "--diff", "main...feature", "--import-sarif", sarif)
    return {"report": saved_copy(fixed(data), name="sample.json"),
            "pr": fixed(live_data(root, "--base", "main", "--import-sarif", sarif))}


@pytest.fixture(scope="module")
def report(sample: dict[str, Any]) -> Any:
    return sample["report"]


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


def screenshot(data: Any, size: tuple[int, int], keys: tuple[str, ...] = ()) -> str:
    async def idle(app: PolarisApp) -> None:
        deadline = time.monotonic() + 30
        while (app.plan_computing or app.pending) and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

    async def run() -> str:
        app = PolarisApp(data=data, options=Options())
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await idle(app)  # a live pull-request review computes its plan in a worker
            for key in keys:
                await pilot.press(key)
                await pilot.pause()
                await idle(app)
            await pilot.pause()
            return app.export_screenshot(simplify=True)

    return asyncio.run(run())


@pytest.fixture(autouse=True)
def plain_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("VISUAL", "EDITOR", "NO_COLOR", "TEXTUAL", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("size", [(80, 24), (120, 40)], ids=["80x24", "120x40"])
@pytest.mark.parametrize("no_color", [False, True], ids=["color", "nocolor"])
def test_cockpit(report, size, no_color, monkeypatch, tmp_path):
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    name = f"cockpit-{size[0]}x{size[1]}" + ("-nocolor" if no_color else "")
    compare(name, screenshot(report, size, ("down",)), tmp_path)


def test_taint_walk(report, tmp_path):
    compare("walk-80x24", screenshot(report, (80, 24), ("down", "t", "G")), tmp_path)


def test_coverage(report, tmp_path):
    compare("coverage-120x40", screenshot(report, (120, 40), ("2", "down", "down", "down", "down", "right", "right")),
            tmp_path)


def test_coverage_80x24(report, tmp_path):
    compare("coverage-80x24", screenshot(report, (80, 24), ("2", "down")), tmp_path)


def test_attack_surface(report, tmp_path):
    compare("surface-80x24", screenshot(report, (80, 24), ("3", "down")), tmp_path)


def test_pr_preview(sample, tmp_path):
    compare("pr-120x40", screenshot(sample["pr"], (120, 40), ("5", "i", "down")), tmp_path)

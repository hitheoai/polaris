"""`polaris setup warp --theme`: Warp themes that match the Polaris website.

Temporary HOME and XDG folders only; Warp's own settings are never touched.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from polaris.check import brand
from polaris.cli import main
from polaris.integrations import setup
from polaris.integrations.themes import (
    ANSI,
    THEME_MARKER,
    theme_yaml,
    warp_themes,
    warp_themes_folder,
)

# The exact colours the Polaris website gives each theme (see polaris.integrations.themes).
NORTH = {
    "name": "Polaris North", "details": "darker", "cursor": "#d7b75d", "foreground": "#e7eee0",
    "accent": {"left": "#d3e5b6", "right": "#d7b75d"}, "background": {"top": "#1c382e", "bottom": "#142f27"},
    "terminal_colors": {
        "normal": {"black": "#234236", "red": "#eeac92", "green": "#b5dcca", "yellow": "#d7b75d",
                   "blue": "#9fb9b2", "magenta": "#c0ae97", "cyan": "#c4d3ae", "white": "#d2decd"},
        "bright": {"black": "#a3b9a2", "red": "#f2cab9", "green": "#d3e5b6", "yellow": "#e9d6ad",
                   "blue": "#bccec8", "magenta": "#e1d7b8", "cyan": "#d1d9bd", "white": "#f7f8f3"},
    },
}
PAPER = {
    "name": "Polaris Paper", "details": "lighter", "cursor": "#2c614b", "foreground": "#20382e",
    "accent": {"left": "#2c614b", "right": "#8a643b"}, "background": "#f7f8f3",
    "terminal_colors": {
        "normal": {"black": "#20382e", "red": "#9c432e", "green": "#326953", "yellow": "#77603e",
                   "blue": "#346b63", "magenta": "#8a643b", "cyan": "#2c614b", "white": "#e1e8dd"},
        "bright": {"black": "#536457", "red": "#7d402e", "green": "#2d5a48", "yellow": "#61563a",
                   "blue": "#2e5c53", "magenta": "#6a5737", "cyan": "#285542", "white": "#ffffff"},
    },
}
EXPECTED = {"polaris_north.yaml": NORTH, "polaris_paper.yaml": PAPER}
PICK = "Pick Polaris North (dark) or Polaris Paper (light) in Warp: Settings > Appearance > Themes."


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    folder = (tmp_path / "home").resolve()
    folder.mkdir()
    for name in ("APPDATA", "POLARIS_MODEL", "CLAUDE_PROJECT_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)
    for key, value in {"HOME": str(folder), "POLARIS_HOME": str(folder / ".polaris"),
                       "XDG_DATA_HOME": str(folder / ".data"), "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": str(folder / ".gitconfig")}.items():
        monkeypatch.setenv(key, value)
    return folder


@pytest.fixture
def project(tmp_path: Path, home: Path) -> Path:
    root = (tmp_path / "project").resolve()
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q", "-b", "main"], check=True, capture_output=True,
                   env={**os.environ})
    return root


def parse(text: str) -> dict[str, Any]:
    """A tiny parser for the theme files' YAML subset: nested `key:` maps by two-space indent,
    and `key: value` leaves with a quoted '#rrggbb' or a plain word."""
    result: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, result)]
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        assert indent % 2 == 0, line
        key, _, value = line.strip().partition(":")
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        assert key not in parent, f"duplicate key {key}"
        if value.strip():
            raw = value.strip()
            parent[key] = raw[1:-1] if raw.startswith("'") and raw.endswith("'") else raw
        else:
            parent[key] = {}
            stack.append((indent, parent[key]))
    return result


def install(*argv: str, project: Path | None = None) -> int:
    return main(["setup", "warp", *argv, *(["--project", str(project)] if project else []), "--engine", "rules"])


def test_setup_writes_both_themes_with_the_website_colours(project: Path, home: Path,
                                                           capsys: pytest.CaptureFixture[str]) -> None:
    folder = warp_themes_folder(home)
    assert install("--theme", project=project) == 0
    out = capsys.readouterr().out
    assert f"Next: {PICK}" in out and "IBM Plex Mono in Settings > Appearance > Text (free download)" in out
    assert "add the Polaris North Warp theme (dark)" in out and "add the Polaris Paper Warp theme (light)" in out
    assert sorted(path.name for path in folder.iterdir()) == ["polaris_north.yaml", "polaris_paper.yaml"]
    for name, expected in EXPECTED.items():
        text = (folder / name).read_text()
        assert text.splitlines()[0] == THEME_MARKER
        assert parse(text) == expected
        # Every colour is a quoted lowercase #rrggbb, and the files read as plain YAML.
        assert yaml.safe_load(text) == expected
        for line in text.splitlines():
            if "#" in line and not line.startswith("#"):
                assert line.rstrip().endswith("'") and len(line.split("'")[1]) == 7, line
    # Only the two theme files: Warp's own settings are never touched.
    written = sorted(path.relative_to(home).as_posix() for path in home.rglob("*")
                     if path.is_file() and ".polaris" not in path.relative_to(home).parts)
    assert written == [(folder / name).relative_to(home).as_posix() for name in sorted(EXPECTED)]


def test_themes_are_idempotent_never_clobbered_and_forced_on_request(project: Path, home: Path,
                                                                     capsys: pytest.CaptureFixture[str]) -> None:
    folder = warp_themes_folder(home)
    assert install("--theme", "--dry-run", project=project) == 0
    assert "polaris_north.yaml: add the Polaris North Warp theme" in capsys.readouterr().out
    assert not folder.exists()
    assert install("--theme", project=project) == 0
    first = {path.name: path.read_bytes() for path in folder.iterdir()}
    capsys.readouterr()
    assert install("--theme", project=project) == 0
    assert "Already set up; nothing to change." in capsys.readouterr().out
    assert {path.name: path.read_bytes() for path in folder.iterdir()} == first
    north, paper = folder / "polaris_north.yaml", folder / "polaris_paper.yaml"
    north.write_text("name: My North\n")  # someone else's theme with the same file name
    paper.write_text(THEME_MARKER + "\nname: Polaris Paper\n")  # an older Polaris version
    assert install("--theme", project=project) == 0
    out = capsys.readouterr().out
    assert north.read_text() == "name: My North\n" and "Kept your existing" in out and "--force" in out
    assert paper.read_bytes() == first["polaris_paper.yaml"] and "update the Polaris Paper Warp theme" in out
    assert install("--theme", "--force", project=project) == 0
    assert north.read_bytes() == first["polaris_north.yaml"]
    backups = [path.read_text() for path in (home / ".polaris" / "backups").rglob("*polaris_north.yaml")]
    assert backups == ["name: My North\n"]
    assert install("--theme", "--global") == 0  # the themes are per user, so global setup can add them too


def test_theme_is_opt_in_and_warp_only(project: Path, home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert install(project=project) == 0
    out = capsys.readouterr().out
    assert not warp_themes_folder(home).exists()
    assert [line for line in out.splitlines() if "--theme" in line] == [
        "Next: Optional: run again with --theme to add the Polaris North (dark) and Polaris Paper (light) Warp "
        "themes, which match the Polaris website."]
    for target in ("cursor", "claude-code", "codex", "vscode", "windsurf", "git-hook"):
        assert main(["setup", target, "--theme", "--project", str(project)]) == 2
        error = capsys.readouterr().err
        assert "only works with `polaris setup warp --theme`" in error, target
    assert not warp_themes_folder(home).exists() and not (project / ".cursor").exists()


@pytest.mark.parametrize("theme", warp_themes(), ids=lambda theme: theme.name)
def test_theme_colours_are_readable(theme: Any) -> None:
    background = theme.background if isinstance(theme.background, str) else theme.background[1]
    assert brand.contrast(theme.foreground, background) >= 7
    if not isinstance(theme.background, str):
        assert brand.contrast(theme.foreground, theme.background[0]) >= 7  # the top of the gradient too
    for group in (theme.normal, theme.bright):
        for name, colour in zip(ANSI, group, strict=True):
            if name not in ("black", "white"):
                assert brand.contrast(colour, background) >= 4.5, (theme.name, name, colour)


def test_themes_follow_the_site_and_warps_folders(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from polaris.check import brand_site as site

    north, paper = warp_themes()
    known = {*site.DARK.values(), *site.LIGHT.values(), *site.CODE.values(), site.STAR_GOLD}
    assert north.background == (site.DARK["navy-1"], site.DARK["carbon"]) and north.cursor == site.STAR_GOLD
    assert paper.background == site.LIGHT["paper"] and {north.foreground, paper.foreground} <= known
    assert theme_yaml(north) == theme_yaml(warp_themes()[0])  # deterministic
    home = tmp_path / "home"
    assert warp_themes_folder(home, platform="darwin") == home / ".warp" / "themes"
    assert warp_themes_folder(home, platform="linux", environ={}) == home / ".local/share/warp-terminal/themes"
    assert warp_themes_folder(home, platform="linux", environ={"XDG_DATA_HOME": "/data"}) == Path(
        "/data/warp-terminal/themes")
    assert warp_themes_folder(home, platform="linux", environ={"XDG_DATA_HOME": "relative"}) == (
        home / ".local/share/warp-terminal/themes")
    assert warp_themes_folder(home, platform="win32", environ={"APPDATA": "/roaming"}) == Path(
        "/roaming/warp/Warp/data/themes")
    assert warp_themes_folder(home, platform="win32", environ={}) == home / "AppData/Roaming/warp/Warp/data/themes"
    with pytest.raises(ValueError):
        theme_yaml(north.__class__(**{**north.__dict__, "cursor": "#ABCDEF"}))
    assert setup.THEME_ONLY_WARP.startswith("--theme adds the Polaris themes to Warp")

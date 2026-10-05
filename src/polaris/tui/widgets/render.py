"""Turn view-model lines into Rich renderables: `Text` objects, never markup strings.

The view model has already cleaned every span; `Text(...)`/`Text.append` never interpret markup,
emoji codes or links, so text like "[red]" or ":smile:" from a repository stays literal. The
brand mark's two roles are drawn by `polaris.tui.brand`, as in the simple view: a gold star
(the terminal's yellow in ANSI themes) and the wordmark's gradient (bold in ANSI and NO_COLOR).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from rich.console import Group, RenderableType
from rich.text import Text

from polaris.tui import brand, theme
from polaris.tui.view import Line


def to_text(value: Line, palette: theme.PaletteName, *, no_wrap: bool = False, end: str = "") -> Text:
    text = Text(no_wrap=no_wrap, overflow="ellipsis" if no_wrap else "fold", end=end)
    for content, role in value:
        if role == "brand.name":
            brand.append_name(text, content, palette)
        elif role == "brand.star":
            text.append(content, style=brand.style("star", palette) or None)
        else:
            text.append(content, style=theme.style(role, palette) or None)
    return text


def is_code(value: Line) -> bool:
    return any(role.startswith("code") for _, role in value)


def to_block(lines: Iterable[Line], palette: theme.PaletteName) -> RenderableType:
    """Many lines: prose wraps, code lines keep their columns (cropped, never wrapped)."""
    return Group(*(to_text(value, palette, no_wrap=is_code(value), end="\n") for value in lines))


def to_cells(cells: Sequence[Line], palette: theme.PaletteName) -> list[Text]:
    return [to_text(cell, palette, no_wrap=True) for cell in cells]

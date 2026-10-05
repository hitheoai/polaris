"""Polaris in Rich and Textual: the website's lockup, its colours and the star's light, for both
terminal views.

Everything comes from `polaris.check.brand`, which follows the website (`brand_site` is
generated from the site's own files): the six-ray star and the POLARIS wordmark drawn with
quadrant blocks, the colour tokens, the wordmark gradients and the star's glows. This module
turns them into Rich `Text` styled cell by cell (never markup strings) and into Textual themes.

* The lockup is the site's header: the star on the left, about 1.4 times as tall as the
  wordmark beside it. Large (59 x 10) and small (40 x 7) versions; the compact "✶ POLARIS" when
  neither fits.
* The wordmark is coloured column by column through the site's gradient. The star is gold,
  warming toward the middle where its rays meet. While a check runs, a sweep of light runs out
  along the rays, briefly reaching the flash colour; otherwise the star is steady.
* The ANSI themes use the terminal's own yellow for the star and bold for the name; NO_COLOR
  keeps the shapes, in bold. Warp renders neither italic nor dim, so nothing here uses them.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from rich.console import JustifyMethod
from rich.text import Text
from textual.theme import Theme

from polaris.check import brand_site as site
from polaris.check.brand import NAME, PALETTES, STAR, STAR_GLOWS, WORDMARK_GRADIENTS
from polaris.tui.theme import PaletteName

Span = tuple[str, str]
Line = tuple[Span, ...]
Size = Literal["large", "small"]

# The twinkle: a sweep of light from the star's middle out to its tips, then a rest.
SWEEP_FRAMES = 12
TWINKLE_FRAMES = 18
SWEEP_WIDTH = 0.22  # how far (as a share of the star's radius) the light spreads around its front


# ---- colours ------------------------------------------------------------------------------------


def _rgb(value: str) -> tuple[int, int, int]:
    digits = value.lstrip("#")
    return int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16)


def _hex(rgb: Sequence[float]) -> str:
    return "#{:02X}{:02X}{:02X}".format(*(max(0, min(255, round(channel))) for channel in rgb))


def mix(start: str, end: str, amount: float) -> str:
    """`start` moved `amount` (0 to 1) of the way to `end`."""
    amount = max(0.0, min(1.0, amount))
    return _hex([a + (b - a) * amount for a, b in zip(_rgb(start), _rgb(end), strict=True)])


def gradient(stops: Sequence[str], count: int) -> list[str]:
    """`count` evenly spaced colours from the first stop to the last, through the ones between."""
    if count <= 0 or not stops:
        return []
    if count == 1 or len(stops) == 1:
        return [_hex(_rgb(stops[0]))] * count
    colours = []
    for index in range(count):
        position = index / (count - 1) * (len(stops) - 1)
        left = min(int(position), len(stops) - 2)
        colours.append(mix(stops[left], stops[left + 1], position - left))
    return colours


# ---- role styles --------------------------------------------------------------------------------


def _site_styles(palette: str) -> dict[str, str]:
    """The simple view's roles in the site's colours (each text colour reads at 4.5:1 or more)."""
    colours = PALETTES[palette]
    on = f" on {colours['selected']}"
    return {
        "text": colours["text"],
        "label": f"bold {colours['heading']}",
        "heading": f"bold {colours['heading']}",
        "brand": f"bold {colours['heading']}",
        "star": f"bold {colours['star']}",
        "fix_now": f"bold {colours['fix_now']}",
        "check_this": f"bold {colours['check_this']}",
        "worth_a_look": f"bold {colours['worth_a_look']}",
        "clear": f"bold {colours['clear']}",
        "muted": colours["muted"],
        "key": f"bold {colours['accent']}",
        "rule": colours["line"],
        "row": colours["text"],
        "row.marker": colours["accent"],
        "row.file": colours["muted"],
        "row.selected": f"bold {colours['selected.text']}{on}",
        "row.marker.selected": f"bold {colours['accent']}{on}",
        "row.file.selected": f"{colours['selected.muted']}{on}",
        "code": colours["code"],
        "code.number": colours["code.number"],
        "before": f"bold {colours['fix_now']}",
        "after": f"bold {colours['clear']}",
        "warning": colours["check_this"],
    }


_DARK = _site_styles("dark")
# The terminal's own 16 colours (its palette, and any contrast or colour-vision settings, decide).
_ANSI: dict[str, str] = {
    **{role: "" for role in _DARK},
    "label": "bold", "heading": "bold", "brand": "bold", "star": "bold yellow", "fix_now": "bold red",
    "check_this": "bold yellow", "worth_a_look": "bold cyan", "clear": "bold green", "key": "bold green",
    "rule": "green", "row.selected": "bold reverse", "row.marker.selected": "bold reverse",
    "row.file.selected": "reverse", "before": "bold red", "after": "bold green", "warning": "yellow",
}
# NO_COLOR: attributes only. Marks and words carry every meaning; bold marks what needs attention.
_NONE: dict[str, str] = {
    **{role: "" for role in _DARK},
    "label": "bold", "heading": "bold", "brand": "bold", "star": "bold", "fix_now": "bold",
    "check_this": "bold", "worth_a_look": "bold", "clear": "bold", "key": "bold",
    "row.selected": "bold reverse", "row.marker.selected": "bold reverse", "row.file.selected": "reverse",
    "before": "bold", "after": "bold",
}
STYLES: dict[str, dict[str, str]] = {"dark": _DARK, "light": _site_styles("light"), "ansi": _ANSI, "none": _NONE}


def style(role: str, palette: PaletteName = "dark") -> str:
    return STYLES[palette].get(role, "")


# ---- Textual themes (both views) ---------------------------------------------------------------


def _theme(name: str, palette: str) -> Theme:
    """A Textual theme in the site's colours. Derived colours Textual would otherwise compute
    (the chosen row, muted text, borders, scrollbars, bars) are pinned to the site's too."""
    colours = PALETTES[palette]
    return Theme(
        name=name, primary=colours["accent"], secondary=colours["clear"], accent=colours["accent"],
        warning=colours["check_this"], error=colours["fix_now"], success=colours["clear"],
        foreground=colours["text"], background=colours["background"], surface=colours["surface"],
        panel=colours["panel"], dark=palette == "dark",
        variables={
            "boost": colours["surface"],
            "text-muted": colours["muted"], "foreground-muted": colours["muted"],
            "block-cursor-background": colours["selected"], "block-cursor-foreground": colours["selected.text"],
            "block-cursor-text-style": "bold", "block-cursor-blurred-background": colours["panel"],
            "block-cursor-blurred-foreground": colours["text"], "block-hover-background": colours["surface"],
            "border": colours["accent"], "border-blurred": colours["line"],
            "scrollbar": colours["line"], "scrollbar-hover": colours["muted"], "scrollbar-active": colours["accent"],
            "scrollbar-background": colours["background"], "scrollbar-background-hover": colours["background"],
            "scrollbar-background-active": colours["background"], "scrollbar-corner-color": colours["background"],
            "input-selection-background": colours["selected"],
            "screen-selection-background": colours["selected"], "screen-selection-foreground": colours["selected.text"],
            "footer-key-foreground": colours["accent"],
        },
    )


POLARIS_DARK = _theme("polaris-dark", "dark")
POLARIS_LIGHT = _theme("polaris-light", "light")
CUSTOM_THEMES: tuple[Theme, ...] = (POLARIS_DARK, POLARIS_LIGHT)


# ---- text ---------------------------------------------------------------------------------------


def append_name(text: Text, value: str, palette: PaletteName) -> None:
    """Append letters in the wordmark's gradient (bold only in the ANSI and NO_COLOR palettes)."""
    if palette in ("dark", "light"):
        for character, colour in zip(value, gradient(WORDMARK_GRADIENTS[palette], len(value)), strict=True):
            text.append(character, style=f"bold {colour}")
    else:
        text.append(value, style="bold")


def to_text(value: Line, palette: PaletteName, *, no_wrap: bool = False, end: str = "",
            justify: JustifyMethod | None = None) -> Text:
    """Spans to Rich `Text`. `Text.append` never parses markup, emoji codes or links."""
    text = Text(no_wrap=no_wrap, overflow="ellipsis" if no_wrap else "fold", end=end, justify=justify)
    for content, role in value:
        if role == "brand.name":
            append_name(text, content, palette)
        else:
            text.append(content, style=style(role, palette) or None)
    return text


# ---- the star's light ---------------------------------------------------------------------------


def twinkle(distance: float, frame: int | None) -> float:
    """How much flash a point of the star gets (0 to 1) at `distance` from its middle (0) to its
    tips (1): a band of light that sweeps outward, then rests. None is the steady star."""
    if frame is None:
        return 0.0
    step = frame % TWINKLE_FRAMES
    if step >= SWEEP_FRAMES:
        return 0.0
    front = -SWEEP_WIDTH + step / (SWEEP_FRAMES - 1) * (1 + 2 * SWEEP_WIDTH)
    return math.exp(-(((distance - front) / SWEEP_WIDTH) ** 2))


def star_style(palette: PaletteName, distance: float, frame: int | None) -> str:
    """One cell of the star: its gold, warming toward the middle, plus the twinkle's light."""
    if palette == "none":
        return "bold"
    light = twinkle(distance, frame)
    if palette == "ansi":
        return "bold bright_yellow" if light > 0.5 else "bold yellow"
    gold, glow, flash = STAR_GLOWS[palette]
    base = mix(glow, gold, distance ** 0.8)  # a soft radial glow
    return f"bold {mix(base, flash, light)}"


def compact(palette: PaletteName, frame: int | None = None) -> Text:
    """The compact mark, "✶ POLARIS": the gold star, pulsing with the twinkle while a check
    runs, and the letters in the wordmark's gradient."""
    text = Text(no_wrap=True, end="")
    if frame is None or palette == "none":
        star = style("star", palette)
    elif palette == "ansi":
        star = star_style(palette, 0.5, frame)
    else:
        gold, _glow, flash = STAR_GLOWS[palette]
        star = f"bold {mix(gold, flash, twinkle(0.5, frame))}"
    text.append(STAR, style=star or None)
    text.append(" ")
    append_name(text, NAME, palette)
    return text


# ---- the lockup ---------------------------------------------------------------------------------

_DECLARED = {name: (columns, rows) for name, _logo, columns, rows, _threshold in site.DRAWINGS}


def _star_distances(name: str, art: Sequence[str]) -> dict[tuple[int, int], float]:
    """Each drawn cell's distance from where the star's rays meet (the middle of the logo), from
    0 there to 1 at the farthest tip, measured in the logo's own units (cells aren't square)."""
    columns, rows = _DECLARED[name]
    width, height = site.STAR_VIEWBOX
    numbers = [float(value) for value in re.findall(r"-?\d*\.?\d+", site.STAR_PATH)]
    top = int(min(numbers[1::2]) // (height / rows))  # blank rows the drawing trimmed above the star
    cells: dict[tuple[int, int], float] = {}
    for row, line in enumerate(art):
        for column, character in enumerate(line):
            if character != " ":
                x = (column + 0.5) * width / columns
                y = (row + top + 0.5) * height / rows
                cells[(row, column)] = math.hypot(x - width / 2, y - height / 2)
    far = max(cells.values())
    return {cell: distance / far for cell, distance in cells.items()}


@dataclass(frozen=True)
class Lockup:
    """The site's header lockup at one size: the star, a gap, then the wordmark beside the
    middle of the star."""

    name: str
    star: tuple[str, ...]
    wordmark: tuple[str, ...]
    star_width: int
    wordmark_width: int
    gap: int
    distances: dict[tuple[int, int], float] = field(compare=False, repr=False)

    @property
    def width(self) -> int:
        return self.star_width + self.gap + self.wordmark_width

    @property
    def height(self) -> int:
        return max(len(self.star), len(self.wordmark))

    @property
    def offset(self) -> int:
        """Blank rows above the wordmark, so it sits beside the star's middle."""
        return (len(self.star) - len(self.wordmark) + 1) // 2

    def plain(self) -> list[str]:
        """The lockup's rows as plain text, each exactly `width` columns."""
        return [line.plain for line in self.render("none")]

    def render(self, palette: PaletteName, frame: int | None = None) -> list[Text]:
        """The rows, styled cell by cell: the star's glow (and twinkle at `frame`), then the
        wordmark's gradient column by column. Each row is exactly `width` columns."""
        if palette in ("dark", "light"):
            columns = [f"bold {colour}" for colour in gradient(WORDMARK_GRADIENTS[palette], self.wordmark_width)]
        else:
            columns = ["bold"] * self.wordmark_width
        rows = []
        for index in range(self.height):
            text = Text(no_wrap=True, end="\n")
            star = self.star[index] if index < len(self.star) else ""
            for column, character in enumerate(star.ljust(self.star_width)):
                distance = self.distances.get((index, column))
                text.append(character, style=star_style(palette, distance, frame) if distance is not None else None)
            text.append(" " * self.gap)
            word_row = index - self.offset
            word = self.wordmark[word_row] if 0 <= word_row < len(self.wordmark) else ""
            for column, character in enumerate(word.ljust(self.wordmark_width)):
                text.append(character, style=columns[column] if character != " " else None)
            rows.append(text)
        return rows


def _lockup(size: Size, gap: int) -> Lockup:
    star_name, word_name = f"STAR_{size.upper()}", f"WORDMARK_{size.upper()}"
    star: tuple[str, ...] = getattr(site, star_name)
    wordmark: tuple[str, ...] = getattr(site, word_name)
    return Lockup(size, star, wordmark, _DECLARED[star_name][0], _DECLARED[word_name][0], gap,
                  _star_distances(star_name, star))


LOCKUPS: dict[Size, Lockup] = {"large": _lockup("large", 3), "small": _lockup("small", 2)}
# The lockup plus the lines under it (a blank line, the tagline, a blank line, three lines of
# progress) and the key bar, with a little room to spare.
TEXT_BELOW = 7


def lockup_size(width: int, height: int, *, below: int = TEXT_BELOW) -> Size | None:
    """The largest lockup that fits a `width` x `height` screen with `below` lines under it."""
    for size in ("large", "small"):
        mark = LOCKUPS[size]
        if width >= mark.width + 4 and height >= mark.height + below + 2:
            return size
    return None

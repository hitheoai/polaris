"""Polaris in the terminal: shared names, words and colours, with no Rich or Textual needed.

Everything here follows the website. `brand_site` is generated from the site's own brand files
(`scripts/brand_from_site.py`): the star and POLARIS wordmark, drawn with block characters, and
the site's colour tokens. The dark palette is the site's forest-green code windows, the light
one its porcelain pages, and the star keeps the logo's gold.

Terminals choose their own font (in Warp: Settings > Appearance > Text), so the brand is drawn
with characters and colour, never a font. Warp renders neither italic nor dim text, so emphasis
uses bold and colour only. Every colour used for text has at least 4.5:1 contrast with its
background (tests check this). Plain text output uses `COMPACT`.
"""

from __future__ import annotations

from polaris.check import brand_site as site

STAR = "\u2736"  # ✶ six-pointed: the one-cell stand-in for the logo's six-ray star
NAME = "POLARIS"
COMPACT = f"{STAR} {NAME}"
TAGLINE = "a security check for your code"
PRIVACY = "Nothing leaves your computer."

_D, _L, _C = site.DARK, site.LIGHT, site.CODE
# Roles -> the website's colours. "dark" is the site's code windows (.dark-surface), "light"
# its porcelain pages. `selected` is the background of the chosen row.
PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "background": _D["carbon"], "surface": _D["navy-1"], "panel": _D["navy-2"], "selected": _D["navy-3"],
        "line": _D["line"], "heading": _D["ink"], "text": _D["smoke"], "muted": _D["space"],
        "selected.text": _D["ink"], "selected.muted": _D["steel"], "accent": _D["violet"],
        "star": site.STAR_GOLD, "fix_now": _D["flag"], "check_this": _D["context"],
        "worth_a_look": _D["violet"], "clear": _D["ok"], "code": _C["foreground"], "code.number": _C["comment"],
    },
    "light": {
        "background": _L["paper"], "surface": _L["navy-1"], "panel": _L["navy-2"], "selected": _L["navy-3"],
        "line": _L["line"], "heading": _L["ink"], "text": _L["cloud"], "muted": _L["space"],
        "selected.text": _L["ink"], "selected.muted": _L["space"], "accent": _L["violet"],
        # The logo's gold has too little contrast on porcelain: the site's brass instead.
        "star": _L["pink"], "fix_now": _L["flag"], "check_this": _L["context"],
        "worth_a_look": _L["blue"], "clear": _L["ok"], "code": _L["ink"], "code.number": _L["space"],
    },
}
# The wordmark, coloured column by column: mint, sage, porcelain and the warm cream of the site's
# code (dark); forest green, teal and brass (light).
WORDMARK_GRADIENTS: dict[str, tuple[str, ...]] = {
    "dark": (_D["ok"], _D["violet"], _D["ink"], _C["function"]),
    "light": (_L["violet"], _L["blue"], _L["pink"]),
}
# The star's light: its gold, a warmer glow toward the middle, and the flash of a twinkle.
STAR_GLOWS: dict[str, tuple[str, str, str]] = {
    "dark": (site.STAR_GOLD, _C["function"], _C["parameter"]),
    "light": (_L["pink"], _L["context"], _L["ink"]),
}

# Earlier names, kept for callers that read the dark palette directly.
GRADIENT: tuple[str, ...] = WORDMARK_GRADIENTS["dark"]
COLORS: dict[str, str] = {
    "brand": PALETTES["dark"]["accent"], "star": site.STAR_GOLD, "fix_now": PALETTES["dark"]["fix_now"],
    "check_this": PALETTES["dark"]["check_this"], "worth_a_look": PALETTES["dark"]["worth_a_look"],
    "clear": PALETTES["dark"]["clear"], "muted": PALETTES["dark"]["muted"],
}

STATUS_WORDS: dict[str, str] = {
    "clear": "Safe to ship",
    "fix_needed": "Not yet",
    "incomplete": "Not fully checked",
}
# Text-presentation symbols (never emoji), so every terminal draws them in the text colour.
STATUS_MARKS: dict[str, str] = {"clear": "\u2714", "fix_needed": "\u2716", "incomplete": "\u25d0"}
PRIORITY_WORDS: dict[str, str] = {
    "fix_now": "Fix now",
    "check_this": "Check this",
    "worth_a_look": "Worth a look",
}
# Every priority has a mark and a word, never colour alone.
PRIORITY_MARKS: dict[str, str] = {"fix_now": "\u25cf", "check_this": "?", "worth_a_look": "\u25cb"}


def contrast(foreground: str, background: str) -> float:
    """The WCAG contrast ratio of two `#rrggbb` colours (1 to 21)."""

    def luminance(value: str) -> float:
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    high, low = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (high + 0.05) / (low + 0.05)

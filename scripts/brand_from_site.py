"""Copy the Polaris website's brand into the terminal: writes `src/polaris/check/brand_site.py`.

It reads, from a checkout of the website's source:

* the logo: `public/brand/polaris-symbol-brass.svg` (the six-ray star and its gold) and
  `public/brand/polaris-wordmark-ink.svg` (the drawn POLARIS lettering);
* the colour tokens: `src/app/globals.css` (`@theme`, the porcelain pages) and the
  `.dark-surface` rules in `src/styles/experience.css` (the forest-green code windows);
* the code colours of the site's `polaris-north` highlighting theme: `src/lib/highlight.ts`.

It then draws the star and the wordmark with quadrant blocks (each terminal cell is split into
2 x 2 squares, which are about square in common monospace fonts) and writes one generated
module, so the terminal logo and colours always come from the same files as the site's. Re-run
it after the site's brand changes; `--check` exits 1 when the module is out of date. The
generated module is committed, so building or testing Polaris never needs the website.

    uv run python scripts/brand_from_site.py --site <website checkout>
    uv run python scripts/brand_from_site.py --site <website checkout> --check
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src" / "polaris" / "check" / "brand_site.py"
SYMBOL = "public/brand/polaris-symbol-brass.svg"
WORDMARK = "public/brand/polaris-wordmark-ink.svg"
GLOBALS = "src/app/globals.css"
SURFACES = "src/styles/experience.css"
HIGHLIGHT = "src/lib/highlight.ts"

# (name, logo, columns, rows, threshold): the drawings the terminal uses. As in the site's header
# lockup, the star stands about 1.4 times as tall as the wordmark beside it. A lower threshold
# thickens thin strokes, so the star's narrow rays survive at small sizes. Blank rows are trimmed.
DRAWINGS: tuple[tuple[str, str, int, int, float], ...] = (
    ("STAR_LARGE", "symbol", 12, 11, .30),  # beside (or above) the large wordmark
    ("STAR_SMALL", "symbol", 8, 7, .22),  # beside the small wordmark
    ("WORDMARK_LARGE", "wordmark", 44, 7, .50),
    ("WORDMARK_SMALL", "wordmark", 30, 5, .50),
)
SAMPLES = 6  # samples per quadrant side
QUADRANTS = {  # (top left, top right, bottom left, bottom right) -> character
    (0, 0, 0, 0): " ", (1, 0, 0, 0): "\u2598", (0, 1, 0, 0): "\u259d", (0, 0, 1, 0): "\u2596",
    (0, 0, 0, 1): "\u2597", (1, 1, 0, 0): "\u2580", (0, 0, 1, 1): "\u2584", (1, 0, 1, 0): "\u258c",
    (0, 1, 0, 1): "\u2590", (1, 0, 0, 1): "\u259a", (0, 1, 1, 0): "\u259e", (1, 1, 1, 0): "\u259b",
    (1, 1, 0, 1): "\u259c", (1, 0, 1, 1): "\u2599", (0, 1, 1, 1): "\u259f", (1, 1, 1, 1): "\u2588",
}
# The first scope of each polaris-north rule -> the name the terminal uses for that colour.
CODE_SCOPES = {
    "comment": "comment", "keyword": "keyword", "string": "string",
    "constant.character.escape": "escape", "entity.name.function": "function",
    "constant.numeric": "number", "entity.name.type": "type", "variable.parameter": "parameter",
    "support.type.property-name": "property", "keyword.operator": "punctuation",
}
TOKEN = re.compile(r"[MLHVCZ]|-?\d*\.?\d+")
HEX = re.compile(r"#[0-9a-fA-F]{6}")
Point = tuple[float, float]


class SiteProblem(Exception):
    """The site checkout doesn't have the expected brand files or tokens."""


# ---- reading the site ------------------------------------------------------------------------


def svg(site: Path, relative: str) -> tuple[str, tuple[float, float], str | None]:
    """An SVG's path data (all paths, joined), its view box size and its fill colour."""
    text = (site / relative).read_text(encoding="utf-8")
    box = re.search(r'viewBox="([^"]+)"', text)
    paths = re.findall(r' d="([^"]+)"', text)
    if box is None or not paths:
        raise SiteProblem(f"{relative} has no view box or path")
    width, height = (float(value) for value in box.group(1).split()[2:4])
    fill = re.search(r'fill="(#[0-9a-fA-F]{6})"', text)
    return " ".join(paths), (width, height), fill.group(1).lower() if fill else None


def css_tokens(text: str, block: str) -> dict[str, str]:
    """`--color-name: #rrggbb` declarations inside the first CSS block that starts with `block`."""
    match = re.search(re.escape(block) + r"\s*\{([^}]*)\}", text)
    if match is None:
        raise SiteProblem(f"no {block} block")
    return {name: value.lower() for name, value in re.findall(r"--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", match.group(1))}


def code_colours(text: str) -> dict[str, str]:
    """The polaris-north code colours, by the terminal's names for them."""
    colours: dict[str, str] = {}
    foreground = re.search(r'"editor\.foreground":\s*"(#[0-9a-fA-F]{6})"', text)
    if foreground is None:
        raise SiteProblem("no editor.foreground in the highlighting theme")
    colours["foreground"] = foreground.group(1).lower()
    for scopes, value in re.findall(r'scope:\s*\[([^\]]*)\][^}]*?foreground:\s*"(#[0-9a-fA-F]{6})"', text):
        first = re.search(r'"([^"]+)"', scopes)
        name = CODE_SCOPES.get(first.group(1)) if first else None
        if name is not None:
            colours[name] = value.lower()
    missing = sorted(set(CODE_SCOPES.values()) - colours.keys())
    if missing:
        raise SiteProblem(f"the highlighting theme lacks {', '.join(missing)}")
    return colours


# ---- drawing ---------------------------------------------------------------------------------


def polygons(data: str) -> list[list[Point]]:
    """Absolute M/L/H/V/C/Z path data as closed polygons (curves flattened into 16 segments)."""
    tokens = TOKEN.findall(data)
    shapes: list[list[Point]] = []
    shape: list[Point] = []
    x = y = 0.0
    index, command = 0, "M"

    def numbers(count: int) -> list[float]:
        values = [float(value) for value in tokens[index:index + count]]
        if len(values) != count:
            raise SiteProblem("truncated path data")
        return values

    while index < len(tokens):
        if tokens[index] in "MLHVCZ":
            command = tokens[index]
            index += 1
            if command == "Z":
                if shape:
                    shapes.append(shape)
                shape = []
                continue
        if command == "M":
            if shape:
                shapes.append(shape)
            x, y = numbers(2)
            shape = [(x, y)]
            index, command = index + 2, "L"
        elif command == "L":
            x, y = numbers(2)
            shape.append((x, y))
            index += 2
        elif command == "H":
            x = numbers(1)[0]
            shape.append((x, y))
            index += 1
        elif command == "V":
            y = numbers(1)[0]
            shape.append((x, y))
            index += 1
        elif command == "C":
            x1, y1, x2, y2, x3, y3 = numbers(6)
            for step in range(1, 17):
                t = step / 16
                u = 1 - t
                shape.append((u ** 3 * x + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t ** 3 * x3,
                              u ** 3 * y + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t ** 3 * y3))
            x, y = x3, y3
            index += 6
        else:
            raise SiteProblem(f"unsupported path command {command}")
    if shape:
        shapes.append(shape)
    return shapes


def inside(shapes: Sequence[Sequence[Point]], px: float, py: float) -> bool:
    """Even-odd fill (the wordmark's fill rule; the star's rays never overlap)."""
    crossings = 0
    for shape in shapes:
        for (x1, y1), (x2, y2) in zip(shape, [*shape[1:], shape[0]], strict=True):
            if (y1 > py) != (y2 > py) and px < x1 + (py - y1) * (x2 - x1) / (y2 - y1):
                crossings += 1
    return crossings % 2 == 1


def draw(data: str, size: tuple[float, float], columns: int, rows: int, threshold: float) -> tuple[str, ...]:
    """The path drawn in `columns` x `rows` cells of quadrant blocks, without trailing spaces or
    blank rows above and below."""
    shapes = polygons(data)
    scale_x, scale_y = size[0] / (columns * 2), size[1] / (rows * 2)
    needed = threshold * SAMPLES * SAMPLES

    def lit(px: int, py: int) -> int:
        hits = sum(inside(shapes, (px + (sx + .5) / SAMPLES) * scale_x, (py + (sy + .5) / SAMPLES) * scale_y)
                   for sx in range(SAMPLES) for sy in range(SAMPLES))
        return int(hits >= needed)

    art = ["".join(QUADRANTS[(lit(2 * c, 2 * r), lit(2 * c + 1, 2 * r), lit(2 * c, 2 * r + 1), lit(2 * c + 1, 2 * r + 1))]
                   for c in range(columns)).rstrip() for r in range(rows)]
    while art and not art[-1]:
        art.pop()
    while art and not art[0]:
        art.pop(0)
    return tuple(art)


# ---- the generated module --------------------------------------------------------------------


def _mapping(name: str, values: dict[str, str], comment: str) -> list[str]:
    lines = [f"# {comment}", f"{name}: dict[str, str] = {{"]
    lines += [f"    {key!r}: {value!r}," for key, value in sorted(values.items())]
    return [*lines, "}"]


def module(site: Path) -> str:
    star_data, star_size, star_gold = svg(site, SYMBOL)
    word_data, word_size, _ = svg(site, WORDMARK)
    if star_gold is None:
        raise SiteProblem(f"{SYMBOL} has no fill colour")
    light = css_tokens((site / GLOBALS).read_text(encoding="utf-8"), "@theme")
    dark = {**light, **css_tokens((site / SURFACES).read_text(encoding="utf-8"), ".dark-surface")}
    code = code_colours((site / HIGHLIGHT).read_text(encoding="utf-8"))
    sources = {"symbol": (star_data, star_size), "wordmark": (word_data, word_size)}
    lines = [
        '"""GENERATED by scripts/brand_from_site.py from the Polaris website. Do not edit by hand.',
        "",
        "The star and the POLARIS wordmark (the site's public/brand SVG files), drawn with quadrant",
        "blocks, and the site's colour tokens: LIGHT for its porcelain pages (src/app/globals.css),",
        "DARK for its forest-green code windows (.dark-surface in src/styles/experience.css), CODE",
        "for its polaris-north code colours (src/lib/highlight.ts), STAR_GOLD for the logo's gold.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        f"STAR_PATH = {star_data!r}",
        f"STAR_VIEWBOX = {star_size!r}",
        f"WORDMARK_PATH = {word_data!r}",
        f"WORDMARK_VIEWBOX = {word_size!r}",
        f"STAR_GOLD = {star_gold!r}",
        "",
        "# (name, logo, columns, rows, threshold) of each drawing below.",
        f"DRAWINGS: tuple[tuple[str, str, int, int, float], ...] = {DRAWINGS!r}",
        "",
    ]
    for name, logo, columns, rows, threshold in DRAWINGS:
        art = draw(*sources[logo], columns, rows, threshold)
        lines.append(f"{name}: tuple[str, ...] = (")
        lines += [f"    {row!r}," for row in art]
        lines += [")", ""]
    lines += _mapping("LIGHT", light, "The site's colour tokens on its porcelain pages (light).")
    lines.append("")
    lines += _mapping("DARK", dark, "The same tokens on its dark surfaces: code windows and the review panel.")
    lines.append("")
    lines += _mapping("CODE", code, "The polaris-north code colours (used on dark surfaces).")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--site", type=Path, required=True, help="A checkout of the Polaris website's source.")
    parser.add_argument("--check", action="store_true", help="Exit 1 if the generated module is out of date.")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    try:
        text = module(args.site.resolve())
    except (OSError, SiteProblem) as problem:
        print(f"brand_from_site: {problem}", file=sys.stderr)
        return 2
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != text:
            print(f"brand_from_site: {args.output} is out of date; re-run without --check", file=sys.stderr)
            return 1
        return 0
    args.output.write_text(text, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

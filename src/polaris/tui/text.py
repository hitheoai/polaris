"""Inert text: repository, finding and SARIF text is displayed, never interpreted.

Control, invisible and bidirectional formatting characters (the "Trojan Source" class, ANSI
escapes and OSC sequences included) are replaced with a visible U+FFFD, tabs are expanded, and
lines are capped so a hostile file cannot stall rendering. The view model emits only cleaned text
in (text, role) spans; the widgets turn spans into Rich `Text`, which never parses markup (Textual
would parse plain `str` values in tables, tree labels and static widgets as markup).
"""

from __future__ import annotations

from polaris.review.models import UNSAFE_TEXT

MAX_LINE = 1_000
MAX_LINES = 20_000
REPLACEMENT = "\ufffd"
TAB = 4


def clean(value: object, limit: int = MAX_LINE) -> str:
    """One printable line: whitespace runs collapse, unsafe characters become U+FFFD."""
    if not isinstance(value, str):
        return ""
    text = " ".join(value[: limit * 4 + 64].split())
    text = UNSAFE_TEXT.sub(REPLACEMENT, text)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def clean_code_line(value: str, limit: int = MAX_LINE) -> str:
    """A source line as written (indentation kept), tabs expanded, unsafe characters replaced."""
    text = value[: limit * 2 + 64].rstrip("\r\n").expandtabs(TAB)
    text = UNSAFE_TEXT.sub(REPLACEMENT, text)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def clean_block(value: object, limit: int = 4_000, *, lines: int = 200) -> list[str]:
    """Multi-line prose (or a prompt) as cleaned lines; blank lines kept, total length bounded."""
    if not isinstance(value, str):
        return []
    return [clean(line, limit) for line in value[:limit].splitlines()[:lines]]


def plural(count: int, word: str, many: str | None = None) -> str:
    return f"{count} {word if count == 1 else many or word + 's'}"

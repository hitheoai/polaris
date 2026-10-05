"""Markdown for pull-request comments: repository-derived values are always inert text.

Paths, symbols, snippets and analyzer messages come from the change under review, which the
pull request's author controls. They are rendered as code spans, code blocks or escaped text, so
they cannot inject HTML, links, images, @mentions, or Polaris's own hidden state markers.
"""

from __future__ import annotations

import html
import re

MARKER_OPEN = "<!-- polaris:"
SUMMARY_MARKER = "<!-- polaris:summary v1 -->"
WORD_JOINER = "\u2060"
# Polaris findings are keyed by hex fingerprints. Results imported from another tool's SARIF
# have their own grammar, "sarif-<tool tag>-<fingerprint>", so the two can never collide and
# publishing can tell which tool an earlier comment came from.
FINDING_KEY = r"[0-9a-f]{16,64}|sarif-[0-9a-f]{8}-[0-9a-f]{24}"
_IMPORTED_KEY = re.compile(r"sarif-([0-9a-f]{8})-[0-9a-f]{24}")
_FINDING_MARKER = re.compile(rf"<!-- polaris:finding v1 key=({FINDING_KEY}) state=(open|resolved) -->\s*\Z")
_SUMMARY_MARKER = re.compile(r"<!-- polaris:summary v1 -->\s*\Z")
# C0/C1 controls (tab and newline excepted) and invisible or bidirectional formatting characters,
# which can make displayed code differ from what is actually there ("Trojan Source").
_INVISIBLE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
# Escaping brackets is enough to stop links and images; parentheses stay readable.
_MARKDOWN = re.compile(r"([\\`*_\[\]|~#])")
_SCHEME = re.compile(r"(?i)\b(https?|ftp|file|javascript|data|vbscript):")
_WWW = re.compile(r"(?i)\bwww\.")
_LEADING_LIST = re.compile(r"^([-+]|\d+[.)])(\s)")


def clean(text: str, limit: int, *, multiline: bool = False) -> str:
    """Printable, bounded text that contains no hidden HTML comment (Polaris markers included)."""
    value = text.replace("\r\n", "\n").replace("\r", "\n")
    value = _INVISIBLE.sub("\ufffd", value)
    if not multiline:
        value = " ".join(value.split())
    value = value.replace("<!--", "<" + WORD_JOINER + "!--").replace("-->", "--" + WORD_JOINER + ">")
    if len(value) > limit:
        value = value[: max(0, limit - 1)] + "…"
    return value


def code(text: str, limit: int = 200) -> str:
    """An inline code span that no content can close early; it renders no markup or mentions."""
    value = clean(text, limit) or "\u00a0"
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{ticks}{pad}{value}{pad}{ticks}"


def fence(text: str, info: str = "", limit: int = 4_000) -> str:
    """A fenced code block whose fence is longer than any backtick run inside it."""
    if "`" in info or "\n" in info:
        raise ValueError("invalid fence info string")
    value = clean(text, limit, multiline=True)
    longest = max((len(run) for run in re.findall(r"`{3,}", value)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{info}\n{value}\n{ticks}"


def _list_marker(match: re.Match[str]) -> str:
    marker = match.group(1)
    # Only punctuation can be backslash-escaped: "\-" and "\+", but "1\." for ordered lists.
    escaped = marker[:-1] + "\\" + marker[-1] if marker[0].isdigit() else "\\" + marker
    return escaped + match.group(2)


def escape(text: str, limit: int = 1_000) -> str:
    """Plain text with no HTML, emphasis, links, images, autolinks, list markers or mentions."""
    value = html.escape(clean(text, limit), quote=False)
    value = _MARKDOWN.sub(r"\\\1", value)
    value = _LEADING_LIST.sub(_list_marker, value)
    value = value.replace("@", "@" + WORD_JOINER)
    value = _SCHEME.sub(lambda match: match.group(1) + WORD_JOINER + ":", value)
    return _WWW.sub("www" + WORD_JOINER + ".", value)


def safe_suggestion(text: str) -> bool:
    """A suggested line is committed verbatim, so it is offered only when nothing needs escaping."""
    return (
        0 < len(text) <= 1_500 and "\n" not in text and "\r" not in text and "```" not in text
        and "<!--" not in text and _INVISIBLE.search(text) is None
    )


def suggestion_block(replacement: str) -> str:
    """GitHub's committable suggestion for the single line a comment is attached to."""
    if not safe_suggestion(replacement):
        raise ValueError("unsafe suggestion")
    return f"```suggestion\n{replacement}\n```"


def finding_marker(key: str, state: str = "open") -> str:
    if not re.fullmatch(FINDING_KEY, key) or state not in ("open", "resolved"):
        raise ValueError("invalid finding marker")
    return f"<!-- polaris:finding v1 key={key} state={state} -->"


def imported_tag(key: str) -> str | None:
    """The tool tag of an imported result's key; None for a Polaris finding's key."""
    match = _IMPORTED_KEY.fullmatch(key)
    return match.group(1) if match else None


def read_finding_marker(body: object) -> tuple[str, str] | None:
    """(key, state) from a comment's final line. A marker anywhere else is content, not state."""
    if not isinstance(body, str) or body.count(MARKER_OPEN) != 1:
        return None
    match = _FINDING_MARKER.search(body)
    return (match.group(1), match.group(2)) if match else None


def is_summary(body: object) -> bool:
    return isinstance(body, str) and body.count(MARKER_OPEN) == 1 and _SUMMARY_MARKER.search(body) is not None


def without_marker(body: str) -> str:
    index = body.rfind(MARKER_OPEN)
    return body[:index].rstrip() if index >= 0 else body

"""How every state looks: a glyph and a word always, colour only as a third cue.

The dark and light palettes are the Polaris website's (`polaris.check.brand.PALETTES`): its
forest-green code windows and its porcelain pages, where every text colour reads at 4.5:1 or
more. Problems take the site's flag colour, cautions its context colour, progress and keys its
accent, and good news its ok colour; secondary text is the site's muted colour, never dim (Warp
doesn't render dim). The ANSI themes use the terminal's own 16 colours (so its palette, and any
high-contrast or colour-blind adjustment the user made, decides), and NO_COLOR removes colour
entirely, keeping only bold and dim. Styles are Rich style strings; nothing here imports Rich or
Textual.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from polaris.check.brand import PALETTES as SITE

PaletteName = Literal["dark", "light", "ansi", "none"]
# --theme choices -> the Textual theme each one selects (polaris-dark and polaris-light are
# registered by the apps from `polaris.tui.brand`; the ANSI ones are Textual's own).
THEMES: dict[str, str] = {
    "dark": "polaris-dark", "light": "polaris-light", "ansi-dark": "ansi-dark", "ansi-light": "ansi-light",
}


@dataclass(frozen=True)
class State:
    glyph: str
    word: str
    role: str

    @property
    def label(self) -> str:
        return f"{self.glyph} {self.word}"


SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY: dict[str, State] = {
    "critical": State("◆", "CRITICAL", "sev.critical"),
    "high": State("▲", "HIGH", "sev.high"),
    "medium": State("△", "MEDIUM", "sev.medium"),
    "low": State("▽", "LOW", "sev.low"),
    "info": State("·", "INFO", "sev.info"),
}
SEVERITY_SHORT = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
# "●" already means FRESH in the trust bar, so issues keep "✖", the glyph of every failure state.
RESULT: dict[str, State] = {
    "flagged": State("✖", "issue", "result.issue"),
    "needs_context": State("?", "verify", "result.verify"),
    "error": State("!", "error", "result.error"),
    "uncertain": State("~", "uncertain", "muted"),
    "unsupported": State("–", "unsupported", "muted"),
    "too_large": State("–", "too large", "muted"),
    "ok": State("✓", "ok", "cov.checked"),
    "suppressed": State("⊘", "suppressed", "muted"),
    "baselined": State("≡", "baselined", "muted"),
}
COVERAGE: dict[str, State] = {
    "checked": State("✓", "checked", "cov.checked"),
    "partial": State("◐", "partial", "cov.partial"),
    "not_checked": State("✗", "not checked", "cov.missing"),
    "not_applicable": State("·", "not applicable", "muted"),
    "excluded": State("⊘", "excluded", "muted"),
    "not_implemented": State("–", "not implemented", "muted"),
    "mixed": State("◐", "partial", "cov.partial"),
}
FRESHNESS: dict[str, State] = {
    "fresh": State("●", "FRESH", "fresh"),
    "stale": State("✖", "STALE", "stale"),
    "saved": State("○", "SAVED", "muted"),
    "running": State("◌", "REVIEWING", "running"),
    "failed": State("!", "FAILED", "stale"),
}
COMPLETENESS: dict[str, State] = {
    "complete": State("✓", "COMPLETE", "cov.checked"),
    "incomplete": State("◐", "INCOMPLETE", "cov.partial"),
    "stale": State("✖", "STALE", "stale"),
    "error": State("!", "ERROR", "stale"),
}
VERIFICATION: dict[str, State] = {
    "verified": State("✓", "verified", "cov.checked"),
    "still_detected": State("✗", "still detected", "cov.missing"),
    "adds_findings": State("✚", "adds findings", "cov.missing"),
    "inconclusive": State("?", "inconclusive", "cov.partial"),
    "not_applicable": State("–", "not applicable", "muted"),
    "pending": State("◌", "verifying", "running"),
    "none": State("○", "not verified yet", "muted"),
    "saved": State("○", "needs a live review", "muted"),
}
GATE: dict[str, State] = {
    "pass": State("✓", "PASS", "cov.checked"),
    "fail": State("✖", "FAIL", "stale"),
    "incomplete": State("◐", "INCOMPLETE", "cov.partial"),
}
STEP: dict[str, State] = {
    "source": State("◉", "source", "step.source"),
    "step": State("○", "step", "step.step"),
    "call": State("↳", "call", "step.step"),
    "sink": State("◎", "sink", "step.sink"),
}
IMPORT_GROUP: dict[str, State] = {
    "corroborated": State("⇄", "corroborated", "cov.checked"),
    "tool_only": State("↗", "tool only", "imported"),
    "polaris_only": State("\u2736", "Polaris only", "result.issue"),
    "dropped": State("⊘", "left out", "muted"),
    "rejected": State("✗", "rejected", "cov.missing"),
}
SURFACE: dict[str, State] = {
    "guarded": State("✓", "guarded", "cov.checked"),
    "public": State("○", "public route", "muted"),
    "unguarded": State("✗", "no auth guard", "cov.missing"),
}
# Marks after a finding's title (not states): it has a suggested edit, other tools reported it too.
MARKS: dict[str, State] = {
    "edit": State("✎", "has a suggested edit (f previews it)", "muted"),
    "corroborated": State("⇄N", "also reported by N imported results", "imported"),
}


def _site(palette: str) -> dict[str, str]:
    """The roles in the website's colours: problems in its flag colour, cautions in its context
    colour, progress and keys in its accent, good news in its ok colour."""
    colours = SITE[palette]
    problem, caution, accent, good = colours["fix_now"], colours["check_this"], colours["accent"], colours["clear"]
    return {
        "sev.critical": f"bold {problem}",
        "sev.high": f"bold {problem}",
        "sev.medium": caution,
        "sev.low": accent,
        "sev.info": colours["muted"],
        "result.issue": f"bold {colours['heading']}",
        "result.verify": f"bold {caution}",
        "result.error": f"bold {problem}",
        "cov.checked": good,
        "cov.partial": caution,
        "cov.missing": f"bold {problem}",
        "fresh": f"bold {good}",
        "stale": f"bold {problem}",
        "running": accent,
        "imported": accent,
        "step.source": f"bold {caution}",
        "step.step": accent,
        "step.sink": f"bold {problem}",
        "code.flagged": f"bold {colours['selected.text']} on {colours['selected']}",
        "code.number": colours["code.number"],
        "code": colours["code"],
        "diff.remove": problem,
        "diff.add": good,
        "key": f"bold {accent}",
        "heading": f"bold underline {colours['heading']}",
        "label": f"bold {colours['heading']}",
        "muted": colours["muted"],
        "warning": caution,
        "text": "",
    }


_DARK: dict[str, str] = _site("dark")
_LIGHT: dict[str, str] = _site("light")
_ANSI = {
    **{role: "" for role in _DARK},
    "sev.critical": "bold red", "sev.high": "bold yellow", "sev.medium": "yellow", "sev.low": "cyan",
    "sev.info": "dim", "result.issue": "bold", "result.verify": "bold magenta", "result.error": "bold red",
    "cov.checked": "green", "cov.partial": "yellow", "cov.missing": "bold red", "fresh": "bold green",
    "stale": "bold red", "running": "cyan", "imported": "cyan", "step.source": "bold yellow",
    "step.step": "cyan", "step.sink": "bold red", "code.flagged": "bold reverse", "code.number": "dim",
    "diff.remove": "red", "diff.add": "green", "key": "bold cyan", "heading": "bold underline",
    "label": "bold", "muted": "dim", "warning": "yellow",
}
# NO_COLOR: attributes only. Glyphs and words carry every meaning; bold marks what needs attention.
_NONE = {
    **{role: "" for role in _DARK},
    "sev.critical": "bold", "sev.high": "bold", "sev.info": "dim", "result.issue": "bold",
    "result.verify": "bold", "result.error": "bold", "cov.missing": "bold", "stale": "bold",
    "fresh": "bold", "step.source": "bold", "step.sink": "bold", "code.flagged": "bold reverse",
    "code.number": "dim", "key": "bold", "heading": "bold underline", "label": "bold", "muted": "dim",
}
PALETTES: dict[str, dict[str, str]] = {"dark": _DARK, "light": _LIGHT, "ansi": _ANSI, "none": _NONE}


def palette_for(*, ansi: bool, dark: bool, no_color: bool) -> PaletteName:
    if no_color:
        return "none"
    if ansi:
        return "ansi"
    return "dark" if dark else "light"


def style(role: str, palette: PaletteName = "dark") -> str:
    return PALETTES[palette].get(role, "")


def severity(value: str | None) -> State:
    return SEVERITY.get(value or "medium", SEVERITY["medium"])


def severity_rank(value: str | None) -> int:
    name = value or "medium"
    return SEVERITIES.index(name) if name in SEVERITIES else 2


def at_least(value: str | None, floor: str) -> bool:
    """True when `value` is at or above `floor` ("high" is at least "medium")."""
    return severity_rank(value) <= severity_rank(floor)

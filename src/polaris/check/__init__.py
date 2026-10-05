"""`polaris check`: one security check in plain words, for people and their AI agents.

- `model`: the `polaris.check/1` result (status, prioritized items, fixes, prompts, next steps).
- `build`: turns a full Polaris review into that result.
- `runner`: runs a check (auto scope, full review, suggested-fix re-checks).
- `output`: text, Markdown and JSON renderings; `brand`: shared names, words and colours.
- `cli`: the `polaris check` command; the interactive view lives in `polaris.tui.simple`.

Importing this package stays light: the analyzers load only when a check runs.
"""

from polaris.check.model import CHECK_FORMAT, CheckItem, CheckResult

__all__ = ["CHECK_FORMAT", "CheckItem", "CheckResult"]

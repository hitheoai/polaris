"""`polaris tui`: an interactive, read-only terminal view of a Polaris review.

Only `polaris.tui.app` and `polaris.tui.widgets` import Textual, and they are loaded only when the
interface actually starts, so building the CLI parser (and `--help`) never imports it. The other
modules are plain Python: the view model, code context, themes and the editor command builder.
"""

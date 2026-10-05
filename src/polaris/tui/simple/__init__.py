"""The simple Polaris view: one question (is my code safe to ship?), plain words, one key per action.

`run` opens it for one `CheckRequest`: the branded checking screen while the check runs, then the
answer and the problems by priority, each one's details, or the all-clear. Read-only: copying a
prompt and opening the editor happen only after a key press.

`x` opens the expert view (`polaris tui`'s `PolarisApp`) on the same review. The simplest safe
hand-over: the simple app exits with the review, then `run` starts `PolarisApp` with it, so the
two apps never share a screen, a worker or a lock. Quitting the expert view ends Polaris, with
the exit code of the last check.
"""

from __future__ import annotations

from polaris.check.runner import CheckRequest


def run(request: CheckRequest, *, animation: bool = True, theme: str = "dark") -> int:
    """Run the check and show it. Returns the last check's exit code (0 clear, 1 something to fix
    now, 2 not fully checked), or 2 when the check couldn't run or didn't finish."""
    from polaris.tui.simple.app import SimpleApp

    app = SimpleApp(request, animation=animation, theme=theme)
    app.run()
    if app.return_code:  # the interface itself failed
        return 2
    if app.expert is not None:
        from polaris.tui.app import Options, PolarisApp

        PolarisApp(data=app.expert, options=Options(theme=app.theme_choice)).run()
    return app.exit_code

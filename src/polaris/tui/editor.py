"""Open a reviewed file in the user's own editor, at a line, without a shell.

`$VISUAL` (then `$EDITOR`) is split with `shlex`, never run through a shell. Editors that take
`+LINE` (the vi family, nano, emacs, micro, helix) get it before the path, the VS Code family gets
`--goto path:line`, and anything else just the path. The path must be a repository-relative path
that resolves (after following links) to a regular file inside the review root; it is passed as an
absolute path, so it can never be read as an option. Only the app runs the command, inside
`App.suspend()`, and only after a key press.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from polaris.review.models import valid_source_path

PLUS_LINE = frozenset({
    "vi", "vim", "nvim", "gvim", "mvim", "view", "nvi", "nano", "emacs", "emacsclient", "micro", "hx", "helix",
})
GOTO = frozenset({"code", "code-insiders", "codium", "vscodium", "cursor", "windsurf"})
# How to set an editor (the interface reads the environment it was started with).
EXAMPLES = ('export EDITOR="code --wait"', "export EDITOR=nvim")
MESSAGES = {
    "editor_not_set": (f"No editor is set. Quit, set $VISUAL or $EDITOR in your shell, for example "
                       f"{EXAMPLES[0]} or {EXAMPLES[1]}, then start polaris tui again."),
    "editor_unparsable": "$VISUAL/$EDITOR could not be parsed; check its quoting.",
    "no_repository": "No repository root is known for this report; run polaris tui from inside the repository.",
    "invalid_path": "This finding has no repository-relative path to open.",
    "outside_root": "That file resolves outside the reviewed repository, so it was not opened.",
    "file_missing": "That file is not in the worktree any more.",
    "editor_failed": "The editor could not be started.",
    "suspend_unsupported": "This terminal session cannot hand control to an editor.",
}


class EditorProblem(Exception):
    """A fixed code from MESSAGES; never the editor value or a file's content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def message(self) -> str:
        return MESSAGES.get(self.code, MESSAGES["editor_failed"])


@dataclass(frozen=True)
class EditorCommand:
    argv: tuple[str, ...]
    cwd: Path
    path: Path
    line: int


def editor_words(environ: Mapping[str, str] | None = None) -> list[str]:
    environ = os.environ if environ is None else environ
    value = (environ.get("VISUAL") or "").strip() or (environ.get("EDITOR") or "").strip()
    if not value:
        raise EditorProblem("editor_not_set")
    try:
        words = shlex.split(value, posix=True)
    except ValueError:
        raise EditorProblem("editor_unparsable") from None
    if not words or any("\0" in word for word in words):
        raise EditorProblem("editor_unparsable")
    return words


def program_name(word: str) -> str:
    name = PurePosixPath(word.replace("\\", "/")).name.lower()
    return name.removesuffix(".exe")


def resolve_inside(root: Path | None, relative: str) -> Path:
    """The regular file a repository-relative path names, refusing anything outside `root`."""
    if root is None:
        raise EditorProblem("no_repository")
    if not valid_source_path(relative):
        raise EditorProblem("invalid_path")
    base = root.resolve()
    try:
        resolved = (base / relative).resolve(strict=True)
    except (OSError, RuntimeError):
        raise EditorProblem("file_missing") from None
    if not resolved.is_relative_to(base):
        raise EditorProblem("outside_root")
    if not resolved.is_file():
        raise EditorProblem("file_missing")
    return resolved


def build_command(
    root: Path | None, relative: str, line: int, environ: Mapping[str, str] | None = None,
) -> EditorCommand:
    words = editor_words(environ)
    path = resolve_inside(root, relative)
    assert root is not None
    line = max(1, int(line))
    name = program_name(words[0])
    if name in GOTO:
        position = ["--goto", f"{path}:{line}"]
    elif name in PLUS_LINE:
        position = [f"+{line}", str(path)]
    else:
        position = [str(path)]
    return EditorCommand(argv=(*words, *position), cwd=root.resolve(), path=path, line=line)


def run_editor(command: EditorCommand, *, runner: Callable[..., object] = subprocess.run) -> None:
    """Run the editor in the foreground terminal (the app has suspended itself)."""
    try:
        runner(list(command.argv), cwd=command.cwd, check=False)
    except OSError:
        raise EditorProblem("editor_failed") from None

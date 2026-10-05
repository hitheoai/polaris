"""Bounded, read-only reading of shell snippets embedded in CI workflows and Dockerfiles.

Nothing is executed, expanded or resolved. The tokenizer recognizes enough POSIX shell syntax
(quotes, escapes, command and process substitution, pipelines and lists, redirections, comments,
heredoc bodies, and `{ }`, `( )` and loop groups) to find simple commands and where their output
goes. What it can't follow stays opaque word text, so the rules built on it under-report rather
than guess. PowerShell download-and-run one-liners are matched separately, line by line.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

MAX_SCRIPT_CHARS = 262_144
MAX_COMMANDS = 10_000
MAX_NESTING = 6


class ShellLimit(ValueError):
    """A script exceeded the tokenizer's size, command or nesting budget (a fixed reason code)."""


@dataclass(frozen=True)
class Word:
    """One shell word: `text` has quotes removed and escapes resolved; parameter expansions and
    substitutions stay verbatim (`$TOKEN`, `$(curl …)`). Offsets index the tokenized script."""

    text: str
    raw: str
    start: int
    end: int
    quoted: bool = False
    subs: tuple[str, ...] = ()  # bodies of $(…), `…`, <(…) and >(…) inside this word


@dataclass(frozen=True)
class Redirect:
    op: str  # >, >>, >|, &>, &>>, >&, <, <<, <<-, <<<, <&, <>
    target: str
    fd: str = ""


@dataclass
class Command:
    words: list[Word]
    redirects: list[Redirect]
    op: str  # what follows: |, |&, ||, &&, ;, &, a newline, ( ) ;; or "" at the end
    start: int


@dataclass(frozen=True)
class HeredocBody:
    """A heredoc body's span in the script, whether its delimiter was quoted (no expansion in
    the body), and the index of the command reading it."""

    start: int
    end: int
    delimiter: str
    quoted: bool
    command: int


_REDIRECTS = ("&>>", "&>", ">>", ">|", ">&", "<<<", "<<-", "<<", "<&", "<>", ">", "<")
_OPERATORS = (";;&", ";;", ";&", "&&", "||", "|&", "|", "&", ";", "(", ")")
_OPENERS = frozenset({"{", "do", "then"})
_CLOSERS = frozenset({"}", "done", "fi"})
_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "fi",
                       "done", "esac", "case", "in"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")


def _prefix(text: str, index: int, options: tuple[str, ...]) -> str | None:
    return next((option for option in options if text.startswith(option, index)), None)


def _backtick_end(text: str, index: int) -> int:
    """Index of the closing backtick (or the end of the text)."""
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == "`":
            return index
        index += 1
    return len(text)


def _double_end(text: str, index: int, depth: int) -> int:
    """Index just after the closing double quote of a string starting at `index`."""
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index + 1
        if char == "`":
            index = _backtick_end(text, index + 1) + 1
            continue
        if char == "$" and text.startswith("$(", index):
            index = _balanced(text, index + 1, depth + 1) + 1
            continue
        index += 1
    return len(text)


def _balanced(text: str, index: int, depth: int = 0) -> int:
    """Index of the parenthesis closing the one at `index` (or the last index of the text)."""
    if depth > MAX_NESTING:
        raise ShellLimit("nesting_limit")
    level = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "'":
            end = text.find("'", index + 1)
            index = len(text) if end < 0 else end + 1
            continue
        if char == '"':
            index = _double_end(text, index + 1, depth)
            continue
        if char == "`":
            index = _backtick_end(text, index + 1) + 1
            continue
        if char == "(":
            level += 1
        elif char == ")":
            level -= 1
            if level == 0:
                return index
        index += 1
    return len(text) - 1


def _brace_end(text: str, index: int) -> int:
    """Index of the brace closing a `${` parameter expansion opened at `index`."""
    level = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in "'\"":
            end = text.find(char, index + 1)
            index = len(text) if end < 0 else end + 1
            continue
        if char == "{":
            level += 1
        elif char == "}":
            level -= 1
            if level == 0:
                return index
        index += 1
    return len(text) - 1


class _Tokenizer:
    def __init__(self, script: str) -> None:
        self.text = script
        self.commands: list[Command] = []
        self.words: list[Word] = []
        self.redirects: list[Redirect] = []
        self.buffer: list[str] = []
        self.word_start: int | None = None
        self.quoted = False
        self.subs: list[str] = []
        self.pending: tuple[str, str] | None = None
        self.heredocs: list[tuple[str, bool, bool, int]] = []  # delimiter, strip tabs, quoted, command
        self.bodies: list[HeredocBody] = []
        self.command_start: int | None = None
        self.groups: list[int] = []
        self.closed_group: int | None = None

    def _start(self, index: int) -> None:
        if self.word_start is None:
            self.word_start = index

    def _reset_word(self) -> None:
        self.buffer, self.word_start, self.quoted, self.subs = [], None, False, []

    def _word(self, end: int) -> None:
        if self.word_start is None:
            return
        text = "".join(self.buffer)
        if self.pending is not None:
            operator, fd = self.pending
            self.redirects.append(Redirect(operator, text, fd))
            if operator in ("<<", "<<-"):
                # The command reading it is the one being built (appended next).
                self.heredocs.append((text, operator == "<<-", self.quoted, len(self.commands)))
            self.pending = None
        else:
            if self.command_start is None:
                self.command_start = self.word_start
            self.words.append(Word(text, self.text[self.word_start:end], self.word_start, end, self.quoted,
                                   tuple(self.subs)))
        self._reset_word()

    def _command(self, operator: str, at: int) -> None:
        self._word(at)
        self.pending = None
        if self.words:
            command = Command(self.words, self.redirects, operator, self.command_start or 0)
            first = command.words[0]
            if not first.quoted and first.text in _OPENERS:
                self.groups.append(len(self.commands))
            elif not first.quoted and first.text in _CLOSERS and self.groups:
                start = self.groups.pop()
                for item in self.commands[start:]:
                    item.redirects.extend(command.redirects)
            self.commands.append(command)
            if len(self.commands) > MAX_COMMANDS:
                raise ShellLimit("command_limit")
            self.closed_group = None
        elif self.redirects and self.closed_group is not None:
            # `( … ) > file`: the redirection applies to every command of the group.
            for item in self.commands[self.closed_group:]:
                item.redirects.extend(self.redirects)
            self.closed_group = None
        if operator == "(":
            self.groups.append(len(self.commands))
        elif operator == ")" and self.groups:
            self.closed_group = self.groups.pop()
        self.words, self.redirects, self.command_start = [], [], None

    def _skip_heredocs(self, index: int) -> int:
        text = self.text
        for delimiter, strip_tabs, quoted, command in self.heredocs:
            start = index
            body_end = len(text)
            while index < len(text):
                end = text.find("\n", index)
                end = len(text) if end < 0 else end
                line = text[index:end].rstrip("\r")
                if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                    body_end = index
                    index = end + 1
                    break
                index = end + 1
            self.bodies.append(HeredocBody(start, min(body_end, len(text)), delimiter, quoted, command))
        self.heredocs.clear()
        return min(index, len(text))

    def _double(self, index: int) -> int:
        text = self.text
        while index < len(text):
            char = text[index]
            if char == '"':
                return index + 1
            if char == "\\" and index + 1 < len(text):
                following = text[index + 1]
                if following != "\n":
                    self.buffer.append(following if following in '$`"\\' else char + following)
                index += 2
                continue
            if char == "`":
                end = _backtick_end(text, index + 1)
                self.subs.append(text[index + 1:end])
                self.buffer.append(text[index:end + 1])
                index = end + 1
                continue
            if char == "$" and text.startswith(("$(", "${"), index):
                index = self._dollar(index)
                continue
            self.buffer.append(char)
            index += 1
        return len(text)

    def _dollar(self, index: int) -> int:
        text = self.text
        following = text[index + 1]
        if following == "(":
            end = _balanced(text, index + 1)
            if not text.startswith("$((", index):
                self.subs.append(text[index + 2:end])
            self.buffer.append(text[index:end + 1])
            return end + 1
        if following == "{":
            end = _brace_end(text, index + 1)
            self.buffer.append(text[index:end + 1])
            return end + 1
        # $'…' (ANSI-C quoting): escapes are kept verbatim, never interpreted.
        cursor = index + 2
        while cursor < len(text) and text[cursor] != "'":
            cursor += 2 if text[cursor] == "\\" else 1
        self.buffer.append(text[index + 2:cursor])
        self.quoted = True
        return cursor + 1

    def run(self) -> list[Command]:
        text = self.text
        index = 0
        while index < len(text):
            char = text[index]
            if char == "\\":
                if text.startswith("\\\n", index):
                    index += 2
                    continue
                self._start(index)
                self.buffer.append(text[index + 1:index + 2])
                self.quoted = True
                index += 2
                continue
            if char == "'":
                self._start(index)
                end = text.find("'", index + 1)
                end = len(text) if end < 0 else end
                self.buffer.append(text[index + 1:end])
                self.quoted = True
                index = end + 1
                continue
            if char == '"':
                self._start(index)
                self.quoted = True
                index = self._double(index + 1)
                continue
            if char == "`":
                self._start(index)
                end = _backtick_end(text, index + 1)
                self.subs.append(text[index + 1:end])
                self.buffer.append(text[index:end + 1])
                index = end + 1
                continue
            if char == "$" and index + 1 < len(text) and text[index + 1] in "({'":
                self._start(index)
                index = self._dollar(index)
                continue
            if char in "<>" and text.startswith("(", index + 1) and self.word_start is None:
                self._start(index)
                end = _balanced(text, index + 1)
                self.subs.append(text[index + 2:end])
                self.buffer.append(text[index:end + 1])
                index = end + 1
                continue
            if char == "#" and self.word_start is None:
                end = text.find("\n", index)
                index = len(text) if end < 0 else end
                continue
            if char in " \t\r":
                self._word(index)
                index += 1
                continue
            if char == "\n":
                self._command("\n", index)
                index = self._skip_heredocs(index + 1)
                continue
            redirect = _prefix(text, index, _REDIRECTS)
            if redirect:
                fd = ""
                if self.word_start is not None and not self.quoted and "".join(self.buffer).isdigit():
                    fd = "".join(self.buffer)
                    self._reset_word()
                else:
                    self._word(index)
                if self.command_start is None:
                    self.command_start = index
                self.pending = (redirect, fd)
                index += len(redirect)
                continue
            operator = _prefix(text, index, _OPERATORS)
            if operator:
                self._command(operator, index)
                index += len(operator)
                continue
            self._start(index)
            self.buffer.append(char)
            index += 1
        self._command("", len(text))
        return self.commands


def tokenize(script: str) -> list[Command]:
    """Simple commands of a script, in order. Raises ShellLimit beyond the fixed budgets."""
    return tokenize_with_heredocs(script)[0]


def tokenize_with_heredocs(script: str) -> tuple[list[Command], list[HeredocBody]]:
    """Commands and the heredoc bodies they read."""
    if len(script) > MAX_SCRIPT_CHARS:
        raise ShellLimit("script_too_large")
    tokenizer = _Tokenizer(script)
    return tokenizer.run(), tokenizer.bodies


def heredoc_data(script: str, offset: int) -> HeredocBody | None:
    """The heredoc body containing `offset` when it is only data: read by a command (cat, tee,
    gh, jq...) that doesn't run its input as code, and not piped into one that does."""
    return data_heredoc(*tokenize_with_heredocs(script), offset)


def data_heredoc(commands: list[Command], bodies: list[HeredocBody], offset: int) -> HeredocBody | None:
    """`heredoc_data` on an already tokenized script."""
    body = next((item for item in bodies if item.start <= offset < item.end), None)
    if body is None or body.command >= len(commands):
        return None
    reader = commands[body.command]
    for pipeline in pipelines(commands):
        position = next((index for index, command in enumerate(pipeline) if command is reader), None)
        if position is not None:
            if any((words := argv(command)) and executes_stdin(words) is not None for command in pipeline[position:]):
                return None
            return body
    return None


def pipelines(commands: list[Command]) -> list[list[Command]]:
    """Commands connected by `|` or `|&`, in order."""
    grouped: list[list[Command]] = []
    current: list[Command] = []
    for command in commands:
        current.append(command)
        if command.op not in ("|", "|&"):
            grouped.append(current)
            current = []
    if current:
        grouped.append(current)
    return grouped


def basename(text: str) -> str:
    return text.rsplit("/", 1)[-1]


def _skip_options(words: list[Word], index: int, takes_value: frozenset[str]) -> int:
    while index < len(words):
        text = words[index].text
        if text == "--":
            return index + 1
        if not text.startswith("-") or text == "-":
            return index
        index += 2 if text in takes_value else 1
    return index


_SUDO_VALUES = frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"})
_ENV_VALUES = frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"})


def argv(command: Command) -> list[Word]:
    """The words of the program actually run: leading keywords (if, then, !), variable
    assignments and wrappers (sudo, env, nohup, exec, command, time, timeout, nice) removed."""
    words = command.words
    index = 0
    while index < len(words):
        word = words[index]
        if not word.quoted and word.text in _KEYWORDS:
            index += 1
            continue
        if _ASSIGNMENT.match(word.raw):
            index += 1
            continue
        name = basename(word.text)
        if name == "sudo":
            index = _skip_options(words, index + 1, _SUDO_VALUES)
        elif name == "env":
            index = _skip_options(words, index + 1, _ENV_VALUES)
        elif name in ("nohup", "exec", "command", "builtin", "stdbuf"):
            index = _skip_options(words, index + 1, frozenset())
        elif name == "nice":
            index = _skip_options(words, index + 1, frozenset({"-n"}))
        elif name == "timeout":
            index = _skip_options(words, index + 1, frozenset({"-s", "-k", "--signal", "--kill-after"})) + 1
        else:
            break
    return words[index:]


# ----------------------------------------------------------------------------------- remote scripts

DOWNLOADERS = frozenset({"curl", "wget"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish"})
_PYTHON = re.compile(r"python(?:\d+(?:\.\d+)?)?|pypy3?")
_INLINE_FLAGS = {"perl": "eE", "ruby": "e", "node": "ep", "nodejs": "ep", "php": "r"}
# Commands that pass a download along unchanged (or only decompressed) to the next one.
_PASS_ALONG = frozenset({"tee", "cat", "gunzip", "zcat", "bunzip2", "unxz", "xzcat"})
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"`|;&<>()]+")


@dataclass(frozen=True)
class RemoteScript:
    """Code downloaded and run without verification: `start` is the downloader's offset."""

    start: int
    url: str | None
    interpreter: str


def _short_flag_value(words: list[Word], index: int, letter: str) -> str | None:
    """For a short-option cluster like `-fsSLo`, the value of `letter` (attached or the next word)."""
    text = words[index].text
    position = text.find(letter, 1)
    if position < 0:
        return None
    attached = text[position + 1:]
    if attached:
        return attached
    return words[index + 1].text if index + 1 < len(words) else ""


def downloads_to_stdout(words: list[Word]) -> bool:
    """Whether a curl/wget command writes the downloaded body to standard output."""
    name = basename(words[0].text).lower()
    if name == "curl":
        for index in range(1, len(words)):
            text = words[index].text
            if text in ("-O", "--remote-name", "--remote-name-all", "--remote-header-name"):
                return False
            if text in ("-o", "--output"):
                return index + 1 < len(words) and words[index + 1].text in ("-", "/dev/stdout")
            if text.startswith("--output="):
                return text.partition("=")[2] in ("-", "/dev/stdout")
            if text.startswith("-") and not text.startswith("--") and len(text) > 1:
                if "O" in text[1:]:
                    return False
                value = _short_flag_value(words, index, "o")
                if value is not None:
                    return value in ("-", "/dev/stdout")
        return True
    if name == "wget":
        for index in range(1, len(words)):
            text = words[index].text
            if text in ("-O", "--output-document"):
                return index + 1 < len(words) and words[index + 1].text in ("-", "/dev/stdout")
            if text.startswith("--output-document="):
                return text.partition("=")[2] in ("-", "/dev/stdout")
            if text.startswith("-") and not text.startswith("--") and len(text) > 1:
                value = _short_flag_value(words, index, "O")
                if value is not None:
                    return value in ("-", "/dev/stdout")
        return False
    return False


def executes_stdin(words: list[Word]) -> str | None:
    """The interpreter's name when this command runs code read from standard input."""
    name = basename(words[0].text).lower()
    args = [word.text for word in words[1:]]
    if name in ("iex", "invoke-expression"):
        return name
    if name in SHELLS:
        from_stdin = skip = False
        for index, text in enumerate(args):
            if skip:
                skip = False
                continue
            if text == "--":
                rest = args[index + 1:]
                return name if from_stdin or not rest or rest[0] == "-" else None
            if text in ("-o", "+o", "-O", "+O"):
                skip = True
                continue
            if text.startswith("-") and len(text) > 1 and not text.startswith("--"):
                if "c" in text[1:]:
                    return None
                from_stdin = from_stdin or "s" in text[1:]
                continue
            if text.startswith(("+", "--")):
                continue
            return name if from_stdin or text == "-" else None
        return name
    if _PYTHON.fullmatch(name):
        skip = False
        for text in args:
            if skip:
                skip = False
                continue
            if text in ("-W", "-X"):
                skip = True
                continue
            if text == "-":
                return name
            if text.startswith(("-c", "-m")):
                return None
            if not text.startswith("-"):
                return None
        return name
    inline = _INLINE_FLAGS.get(name)
    if inline is not None:
        for text in args:
            if text == "-":
                return name
            if text.startswith("--"):
                if text.split("=", 1)[0] in ("--eval", "--print"):
                    return None
                continue
            if text.startswith("-"):
                if any(flag in text[1:] for flag in inline):
                    return None
                continue
            return None
        return name
    if name.removesuffix(".exe") in ("pwsh", "powershell"):
        lowered = [text.lower() for text in args]
        for index, text in enumerate(lowered):
            if text in ("-command", "-c", "-file", "-f"):
                return name if index + 1 < len(lowered) and lowered[index + 1] == "-" else None
        return name if all(text.startswith("-") for text in lowered) else None
    return None


def _url(words: list[Word]) -> str | None:
    for word in words[1:]:
        match = _URL.match(word.text)
        if match:
            return match.group(0)
    return None


def _downloaded(script: str, depth: int) -> tuple[bool, str | None]:
    """Whether a substitution body prints a download (a curl/wget writing to stdout, possibly
    passed along unchanged), and the URL."""
    for pipeline in pipelines(tokenize(script)):
        commands = [argv(command) for command in pipeline]
        for index, words in enumerate(commands):
            if words and basename(words[0].text).lower() in DOWNLOADERS and downloads_to_stdout(words):
                rest = [later for later in commands[index + 1:] if later]
                if all(basename(later[0].text).lower() in _PASS_ALONG for later in rest):
                    return True, _url(words)
    return False, None


def _scan(script: str, base: int | None, found: list[RemoteScript], depth: int) -> None:
    if depth > MAX_NESTING:
        return
    commands = tokenize(script)
    for pipeline in pipelines(commands):
        argvs = [argv(command) for command in pipeline]
        for index, words in enumerate(argvs):
            if not words or basename(words[0].text).lower() not in DOWNLOADERS or not downloads_to_stdout(words):
                continue
            for later in argvs[index + 1:]:
                if not later:
                    continue
                interpreter = executes_stdin(later)
                if interpreter is not None:
                    found.append(RemoteScript(words[0].start if base is None else base, _url(words), interpreter))
                    break
                if basename(later[0].text).lower() not in _PASS_ALONG:
                    break
        for words in argvs:
            if not words:
                continue
            name = basename(words[0].text).lower()
            runs_text = name in ("eval", "source", ".")
            for position, word in enumerate(words[1:], 1):
                if not word.subs:
                    continue
                previous = words[position - 1].text
                inline = name in SHELLS and previous.startswith("-") and not previous.startswith("--") and "c" in previous
                script_file = (name in SHELLS or name in _INLINE_FLAGS or bool(_PYTHON.fullmatch(name))) \
                    and word.raw.startswith("<(")
                if not (runs_text or inline or script_file):
                    continue
                for sub in word.subs:
                    downloaded, url = _downloaded(sub, depth + 1)
                    if downloaded:
                        found.append(RemoteScript(word.start if base is None else base, url, name))
                        break
        for command in pipeline:
            for word in command.words:
                for sub in word.subs:
                    _scan(sub, word.start if base is None else base, found, depth + 1)


_PS_RUN = re.compile(r"(?i)(?<![\w-])(?:iex|invoke-expression)(?![\w-])")
_PS_GET = re.compile(r"(?i)\.download(?:string|data)\s*\(|invoke-webrequest|invoke-restmethod|(?<![\w-])(?:iwr|irm)(?![\w-])")


def _powershell(script: str) -> list[RemoteScript]:
    """`iex`/`Invoke-Expression` with a web download in one statement (backtick continuations
    joined); reported at the download."""
    found = []
    offset = 0
    pieces: list[tuple[int, str]] = []
    for line in script.splitlines(keepends=True):
        start = offset
        offset += len(line)
        body = line.rstrip("\r\n")
        pieces.append((start, body[:-1] if body.endswith("`") else body))
        if body.endswith("`"):
            continue
        joined = " ".join(text for _, text in pieces)
        download = _PS_GET.search(joined)
        if download and _PS_RUN.search(joined):
            position, index = download.start(), 0
            while index < len(pieces) - 1 and position > len(pieces[index][1]):
                position -= len(pieces[index][1]) + 1  # the joining space
                index += 1
            match = _URL.search(joined)
            found.append(RemoteScript(pieces[index][0] + max(0, position), match.group(0) if match else None,
                                      "powershell"))
        pieces = []
    return found


def remote_scripts(script: str) -> list[RemoteScript]:
    """Downloads piped or substituted into an interpreter, one per location."""
    found: list[RemoteScript] = []
    _scan(script, None, found, 0)
    found.extend(_powershell(script))
    unique: dict[int, RemoteScript] = {}
    for item in found:
        unique.setdefault(item.start, item)
    return sorted(unique.values(), key=lambda item: item.start)


def is_remote(url: str | None) -> bool:
    """False for loopback addresses (a local test server is not a supply-chain download)."""
    if url is None:
        return True
    host = re.sub(r"(?i)^[a-z]+://", "", url).split("/", 1)[0].rsplit("@", 1)[-1]
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host.lower() not in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1")


# ----------------------------------------------------------------------------------- printed values

PRINTERS = frozenset({"echo", "printf"})
# Commands that print what they receive: unchanged (GitHub still masks it) or transformed (it can't).
UNCHANGED = frozenset({"cat", "tee", "head", "tail", "sort", "uniq"})
TRANSFORMING = frozenset({"base64", "base32", "basenc", "xxd", "od", "hexdump", "rev", "tr", "sed", "awk",
                          "gawk", "cut", "fold", "iconv", "jq"})
_NOT_PRINTED = ("::add-mask::", "::set-output", "::save-state", "::stop-commands")


@dataclass(frozen=True)
class Printed:
    """An echo/printf whose argument `word` reaches the job log, possibly through `transformer`."""

    start: int
    word: Word
    transformer: str | None


def writes_to_log(command: Command) -> bool:
    """Whether a command's standard output goes to the job log (not a file or /dev/null)."""
    for redirect in command.redirects:
        if redirect.fd not in ("", "1"):
            continue
        if redirect.op in (">", ">>", ">|", "&>", "&>>"):
            return redirect.target in ("/dev/stdout", "/dev/stderr", "/dev/tty")
        if redirect.op == ">&":
            return redirect.target in ("1", "2")
    return True


def printed(script: str, carries_secret: Callable[[Word], bool]) -> list[Printed]:
    """echo/printf arguments that `carries_secret` accepts and that end up in the log.

    Output captured by a substitution, redirected to a file or consumed by another program
    (`docker login --password-stdin`) is not printed. Masking markers (::add-mask::) are skipped.
    """
    found: list[Printed] = []
    for pipeline in pipelines(tokenize(script)):
        argvs = [argv(command) for command in pipeline]
        for index, words in enumerate(argvs):
            if not words or basename(words[0].text) not in PRINTERS:
                continue
            args = words[1:]
            if any(marker in word.text for word in args for marker in _NOT_PRINTED):
                continue
            carrier = next((word for word in args if carries_secret(word)), None)
            if carrier is None:
                continue
            if index == len(pipeline) - 1:
                if writes_to_log(pipeline[index]):
                    found.append(Printed(words[0].start, carrier, None))
                continue
            transformer: str | None = None
            reaches_log = writes_to_log(pipeline[-1])
            for later in argvs[index + 1:]:
                name = basename(later[0].text) if later else ""
                if name in TRANSFORMING:
                    transformer = transformer or name
                elif name == "openssl" and len(later) > 1 and later[1].text in ("base64", "enc"):
                    transformer = transformer or name
                elif name not in UNCHANGED:
                    reaches_log = False
                    break
            if reaches_log:
                found.append(Printed(words[0].start, carrier, transformer))
    return found


# ----------------------------------------------------------------------------------- quoting context


def quote_context(script: str, offset: int) -> str:
    """The quoting at `offset`: "unquoted", "double", "single", or "other" (inside a substitution,
    heredoc body, comment or escape), for building exact one-line replacements."""
    state = "unquoted"
    heredocs: list[tuple[str, bool]] = []
    index = 0
    word_start = True
    while index < offset:
        char = script[index]
        if state == "single":
            if char == "'":
                state = "unquoted"
            index += 1
            continue
        if char == "\\":
            if index + 1 == offset:
                return "other"
            index += 2
            continue
        if state == "double":
            if char == '"':
                state = "unquoted"
            elif char == "`" or script.startswith("$(", index):
                end = _backtick_end(script, index + 1) if char == "`" else _balanced(script, index + 1)
                if offset <= end:
                    return "other"
                index = end
            index += 1
            continue
        if char == "'":
            state = "single"
        elif char == '"':
            state = "double"
        elif char == "`" or script.startswith("$(", index) or (char in "<>" and script.startswith("(", index + 1)):
            end = _backtick_end(script, index + 1) if char == "`" else _balanced(script, index + 1)
            if offset <= end:
                return "other"
            index = end
        elif char == "#" and word_start:
            end = script.find("\n", index)
            if end < 0 or offset <= end:
                return "other"
            index = end - 1
        elif script.startswith("<<", index) and not script.startswith("<<<", index):
            match = re.match(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2", script[index:])
            if match:
                heredocs.append((match.group(3), bool(match.group(1))))
                index += match.end() - 1
        elif char == "\n" and heredocs:
            cursor = index + 1
            for delimiter, strip_tabs in heredocs:
                while cursor < len(script):
                    end = script.find("\n", cursor)
                    end = len(script) if end < 0 else end
                    line = script[cursor:end]
                    if cursor <= offset <= end:
                        return "other"
                    cursor = end + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
            heredocs.clear()
            index = cursor - 1
        word_start = char in " \t\n;|&()"
        index += 1
    return state

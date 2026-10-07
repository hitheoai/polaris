"""Deterministic Python fixes for rules whose repair is mechanical.

Each codemod reads the whole file with `ast`, changes exactly one call that the finding points
at, and returns the whole edited file. It declines (returns None) whenever the shape isn't one it
fully understands, so it never guesses: anything it returns still goes through the same
re-review as every other candidate, and a fix that doesn't clear the finding is thrown away.

Nothing here executes the code it edits.
"""

from __future__ import annotations

import ast
import json
import posixpath
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from polaris.refactor.fixes import Fix, Positions
from polaris.refactor.gha_env import env_indirection
from polaris.refactor.js_tls import node_tls_unset, reject_unauthorized_true
from polaris.refactor.sql_params import sql_parameters
from polaris.review.rules import OPTION_PROGRAMS, SHELLS

# Text allowed in the fixed part of a command: no quoting, globbing, redirection or expansion.
SAFE_LITERAL = re.compile(r"^[A-Za-z0-9_@%+=:,./ \t-]*$")
PLAIN_LITERAL = re.compile(r'"[^"\\]*"')  # one json-quoted piece of fixed text
# `subprocess.*` calls that take the command as the first argument and run a shell with shell=True.
SUBPROCESS_CALLS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
})


Codemod = Callable[[str, int], Fix | None]


def _parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def _dotted(node: ast.expr) -> str | None:
    names: list[str] = []
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(names)])


def _offset(line: str, byte_column: int) -> int:
    """A character index in `line` for a UTF-8 byte column (what `ast` reports)."""
    return len(line.encode("utf-8")[:byte_column].decode("utf-8", "ignore"))


def _replace(lines: list[str], node: ast.AST, new: str) -> bool:
    """Replace one single-line node's source; False when the node spans lines."""
    line, end = getattr(node, "lineno", 0), getattr(node, "end_lineno", None)
    column, end_column = getattr(node, "col_offset", None), getattr(node, "end_col_offset", None)
    if end != line or column is None or end_column is None or not 1 <= line <= len(lines):
        return False
    current = lines[line - 1]
    lines[line - 1] = current[:_offset(current, column)] + new + current[_offset(current, end_column):]
    return True


def _calls_at(tree: ast.Module, line: int) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call) and node.lineno == line]


def _constant(node: ast.expr, value: bool) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def _keyword_flip(text: str, line: int, argument: str, old: bool, *, method: str | None,
                  rationale: str, name: str) -> Fix | None:
    """Flip a literal boolean keyword argument of the one call on `line` that has it."""
    tree = _parse(text)
    if tree is None or "\r" in text:
        return None
    matches = [
        (call, keyword) for call in _calls_at(tree, line) for keyword in call.keywords
        if keyword.arg == argument and _constant(keyword.value, old)
        and (method is None or (isinstance(call.func, ast.Attribute) and call.func.attr == method))
    ]
    if len(matches) != 1:
        return None
    lines = text.split("\n")
    if not _replace(lines, matches[0][1].value, str(not old)):
        return None
    return Fix("\n".join(lines), rationale, name)


def tls_verification_on(text: str, line: int) -> Fix | None:
    """`verify=False` becomes `verify=True` in the HTTP call the finding points at."""
    return _keyword_flip(
        text, line, "verify", False, method=None, name="tls_verification_on",
        rationale="Turn certificate verification back on (verify=True) so the connection is checked.",
    )


def debug_off(text: str, line: int) -> Fix | None:
    """`app.run(debug=True)` becomes `app.run(debug=False)`."""
    return _keyword_flip(
        text, line, "debug", True, method="run", name="debug_off",
        rationale="Turn the debugger off (debug=False): debug mode lets anyone who can reach the app run code.",
    )


# ---- shell command strings to argument lists ---------------------------------------------------


@dataclass(frozen=True)
class _Part:
    literal: str | None = None
    value: str | None = None  # source of a plain name or attribute chain
    stringify: bool = False  # f-string parts are converted with str()


def _flatten(node: ast.expr, text: str) -> list[_Part] | None:
    """The pieces of `"literal" + name + ...` or an f-string, or None for any other shape."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [_Part(literal=node.value)]
    if isinstance(node, (ast.Name, ast.Attribute)) and _dotted(node) is not None:
        source = ast.get_source_segment(text, node)
        return [_Part(value=source)] if source else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _flatten(node.left, text), _flatten(node.right, text)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts: list[_Part] = []
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                parts.append(_Part(literal=item.value))
            elif (isinstance(item, ast.FormattedValue) and item.conversion == -1 and item.format_spec is None
                  and isinstance(item.value, (ast.Name, ast.Attribute)) and _dotted(item.value) is not None):
                source = ast.get_source_segment(text, item.value)
                if not source:
                    return None
                parts.append(_Part(value=source, stringify=True))
            else:
                return None
        return parts
    return None


def _elements(parts: Sequence[_Part]) -> list[str] | None:
    """Split the fixed text on whitespace into argv elements; a name stays inside its element."""
    elements: list[str] = []
    pieces: list[str] = []

    def flush() -> None:
        if pieces:
            elements.append(pieces[0] if len(pieces) == 1 else " + ".join(pieces))
            pieces.clear()

    for part in parts:
        if part.literal is not None:
            if not SAFE_LITERAL.fullmatch(part.literal):
                return None
            for chunk in re.split(r"(\s+)", part.literal):
                if chunk.isspace():
                    flush()
                elif chunk:
                    pieces.append(json.dumps(chunk))
        else:
            assert part.value is not None
            pieces.append(f"str({part.value})" if part.stringify else part.value)
    flush()
    return elements or None


def _import_line(tree: ast.Module) -> int | None:
    """Where to add `import subprocess`: after the leading imports, or None if it's already there."""
    last = 0
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        last = body[0].end_lineno or 1
        body = body[1:]
    for node in body:
        if isinstance(node, ast.Import):
            if any(alias.name == "subprocess" and alias.asname is None for alias in node.names):
                return None
            last = node.end_lineno or last
        elif isinstance(node, ast.ImportFrom):
            last = node.end_lineno or last
        else:
            break
    return last


def command_as_list(text: str, line: int) -> Fix | None:
    """`os.system("ping " + host)` or `subprocess.run(f"ping {host}", shell=True)` becomes a call
    with an argument list and no shell, when the fixed text is plain words and the program is one
    whose arguments the review accepts.

    `os.system` is only rewritten as a standalone statement, since its return value differs.
    """
    tree = _parse(text)
    if tree is None or "\r" in text:
        return None
    calls = [call for call in _calls_at(tree, line)
             if (_dotted(call.func) in SUBPROCESS_CALLS or _dotted(call.func) == "os.system") and call.args]
    if len(calls) != 1 or calls[0].lineno != calls[0].end_lineno:
        return None
    call = calls[0]
    name = _dotted(call.func)
    other_keywords = [keyword for keyword in call.keywords if keyword.arg != "shell"]
    if any(keyword.arg is None for keyword in call.keywords):
        return None
    if name == "os.system":
        statement = any(isinstance(node, ast.Expr) and node.value is call for node in ast.walk(tree))
        if len(call.args) != 1 or call.keywords or not statement:
            return None
    else:
        shell = [keyword for keyword in call.keywords if keyword.arg == "shell"]
        if len(shell) != 1 or not _constant(shell[0].value, True):
            return None
    parts = _flatten(call.args[0], text)
    elements = _elements(parts) if parts is not None else None
    if not elements or not PLAIN_LITERAL.fullmatch(elements[0]):
        return None  # the program itself must be one piece of fixed text
    program = posixpath.basename(json.loads(elements[0]))
    if program in SHELLS or program in OPTION_PROGRAMS:
        return None
    listed = "[" + ", ".join(elements) + "]"
    if name == "os.system":
        replacement = f"subprocess.run({listed})"
    else:
        function = ast.get_source_segment(text, call.func)
        rest = [ast.get_source_segment(text, node) for node in (*call.args[1:], *other_keywords)]
        if function is None or any(item is None for item in rest):
            return None
        replacement = f"{function}({', '.join([listed, *(item for item in rest if item)])})"
    lines = text.split("\n")
    if not _replace(lines, call, replacement):
        return None
    insert_after = _import_line(tree) if name == "os.system" else None
    if insert_after is not None:
        lines.insert(insert_after, "import subprocess")
    return Fix(
        "\n".join(lines),
        "Run the command with an argument list and no shell, so a value can't add commands "
        "(command injection); the fixed program and its options are unchanged.",
        "command_as_list",
    )


# ---- yaml.load to yaml.safe_load ---------------------------------------------------------------

# Loaders that can build arbitrary Python objects. Anything else (SafeLoader, BaseLoader, the C
# loaders, a variable) is left alone: the first is already safe and the rest change more than the call.
UNSAFE_YAML_LOADERS = frozenset({"Loader", "UnsafeLoader", "FullLoader"})
YAML_SAFE_CALL = {"load": "safe_load", "load_all": "safe_load_all",
                  "unsafe_load": "safe_load", "unsafe_load_all": "safe_load_all"}
YAML_SAFE_RATIONALE = (
    "Parse the document with yaml.safe_load, which only builds plain data (strings, numbers, lists, "
    "mappings, dates) and never Python objects. A document that relies on Python-specific tags such "
    "as !!python/object will now raise an error: Polaris did not run your code, so check that none do."
)


def _bindings(tree: ast.Module, name: str) -> list[ast.AST]:
    """Every place in the file that binds `name`, whatever the kind of binding."""
    found: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name and not isinstance(node.ctx, ast.Load):
            found.append(node)
        elif isinstance(node, ast.arg) and node.arg == name:
            found.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            found.append(node)
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            found.append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            found.extend(node for alias in node.names if (alias.asname or alias.name.split(".")[0]) == name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name:
            found.append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest == name:
            found.append(node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            found.append(node)
    return found


def _yaml_module_name(tree: ast.Module, name: str) -> bool:
    """`name` is the PyYAML module: every binding of it in the file is an `import yaml [as name]`."""
    bindings = _bindings(tree, name)
    return bool(bindings) and all(
        isinstance(node, ast.Import) and any(
            alias.name == "yaml" and (alias.asname or "yaml") == name for alias in node.names)
        for node in bindings
    )


def _yaml_loader_name(tree: ast.Module, name: str) -> str | None:
    """The yaml loader class a bare `name` stands for, when its only binding is `from yaml import X [as name]`."""
    bindings = _bindings(tree, name)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.ImportFrom):
        return None
    node = bindings[0]
    if node.level != 0 or node.module != "yaml":
        return None
    for alias in node.names:
        if (alias.asname or alias.name) == name:
            return alias.name
    return None


def _unsafe_loader(tree: ast.Module, node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.attr in UNSAFE_YAML_LOADERS and _yaml_module_name(tree, node.value.id)
    if isinstance(node, ast.Name):
        return _yaml_loader_name(tree, node.id) in UNSAFE_YAML_LOADERS
    return False


def yaml_safe_load(text: str, line: int) -> Fix | None:
    """`yaml.load(x)`, `yaml.load(x, Loader=yaml.Loader)` (also UnsafeLoader and FullLoader),
    `yaml.unsafe_load(x)` and their `_all` forms become `yaml.safe_load(x)` / `yaml.safe_load_all(x)`.

    Only the function name and the Loader argument change; the stream expression is not touched. The
    module has to be the PyYAML module (`import yaml`, optionally aliased), with no other binding of
    that name in the file. It declines everything else: other Loader values, extra arguments,
    `from yaml import load` (the safe function would need a new import), parenthesized or
    commented arguments, and two yaml calls on one line.
    """
    tree = _parse(text)
    if tree is None or "\r" in text:
        return None
    calls = [
        call for call in _calls_at(tree, line)
        if isinstance(call.func, ast.Attribute) and call.func.attr in YAML_SAFE_CALL
        and isinstance(call.func.value, ast.Name) and _yaml_module_name(tree, call.func.value.id)
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    assert isinstance(call.func, ast.Attribute)
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return None
    positions = Positions(text)
    whole, function = positions.span(call), positions.span(call.func)
    if whole is None or function is None or text[function[1] - len(call.func.attr):function[1]] != call.func.attr:
        return None
    edits: list[tuple[int, int, str]] = [
        (function[1] - len(call.func.attr), function[1], YAML_SAFE_CALL[call.func.attr])]
    unsafe_only = call.func.attr.startswith("unsafe_")
    loader: ast.AST | None = None
    if unsafe_only:
        if len(call.args) != 1 or call.keywords:
            return None
    else:
        if not call.args or len(call.args) > 2:
            return None
        keyword_loaders = [kw for kw in call.keywords if kw.arg == "Loader"]
        if len(call.args) == 2 and (call.keywords or not _unsafe_loader(tree, call.args[1])):
            return None
        if len(call.args) == 1 and call.keywords:
            if len(call.keywords) != 1 or not keyword_loaders or not _unsafe_loader(tree, keyword_loaders[0].value):
                return None
        loader = call.args[1] if len(call.args) == 2 else (keyword_loaders[0] if keyword_loaders else None)
    if loader is not None:
        stream, spot = positions.span(call.args[0]), positions.span(loader)
        if stream is None or spot is None:
            return None
        # Only whitespace and the separating comma may sit between the stream and the Loader, and only an
        # optional trailing comma after it: a comment or parenthesis there means this isn't the plain form.
        if not re.fullmatch(r"\s*,\s*", text[stream[1]:spot[0]]) or not re.fullmatch(r"\s*,?\s*\)", text[spot[1]:whole[1]]):
            return None
        edits.append((stream[1], spot[1], ""))
    edited = text
    for start, end, new in sorted(edits, reverse=True):
        edited = edited[:start] + new + edited[end:]
    return Fix(edited, YAML_SAFE_RATIONALE, "yaml_safe_load")


# The rules these apply to; a codemod only ever sees findings of its own rule.
CODEMODS: dict[str, tuple[Codemod, ...]] = {
    "polaris.python.tls_disabled": (tls_verification_on,),
    "polaris.python.debug_enabled": (debug_off,),
    "polaris.python.command_injection": (command_as_list,),
    "polaris.python.code_injection": (yaml_safe_load,),
    "polaris.python.sql_injection": (sql_parameters,),
    "polaris.gha.workflow_injection.run": (env_indirection,),
    "polaris.js.unsafe_security_configuration.tls_disabled": (reject_unauthorized_true, node_tls_unset),
}

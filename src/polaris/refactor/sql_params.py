"""Move the values of a DB-API `execute()` call out of its SQL text and into parameters.

    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))

This is the riskiest codemod, so it only handles shapes where the meaning can be read off the
syntax, and it declines the moment anything is unclear:

- the first argument is the whole query, built inline by `+`, an f-string, `%` or `.format()`;
- each inserted piece is a plain name, attribute or constant subscript (never a call), and sits in
  value position: right after a comparison operator or inside `VALUES (...)`. A quoted piece must
  fill its quotes exactly (`'` + value + `'`), and the quotes are removed with it. A piece inside
  a longer string (`'%` + value + `%'`), after `IN`, `LIKE`, `LIMIT`, `ORDER BY`, `FROM` or in
  any other position is declined, because a placeholder there would mean something else;
- the query is a plain SELECT, INSERT, UPDATE or DELETE with no comments, no second statement, no
  backslashes, no double quotes and no text that already looks like a placeholder;
- the placeholder style comes from the file's imports: `?` for sqlite3, `%s` for psycopg2,
  psycopg, pymysql, MySQLdb and mysql.connector. A file that imports two styles, or any other
  database library (SQLAlchemy, Django, asyncpg, ...), is declined.

Values are then sent as the values themselves instead of being turned into text first, so a
value that was not a string is bound with its own type. Nothing here runs the code.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from polaris.refactor.fixes import Fix, Positions

# DB-API modules whose parameter style is fixed by the module (`paramstyle`).
PLACEHOLDERS = {
    "sqlite3": "?", "psycopg2": "%s", "psycopg": "%s", "pymysql": "%s", "MySQLdb": "%s", "mysql.connector": "%s",
}
# Libraries whose `execute` takes other query shapes or other bind syntax: a file that uses one is
# declined, because the receiver of `.execute(` could be theirs.
OTHER_DATABASE_ROOTS = frozenset({
    "sqlalchemy", "django", "peewee", "pony", "asyncpg", "aiosqlite", "aiomysql", "aiopg", "pg8000", "pyodbc",
    "pymssql", "cx_Oracle", "oracledb", "duckdb", "snowflake", "databases", "records", "sqlmodel", "tortoise",
    "mariadb", "clickhouse_driver", "apsw", "dataset", "cassandra", "ibm_db", "teradatasql", "trino", "pyhive",
    "sqlite_utils", "pandas", "ibis", "jaydebeapi", "pymongo", "redis",
})
STATEMENT = re.compile(r"(?i)\s*(select|insert|update|delete)\b")
# A value may follow a comparison operator, or sit in an INSERT's VALUES list after other plain values.
COMPARISON = re.compile(r"(?:=|<>|!=|<=|>=|<|>)$")
VALUES_LIST = re.compile(r"(?is)\bvalues\s*\((?:\s*(?:\x00|'[^']*'|-?\d+(?:\.\d+)?|null)\s*,)*$")
# Text that would be misread once parameters are passed, or that this codemod does not model.
UNSUPPORTED_TEXT = ("\"", "`", "\\", ";", "$", "?", "--", "/*", "*/", "''", ":", "@", "\x00")
MAX_VALUE_SOURCE = 80

RATIONALE = (
    "Send the values as query parameters instead of building them into the SQL text, so a value can't "
    "change the statement (SQL injection). The SQL text keeps its shape and the quotes around each value "
    "are removed with it. Values are now sent as their own type instead of as text; Polaris did not run "
    "your code, so run your tests."
)


@dataclass(frozen=True)
class _Text:
    value: str


@dataclass(frozen=True)
class _Value:
    source: str


_Piece = _Text | _Value


def _chain(node: ast.expr) -> bool:
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)


def _root(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _plain_value(node: ast.expr) -> str | None:
    """Source of a name, attribute chain or constant subscript of one; None for anything else.

    ALL_CAPS roots are module constants, often SQL fragments, so they are not treated as values.
    """
    if isinstance(node, ast.Subscript):
        index = node.slice
        constant = isinstance(index, ast.Constant) and isinstance(index.value, (str, int)) \
            and not isinstance(index.value, bool)
        if not (constant or (isinstance(index, ast.Name) and not index.id.isupper())) or not _chain(node.value):
            return None
    elif not (isinstance(node, (ast.Name, ast.Attribute)) and _chain(node)):
        return None
    root = _root(node)
    if root is None or root.isupper():
        return None
    source = ast.unparse(node)
    return source if len(source) <= MAX_VALUE_SOURCE else None


def _merged(pieces: list[_Piece]) -> list[_Piece]:
    merged: list[_Piece] = []
    for piece in pieces:
        if merged and isinstance(piece, _Text) and isinstance(merged[-1], _Text):
            merged[-1] = _Text(merged[-1].value + piece.value)
        else:
            merged.append(piece)
    return merged


def _concatenation(node: ast.expr) -> list[_Piece] | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _concatenation(node.left), _concatenation(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [_Text(node.value)]
    source = _plain_value(node)
    return [_Value(source)] if source else None


def _fstring(node: ast.JoinedStr) -> list[_Piece] | None:
    pieces: list[_Piece] = []
    for item in node.values:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            pieces.append(_Text(item.value))
        elif isinstance(item, ast.FormattedValue) and item.conversion == -1 and item.format_spec is None:
            source = _plain_value(item.value)
            if source is None:
                return None
            pieces.append(_Value(source))
        else:
            return None
    return pieces


def _template(template: str, marker: str, sources: list[str]) -> list[_Piece] | None:
    """Split a `%s` or `{}` template over its values; any other use of the marker characters declines."""
    parts = re.split("(" + re.escape(marker) + ")", template)
    pieces: list[_Piece] = []
    values = iter(sources)
    for part in parts:
        if part == marker:
            source = next(values, None)
            if source is None:
                return None
            pieces.append(_Value(source))
        else:
            if any(char in part for char in ("%" if marker == "%s" else "{}")):
                return None
            pieces.append(_Text(part))
    return pieces if next(values, None) is None else None


def _pieces(node: ast.expr) -> list[_Piece] | None:
    """The SQL text and the values it is built from, for the four string-building forms."""
    found: list[_Piece] | None = None
    if isinstance(node, ast.JoinedStr):
        found = _fstring(node)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            operands = list(node.right.elts) if isinstance(node.right, ast.Tuple) else [node.right]
            sources = [_plain_value(item) for item in operands if not isinstance(item, ast.Starred)]
            if len(sources) == len(operands) and all(sources):
                found = _template(node.left.value, "%s", [item for item in sources if item])
    elif isinstance(node, ast.BinOp):
        found = _concatenation(node)
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
          and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
          and not node.keywords and not any(isinstance(arg, ast.Starred) for arg in node.args)):
        sources = [_plain_value(arg) for arg in node.args]
        if all(sources):
            found = _template(node.func.value.value, "{}", [item for item in sources if item])
    return _merged(found) if found else None


def _value_context(text: str) -> bool:
    before = text.rstrip()
    return bool(COMPARISON.search(before) or VALUES_LIST.search(before))


def _rebuilt(pieces: list[_Piece], placeholder: str) -> tuple[str, list[str]] | None:
    """The query with a placeholder for every value, and the values in order; None when any value is not
    in a position this codemod can prove to be a plain value."""
    first = pieces[0]
    if not isinstance(first, _Text) or not STATEMENT.match(first.value):
        return None
    out = ""
    params: list[str] = []
    in_quote = False  # inside a '...' literal of the query
    opened_in_value_position = False
    opened_at = -1
    expect_close = False  # a quoted value was replaced: the next text starts with its closing quote
    boundary = False  # a placeholder was just written: the next character must end the token
    for piece in pieces:
        if isinstance(piece, _Text):
            text = piece.value
            if not text.isprintable() or any(bad in text for bad in UNSUPPORTED_TEXT):
                return None
            if expect_close:
                if not text.startswith("'"):
                    return None
                text, expect_close = text[1:], False
            if boundary and text:
                if text[0] not in " ,)":
                    return None
                boundary = False
            for char in text:
                if char == "'":
                    if in_quote:
                        in_quote = False
                    else:
                        in_quote, opened_in_value_position, opened_at = True, _value_context(out), len(out)
                out += char
            continue
        if boundary or expect_close:
            return None
        if in_quote:
            # Only a value that fills its quotes exactly: the quote just opened is the last character.
            if not (opened_in_value_position and opened_at == len(out) - 1):
                return None
            out, in_quote, expect_close = out[:-1] + "\x00", False, True
        else:
            if not _value_context(out):
                return None
            out += "\x00"
        boundary = True
        params.append(piece.source)
    if in_quote or expect_close or not params:
        return None
    if placeholder == "%s" and "%" in out:
        return None
    return out.replace("\x00", placeholder), params


def _placeholder_style(tree: ast.Module) -> str | None:
    """The one placeholder style the file's imports agree on; None for no driver, two styles or any
    other database library."""
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module)
            if node.module == "mysql":
                modules.update(f"mysql.{alias.name}" for alias in node.names)
    styles: set[str] = set()
    for module in modules:
        if module.split(".")[0] in OTHER_DATABASE_ROOTS:
            return None
        styles.update(style for name, style in PLACEHOLDERS.items()
                      if module == name or module.startswith(name + "."))
    return next(iter(styles)) if len(styles) == 1 else None


def _receiver_ok(node: ast.expr) -> bool:
    """A cursor or connection reached by a plain name, or `<that>.cursor()`."""
    if isinstance(node, ast.Call):
        return (isinstance(node.func, ast.Attribute) and node.func.attr == "cursor" and not node.args
                and not node.keywords and _chain(node.func.value))
    return _chain(node)


def sql_parameters(text: str, line: int) -> Fix | None:
    """`cursor.execute("... '" + value + "'")` becomes `cursor.execute("... ?", (value,))`.

    See the module notes for what is handled; everything else is declined.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    if "\r" in text:
        return None
    placeholder = _placeholder_style(tree)
    if placeholder is None:
        return None
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and node.lineno == line and isinstance(node.func, ast.Attribute)
             and node.func.attr == "execute"]
    if len(calls) != 1:
        return None
    call = calls[0]
    assert isinstance(call.func, ast.Attribute)
    if len(call.args) != 1 or call.keywords or not _receiver_ok(call.func.value):
        return None
    pieces = _pieces(call.args[0])
    rebuilt = _rebuilt(pieces, placeholder) if pieces else None
    if rebuilt is None:
        return None
    sql, params = rebuilt
    positions = Positions(text)
    function, argument, whole = positions.span(call.func), positions.span(call.args[0]), positions.span(call)
    if function is None or argument is None or whole is None:
        return None
    # The query must be the only argument and stand directly inside the call's parentheses: no extra
    # parentheses (the new argument is two items), no comment, no other argument.
    if not re.fullmatch(r"\s*\(\s*", text[function[1]:argument[0]]) \
            or not re.fullmatch(r"\s*,?\s*\)", text[argument[1]:whole[1]]):
        return None
    bound = f"({params[0]},)" if len(params) == 1 else "(" + ", ".join(params) + ")"
    replacement = f'"{sql}", {bound}'
    return Fix(text[:argument[0]] + replacement + text[argument[1]:], RATIONALE, "sql_parameters")

"""Turn Node's TLS certificate checks back on, on tree-sitter nodes (never by searching text).

Two shapes, both reported by `polaris.js.unsafe_security_configuration.tls_disabled`:

- `{ rejectUnauthorized: false }` becomes `{ rejectUnauthorized: true }`: only the `false` literal's
  exact byte range changes;
- the statement `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` is deleted, which gives the process
  Node's default (certificates are checked) back.

The file has to parse without any error. The second codemod also re-parses its result and checks
that the enclosing block lost exactly that statement and nothing was merged into its neighbours
(removing a line can change how a following line without a semicolon is read).

Neither can know whether the program talks to a server whose certificate Node doesn't trust: after
the fix such a connection fails until the right CA is configured. The rationale says so. Nothing
here runs the code.
"""

from __future__ import annotations

import re
from typing import Any

from polaris.refactor.fixes import Fix

MAX_NODES = 200_000
GRAMMARS = ("javascript", "typescript", "tsx")
ENV_NAMES = frozenset({
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED",
    "process.env['NODE_TLS_REJECT_UNAUTHORIZED']",
    'process.env["NODE_TLS_REJECT_UNAUTHORIZED"]',
})
BLANK = re.compile(rb"[ \t]*")

REJECT_RATIONALE = (
    "Turn certificate verification back on (rejectUnauthorized: true) so the connection is checked. A "
    "server with a self-signed or mismatched certificate will now be refused until its certificate is "
    "trusted (for example with the ca option); Polaris did not run your code."
)
ENV_RATIONALE = (
    "Remove the line that turns off TLS certificate checking for the whole process "
    "(NODE_TLS_REJECT_UNAUTHORIZED = '0'), so Node's default applies and certificates are verified. A "
    "server with a self-signed certificate will now be refused until Node trusts it (for example with "
    "NODE_EXTRA_CA_CERTS); Polaris did not run your code."
)


def _parse(source: bytes) -> Any | None:
    """The root node of the first grammar that reads the file without any error."""
    from tree_sitter import Parser

    from polaris.review.js.engine import _language

    for grammar in GRAMMARS:
        try:
            root = Parser(_language(grammar)).parse(source).root_node
        except (ValueError, RuntimeError, MemoryError):
            continue
        if not root.has_error:
            return root
    return None


def _walk(root: Any) -> list[Any] | None:
    """Every node, or None for a tree too large to handle."""
    found: list[Any] = []
    stack = [root]
    while stack:
        node = stack.pop()
        found.append(node)
        if len(found) > MAX_NODES:
            return None
        stack.extend(reversed(node.children))
    return found


def _text(node: Any, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _string_value(node: Any, source: bytes) -> str | None:
    """The value of a plain string literal (no escapes, no template substitutions), else None."""
    if node.type != "string":
        return None
    raw = _text(node, source)
    if len(raw) < 2 or raw[0] not in "'\"" or raw[-1] != raw[0] or "\\" in raw:
        return None
    return raw[1:-1]


def _line(node: Any) -> int:
    return int(node.start_point[0]) + 1


def _prepared(text: str) -> tuple[bytes, list[Any]] | None:
    if "\r" in text:
        return None
    source = text.encode("utf-8")
    root = _parse(source)
    nodes = _walk(root) if root is not None else None
    return (source, nodes) if nodes is not None else None


def reject_unauthorized_true(text: str, line: int) -> Fix | None:
    """`rejectUnauthorized: false` becomes `rejectUnauthorized: true` in the object literal the finding
    points at. Declines a value that isn't the bare `false` literal, a key that isn't spelled out, and
    a line with two such pairs."""
    prepared = _prepared(text)
    if prepared is None:
        return None
    source, nodes = prepared
    values: list[Any] = []
    for node in nodes:
        if node.type != "pair" or _line(node) != line or node.parent is None or node.parent.type != "object":
            continue
        key, value = node.child_by_field_name("key"), node.child_by_field_name("value")
        if key is None or value is None or value.type != "false":
            continue
        name = _text(key, source) if key.type == "property_identifier" else _string_value(key, source)
        if name == "rejectUnauthorized":
            values.append(value)
    if len(values) != 1:
        return None
    edited = source[:values[0].start_byte] + b"true" + source[values[0].end_byte:]
    if _parse(edited) is None:
        return None
    return Fix(edited.decode("utf-8"), REJECT_RATIONALE, "tls_reject_unauthorized_true")


def _is_tls_env_target(node: Any, source: bytes) -> bool:
    if node.type not in ("member_expression", "subscript_expression"):
        return False
    return re.sub(r"\s+", "", _text(node, source)) in ENV_NAMES


def _path_to(node: Any) -> list[int] | None:
    """The child indexes that lead from the root to `node`."""
    path: list[int] = []
    while node.parent is not None:
        parent = node.parent
        index = next((i for i, child in enumerate(parent.children) if child == node), None)
        if index is None:
            return None
        path.append(index)
        node = parent
    return path[::-1]


def node_tls_unset(text: str, line: int) -> Fix | None:
    """Delete the statement `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` (or `= 0`, or the bracket
    form) when it is a statement of its own, alone on its line(s), directly in a file or a `{ }` block.

    It declines a chained or nested assignment, an unbraced `if (x) process.env... = '0'` (deleting the
    statement would hand the `if` to the next line), a trailing comment or other code on the line, and
    any removal after which the enclosing block does not hold exactly the same other statements.
    """
    prepared = _prepared(text)
    if prepared is None:
        return None
    source, nodes = prepared
    targets: list[Any] = []
    for node in nodes:
        if node.type != "assignment_expression" or _line(node) != line:
            continue
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None or not _is_tls_env_target(left, source):
            continue
        if not (_text(right, source) == "0" and right.type == "number" or _string_value(right, source) == "0"):
            continue
        targets.append(node)
    if len(targets) != 1:
        return None
    statement = targets[0].parent
    if statement is None or statement.type != "expression_statement" or len(statement.named_children) != 1:
        return None
    block = statement.parent
    if block is None or block.type not in ("program", "statement_block"):
        return None
    line_start = source.rfind(b"\n", 0, statement.start_byte) + 1
    newline = source.find(b"\n", statement.end_byte)
    line_end = len(source) if newline < 0 else newline
    if not BLANK.fullmatch(source[line_start:statement.start_byte]) \
            or not BLANK.fullmatch(source[statement.end_byte:line_end]):
        return None
    siblings = list(block.named_children)
    position = siblings.index(statement)
    after = next((item for item in siblings[position + 1:] if item.type != "comment"), None)
    if after is not None and after.type == "expression_statement" and after.named_children \
            and after.named_children[0].type == "string":
        return None  # the next line would become a directive prologue
    edited = source[:line_start] + source[min(len(source), line_end + 1):]
    path = _path_to(block)
    new_root = _parse(edited)
    if path is None or new_root is None:
        return None
    new_block = new_root
    for index in path:
        if index >= len(new_block.children):
            return None
        new_block = new_block.children[index]
    expected = [_text(item, source) for item in siblings if item != statement]
    if new_block.type != block.type or [_text(item, edited) for item in new_block.named_children] != expected:
        return None
    return Fix(edited.decode("utf-8"), ENV_RATIONALE, "tls_env_check_restored")

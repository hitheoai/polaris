"""Cheap, deterministic checks every candidate passes before it is re-reviewed.

A fix for one finding should change code near that finding and little else. Nothing here can
prove a fix is right; it only refuses candidates that wander (a model rewriting a whole file, a
codemod editing somewhere else) so that what a person reviews stays small and local.
"""

from __future__ import annotations

import ast
import difflib
import re
from typing import Any

from polaris.review.models import WorkflowFinding

WINDOW = 40  # lines around the finding where a fix may change code
MAX_CHANGED_LINES = 60
# Adding an import is the one change a fix often needs far from the finding.
IMPORT_LINE = re.compile(r"^(?:import [A-Za-z_][\w.]*(?: as \w+)?(?:, ?[A-Za-z_][\w.]*(?: as \w+)?)*"
                         r"|from [A-Za-z_][\w.]* import [\w*, ]+)$")
IMPORT_REGION = 200


def argument_names(text: str, line: int) -> set[str]:
    """Variable names read in the arguments of the calls that start on `line` (Python).

    Callees (`str` in `str(x)`, `db` in `db.execute(...)`) are not values, so they are skipped.
    An unparseable file or a line with no call gives an empty set.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    callees = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno == line:
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                for child in ast.walk(argument):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and id(child) not in callees:
                        names.add(child.id)
    return names


def drops_a_value(original: str, replacement: str, finding: WorkflowFinding) -> bool:
    """True when a value the flagged call read no longer appears in any line the fix adds.

    A fix may stop passing a value through the dangerous path, but it must still use it: an AI that
    turns `execute("... " + name)` into `execute("... %s")` removes the injection and the value too,
    and the code stops working. The same answer that keeps `user` but drops `user.name` is the same
    failure. The static re-review can't see either, because a constant query is safe, so this check
    does. It reads Python with `ast` and JavaScript/TypeScript with tree-sitter, and only values in
    the sink call's own arguments (not names only a callback reads). `user["name"]` counts as
    `user.name`. It can miss a drop: a value copied into a variable that nothing then reads, an
    index it can't represent, a language it doesn't parse, or a file that doesn't parse. It never
    blocks a fix on a guess, and a file that doesn't parse is the re-review's to report.
    """
    if _language_of(finding.path) is None:
        return False
    required = _call_reads(original, finding.path, finding.start_line)
    if not required:
        return False
    before, after = original.splitlines(), replacement.splitlines()
    opcodes = difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes()
    if not any(tag in ("replace", "delete") and start <= finding.start_line - 1 < end
               for tag, start, end, _, _ in opcodes):
        return False  # the flagged line itself is untouched: nothing was dropped from it
    added = {number + 1 for tag, _, _, new_start, new_end in opcodes if tag in ("insert", "replace")
             for number in range(new_start, new_end)}
    used = _reads_on_lines(replacement, finding.path, added)
    if used is None:
        return False
    return not required <= used


def _language_of(path: str) -> str | None:
    lowered = path.lower()
    if lowered.endswith((".py", ".pyi")):
        return "python"
    if lowered.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if lowered.endswith(".tsx"):
        return "tsx"
    if lowered.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    return None


def _call_reads(text: str, path: str, line: int) -> set[str]:
    """Values read by calls that start on `line`. Empty when the file can't be read."""
    if _language_of(path) == "python":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return set()
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno == line:
                found |= {item for item, _lineno in _py_argument_reads(node)}
        return found
    root = _js_tree(text, path)
    if root is None:
        return set()
    return {item for item, _lineno in _js_calls_on(root, line)}


def _reads_on_lines(text: str, path: str, lines: set[int]) -> set[str] | None:
    """Value reads on `lines`, or None when the file can't be read (don't guess)."""
    if _language_of(path) == "python":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return None
        return {item for item, lineno in _py_value_reads(tree) if lineno in lines}
    root = _js_tree(text, path)
    if root is None:
        return None
    return {item for item, lineno in _js_value_reads(root, skip_functions=False) if lineno in lines}


_PY_IDENT = re.compile(r"^[A-Za-z_]\w*$")
_JS_IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_JS_WRAPPERS = frozenset({
    "parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression",
    "type_assertion",
})
_JS_FUNCTIONS = frozenset({
    "function_expression", "function", "arrow_function", "generator_function",
    "generator_function_declaration", "function_declaration", "method_definition",
    "class_declaration", "class", "class_expression",
})


def _py_path(node: ast.AST) -> str | None:
    """A value this node reads, or None. `user.name` and `user["name"]` are the same value."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        base = _py_path(node.value)
        if base is None or not _PY_IDENT.fullmatch(node.attr):
            return None
        return f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        base = _py_path(node.value)
        return None if base is None else _index(base, node.slice, _py_path)
    return None


def _index(base: str, node: ast.AST, path_of: Any) -> str | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str) and _PY_IDENT.fullmatch(node.value):
            return f"{base}.{node.value}"
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return f"{base}[{node.value}]"
        return None
    indexed = path_of(node)
    if indexed is not None and _PY_IDENT.fullmatch(indexed):
        return f"{base}[{indexed}]"
    return None


def _py_value_reads(node: ast.AST, *, skip_nested: bool = False) -> set[tuple[str, int]]:
    if skip_nested and isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return set()
    if isinstance(node, ast.Call):
        found: set[tuple[str, int]] = set()
        for arg in [*node.args, *(keyword.value for keyword in node.keywords)]:
            found |= _py_value_reads(arg, skip_nested=skip_nested)
        func = node.func
        if isinstance(func, ast.Attribute):
            found |= _py_value_reads(func.value, skip_nested=skip_nested)  # the receiver, not the method
        elif not isinstance(func, ast.Name):
            found |= _py_value_reads(func, skip_nested=skip_nested)
        return found
    path = _py_path(node)
    if path is not None and isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return {(path, node.lineno)}
    found = set()
    for child in ast.iter_child_nodes(node):
        found |= _py_value_reads(child, skip_nested=skip_nested)
    return found


def _callee_root(func: ast.AST) -> str | None:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    if isinstance(func, ast.Name):
        return func.id
    return None


def _module_option(node: ast.AST, receiver: str) -> bool:
    """`yaml.Loader` on `yaml.load` is the option the fix removes, not a value the call used."""
    if not isinstance(node, ast.Attribute):
        return False
    root = node.value
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id == receiver


def _py_argument_reads(call: ast.Call) -> set[tuple[str, int]]:
    receiver = _callee_root(call.func)
    found: set[tuple[str, int]] = set()
    for arg in [*call.args, *(keyword.value for keyword in call.keywords)]:
        if receiver and _module_option(arg, receiver):
            continue
        found |= _py_value_reads(arg, skip_nested=True)
    return found


def _js_tree(text: str, path: str) -> Any | None:
    """A parse tree, or None when it can't be read. An error node is not a basis for a refusal."""
    try:
        from tree_sitter import Parser

        from polaris.review.js.engine import _language, grammar_for

        tree = Parser(_language(grammar_for(path))).parse(text.encode())
    except (ImportError, OSError, ValueError, AttributeError, TypeError, UnicodeError, RecursionError, MemoryError):
        return None
    root = tree.root_node
    return None if root.has_error else root


def _unwrap(node: Any) -> Any:
    while node is not None and node.type in _JS_WRAPPERS:
        inner = next((child for child in node.named_children if child.type != "comment"), None)
        if inner is None:
            break
        node = inner
    return node


def _js_line(node: Any) -> int:
    return int(node.start_point[0]) + 1


def _js_text(node: Any) -> str:
    value = node.text
    return value.decode("utf-8", "replace") if value is not None else ""


def _js_string(node: Any) -> str | None:
    from polaris.review.js.engine import string_value

    return string_value(node)


def _js_path(node: Any) -> str | None:
    node = _unwrap(node)
    if node is None:
        return None
    if node.type in ("identifier", "this", "super", "shorthand_property_identifier"):
        text = _js_text(node)
        return text if _JS_IDENT.fullmatch(text) else None
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop is None or prop.type != "property_identifier":
            return None
        base = _js_path(node.child_by_field_name("object"))
        attr = _js_text(prop)
        if base is None or not _JS_IDENT.fullmatch(attr):
            return None
        return f"{base}.{attr}"
    if node.type == "subscript_expression":
        base = _js_path(node.child_by_field_name("object"))
        index = _unwrap(node.child_by_field_name("index"))
        if base is None or index is None:
            return None
        if index.type == "string":
            value = _js_string(index)
            if value is not None and _JS_IDENT.fullmatch(value):
                return f"{base}.{value}"
            return None
        if index.type == "number" and re.fullmatch(r"\d+", _js_text(index)):
            return f"{base}[{_js_text(index)}]"
        if index.type == "unary_expression":
            inner = _unwrap(next(iter(index.named_children), None))
            if inner is not None and inner.type == "number" and re.fullmatch(r"\d+", _js_text(inner)) \
                    and _js_text(index).lstrip().startswith("-"):
                return f"{base}[-{_js_text(inner)}]"
            return None
        indexed = _js_path(index)
        if indexed is not None and _JS_IDENT.fullmatch(indexed):
            return f"{base}[{indexed}]"
    return None


def _js_arguments(node: Any) -> Any:
    args = node.child_by_field_name("arguments")
    if args is not None:
        return args
    return next((child for child in node.named_children if child.type == "arguments"), None)


def _js_value_reads(node: Any, *, skip_functions: bool) -> set[tuple[str, int]]:
    if node is None or node.type in ("comment", "import_statement"):
        return set()
    if node.type in _JS_FUNCTIONS:
        if skip_functions:
            return set()
        return _js_value_reads(node.child_by_field_name("body"), skip_functions=False)
    if node.type in ("call_expression", "new_expression"):
        return _js_value_reads(_js_arguments(node), skip_functions=skip_functions)
    if node.type == "variable_declarator":
        return _js_value_reads(node.child_by_field_name("value"), skip_functions=skip_functions)
    if node.type == "assignment_expression":
        found = _js_value_reads(node.child_by_field_name("right"), skip_functions=skip_functions)
        left = node.child_by_field_name("left")
        if left is not None and left.type not in ("identifier", "object_pattern", "array_pattern"):
            found |= _js_value_reads(left, skip_functions=skip_functions)
        return found
    if node.type in ("for_in_statement", "for_of_statement"):
        return (_js_value_reads(node.child_by_field_name("right"), skip_functions=skip_functions)
                | _js_value_reads(node.child_by_field_name("body"), skip_functions=skip_functions))
    if node.type in ("catch_clause",):
        return _js_value_reads(node.child_by_field_name("body"), skip_functions=skip_functions)
    if node.type in ("object_pattern", "array_pattern", "formal_parameters", "rest_pattern",
                     "shorthand_property_identifier_pattern"):
        return set()
    path = _js_path(node)
    if path is not None:
        return {(path, _js_line(node))}
    found = set()
    for child in node.named_children:
        found |= _js_value_reads(child, skip_functions=skip_functions)
    return found


def _js_calls_on(node: Any, line: int) -> set[tuple[str, int]]:
    found: set[tuple[str, int]] = set()
    if node.type in ("call_expression", "new_expression") and _js_line(node) == line:
        found |= _js_value_reads(_js_arguments(node), skip_functions=True)
    for child in node.named_children:
        found |= _js_calls_on(child, line)
    return found


def scope_problem(
    original: str, replacement: str, finding: WorkflowFinding, *,
    window: int = WINDOW, max_changed_lines: int = MAX_CHANGED_LINES,
) -> str | None:
    """A short reason code when the replacement strays from the finding, else None."""
    before, after = original.splitlines(), replacement.splitlines()
    low = finding.start_line - window
    high = max(finding.start_line, finding.end_line or finding.start_line) + window
    changed = 0
    for tag, start, end, new_start, new_end in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        changed += (end - start) + (new_end - new_start)
        if tag == "insert":
            inserted = after[new_start:new_end]
            if start <= IMPORT_REGION and all(IMPORT_LINE.fullmatch(line.strip()) for line in inserted) \
                    and all(line == line.strip() for line in inserted):
                continue  # a top-level import added near the top of the file
            if not low - 1 <= start <= high:
                return "change_outside_scope"
        elif start + 1 < low or end > high:
            return "change_outside_scope"
    if changed == 0:
        return "no_change"
    if changed > max_changed_lines:
        return "change_too_large"
    if drops_a_value(original, replacement, finding):
        return "fix_drops_a_value"
    return None

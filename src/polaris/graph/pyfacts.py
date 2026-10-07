"""Python facts of one file: imports, definitions, calls with argument facts, references.

`extract_python(path, text)` depends on nothing but its two arguments, so its result can be
cached by the file's digest. Nothing here looks at other files; the builder resolves names across
files. Code is parsed, never imported or executed.

Request-handler recognition and the taint rules are the review analyzer's own
(`polaris.review.analyzers.python._entry_kind`, `polaris.review.dataflow`): the graph does not
invent a second data-flow engine. It records, for every call, what each argument is made of, using
the same forward pass the analyzer runs per function.
"""

from __future__ import annotations

import ast
import posixpath
from dataclasses import dataclass, field
from typing import Any

from polaris.graph.model import MODULE_SUFFIX, ArgFact, ParamFact, SinkFact
from polaris.review.analyzers.python import ROUTE_DECORATORS, VIEW_DECORATORS, _entry_kind
from polaris.review.dataflow import (
    CHECK_FOR_KIND,
    ArgInfo,
    _Analyzer,
    dotted,
    module_http_clients,
    module_imports,
)
from polaris.review.extract import _definitions, _module_statements, parse

MAX_AST_NODES_PER_UNIT = 100_000
LITERAL_TYPES = (str, bytes, int, float, complex, bool, type(None), type(Ellipsis))
HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
VIEWSET_ACTIONS = frozenset({"list", "create", "retrieve", "update", "partial_update", "destroy"})


@dataclass(slots=True)
class RawImport:
    line: int
    scope: str  # qualified name of the enclosing function, "" at module level
    kind: str  # import | from | star
    module: str  # dotted name; relative imports keep their dots
    level: int
    name: str
    alias: str | None


@dataclass(slots=True)
class Binding:
    kind: str  # def | class | import | assign | other
    ref: Any  # qualname (def/class), import index (import), literal flag (assign)
    line: int


@dataclass(slots=True)
class RawDef:
    qualname: str
    kind: str  # function | method | class
    is_async: bool
    line: int
    end_line: int
    parent: str | None  # qualname of the enclosing class/function
    params: tuple[ParamFact, ...]
    decorators: tuple[str, ...]
    bases: tuple[tuple[str, ...] | None, ...]
    static: bool
    analysis_unit: bool
    analyzer_entry: str | None
    mutating: bool
    class_view: bool
    sinks: tuple[SinkFact, ...] = ()


@dataclass(slots=True)
class RawCall:
    caller: str  # definition qualname or MODULE_SUFFIX
    line: int
    column: int
    chain: tuple[str, ...] | None
    last: str | None  # last attribute name for calls on computed receivers
    binding: tuple[str, Any]  # how the chain's first name is bound at the call site
    args: tuple[ArgFact, ...]


@dataclass(slots=True)
class RawRef:
    source: str
    line: int
    chain: tuple[str, ...]
    binding: tuple[str, Any]


@dataclass(slots=True)
class FileFacts:
    path: str
    status: str = "ok"
    imports: list[RawImport] = field(default_factory=list)
    bindings: dict[str, list[Binding]] = field(default_factory=dict)
    defs: list[RawDef] = field(default_factory=list)
    calls: list[RawCall] = field(default_factory=list)
    refs: list[RawRef] = field(default_factory=list)
    all_names: tuple[str, ...] | None | str = None  # tuple, None (absent) or "dynamic"
    global_names: frozenset[str] = frozenset()
    nodes: int = 0


# ---- small helpers --------------------------------------------------------------------------


def chain_of(node: ast.AST) -> tuple[str, ...] | None:
    """`a.b.c` as ("a", "b", "c"), or None when the expression is not a plain dotted name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return (node.id, *reversed(parts))
    return None


def is_literal(node: ast.AST | None) -> bool:
    """A value made only of constants (no names, no calls)."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, LITERAL_TYPES)
    if isinstance(node, ast.JoinedStr):
        return all(is_literal(value.value) if isinstance(value, ast.FormattedValue) else is_literal(value)
                   for value in node.values)
    if isinstance(node, ast.BinOp):
        return is_literal(node.left) and is_literal(node.right)
    if isinstance(node, ast.UnaryOp):
        return is_literal(node.operand)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(is_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and is_literal(key) and is_literal(value)
                   for key, value in zip(node.keys, node.values, strict=True))
    return False


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> tuple[str, ...]:
    names = []
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        names.append(dotted(target, {}) or "<expression>")
    return tuple(names)


def _params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ParamFact, ...]:
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    result: list[ParamFact] = []

    def default_of(value: ast.expr | None) -> str:
        if value is None:
            return "none"
        return "literal" if is_literal(value) else "other"

    for index, argument in enumerate(positional):
        kind = "posonly" if index < len(args.posonlyargs) else "pos"
        result.append(ParamFact(argument.arg, kind, default_of(defaults[index])))  # type: ignore[arg-type]
    if args.vararg is not None:
        result.append(ParamFact(args.vararg.arg, "vararg"))
    for argument, value in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        result.append(ParamFact(argument.arg, "kwonly", default_of(value)))  # type: ignore[arg-type]
    if args.kwarg is not None:
        result.append(ParamFact(args.kwarg.arg, "varkw"))
    return tuple(result)


def _class_view(node: ast.FunctionDef | ast.AsyncFunctionDef, class_node: ast.ClassDef) -> bool:
    """A method of a class-based view (a base named ...View/ViewSet) taking `request`.

    The review analyzer does not recognize these; the graph does and says so on the entry point.
    """
    bases = [chain_of(base) for base in class_node.bases]
    if not any(base and base[-1].endswith(("View", "ViewSet", "APIView")) for base in bases):
        return False
    names = [argument.arg for argument in node.args.args]
    if len(names) < 2 or names[1] != "request":
        return False
    return node.name in HTTP_VERBS or node.name in VIEWSET_ACTIONS


# ---- scopes ---------------------------------------------------------------------------------


@dataclass(slots=True)
class _Scope:
    kind: str  # module | function | class
    qualname: str
    parent: _Scope | None
    locals: dict[str, tuple[str, Any]] = field(default_factory=dict)
    first_param: str | None = None
    method_class: str | None = None
    class_param: bool = False  # the first parameter is the class (classmethod)
    declared_global: frozenset[str] = frozenset()


def _target_names(target: ast.AST) -> list[str]:
    return [item.id for item in ast.walk(target) if isinstance(item, ast.Name)]


class _Extractor:
    def __init__(self, path: str, tree: ast.Module) -> None:
        self.path = path
        self.tree = tree
        self.facts = FileFacts(path)
        self.import_index: dict[tuple[int, int], int] = {}
        self.imports_map = module_imports(tree)
        self.recorded: dict[int, tuple[ArgFact, ...]] = {}
        self.units: dict[int, _UnitResult] = {}
        self.callee_nodes: set[int] = set()
        self.def_nodes: dict[int, str] = {}
        self.def_records: dict[int, RawDef] = {}

    # ---- module-level bindings, imports -----------------------------------------------------

    def run(self) -> FileFacts:
        module_scope = _Scope("module", "", None)
        self._collect_imports()
        self._collect_module_bindings()
        self._collect_defs(self.tree.body, "", None, module_scope, in_function=False)
        self._analyze_units()
        self._walk(module_scope)
        self._attach_sinks()
        return self.facts

    def _collect_imports(self) -> None:
        # Enclosing function qualname for every import statement (module level -> "").
        owners: dict[int, str] = {}

        def visit(body: list[ast.stmt], scope: str, prefix: str, in_function: bool) -> None:
            for node in body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    owners[id(node)] = scope
                    continue
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qual = f"{prefix}{node.name}"
                    visit(node.body, qual, f"{qual}.<locals>.", True)
                elif isinstance(node, ast.ClassDef):
                    qual = f"{prefix}{node.name}"
                    visit(node.body, scope, f"{qual}.", in_function)
                else:
                    for field_name in ("body", "orelse", "finalbody"):
                        sub = getattr(node, field_name, None)
                        if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                            visit(sub, scope, prefix, in_function)
                    for handler in getattr(node, "handlers", []) or []:
                        visit(handler.body, scope, prefix, in_function)
                    for case in getattr(node, "cases", []) or []:
                        visit(case.body, scope, prefix, in_function)

        visit(self.tree.body, "", "", False)
        statements: list[tuple[int, ast.Import | ast.ImportFrom]] = [
            (index, node) for index, node in enumerate(ast.walk(self.tree)) if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        statements.sort(key=lambda item: (item[1].lineno, item[1].col_offset, item[0]))
        for _, node in statements:
            scope = owners.get(id(node), "")
            if isinstance(node, ast.Import):
                for position, alias in enumerate(node.names):
                    self.import_index[(id(node), position)] = len(self.facts.imports)
                    self.facts.imports.append(RawImport(node.lineno, scope, "import", alias.name, 0, "", alias.asname))
            else:
                module = node.module or ""
                for position, alias in enumerate(node.names):
                    self.import_index[(id(node), position)] = len(self.facts.imports)
                    kind = "star" if alias.name == "*" else "from"
                    self.facts.imports.append(RawImport(
                        node.lineno, scope, kind, module, node.level, "" if kind == "star" else alias.name, alias.asname,
                    ))

    def _bind(self, name: str, binding: Binding) -> None:
        self.facts.bindings.setdefault(name, []).append(binding)

    def _collect_module_bindings(self) -> None:
        facts = self.facts
        declared: set[str] = set()
        all_state: list[str] | None = None
        dynamic = False

        def literal_strings(node: ast.AST | None) -> list[str] | None:
            if isinstance(node, (ast.List, ast.Tuple)) and all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str) for item in node.elts):
                return [str(item.value) for item in node.elts]  # type: ignore[attr-defined]
            return None

        def visit(body: list[ast.stmt]) -> None:
            nonlocal all_state, dynamic
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._bind(node.name, Binding("def", node.name, node.lineno))
                elif isinstance(node, ast.ClassDef):
                    self._bind(node.name, Binding("class", node.name, node.lineno))
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for position, alias in enumerate(node.names):
                        index = self.import_index[(id(node), position)]
                        if alias.name == "*":
                            continue
                        if isinstance(node, ast.Import):
                            name = alias.asname or alias.name.split(".")[0]
                        else:
                            name = alias.asname or alias.name
                        self._bind(name, Binding("import", index, node.lineno))
                elif isinstance(node, ast.Assign):
                    value_is_literal = is_literal(node.value)
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id == "__all__":
                                listed = literal_strings(node.value)
                                if listed is None:
                                    dynamic = True
                                else:
                                    all_state = listed
                            self._bind(target.id, Binding("assign", value_is_literal and len(node.targets) == 1, node.lineno))
                        else:
                            for name in _target_names(target):
                                self._bind(name, Binding("other", None, node.lineno))
                elif isinstance(node, ast.AnnAssign):
                    if isinstance(node.target, ast.Name):
                        literal = node.value is not None and is_literal(node.value)
                        if node.value is None:
                            self._bind(node.target.id, Binding("other", None, node.lineno))
                        else:
                            self._bind(node.target.id, Binding("assign", literal, node.lineno))
                elif isinstance(node, ast.AugAssign):
                    if isinstance(node.target, ast.Name):
                        if node.target.id == "__all__":
                            listed = literal_strings(node.value)
                            if listed is None or all_state is None:
                                dynamic = True
                            else:
                                all_state = [*all_state, *listed]
                        self._bind(node.target.id, Binding("other", None, node.lineno))
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    call = node.value
                    if (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                            and call.func.value.id == "__all__"):
                        dynamic = True
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    for name in _target_names(node.target):
                        self._bind(name, Binding("other", None, node.lineno))
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if item.optional_vars is not None:
                            for name in _target_names(item.optional_vars):
                                self._bind(name, Binding("other", None, node.lineno))
                elif isinstance(node, ast.Delete):
                    for target in node.targets:
                        for name in _target_names(target):
                            self._bind(name, Binding("other", None, node.lineno))
                elif isinstance(node, ast.Global):
                    declared.update(node.names)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for field_name in ("body", "orelse", "finalbody"):
                    sub = getattr(node, field_name, None)
                    if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                        visit(sub)
                for handler in getattr(node, "handlers", []) or []:
                    if handler.name:
                        self._bind(handler.name, Binding("other", None, handler.lineno))
                    visit(handler.body)
                for case in getattr(node, "cases", []) or []:
                    visit(case.body)

        visit(self.tree.body)
        # `global X` inside any function: X may be rebound at runtime.
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Global):
                declared.update(node.names)
        facts.global_names = frozenset(declared)
        facts.all_names = "dynamic" if dynamic else (tuple(all_state) if all_state is not None else None)

    # ---- definitions -----------------------------------------------------------------------

    def _collect_defs(self, body: list[ast.stmt], prefix: str, parent: str | None, scope: _Scope, *,
                      in_function: bool) -> None:
        """Record every function and class below `body` with its qualified name."""
        unit_nodes = {id(node) for _, node in _definitions(self.tree)}
        stack: list[tuple[list[ast.stmt], str, str | None, ast.ClassDef | None]] = [(body, prefix, parent, None)]
        while stack:
            statements, qual_prefix, owner, owner_class = stack.pop()
            for node in statements:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{qual_prefix}{node.name}"
                    method = owner_class is not None
                    names = _decorator_names(node)
                    static = "staticmethod" in names
                    start = min([node.lineno, *(item.lineno for item in node.decorator_list)])
                    entry, mutating = _entry_kind(node, self.path) if id(node) in unit_nodes else (False, False)
                    entry_kind: str | None = None
                    if entry:
                        entry_kind = _entry_label(node)
                    class_view = bool(method and owner_class is not None and _class_view(node, owner_class))
                    self.def_nodes[id(node)] = qualname
                    record = RawDef(
                        qualname=qualname, kind="method" if method else "function",
                        is_async=isinstance(node, ast.AsyncFunctionDef), line=start, end_line=node.end_lineno or node.lineno,
                        parent=owner, params=_params(node), decorators=names, bases=(), static=static,
                        analysis_unit=id(node) in unit_nodes, analyzer_entry=entry_kind, mutating=mutating,
                        class_view=class_view,
                    )
                    self.def_records[id(node)] = record
                    self.facts.defs.append(record)
                    stack.append((node.body, f"{qualname}.<locals>.", qualname, None))
                elif isinstance(node, ast.ClassDef):
                    qualname = f"{qual_prefix}{node.name}"
                    start = min([node.lineno, *(item.lineno for item in node.decorator_list)])
                    self.def_nodes[id(node)] = qualname
                    self.facts.defs.append(RawDef(
                        qualname=qualname, kind="class", is_async=False, line=start,
                        end_line=node.end_lineno or node.lineno, parent=owner, params=(),
                        decorators=_decorator_names(node), bases=tuple(chain_of(base) for base in node.bases),
                        static=False, analysis_unit=False, analyzer_entry=None, mutating=False, class_view=False,
                    ))
                    stack.append((node.body, f"{qualname}.", qualname, node))
                else:
                    for field_name in ("body", "orelse", "finalbody"):
                        sub = getattr(node, field_name, None)
                        if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                            stack.append((sub, qual_prefix, owner, owner_class))
                    for handler in getattr(node, "handlers", []) or []:
                        stack.append((handler.body, qual_prefix, owner, owner_class))
                    for case in getattr(node, "cases", []) or []:
                        stack.append((case.body, qual_prefix, owner, owner_class))

    # ---- analysis units (one forward pass per function, as the analyzer does) ------------------

    def _analyze_units(self) -> None:
        clients = module_http_clients(self.tree, self.imports_map)
        for symbol, node in _definitions(self.tree):
            entry, _ = _entry_kind(node, self.path)
            self._run_unit(symbol, node, entry, clients)
        statements = _module_statements(self.tree)
        if statements:
            module = ast.Module(body=list(statements), type_ignores=[])
            self._run_unit(MODULE_SUFFIX, module, False, clients)

    def _run_unit(self, symbol: str, node: ast.AST, entry: bool, clients: frozenset[str]) -> None:
        params: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                      if a.arg not in ("self", "cls")]
            for extra in (node.args.vararg, node.args.kwarg):
                if extra is not None:
                    params.append(extra.arg)
            body = node.body
        elif isinstance(node, ast.Module):
            body = node.body
        else:
            return
        if sum(1 for _ in ast.walk(node)) > MAX_AST_NODES_PER_UNIT:
            self.units[id(node)] = _UnitResult(symbol, (), failed="ast_node_limit")
            return
        recorder = _Recorder(self, self.imports_map, params, entry=entry and bool(params), clients=clients)
        try:
            recorder.statements(body)
        except (RecursionError, MemoryError, ValueError, TypeError, AttributeError):
            self.units[id(node)] = _UnitResult(symbol, (), failed="analysis_error")
            for key, value in recorder.facts.items():
                self.recorded.setdefault(key, value)
            return
        for key, value in recorder.facts.items():
            self.recorded.setdefault(key, value)
        sinks: list[SinkFact] = []
        for sink in recorder.sinks:
            found = tuple(sorted({o[len("parameter "):] for o in sink.origins if o.startswith("parameter ")}))
            if found and sink.kind in CHECK_FOR_KIND:
                sinks.append(SinkFact(sink.kind, sink.line, sink.call, found))
        self.units[id(node)] = _UnitResult(symbol, tuple(sinks))

    def _attach_sinks(self) -> None:
        for node_id, result in self.units.items():
            item = self.def_records.get(node_id)
            if item is not None and result.sinks:
                item.sinks = tuple(sorted(set(result.sinks), key=lambda s: (s.line, s.kind, s.call, s.params)))

    # ---- scope-aware walk: calls and references ----------------------------------------------

    def _function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef, parent: _Scope, qualname: str,
                        method_class: str | None) -> _Scope:
        scope = _Scope("function", qualname, parent)
        names = _decorator_names(node)
        positional = [*node.args.posonlyargs, *node.args.args]
        if method_class is not None and "staticmethod" not in names and positional:
            scope.first_param = positional[0].arg
            scope.method_class = method_class
            scope.class_param = "classmethod" in names
        bound_count: dict[str, int] = {}
        kinds: dict[str, tuple[str, Any]] = {}
        declared: set[str] = set()

        def bind(name: str, kind: tuple[str, Any]) -> None:
            bound_count[name] = bound_count.get(name, 0) + 1
            kinds[name] = kind

        for argument in [*positional, *node.args.kwonlyargs, *(a for a in (node.args.vararg, node.args.kwarg) if a)]:
            bind(argument.arg, ("param", None))
        nested_prefix = f"{qualname}.<locals>."
        stack: list[ast.AST] = list(reversed(node.body))
        while stack:
            item = stack.pop()
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bind(item.name, ("def", f"{nested_prefix}{item.name}"))
                continue
            if isinstance(item, ast.ClassDef):
                bind(item.name, ("class", f"{nested_prefix}{item.name}"))
                continue
            if isinstance(item, ast.Lambda):
                for argument in [*item.args.posonlyargs, *item.args.args, *item.args.kwonlyargs]:
                    bind(argument.arg, ("var", None))
                for extra in (item.args.vararg, item.args.kwarg):
                    if extra is not None:
                        bind(extra.arg, ("var", None))
                stack.append(item.body)
                continue
            if isinstance(item, (ast.Global, ast.Nonlocal)):
                declared.update(item.names)
                continue
            if isinstance(item, (ast.Import, ast.ImportFrom)):
                for position, alias in enumerate(item.names):
                    if alias.name == "*":
                        continue
                    index = self.import_index.get((id(item), position))
                    if isinstance(item, ast.Import):
                        name = alias.asname or alias.name.split(".")[0]
                    else:
                        name = alias.asname or alias.name
                    bind(name, ("import", index))
                continue
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                bind(item.id, ("var", None))
            elif isinstance(item, ast.ExceptHandler) and item.name:
                bind(item.name, ("var", None))
            elif isinstance(item, ast.MatchAs) and item.name:
                bind(item.name, ("var", None))
            elif isinstance(item, ast.MatchStar) and item.name:
                bind(item.name, ("var", None))
            elif isinstance(item, ast.MatchMapping) and item.rest:
                bind(item.rest, ("var", None))
            stack.extend(ast.iter_child_nodes(item))
        for name, kind in kinds.items():
            if name in declared:
                continue
            scope.locals[name] = kind if bound_count[name] == 1 else ("var", None)
        scope.declared_global = frozenset(declared)
        return scope

    def _class_scope(self, node: ast.ClassDef, parent: _Scope, qualname: str) -> _Scope:
        scope = _Scope("class", qualname, parent)
        counts: dict[str, int] = {}
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                counts[item.name] = counts.get(item.name, 0) + 1
                scope.locals[item.name] = ("var", None) if counts[item.name] > 1 else ("class_attr", None)
            else:
                for child in ast.walk(item):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        scope.locals[child.id] = ("var", None)
        return scope

    def _binding(self, root: str, scope: _Scope) -> tuple[str, Any]:
        current: _Scope | None = scope
        first = True
        while current is not None:
            if current.kind == "class" and not first:
                current = current.parent
                continue
            first = False
            if current.kind == "module":
                return ("module", None)
            found = current.locals.get(root)
            if found is not None:
                kind, ref = found
                if kind == "param" and current.first_param == root and current.method_class is not None:
                    return ("self", (current.method_class, current.class_param))
                if kind == "def" or kind == "class":
                    return ("local_def", ref)
                if kind == "import" and ref is not None:
                    return ("local_import", ref)
                return ("local", kind)
            if root in current.declared_global:
                return ("module", None)
            current = current.parent
        return ("module", None)

    def _walk(self, module_scope: _Scope) -> None:
        facts = self.facts
        stack: list[tuple[ast.AST, _Scope, str, str | None]] = []
        # (node, scope, caller qualname, enclosing class qualname for a method body)
        for statement in reversed(self.tree.body):
            stack.append((statement, module_scope, MODULE_SUFFIX, None))
        while stack:
            node, scope, caller, class_qual = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = self.def_nodes.get(id(node)) or f"{scope.qualname}.{node.name}".lstrip(".")
                method_class = scope.qualname if scope.kind == "class" else None
                inner = self._function_scope(node, scope, qualname, method_class)
                for decorator in node.decorator_list:
                    stack.append((decorator, scope, caller, class_qual))
                for default in [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]:
                    stack.append((default, scope, caller, class_qual))
                for child in reversed(node.body):
                    stack.append((child, inner, qualname, None))
                continue
            if isinstance(node, ast.ClassDef):
                qualname = self.def_nodes.get(id(node)) or f"{scope.qualname}.{node.name}".lstrip(".")
                inner = self._class_scope(node, scope, qualname)
                for decorator in node.decorator_list:
                    stack.append((decorator, scope, caller, class_qual))
                for base in node.bases:
                    stack.append((base, scope, caller, class_qual))
                for keyword in node.keywords:
                    stack.append((keyword.value, scope, caller, class_qual))
                for child in reversed(node.body):
                    stack.append((child, inner, qualname, None))
                continue
            if isinstance(node, ast.Call):
                chain = chain_of(node.func)
                last: str | None = None
                if chain is None and isinstance(node.func, ast.Attribute):
                    last = node.func.attr
                binding: tuple[str, Any] = self._binding(chain[0], scope) if chain else ("module", None)
                if chain is not None:
                    inner_node: ast.AST = node.func
                    while isinstance(inner_node, ast.Attribute):
                        self.callee_nodes.add(id(inner_node))
                        inner_node = inner_node.value
                    self.callee_nodes.add(id(inner_node))
                facts.calls.append(RawCall(
                    caller=caller, line=node.lineno, column=node.col_offset, chain=chain, last=last,
                    binding=binding, args=self.recorded.get(id(node)) or _unanalyzed_args(node),
                ))
                stack.extend((child, scope, caller, class_qual) for child in ast.iter_child_nodes(node))
                continue
            if isinstance(node, (ast.Name, ast.Attribute)) and id(node) not in self.callee_nodes \
                    and isinstance(getattr(node, "ctx", None), ast.Load):
                reference = chain_of(node)
                if reference is not None:
                    inner_node = node
                    while isinstance(inner_node, ast.Attribute):
                        self.callee_nodes.add(id(inner_node))
                        inner_node = inner_node.value
                    self.callee_nodes.add(id(inner_node))
                    binding = self._binding(reference[0], scope)
                    # Only names that can lead to a function or class: module-level defs, classes and
                    # imports, local defs and local imports. Instance attributes (`self.x`) are not tracked.
                    if len(reference) <= 3 and (
                        binding[0] in ("local_def", "local_import")
                        or (binding[0] == "module" and any(
                            item.kind in ("def", "class", "import") for item in facts.bindings.get(reference[0], ())))
                    ):
                        facts.refs.append(RawRef(caller, node.lineno, reference, binding))
                    continue
            stack.extend((child, scope, caller, class_qual) for child in ast.iter_child_nodes(node))
        facts.nodes = len(facts.defs) + len(facts.calls) + len(facts.imports)


@dataclass(slots=True)
class _UnitResult:
    symbol: str
    sinks: tuple[SinkFact, ...]
    failed: str | None = None


def _entry_label(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted(target, {}) or ""
        last = name.split(".")[-1]
        if last in ROUTE_DECORATORS and "." in name:
            return "route"
        if last in VIEW_DECORATORS:
            return "view_decorator"
    return "request_parameter"


def _unanalyzed_args(call: ast.Call) -> tuple[ArgFact, ...]:
    facts: list[ArgFact] = []
    for index, argument in enumerate(call.args):
        if isinstance(argument, ast.Starred):
            facts.append(ArgFact("star", None, None, "unknown", reason="star_argument"))
        else:
            facts.append(ArgFact("pos", index, None, "unknown", reason="not_analyzed"))
    for keyword in call.keywords:
        if keyword.arg is None:
            facts.append(ArgFact("dstar", None, None, "unknown", reason="star_argument"))
        else:
            facts.append(ArgFact("kw", None, keyword.arg, "unknown", reason="not_analyzed"))
    return tuple(facts)


class _Recorder(_Analyzer):
    """The analyzer's forward pass, additionally noting what every call's arguments are made of."""

    def __init__(self, extractor: _Extractor, imports: dict[str, str], params: list[str], *, entry: bool,
                 clients: frozenset[str]) -> None:
        super().__init__(imports, params, entry=entry, web=True, clients=clients)
        self.extractor = extractor
        self.facts: dict[int, tuple[ArgFact, ...]] = {}

    def sink(self, call: ast.Call) -> None:
        if id(call) not in self.facts:
            try:
                self.facts[id(call)] = self._arguments(call)
            except (RecursionError, ValueError, TypeError, AttributeError):
                self.facts[id(call)] = _unanalyzed_args(call)
        super().sink(call)

    def _arguments(self, call: ast.Call) -> tuple[ArgFact, ...]:
        facts: list[ArgFact] = []
        after_star = False
        for index, argument in enumerate(call.args):
            if isinstance(argument, ast.Starred):
                facts.append(ArgFact("star", None, None, "unknown", reason="star_argument"))
                after_star = True
                continue
            if after_star:
                facts.append(ArgFact("pos", None, None, "unknown", reason="position_unknown_after_star"))
                continue
            facts.append(self._classify("pos", index, None, argument))
        for keyword in call.keywords:
            if keyword.arg is None:
                facts.append(ArgFact("dstar", None, None, "unknown", reason="star_argument"))
            else:
                facts.append(self._classify("kw", None, keyword.arg, keyword.value))
        return tuple(facts)

    def _literal_refs(self, node: ast.AST) -> tuple[str, ...] | None:
        refs: list[str] = []

        def ok(item: ast.AST) -> bool:
            if isinstance(item, ast.Constant):
                return isinstance(item.value, LITERAL_TYPES)
            if isinstance(item, ast.JoinedStr):
                return all(ok(v.value) if isinstance(v, ast.FormattedValue) else ok(v) for v in item.values)
            if isinstance(item, ast.BinOp):
                return ok(item.left) and ok(item.right)
            if isinstance(item, ast.UnaryOp):
                return ok(item.operand)
            if isinstance(item, (ast.Tuple, ast.List, ast.Set)):
                return all(ok(element) for element in item.elts)
            if isinstance(item, ast.Dict):
                return all(key is not None and ok(key) and ok(value) for key, value in zip(item.keys, item.values, strict=True))
            if isinstance(item, ast.IfExp):
                return ok(item.body) and ok(item.orelse)
            if isinstance(item, ast.Name):
                known = self.values.get(item.id)
                if known is not None:
                    if known.form in ("literal", "literal with placeholders"):
                        return True
                    if known.form == "constant" and known.via:
                        refs.append(known.via)
                        return True
                    return False
                if item.id in self.params or item.id in self.tainted:
                    return False
                if item.id.isupper():
                    refs.append(item.id)
                    return True
            return False

        return tuple(dict.fromkeys(refs)) if ok(node) else None

    def _classify(self, kind: str, position: int | None, keyword: str | None, expr: ast.expr) -> ArgFact:
        info: ArgInfo = self.describe(expr)
        origins = self._origins(info.tainted)
        request = tuple(origin for origin in origins if origin.startswith(("request input", "request data")))
        if request:
            return ArgFact(kind, position, keyword, "request", sources=request[:3])  # type: ignore[arg-type]
        parameters = tuple(dict.fromkeys(origin[len("parameter "):] for origin in origins if origin.startswith("parameter ")))
        if parameters:
            return ArgFact(kind, position, keyword, "param", params=parameters)  # type: ignore[arg-type]
        if info.tainted:
            return ArgFact(kind, position, keyword, "unknown", reason="non_request_source")  # type: ignore[arg-type]
        refs = self._literal_refs(expr)
        if refs is not None:
            return ArgFact(kind, position, keyword, "constant", const_refs=refs)  # type: ignore[arg-type]
        if info.sanitized and info.visible:
            return ArgFact(kind, position, keyword, "sanitized")  # type: ignore[arg-type]
        reason = {"call": "call_result", "attribute": "attribute", "outside": "outside_name"}.get(info.form)
        if reason is None:
            reason = "origin_not_visible" if not info.visible else "expression_not_resolved"
        return ArgFact(kind, position, keyword, "unknown", reason=reason)  # type: ignore[arg-type]


def extract_python(path: str, text: str) -> FileFacts:
    """Facts of one Python file. A file that does not parse yields `status="parse_error"`."""
    tree = parse(text)
    if tree is None:
        return FileFacts(path, status="parse_error")
    try:
        return _Extractor(path, tree).run()
    except (RecursionError, MemoryError):
        return FileFacts(path, status="analysis_error")


def module_name_parts(path: str) -> tuple[str, bool]:
    """(dotted module path relative to the repository root, is a package `__init__`)."""
    stem = path[:-3] if path.endswith(".py") else path
    package = posixpath.basename(stem) == "__init__"
    if package:
        stem = posixpath.dirname(stem)
    return stem.replace("/", "."), package

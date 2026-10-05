"""In-process TypeScript/JavaScript analysis on tree-sitter syntax trees. Code is never executed.

One forward pass per function tracks values from entry-point inputs (Next.js route handlers,
pages, server actions, `pages/api`, Express/Hono/Fastify handlers, client URL APIs) to sinks.
Branches and loops are joined conservatively; validation guards with early exits, sanitizers
and fixed URL origins remove taint. Calls into functions of reviewed or related files use
on-demand summaries (parameter -> sink, parameter -> return), so flows across helpers and
imports are reported at the call site with the full trace.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import Any

from polaris.review.js.model import (
    ALL_CHECKS,
    AUTH_GUARD,
    AUTH_GUARD_EXACT,
    AUTH_RESPONSE,
    CLEAN,
    CODE_CALLS,
    CONTEXT_PARAM_NAMES,
    DATA_RECEIVER,
    EXIT_CALLS,
    FS_MODULES,
    FS_PATH_FUNCTIONS,
    GUARD_METHODS,
    GUARD_NAME,
    HTTP_CLIENT_METHODS,
    HTTP_CLIENTS,
    HTTP_METHODS,
    INJECTION_CHECKS,
    ITERATORS,
    LOG_CALLS,
    LOG_RECEIVERS,
    NAVIGATION_METHODS,
    OPTION_PROGRAMS,
    PROPAGATING_METHODS,
    RATE_LIMIT,
    RAW_SQL_METHODS,
    READ_METHODS,
    REAL_KINDS,
    REDIRECT_CALLS,
    REDIRECT_RECEIVERS,
    RESPONSE_SECRET_SINKS,
    ROUTER_METHODS,
    SAFE_SCHEMA,
    SANITIZE_ALL,
    SANITIZERS,
    SECRET_KIND,
    SEND_FILE_METHODS,
    SHELL_CALLS,
    SPAWN_CALLS,
    SQL_KEYWORDS,
    SQL_TEXT_METHODS,
    UNAMBIGUOUS_READS,
    UNAMBIGUOUS_WRITES,
    UNKNOWN,
    VERIFIER_GUARD,
    WRITE_METHODS,
    Hit,
    Origin,
    Summary,
    Taint,
    Value,
    join,
    literal,
)
from polaris.review.js.tsconfig import AliasConfig, config_paths_for

FUNCTION_TYPES = frozenset({
    "function_declaration", "generator_function_declaration", "function_expression", "function",
    "arrow_function", "method_definition", "generator_function",
})
WRAPPER_TYPES = frozenset({
    "parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression",
    "type_assertion",
})
SECRET_ENV = re.compile(r"(?i)(secret|token|password|passwd|private|api_?key|access_?key|service_?role|credential)")
NOT_SECRET_ENV = re.compile(
    r"(?i)(public|publishable|anon|site_?key|client_?id|_url$|_uri$|_host$|_region$|_name$|_id$|_dsn$|_bucket$|"
    r"_project$|_kid$|_redirect|_base$|_callback|_scope|_audience$|_issuer$|_enabled$|_ttl$|_expir)"
)
CLIENT_LOCATION = re.compile(
    r"^(window\.|document\.|globalThis\.)?(location\.(search|hash|href|pathname)|location|referrer|URL|documentURI|name)$"
)
ROUTE_FILE = re.compile(r"(^|/)app/(.+/)?route\.(t|j)sx?$|(^|/)app/(.+/)?route\.m?[tj]s$")
PAGES_API = re.compile(r"(^|/)pages/api/")
PAGE_FILE = re.compile(r"(^|/)app/(.+/)?(page|layout|default|template)\.(t|j)sx?$")
MIDDLEWARE_FILE = re.compile(r"(^|/)(src/)?middleware\.(t|j)s$")
ROUTER_RECEIVER = re.compile(r"(?i)^(app|router|server|api|routes?|fastify|hono|express|web|http|v\d|\w*(Router|Routes|App|Api))$")
RESOLVE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
# Destructured members of a request-like object that are themselves input containers.
OBJECT_PROPS = frozenset({
    "searchParams", "params", "query", "body", "headers", "cookies", "nextUrl", "req", "request",
    "formData", "files", "data",
})
MAX_SUMMARY_DEPTH = 4
MAX_NODES = 400_000
# The deployment's own URL parts: routing already matched this host, so they aren't attacker input.
OWN_ORIGIN_PROPS = frozenset({"origin", "host", "hostname", "protocol", "port", "basePath", "locale", "defaultLocale"})
OWN_URL = re.compile(r"(^|\.)nextUrl\.(origin|host|hostname|protocol|port|basePath|locale|defaultLocale)$")
# Calls that check a URL or host against private, internal or non-allowlisted targets. Calling one
# on an input counts as validating it for SSRF (whether the result is then checked isn't proven).
SSRF_GUARD = re.compile(
    r"(?i)(ssrf|safe_?url|url_?safe|url_?is_?safe|public_?(url|host|hostname|ip|address)|"
    r"private_?(url|host|hostname|ip|address|network)|internal_?(url|host|hostname|ip)|"
    r"allowed_?(url|host|hostname|domain)|dns_?(safe|public)|resolved_?public)"
)


@lru_cache(maxsize=4)
def _language(name: str) -> Any:
    from tree_sitter import Language

    if name == "javascript":
        import tree_sitter_javascript

        return Language(tree_sitter_javascript.language())
    import tree_sitter_typescript

    return Language(tree_sitter_typescript.language_tsx() if name == "tsx"
                    else tree_sitter_typescript.language_typescript())


def grammar_for(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    return "tsx" if lowered.endswith(".tsx") else "typescript"


def txt(node: Any) -> str:
    value = node.text
    return value.decode("utf-8", "replace") if value is not None else ""


def line_of(node: Any) -> int:
    return int(node.start_point[0]) + 1


def unwrap(node: Any) -> Any:
    while node is not None and node.type in WRAPPER_TYPES:
        inner = next((child for child in node.named_children if child.type != "comment"), None)
        if inner is None:
            break
        node = inner
    return node


def named(node: Any) -> list[Any]:
    return [child for child in node.named_children if child.type != "comment"]


def string_value(node: Any) -> str | None:
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        return "".join(txt(child) for child in node.named_children if child.type in ("string_fragment", "escape_sequence"))
    if node.type == "template_string" and not any(child.type == "template_substitution" for child in node.named_children):
        return "".join(txt(child) for child in node.named_children if child.type in ("string_fragment", "escape_sequence"))
    return None


WHITESPACE = re.compile(r"\s+")


def short_text(node: Any, limit: int = 120) -> str:
    raw = node.text or b""
    window = limit * 8
    if len(raw) > window:
        # Labels only need the first `limit` characters: collapse a bounded prefix instead of
        # decoding whole function bodies. A cut multibyte character can only affect the tail.
        value = WHITESPACE.sub(" ", raw[:window].decode("utf-8", "ignore")).lstrip()
        if len(value) > limit + 1:
            return value[: limit - 1] + "…"
    value = WHITESPACE.sub(" ", txt(node)).strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def fixed_origin(pre: str) -> bool:
    """True when the URL's scheme/host (or a same-site relative path) is fixed before any input."""
    if pre.startswith("/") and not pre.startswith("//") and not pre.startswith("/\\"):
        return len(pre) > 1 and pre[1] not in "/\\"
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#\x00]+[/?#]", pre):
        return True
    if pre.startswith("\x00") and re.search(r"[/?#]", pre[1:]):
        return True  # an untainted base (e.g. process.env.API_URL) followed by a path
    return False


def relative_redirect(pre: str) -> bool:
    if fixed_origin(pre):
        return True
    return pre.startswith("?") or pre.startswith("#")


def leads(value: Value) -> bool:
    """True when the tainted part is the start of the value (nothing fixed comes before it)."""
    return value.pre == "" or (value.pre == "\x00" and value.kind not in ("template", "concat", "join"))


def without_params(taint: Taint) -> Taint:
    """Drop a function's own parameter origins (they are mapped to arguments separately)."""
    if not any(origin.kind == "param" for origin in taint.origins):
        return taint
    origins = frozenset(origin for origin in taint.origins if origin.kind != "param")
    return Taint(origins, taint.steps, taint.sanitized) if origins else CLEAN


@dataclass
class Entry:
    node: Any
    kind: str                      # route_handler, pages_api, server_action, express_handler, middleware, page
    name: str
    method: str | None = None
    wrappers: list[str] = field(default_factory=list)


@dataclass
class AuthFacts:
    entry: Entry
    path: str
    line: int
    guarded: bool = False
    guard_names: list[str] = field(default_factory=list)
    writes: list[tuple[int, str]] = field(default_factory=list)
    reads: list[tuple[int, str]] = field(default_factory=list)
    sinks: int = 0
    rate_limited: bool = False


class JsFile:
    def __init__(self, path: str, text: str, *, role: str = "review") -> None:
        from tree_sitter import Parser

        self.path = path
        self.text = text
        self.role = role
        self.source = text.encode("utf-8")
        self.line_bytes = self.source.split(b"\n")
        parser = Parser(_language(grammar_for(path)))
        self.tree = parser.parse(self.source)
        self.root = self.tree.root_node
        self.error_ratio = self._error_ratio()
        self.directives = self._directives()
        self.client = "use client" in self.directives
        self.server_actions = "use server" in self.directives
        self.imports: dict[str, str] = {}
        # local name -> (module specifier, exported name | "default" | "*")
        self.import_specs: dict[str, tuple[str, str]] = {}
        self.functions: dict[str, Any] = {}
        self.exports: dict[str, Any] = {}
        self.export_wrappers: dict[str, list[str]] = {}
        self.default_export: Any = None
        self.constants: dict[str, Any] = {}
        self.entries: list[Entry] = []
        self.classes: list[Any] = []
        self._index()

    # ---- indexing ------------------------------------------------------------------------

    def _error_ratio(self) -> float:
        if not self.root.has_error:
            return 0.0
        erroneous = 0
        stack = [self.root]
        visited = 0
        while stack and visited < MAX_NODES:
            node = stack.pop()
            visited += 1
            if node.type == "ERROR" or node.is_missing:
                erroneous += max(1, node.end_byte - node.start_byte)
                continue
            if node.has_error:
                stack.extend(node.children)
        return erroneous / max(1, len(self.source))

    def _directives(self) -> set[str]:
        found: set[str] = set()
        for child in named(self.root):
            if child.type != "expression_statement":
                break
            value = string_value(child.named_children[0]) if child.named_children else None
            if value is None:
                break
            found.add(value)
        return found

    def column(self, node: Any) -> int:
        row, byte_column = node.start_point
        if row >= len(self.line_bytes):
            return 0
        return len(self.line_bytes[row][:byte_column].decode("utf-8", "replace"))

    def _module(self, value: str) -> str:
        value = value.removeprefix("node:")
        return value

    def _index(self) -> None:
        for statement in named(self.root):
            node = statement
            exported = False
            if node.type == "export_statement":
                exported = True
                self._export(node)
                declaration = node.child_by_field_name("declaration")
                if declaration is None:
                    continue
                node = declaration
            if node.type == "import_statement":
                self._import(node)
            elif node.type in ("function_declaration", "generator_function_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    self.functions[txt(name_node)] = node
                    if exported:
                        self.exports[txt(name_node)] = node
            elif node.type in ("lexical_declaration", "variable_declaration"):
                for declarator in named(node):
                    if declarator.type != "variable_declarator":
                        continue
                    name_node = declarator.child_by_field_name("name")
                    value = unwrap(declarator.child_by_field_name("value"))
                    if name_node is None or value is None:
                        continue
                    self._require(name_node, value)
                    if name_node.type != "identifier":
                        continue
                    name = txt(name_node)
                    function, wrappers = self._function_value(value)
                    if function is not None:
                        self.functions[name] = function
                        if exported:
                            self.exports[name] = function
                            self.export_wrappers[name] = wrappers
                    else:
                        self.constants[name] = value
            elif node.type == "class_declaration":
                self.classes.append(node)
            elif node.type == "expression_statement":
                inner = unwrap(node.named_children[0]) if node.named_children else None
                if inner is not None and inner.type == "assignment_expression":
                    left = txt(inner.child_by_field_name("left") or inner)
                    right = unwrap(inner.child_by_field_name("right"))
                    if left in ("module.exports", "exports.default") and right is not None:
                        function, _ = self._function_value(right)
                        if function is not None:
                            self.default_export = function
        self._entries()

    def _function_value(self, value: Any) -> tuple[Any, list[str]]:
        """A function, possibly wrapped by higher-order calls such as withAuth(handler)."""
        wrappers: list[str] = []
        node = unwrap(value)
        for _ in range(4):
            if node is None:
                return None, wrappers
            if node.type in FUNCTION_TYPES:
                return node, wrappers
            if node.type == "call_expression":
                function = node.child_by_field_name("function")
                arguments = node.child_by_field_name("arguments")
                if function is None or arguments is None or arguments.type != "arguments":
                    return None, wrappers
                wrappers.append(self.callee(function) or short_text(function, 60))
                candidates = [unwrap(item) for item in named(arguments)]
                inner = next((item for item in candidates if item is not None and item.type in FUNCTION_TYPES), None)
                if inner is None:
                    identifier = next((item for item in candidates if item is not None and item.type == "identifier"
                                       and txt(item) in self.functions), None)
                    return (self.functions[txt(identifier)], wrappers) if identifier is not None else (None, wrappers)
                node = inner
                continue
            return None, wrappers
        return None, wrappers

    def _import(self, node: Any) -> None:
        source = node.child_by_field_name("source")
        module = self._module(string_value(source) or "") if source is not None else ""
        if not module or txt(node).startswith("import type"):
            return
        for clause in named(node):
            if clause.type != "import_clause":
                continue
            for part in named(clause):
                if part.type == "identifier":
                    self.imports[txt(part)] = module
                    self.import_specs[txt(part)] = (module, "default")
                elif part.type == "namespace_import":
                    identifier = next((item for item in named(part) if item.type == "identifier"), None)
                    if identifier is not None:
                        self.imports[txt(identifier)] = module
                        self.import_specs[txt(identifier)] = (module, "*")
                elif part.type == "named_imports":
                    for specifier in named(part):
                        if specifier.type != "import_specifier" or txt(specifier).startswith("type "):
                            continue
                        name = specifier.child_by_field_name("name")
                        alias = specifier.child_by_field_name("alias")
                        if name is None:
                            continue
                        self.imports[txt(alias or name)] = f"{module}.{txt(name)}"
                        self.import_specs[txt(alias or name)] = (module, txt(name))

    def _require(self, pattern: Any, value: Any) -> None:
        if value.type == "await_expression" and value.named_children:
            value = unwrap(value.named_children[0])
        if value is None or value.type != "call_expression":
            return
        function = value.child_by_field_name("function")
        arguments = value.child_by_field_name("arguments")
        if function is None or txt(function) != "require" or arguments is None:
            return
        first = next(iter(named(arguments)), None)
        module = self._module(string_value(first) or "") if first is not None else ""
        if not module:
            return
        if pattern.type == "identifier":
            self.imports[txt(pattern)] = module
            self.import_specs[txt(pattern)] = (module, "*")
        elif pattern.type == "object_pattern":
            for item in named(pattern):
                if item.type == "shorthand_property_identifier_pattern":
                    self.imports[txt(item)] = f"{module}.{txt(item)}"
                    self.import_specs[txt(item)] = (module, txt(item))
                elif item.type == "pair_pattern":
                    key, alias = item.child_by_field_name("key"), item.child_by_field_name("value")
                    if key is not None and alias is not None and alias.type == "identifier":
                        self.imports[txt(alias)] = f"{module}.{txt(key)}"
                        self.import_specs[txt(alias)] = (module, txt(key))

    def _export(self, node: Any) -> None:
        value = node.child_by_field_name("value")
        if value is not None or any(child.type == "default" for child in node.children):
            target = value if value is not None else node.child_by_field_name("declaration")
            if target is not None:
                function, wrappers = self._function_value(target)
                if function is None and target.type == "identifier":
                    function = self.functions.get(txt(target))
                if function is not None:
                    self.default_export = function
                    self.export_wrappers["default"] = wrappers
        for clause in named(node):
            if clause.type != "export_clause":
                continue
            for specifier in named(clause):
                name = specifier.child_by_field_name("name")
                alias = specifier.child_by_field_name("alias")
                if name is not None:
                    self.export_wrappers.setdefault(txt(alias or name), [])
                    self._late_exports = getattr(self, "_late_exports", [])
                    self._late_exports.append((txt(name), txt(alias or name)))

    def _entries(self) -> None:
        for local, exported in getattr(self, "_late_exports", []):
            if local in self.functions:
                self.exports[exported] = self.functions[local]
        path = self.path
        if ROUTE_FILE.search(path):
            for name, function in self.exports.items():
                if name in HTTP_METHODS:
                    self.entries.append(Entry(function, "route_handler", name, name, self.export_wrappers.get(name, [])))
        if PAGES_API.search(path) and self.default_export is not None:
            self.entries.append(Entry(self.default_export, "pages_api", "default", None,
                                      self.export_wrappers.get("default", [])))
        if MIDDLEWARE_FILE.search(path):
            function = self.exports.get("middleware") or self.default_export
            if function is not None:
                self.entries.append(Entry(function, "middleware", "middleware"))
        if PAGE_FILE.search(path):
            if self.default_export is not None:
                self.entries.append(Entry(self.default_export, "page", "default"))
            for name in ("generateMetadata",):
                if name in self.exports:
                    self.entries.append(Entry(self.exports[name], "page", name))
        if self.server_actions:
            for name, function in self.exports.items():
                if not any(entry.node == function for entry in self.entries):
                    self.entries.append(Entry(function, "server_action", name))
        for name, function in self.functions.items():
            body = function.child_by_field_name("body")
            if body is not None and body.type == "statement_block":
                first = next(iter(named(body)), None)
                if first is not None and first.type == "expression_statement" and first.named_children \
                        and string_value(first.named_children[0]) == "use server":
                    if not any(entry.node == function for entry in self.entries):
                        self.entries.append(Entry(function, "server_action", name))

    # ---- names -------------------------------------------------------------------------------

    def callee(self, node: Any) -> str | None:
        """Canonical dotted name: imports resolved (`child_process.exec`), locals kept (`res.redirect`)."""
        def bare(item: Any) -> Any:
            item = unwrap(item)
            while item is not None and item.type == "await_expression":  # (await cookies()).set(...)
                item = unwrap(next(iter(named(item)), None))
            return item

        node = bare(node)
        parts: list[str] = []
        while node is not None and node.type in ("member_expression", "subscript_expression"):
            if node.type == "member_expression":
                prop = node.child_by_field_name("property")
                if prop is None:
                    return None
                parts.append(txt(prop))
                node = bare(node.child_by_field_name("object"))
            else:
                index = node.child_by_field_name("index")
                value = string_value(index) if index is not None else None
                if value is None:
                    return None
                parts.append(value)
                node = bare(node.child_by_field_name("object"))
        if node is None:
            return None
        if node.type == "identifier":
            root = self.imports.get(txt(node), txt(node))
        elif node.type in ("this", "super"):
            root = node.type
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is not None and txt(function) == "require" and arguments is not None:
                module = string_value(next(iter(named(arguments)), None)) if named(arguments) else None
                if module:
                    root = self._module(module)
                    name = ".".join([root, *reversed(parts)])
                    return name
            inner = self.callee(function)
            if inner is None:
                return None
            root = inner + "()"
        else:
            return None
        name = ".".join([root, *reversed(parts)])
        return name.replace("fs.promises.", "fs/promises.").replace("fs-extra.promises.", "fs/promises.")


class Project:
    """Parsed files (reviewed + related context) with module resolution and summaries.

    `files` holds the files analyzed in this pass (role "review"); `loader` parses any other
    supplied file on first use, so large reviews can be analyzed in batches without keeping
    every syntax tree alive at once.
    """

    def __init__(self, files: dict[str, JsFile], *, guards: list[str] | None = None,
                 aliases: dict[str, AliasConfig] | None = None,
                 loader: Callable[[str], JsFile | None] | None = None) -> None:
        self.files = files
        self.loader = loader
        self._missing: set[str] = set()
        self.guards = [item for item in (guards or [])]
        self.aliases = aliases or {}
        self.summaries: dict[tuple[str, int, int], Summary] = {}
        self.in_progress: set[tuple[str, int, int]] = set()
        self.hits: list[Hit] = []
        self.helper_hits: list[tuple[str, str, Hit, bool, tuple[str, int, int]]] = []
        self.call_records: dict[tuple[str, int, int], list[tuple[str, int, str]]] = {}
        self.auth: list[AuthFacts] = []
        self._seen: dict[tuple[str, int, str, str], int] = {}

    def load(self, path: str) -> JsFile | None:
        file = self.files.get(path)
        if file is not None or self.loader is None or path in self._missing:
            return file
        file = self.loader(path)
        if file is None:
            self._missing.add(path)
        else:
            self.files[path] = file
        return file

    def is_reviewed(self, path: str) -> bool:
        file = self.files.get(path)
        return file is not None and file.role == "review"

    def imports_reviewed(self, file: JsFile) -> bool:
        """True when a (context) file imports one of the reviewed files."""
        for module, _ in file.import_specs.values():
            target = self.resolve(file.path, module)
            if target is not None and target.role == "review":
                return True
        return False

    def alias_for(self, importer: str) -> AliasConfig | None:
        for candidate in config_paths_for(importer):
            if candidate in self.aliases:
                return self.aliases[candidate]
        return None

    def resolve(self, importer: str, specifier: str) -> JsFile | None:
        if specifier.startswith("."):
            return self._lookup(posixpath.normpath(posixpath.join(posixpath.dirname(importer), specifier)))
        if specifier.startswith("/"):
            return None
        config = self.alias_for(importer)
        candidates = config.candidates(specifier) if config is not None else []
        if specifier.startswith(("@/", "~/")):
            # Common Next.js/Vite defaults when no tsconfig was supplied or it didn't match.
            rest = specifier[2:]
            anchors = list(dict.fromkeys([config.directory if config is not None else "", ""]))
            for anchor in anchors:
                for prefix in ("src/", "", "app/"):
                    candidates.append(posixpath.join(anchor, prefix + rest) if anchor else prefix + rest)
        for candidate in candidates:
            found = self._lookup(candidate)
            if found is not None:
                return found
        return None

    def _lookup(self, base: str) -> JsFile | None:
        found = self.load(base)
        if found is not None:
            return found
        for extension in RESOLVE_EXTENSIONS:
            for candidate in (base + extension, f"{base}/index{extension}"):
                found = self.load(candidate)
                if found is not None:
                    return found
        stem, extension = posixpath.splitext(base)
        if extension in (".js", ".jsx", ".mjs", ".cjs"):
            for replacement in (".ts", ".tsx", ".mts", ".cts"):
                found = self.load(stem + replacement)
                if found is not None:
                    return found
        return None

    def function_for(self, file: JsFile, function: Any) -> tuple[JsFile, Any] | None:
        """Resolve a called expression to a local or imported function definition."""
        function = unwrap(function)
        if function is None:
            return None
        member = ""
        if function.type == "member_expression":
            obj = unwrap(function.child_by_field_name("object"))
            prop = function.child_by_field_name("property")
            if obj is None or prop is None or obj.type != "identifier":
                return None
            local, member = txt(obj), txt(prop)
        elif function.type == "identifier":
            local = txt(function)
        else:
            return None
        if not member and local in file.functions and local not in file.import_specs:
            return file, file.functions[local]
        spec = file.import_specs.get(local)
        if spec is None:
            return None
        module, exported = spec
        if member and exported not in ("*", "default"):
            return None
        resolved = self.resolve(file.path, module)
        if resolved is None:
            return None
        symbol = member or exported
        if symbol == "default":
            return (resolved, resolved.default_export) if resolved.default_export is not None else None
        if symbol == "*":
            return None
        target = resolved.exports.get(symbol) or resolved.functions.get(symbol)
        return (resolved, target) if target is not None else None

    def key(self, file: JsFile, node: Any) -> tuple[str, int, int]:
        return (file.path, int(node.start_byte), int(node.end_byte))

    def summary(self, file: JsFile, node: Any, depth: int) -> Summary:
        key = self.key(file, node)
        if key in self.summaries:
            return self.summaries[key]
        if key in self.in_progress or depth > MAX_SUMMARY_DEPTH:
            return Summary()
        self.in_progress.add(key)
        try:
            analysis = FunctionAnalysis(self, file, node, depth=depth + 1, report=False)
            analysis.run()
            self.summaries[key] = analysis.summary
            return analysis.summary
        finally:
            self.in_progress.discard(key)

    def report(self, hit: Hit) -> None:
        key = (hit.path, hit.line, hit.check, hit.rule_id)
        position = self._seen.get(key)
        if position is None:
            self._seen[key] = len(self.hits)
            self.hits.append(hit)
        elif self.hits[position].dynamic and not hit.dynamic:
            # A handler is first walked as a closure (parameters unknown), then as an entry point
            # with request input: the tainted flow is the stronger evidence for the same sink.
            self.hits[position] = hit

    def is_guard(self, name: str) -> bool:
        last = name.split(".")[-1].removesuffix("()")
        if name in self.guards or last in self.guards:
            return True
        return (last in AUTH_GUARD_EXACT or bool(AUTH_GUARD.match(last)) or bool(AUTH_RESPONSE.match(last))
                or bool(VERIFIER_GUARD.search(last))
                or name.endswith(("auth.getUser", "auth.getSession", "auth().protect", "auth.api.getSession")))

    # ---- driver -----------------------------------------------------------------------------

    def analyze(self, file: JsFile) -> None:
        entry_nodes = {entry.node: entry for entry in file.entries}
        registered: list[tuple[Entry, dict[str, Value]]] = []
        for entry in file.entries:
            analysis = FunctionAnalysis(self, file, entry.node, entry=entry, report=True)
            analysis.run()
            if entry.kind in ("route_handler", "pages_api", "server_action", "express_handler"):
                self.auth.append(analysis.auth_facts())
            registered.extend((item, analysis.env) for item in analysis.registered)
        exported = set(file.exports.values()) | ({file.default_export} if file.default_export is not None else set())
        for name, node in file.functions.items():
            if node in entry_nodes:
                continue
            analysis = FunctionAnalysis(self, file, node, report=True, symbol=name)
            analysis.run()
            registered.extend((item, analysis.env) for item in analysis.registered)
            for index_hits in analysis.summary.param_hits.values():
                for hit in index_hits:
                    self.helper_hits.append((file.path, name, hit, node in exported, self.key(file, node)))
        for klass in file.classes:
            body = klass.child_by_field_name("body")
            for member in named(body) if body is not None else []:
                if member.type == "method_definition":
                    name_node = member.child_by_field_name("name")
                    analysis = FunctionAnalysis(self, file, member, report=True,
                                                symbol=txt(name_node) if name_node is not None else "method")
                    analysis.run()
        module = FunctionAnalysis(self, file, file.root, report=True, symbol="<module>")
        module.run()
        registered.extend((item, module.env) for item in module.registered)
        for entry, env in registered:
            analysis = FunctionAnalysis(self, file, entry.node, entry=entry, report=True, env=env)
            analysis.run()
            self.auth.append(analysis.auth_facts())


class FunctionAnalysis:
    def __init__(
        self, project: Project, file: JsFile, node: Any, *, entry: Entry | None = None,
        report: bool, depth: int = 0, env: dict[str, Value] | None = None, symbol: str | None = None,
        bindings: list[Value] | None = None,
    ) -> None:
        self.project = project
        self.file = file
        self.node = node
        self.entry = entry
        self.report = report
        self.depth = depth
        self.env: dict[str, Value] = dict(env) if env is not None else {}
        self.symbol = symbol or (entry.name if entry else self._name())
        self.summary = Summary()
        self.bindings = bindings
        self.guards: list[str] = list(entry.wrappers if entry else [])
        self.writes: list[tuple[int, str]] = []
        self.reads: list[tuple[int, str]] = []
        self.sink_count = 0
        self.registered: list[Entry] = []
        self.visited = 0
        self.returns = CLEAN
        self.rate_limited = False

    def _name(self) -> str:
        name = self.node.child_by_field_name("name") if self.node.type != "program" else None
        return txt(name) if name is not None else "<anonymous>"

    # ---- driver -----------------------------------------------------------------------------

    def run(self) -> None:
        node = self.node
        if node.type == "program":
            self._module_constants()
            for statement in named(node):
                if statement.type in ("function_declaration", "generator_function_declaration", "import_statement"):
                    continue
                if statement.type == "export_statement":
                    declaration = statement.child_by_field_name("declaration")
                    if declaration is None or declaration.type in ("function_declaration", "generator_function_declaration"):
                        continue
                    statement = declaration
                if statement.type in ("lexical_declaration", "variable_declaration") and self._only_functions(statement):
                    continue
                self.stmt(statement)
            return
        self._module_constants()
        self._bind_parameters()
        body = node.child_by_field_name("body")
        if body is None:
            return
        if body.type == "statement_block":
            self.block(body)
        else:
            value = self.ev(body)
            self._return(value)
        # Parameter flows are recorded in returns_params; leaving this function's parameter
        # origins in `returns` would make callers mistake them for their own parameters.
        self.summary.returns = join(self.summary.returns, without_params(self.returns))
        own_guards = [name for name in self.guards if name not in (self.entry.wrappers if self.entry else [])]
        self.summary.guarded = bool(own_guards)
        self.summary.writes = self.writes[:10]
        self.summary.reads = self.reads[:10]

    def _only_functions(self, statement: Any) -> bool:
        for declarator in named(statement):
            value = unwrap(declarator.child_by_field_name("value")) if declarator.type == "variable_declarator" else None
            if value is None or value.type not in FUNCTION_TYPES:
                return False
        return True

    def _module_constants(self) -> None:
        for name, value in self.file.constants.items():
            if name in self.env:
                continue
            if value.type in ("string", "template_string", "number", "true", "false"):
                text = string_value(value)
                self.env[name] = literal(text, name) if text is not None else Value(kind="number", text=name)
            elif value.type in ("new_expression", "array", "object", "call_expression"):
                self.env[name] = Value(kind="constant", text=name, literal=None, sql_text=txt(value)[:500])

    def _parameters(self) -> list[Any]:
        node = self.node
        params = node.child_by_field_name("parameters")
        if params is None:
            single = node.child_by_field_name("parameter")
            return [single] if single is not None else []
        return named(params)

    def _bind_parameters(self) -> None:
        params = self._parameters()
        entry = self.entry
        for index, param in enumerate(params):
            pattern = param
            if param.type in ("required_parameter", "optional_parameter"):
                pattern = param.child_by_field_name("pattern") or param
            if pattern.type == "assignment_pattern":
                pattern = pattern.child_by_field_name("left") or pattern
            if pattern.type == "rest_pattern":
                pattern = next(iter(named(pattern)), pattern)
            name = txt(pattern)
            line = line_of(param)
            if self.bindings is not None:
                self.bind(pattern, self.bindings[index] if index < len(self.bindings) else UNKNOWN, line)
                continue
            if entry is not None:
                value = self._entry_value(entry, index, name, line)
            elif pattern.type == "object_pattern":
                props = {}
                for item in named(pattern):
                    key = item if item.type == "shorthand_property_identifier_pattern" else (
                        item.child_by_field_name("key") if item.type == "pair_pattern" else
                        item.child_by_field_name("left") if item.type == "object_assignment_pattern" else None)
                    if key is not None:
                        label = string_value(key) or txt(key)
                        props[label] = Value(taint=Taint(frozenset({Origin("param", label, line, index)})), text=label)
                value = Value(taint=Taint(frozenset({Origin("param", name, line, index)})), text=name, props=props)
            else:
                value = Value(taint=Taint(frozenset({Origin("param", name, line, index)})), text=name)
            self.bind(pattern, value, line, refine=False)

    def _symbolic(self) -> bool:
        return self.node.type != "program"

    def _entry_value(self, entry: Entry, index: int, name: str, line: int) -> Value:
        def source(kind: str, label: str, root: bool = True) -> Value:
            return Value(taint=Taint(frozenset({Origin(kind, label, line, root=root)})), text=label,
                         obj="source-object" if root else None)

        if entry.kind in ("route_handler", "middleware", "pages_api"):
            if index == 0:
                return source("request", name or "request")
            if index == 1 and entry.kind == "route_handler":
                return source("route_param", "route params")
            return UNKNOWN
        if entry.kind == "express_handler":
            if index == 0:
                if name in CONTEXT_PARAM_NAMES:
                    return source("request", name)
                return source("request", name or "req")
            return UNKNOWN
        if entry.kind == "page":
            return source("page_prop", "page props")
        if entry.kind == "server_action":
            return source("action_input", f"server action argument {name}" if name else "server action argument", root=False)
        return UNKNOWN

    # ---- statements -------------------------------------------------------------------------

    def block(self, node: Any) -> bool:
        """Run statements; True when the block always exits (return/throw)."""
        for statement in named(node):
            if self.stmt(statement):
                return True
        return False

    def _budget(self) -> bool:
        self.visited += 1
        return self.visited < MAX_NODES

    def stmt(self, node: Any) -> bool:
        if not self._budget():
            return False
        kind = node.type
        if kind == "expression_statement":
            for child in named(node):
                self.ev(child)
            return False
        if kind in ("lexical_declaration", "variable_declaration"):
            for declarator in named(node):
                if declarator.type != "variable_declarator":
                    continue
                pattern = declarator.child_by_field_name("name")
                value_node = declarator.child_by_field_name("value")
                value = self.ev(value_node) if value_node is not None else UNKNOWN
                if pattern is not None:
                    self.bind(pattern, value, line_of(declarator))
            return False
        if kind == "return_statement":
            argument = next(iter(named(node)), None)
            self._return(self.ev(argument) if argument is not None else UNKNOWN)
            return True
        if kind == "throw_statement":
            for child in named(node):
                self.ev(child)
            return True
        if kind == "if_statement":
            return self._if(node)
        if kind == "statement_block":
            return self.block(node)
        if kind in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            before = dict(self.env)
            for child in named(node):
                if child.type == "statement_block" or child.type.endswith("statement"):
                    continue
                value = self.ev(child)
                if kind == "for_in_statement" and child == node.child_by_field_name("right"):
                    left = node.child_by_field_name("left")
                    if left is not None:
                        self.bind(left, value, line_of(left))
            body = node.child_by_field_name("body")
            if body is not None:
                self.stmt(body)
            self._merge(before, self.env)
            return False
        if kind == "try_statement":
            before = dict(self.env)
            body = node.child_by_field_name("body")
            exits = self.stmt(body) if body is not None else False
            after_body = dict(self.env)
            handler = node.child_by_field_name("handler")
            if handler is not None:
                self.env = dict(before)
                handler_body = handler.child_by_field_name("body")
                handler_exits = self.stmt(handler_body) if handler_body is not None else False
                exits = exits and handler_exits
                self._merge(after_body, self.env)
            finalizer = node.child_by_field_name("finalizer")
            if finalizer is not None:
                for child in named(finalizer):
                    self.stmt(child)
            return exits
        if kind == "switch_statement":
            value = node.child_by_field_name("value")
            if value is not None:
                self.ev(value)
            before = dict(self.env)
            merged = dict(before)
            body = node.child_by_field_name("body")
            for case in named(body) if body is not None else []:
                self.env = dict(before)
                for child in named(case):
                    if child.type.endswith("statement") or child.type in ("lexical_declaration", "variable_declaration"):
                        self.stmt(child)
                    else:
                        self.ev(child)
                self._merge(merged, self.env)
                merged = dict(self.env)
            return False
        if kind == "labeled_statement":
            body = node.child_by_field_name("body")
            return self.stmt(body) if body is not None else False
        if kind in ("function_declaration", "generator_function_declaration"):
            self._closure(node)
            return False
        if kind == "class_declaration":
            return False
        if kind in ("import_statement", "empty_statement", "break_statement", "continue_statement", "debugger_statement"):
            return False
        if kind == "export_statement":
            declaration = node.child_by_field_name("declaration")
            if declaration is not None:
                return self.stmt(declaration)
            value = node.child_by_field_name("value")
            if value is not None:
                self.ev(value)
            return False
        for child in named(node):
            self.ev(child)
        return False

    def _merge(self, base: dict[str, Value], other: dict[str, Value]) -> None:
        merged: dict[str, Value] = {}
        for name in set(base) | set(other):
            left, right = base.get(name), other.get(name)
            if left is None or right is None or left is right:
                merged[name] = left or right or UNKNOWN
                continue
            if not left.taint.tainted and not right.taint.tainted:
                merged[name] = right
                continue
            merged[name] = Value(taint=join(left.taint, right.taint), kind="join", pre="",
                                 text=right.text or left.text, obj=right.obj or left.obj,
                                 props=right.props or left.props, items=right.items or left.items,
                                 sql_text=left.sql_text + " " + right.sql_text, is_html=left.is_html or right.is_html)
        self.env = merged

    def _if(self, node: Any) -> bool:
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        guarded = self._guarded_names(condition) if condition is not None else set()
        if condition is not None:
            self.ev(condition)
            self._auth_condition(condition)
        before = dict(self.env)
        consequence_exits = self._exits(consequence)
        if guarded and not consequence_exits:
            self._validate(guarded)  # positive form: if (ALLOWED.has(x)) { use(x) }
        # A block ending in redirect()/notFound()/process.exit() never falls through either.
        exits = (self.stmt(consequence) if consequence is not None else False) or consequence_exits
        after_consequence = dict(self.env)
        self.env = dict(before)
        alternative_exits = False
        if alternative is not None:
            for child in named(alternative):
                alternative_exits = self.stmt(child) or self._exits(child) or alternative_exits
        after_alternative = dict(self.env)
        if exits and alternative is None:
            self.env = after_alternative
            if guarded:
                self._validate(guarded)  # negative form: if (!ALLOWED.has(x)) return;
            return False
        if exits and alternative_exits:
            return True
        if exits:
            self.env = after_alternative
            return False
        if alternative_exits:
            self.env = after_consequence
            return False
        self.env = after_consequence
        self._merge(after_consequence, after_alternative)
        return False

    def _exits(self, node: Any) -> bool:
        if node is None:
            return False
        if node.type in ("return_statement", "throw_statement"):
            return True
        if node.type == "statement_block":
            statements = named(node)
            return bool(statements) and self._exits(statements[-1])
        if node.type == "expression_statement" and node.named_children:
            inner = unwrap(node.named_children[0])
            if inner is not None and inner.type == "await_expression" and inner.named_children:
                inner = unwrap(inner.named_children[0])
            if inner is not None and inner.type == "call_expression":
                name = self.file.callee(inner.child_by_field_name("function")) or ""
                return name.split(".")[-1] in EXIT_CALLS or name in EXIT_CALLS
        return False

    def _guarded_names(self, condition: Any) -> set[str]:
        """Names a validation condition constrains (allowlists, prefix checks, strict comparisons)."""
        names: set[str] = set()
        stack = [condition]
        validation = False
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                function = unwrap(node.child_by_field_name("function"))
                name = self.file.callee(function) or ""
                method = name.split(".")[-1]
                if not name and function is not None and function.type == "member_expression":
                    # new Set(ALLOWED).has(x): the receiver has no dotted name, the method still counts.
                    prop = function.child_by_field_name("property")
                    method = txt(prop) if prop is not None else ""
                if method in GUARD_METHODS or GUARD_NAME.match(method):
                    validation = True
                    arguments = node.child_by_field_name("arguments")
                    for argument in named(arguments) if arguments is not None else []:
                        names.update(self._identifiers(argument))
                    if function is not None and function.type == "member_expression":
                        names.update(self._identifiers(function.child_by_field_name("object")))
            elif node.type == "binary_expression":
                operator = node.child_by_field_name("operator")
                left = unwrap(node.child_by_field_name("left"))
                right = unwrap(node.child_by_field_name("right"))
                op = txt(operator) if operator is not None else ""
                if op in ("===", "!==", "==", "!=") and left is not None and right is not None:
                    sides = (left, right)
                    if any(side.type == "unary_expression" and txt(side).startswith("typeof") for side in sides):
                        pass
                    elif any(side.type in ("string", "template_string") and string_value(side) for side in sides):
                        validation = True
                        for side in sides:
                            names.update(self._identifiers(side))
                elif op == "instanceof" and left is not None:
                    validation = True
                    names.update(self._identifiers(left))
            stack.extend(named(node))
        if not validation:
            return set()
        return {name for name in names if name in self.env and self.env[name].taint.tainted}

    def _identifiers(self, node: Any) -> set[str]:
        if node is None:
            return set()
        node = unwrap(node)
        if node is None:
            return set()
        if node.type == "identifier":
            return {txt(node)}
        if node.type == "member_expression":
            root = node
            while root is not None and root.type == "member_expression":
                root = unwrap(root.child_by_field_name("object"))
            if root is not None and root.type == "identifier":
                return {txt(root)}
            if root is not None and root.type == "call_expression":
                return self._identifiers(root)
            return set()
        if node.type == "call_expression":
            function = unwrap(node.child_by_field_name("function"))
            found: set[str] = set()
            if function is not None and function.type == "member_expression":
                found |= self._identifiers(function.child_by_field_name("object"))
            arguments = node.child_by_field_name("arguments")
            for argument in named(arguments) if arguments is not None else []:
                found |= self._identifiers(argument)
            return found
        if node.type == "new_expression":
            arguments = node.child_by_field_name("arguments")
            found = set()
            for argument in named(arguments) if arguments is not None else []:
                found |= self._identifiers(argument)
            return found
        return set()

    def _validate(self, names: set[str]) -> None:
        for name in names:
            value = self.env.get(name)
            if value is not None and value.taint.tainted:
                self.env[name] = Value(taint=value.taint.sanitize(ALL_CHECKS), kind="validated",
                                       literal=value.literal, pre="\x00/", obj=value.obj, props=value.props,
                                       items=value.items, text=value.text)

    def _auth_condition(self, condition: Any) -> None:
        """API-key/cron-secret comparisons against secret environment values count as auth."""
        text = txt(condition)
        if re.search(r"process\.env\.\w*(SECRET|KEY|TOKEN|PASSWORD)\w*", text) and re.search(
            r"(authorization|x-api-key|api[-_]key|token|secret|bearer|signature)", text, re.IGNORECASE,
        ):
            self.guards.append("secret-compare")
            return
        # The same check through variables: `if (token !== cronSecret) return 401`.
        for node in iter_nodes(condition, limit=2_000):
            operator = node.child_by_field_name("operator") if node.type == "binary_expression" else None
            if operator is None or txt(operator) not in ("===", "!==", "==", "!="):
                continue
            sides = [self._peek(node.child_by_field_name("left")), self._peek(node.child_by_field_name("right"))]
            if any(side.taint.secrets() for side in sides) and any(side.taint.real() for side in sides):
                self.guards.append("secret-compare")
                return

    def _peek(self, node: Any) -> Value:
        """The value of a variable or property path, without evaluating calls again."""
        node = unwrap(node)
        root = node
        while root is not None and root.type == "member_expression":
            root = unwrap(root.child_by_field_name("object"))
        if node is None or root is None or root.type != "identifier":
            return UNKNOWN
        return self.env.get(txt(node), UNKNOWN) if node.type == "identifier" else self._member(node)

    def _return(self, value: Value) -> None:
        self.returns = join(self.returns, value.taint)
        for origin in value.taint.params():
            self.summary.returns_params.add(origin.index)

    # ---- binding ----------------------------------------------------------------------------

    def bind(self, pattern: Any, value: Value, line: int, *, refine: bool = True) -> None:
        pattern = unwrap(pattern)
        if pattern is None:
            return
        if pattern.type in ("identifier", "shorthand_property_identifier_pattern"):
            name = txt(pattern)
            keep_root = value.obj == "source-object" or not refine
            taint = value.taint if keep_root or not value.taint.tainted else self._refine(value.taint, value.text or name, line)
            self.env[name] = Value(taint=taint if keep_root else taint.with_step(line, name), kind=value.kind,
                                   literal=value.literal, pre=value.pre, obj=value.obj, props=value.props,
                                   items=value.items, text=name, function=value.function,
                                   sql_text=value.sql_text, shell_option=value.shell_option,
                                   is_html=value.is_html)
            return
        if pattern.type == "object_pattern":
            for item in named(pattern):
                if item.type == "shorthand_property_identifier_pattern":
                    self.bind(item, self._prop(value, txt(item)), line)
                elif item.type == "pair_pattern":
                    key = item.child_by_field_name("key")
                    target = item.child_by_field_name("value")
                    if key is not None and target is not None:
                        self.bind(target, self._prop(value, string_value(key) or txt(key)), line)
                elif item.type == "object_assignment_pattern":
                    left = item.child_by_field_name("left")
                    if left is not None:
                        self.bind(left, self._prop(value, txt(left)), line)
                elif item.type == "rest_pattern":
                    self.bind(next(iter(named(item)), item), value, line)
            return
        if pattern.type == "array_pattern":
            for index, item in enumerate(named(pattern)):
                element = value.items[index] if value.items and index < len(value.items) else Value(
                    taint=value.taint, text=value.text)
                self.bind(item, element, line)
            return
        if pattern.type == "assignment_pattern":
            left = pattern.child_by_field_name("left")
            right = pattern.child_by_field_name("right")
            default = self.ev(right) if right is not None else UNKNOWN
            if left is not None:
                self.bind(left, Value(taint=join(value.taint, default.taint), text=value.text), line)

    def _prop(self, value: Value, name: str) -> Value:
        if value.props and name in value.props:
            return value.props[name]
        if not value.taint.tainted:
            return Value(text=name, obj="router" if value.obj == "router" else None)
        if name in OBJECT_PROPS and any(origin.root for origin in value.taint.origins):
            return Value(taint=value.taint, text=name, obj="source-object")
        return Value(taint=self._refine(value.taint, name), text=name)

    def _refine(self, taint: Taint, label: str, line: int | None = None) -> Taint:
        """Replace unrefined root origins (request, params) by the expression that reads them."""
        if not any(origin.root for origin in taint.origins):
            return taint
        refined = frozenset(
            Origin(origin.kind, label if origin.kind != "route_param" or "param" in label.lower()
                   else f"{label} (route param)", line or origin.line, origin.index, False, origin.path)
            if origin.root else origin
            for origin in taint.origins
        )
        return Taint(refined, taint.steps, taint.sanitized)

    # ---- expressions ------------------------------------------------------------------------

    def ev(self, node: Any) -> Value:
        if node is None or not self._budget():
            return UNKNOWN
        kind = node.type
        if kind in WRAPPER_TYPES:
            inner = unwrap(node)
            return self.ev(inner) if inner is not node else UNKNOWN
        if kind == "identifier":
            name = txt(node)
            if name in self.env:
                return self.env[name]
            if name in self.file.functions and name not in self.file.imports:
                return Value(kind="function", function=self.file.functions[name], text=name)
            return Value(text=name)
        if kind in ("string", "template_string") and string_value(node) is not None:
            return literal(string_value(node) or "", short_text(node, 80))
        if kind == "template_string":
            return self._template(node)
        if kind in ("number", "true", "false", "null", "undefined", "regex"):
            return Value(kind="number" if kind == "number" else "constant", literal=txt(node), pre=txt(node),
                         text=txt(node))
        if kind == "await_expression":
            inner = next(iter(named(node)), None)
            return self.ev(inner)
        if kind == "binary_expression":
            return self._binary(node)
        if kind == "unary_expression":
            argument = node.child_by_field_name("argument")
            self.ev(argument)
            return Value(kind="constant", text=short_text(node, 60))
        if kind in ("update_expression",):
            return Value(kind="number")
        if kind == "ternary_expression":
            return self._ternary(node)
        if kind == "member_expression":
            return self._member(node)
        if kind == "subscript_expression":
            obj = self.ev(node.child_by_field_name("object"))
            index = node.child_by_field_name("index")
            key = string_value(index) if index is not None else None
            if index is not None and key is None:
                self.ev(index)
            if key is not None and obj.props and key in obj.props:
                return obj.props[key]
            if obj.items and index is not None and index.type == "number":
                position = int(txt(index)) if txt(index).isdigit() else -1
                if 0 <= position < len(obj.items):
                    return obj.items[position]
            if obj.taint.tainted:
                return Value(taint=self._refine(obj.taint, short_text(node, 80)), text=short_text(node, 80))
            if (self.file.callee(node.child_by_field_name("object")) or "") == "process.env" and key:
                return self._env(key, node)
            return Value(text=short_text(node, 80))
        if kind == "call_expression":
            return self._call(node)
        if kind == "new_expression":
            return self._new(node)
        if kind == "object":
            return self._object(node)
        if kind == "array":
            items = [self.ev(item) for item in named(node)]
            return Value(taint=join(*(item.taint for item in items)), kind="array", items=items,
                         text=short_text(node, 80), pre="" if any(item.taint.tainted for item in items) else "\x00")
        if kind in FUNCTION_TYPES:
            self._closure(node)
            return Value(kind="function", function=node, text="function")
        if kind == "assignment_expression":
            return self._assign(node)
        if kind == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            right = self.ev(node.child_by_field_name("right"))
            if left is not None and left.type == "identifier":
                previous = self.env.get(txt(left), UNKNOWN)
                self.env[txt(left)] = Value(taint=join(previous.taint, right.taint).with_step(line_of(node), txt(left)),
                                            kind="concat", pre=previous.pre if not previous.taint.tainted else "",
                                            text=txt(left), sql_text=previous.sql_text + right.sql_text,
                                            is_html=previous.is_html or right.is_html)
            return right
        if kind == "sequence_expression":
            value = UNKNOWN
            for child in named(node):
                value = self.ev(child)
            return value
        if kind == "spread_element":
            return self.ev(next(iter(named(node)), None))
        if kind in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
            self._jsx(node)
            return Value(kind="jsx", text="<jsx>")
        if kind == "jsx_expression":
            inner = next(iter(named(node)), None)
            return self.ev(inner)
        for child in named(node):
            self.ev(child)
        return Value(text=short_text(node, 60))

    def _template(self, node: Any) -> Value:
        taints: list[Taint] = []
        pre_parts: list[str] = []
        pre_done = False
        literal_parts: list[str] = []
        for child in node.named_children:
            if child.type in ("string_fragment", "escape_sequence"):
                text = txt(child)
                literal_parts.append(text)
                if not pre_done:
                    pre_parts.append(text)
            elif child.type == "template_substitution":
                inner = next(iter(named(child)), None)
                value = self.ev(inner)
                taints.append(self._refine(value.taint, value.text, line_of(child)) if value.taint.tainted else value.taint)
                literal_parts.append(" ? ")
                if not pre_done:
                    if value.taint.tainted and not value.taint.sanitized >= INJECTION_CHECKS:
                        pre_done = True
                    else:
                        pre_parts.append(value.literal if value.literal is not None else "\x00")
        joined = "".join(literal_parts)
        return Value(taint=join(*taints), kind="template", pre="".join(pre_parts) if pre_done else "".join(pre_parts),
                     text=short_text(node, 120), sql_text=joined, is_html="<" in joined and ">" in joined,
                     literal=None if taints else "".join(pre_parts))

    def _binary(self, node: Any) -> Value:
        operator_node = node.child_by_field_name("operator")
        operator = txt(operator_node) if operator_node is not None else ""
        left = self.ev(node.child_by_field_name("left"))
        right = self.ev(node.child_by_field_name("right"))
        if operator == "+":
            if left.taint.tainted:
                pre = left.pre if left.kind in ("template", "concat") else ""
            elif right.taint.tainted:
                pre = (left.literal if left.literal is not None else (left.pre if left.kind in ("template", "concat") else "\x00"))
                pre += right.pre if right.kind in ("template", "concat") else ""
            else:
                pre = (left.literal or "\x00") + (right.literal or "")
            literal_value = left.literal + right.literal if left.literal is not None and right.literal is not None else None
            sql = left.sql_text + " ? " + right.sql_text
            return Value(taint=join(left.taint, right.taint), kind="concat", pre=pre, literal=literal_value,
                         text=short_text(node, 120), sql_text=sql, is_html=left.is_html or right.is_html)
        if operator in ("||", "??", "&&"):
            return Value(taint=join(left.taint, right.taint), kind="join",
                         pre=left.pre if left.taint.tainted else (right.pre if right.taint.tainted else left.pre),
                         text=short_text(node, 100), obj=left.obj or right.obj, props=left.props or right.props,
                         literal=left.literal if left.literal is not None and right.literal is None else None,
                         sql_text=left.sql_text + right.sql_text)
        return Value(kind="constant", text=short_text(node, 60))

    def _ternary(self, node: Any) -> Value:
        condition = node.child_by_field_name("condition")
        guarded = self._guarded_names(condition) if condition is not None else set()
        self.ev(condition)
        saved = dict(self.env)
        if guarded:
            self._validate(guarded)
        consequence = self.ev(node.child_by_field_name("consequence"))
        self.env = saved
        alternative = self.ev(node.child_by_field_name("alternative"))
        return Value(taint=join(consequence.taint, alternative.taint), kind="join",
                     pre="" if consequence.taint.tainted or alternative.taint.tainted else consequence.pre,
                     text=short_text(node, 100), obj=consequence.obj or alternative.obj)

    def _env(self, name: str, node: Any) -> Value:
        text = f"process.env.{name}"
        if SECRET_ENV.search(name) and not NOT_SECRET_ENV.search(name) and not name.startswith("NEXT_PUBLIC_"):
            return Value(taint=Taint(frozenset({Origin(SECRET_KIND, text, line_of(node))})), text=text, obj="env")
        return Value(kind="env", text=text, obj="env")

    def _member(self, node: Any) -> Value:
        name = self.file.callee(node) or ""
        text = short_text(node, 100)
        if name == "process.argv" or name.startswith("process.argv."):
            return Value(taint=Taint(frozenset({Origin("argv", "process.argv", line_of(node))})), text=text)
        if name.startswith("process.env."):
            return self._env(name.split(".", 2)[2], node)
        if CLIENT_LOCATION.match(name) and not self._shadowed(name.split(".")[0]):
            if name.endswith(("pathname",)) or name in ("location", "window.location", "document.location"):
                return Value(taint=Taint(frozenset({Origin("client_input", text, line_of(node))})), text=text,
                             obj="location")
            return Value(taint=Taint(frozenset({Origin("client_input", text, line_of(node))})), text=text)
        obj_node = node.child_by_field_name("object")
        prop_node = node.child_by_field_name("property")
        obj = self.ev(obj_node)
        prop = txt(prop_node) if prop_node is not None else ""
        if prop == "length":
            return Value(kind="number", text=text)
        if obj.props and prop in obj.props:
            return obj.props[prop]
        if obj.taint.tainted:
            if prop in ("method", "signal", "bodyUsed", "ok", "status"):
                return Value(text=text)
            if prop in OWN_ORIGIN_PROPS and (OWN_URL.search(name) or (obj.kind == "url" and obj.obj == "source-object")):
                return Value(kind="env", text=text)  # request.nextUrl.origin, new URL(request.url).origin
            # Root origins (request, params) are refined where the value is bound or used.
            return Value(taint=obj.taint, text=text, obj=obj.obj if obj.obj in ("url",) else None, pre="")
        if obj.obj == "router":
            return Value(text=text, obj="router-method")
        return Value(text=text, obj=obj.obj if obj.obj in ("location", "env") else None)

    def _shadowed(self, name: str) -> bool:
        return name in self.env and not self.env[name].taint.tainted and self.env[name].kind != "unknown"

    def _object(self, node: Any) -> Value:
        props: dict[str, Value] = {}
        taints: list[Taint] = []
        shell = False
        for item in named(node):
            if item.type == "pair":
                key_node = item.child_by_field_name("key")
                value_node = item.child_by_field_name("value")
                key = (string_value(key_node) or txt(key_node)) if key_node is not None else ""
                value = self.ev(value_node)
                props[key] = value
                taints.append(value.taint)
                if key == "shell" and value_node is not None and txt(value_node) not in ("false", "undefined", "null"):
                    shell = True
            elif item.type == "shorthand_property_identifier":
                value = self.env.get(txt(item), Value(text=txt(item)))
                props[txt(item)] = value
                taints.append(value.taint)
            elif item.type == "spread_element":
                value = self.ev(item)
                taints.append(value.taint)
                if value.props:
                    props.update(value.props)
            elif item.type == "method_definition":
                self._closure(item)
        return Value(taint=join(*taints), kind="object", props=props, text=short_text(node, 80), shell_option=shell)

    def _assign(self, node: Any) -> Value:
        left = unwrap(node.child_by_field_name("left"))
        value = self.ev(node.child_by_field_name("right"))
        line = line_of(node)
        if left is None:
            return value
        if left.type == "identifier":
            name = txt(left)
            self.env[name] = Value(taint=value.taint.with_step(line, name), kind=value.kind, literal=value.literal,
                                   pre=value.pre, obj=value.obj, props=value.props, items=value.items, text=name,
                                   function=value.function, sql_text=value.sql_text, is_html=value.is_html)
            return value
        if left.type == "member_expression":
            target = self.file.callee(left) or short_text(left, 80)
            prop = target.split(".")[-1]
            if prop in ("innerHTML", "outerHTML"):
                self.sink("xss", "polaris.js.xss.dom_html", value, node, f"{target} = …", dynamic=True)
            elif target in ("window.location", "location", "document.location", "window.location.href",
                            "location.href", "document.location.href", "top.location", "window.top.location"):
                if not relative_redirect(value.pre):
                    self.sink("open_redirect", "polaris.js.open_redirect.client_navigation", value, node, f"{target} = …")
            else:
                self.ev(left.child_by_field_name("object"))
        return value

    def _closure(self, node: Any) -> None:
        """Analyze a nested function with the enclosing variables (callbacks, handlers, effects)."""
        if self.depth > MAX_SUMMARY_DEPTH:
            return
        nested = FunctionAnalysis(self.project, self.file, node, report=self.report, depth=self.depth + 1,
                                  env=self.env, symbol=self.symbol, bindings=[])
        nested.run()
        self.guards.extend(nested.guards)
        self.writes.extend(nested.writes)
        self.reads.extend(nested.reads)
        self.sink_count += nested.sink_count
        self.rate_limited = self.rate_limited or nested.rate_limited
        self._absorb(nested)

    def _absorb(self, nested: FunctionAnalysis) -> None:
        for index, hits in nested.summary.param_hits.items():
            self.summary.param_hits.setdefault(index, []).extend(hits)

    # ---- JSX --------------------------------------------------------------------------------

    def _jsx(self, node: Any) -> None:
        if node.type == "jsx_self_closing_element":
            self._jsx_attributes(node)
            return
        for child in named(node):
            if child.type == "jsx_opening_element":
                self._jsx_attributes(child)
            elif child.type in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
                self._jsx(child)
            elif child.type == "jsx_expression":
                self.ev(child)

    def _jsx_attributes(self, node: Any) -> None:
        for attribute in named(node):
            if attribute.type == "jsx_attribute":
                self._jsx_attribute(attribute)
            elif attribute.type == "jsx_expression":
                self.ev(attribute)

    def _jsx_attribute(self, attribute: Any) -> None:
        parts = named(attribute)
        if not parts:
            return
        name = txt(parts[0])
        value_node = parts[1] if len(parts) > 1 else None
        if value_node is None:
            return
        if name == "dangerouslySetInnerHTML" and value_node.type == "jsx_expression":
            inner = unwrap(next(iter(named(value_node)), None))
            html = None
            if inner is not None and inner.type == "object":
                for item in named(inner):
                    if item.type == "pair":
                        key = item.child_by_field_name("key")
                        if key is not None and (string_value(key) or txt(key)) == "__html":
                            html = item.child_by_field_name("value")
                    elif item.type == "shorthand_property_identifier" and txt(item) == "__html":
                        html = item
            value = self.ev(html) if html is not None else self.ev(inner)
            self.sink("xss", "polaris.js.xss.dangerously_set_inner_html", value, attribute,
                      "dangerouslySetInnerHTML", dynamic=True)
            return
        if value_node.type == "jsx_expression":
            self.ev(value_node)

    # ---- calls ------------------------------------------------------------------------------

    def _arguments(self, node: Any, *, refine: bool = True) -> tuple[list[Value], list[Any]]:
        arguments = node.child_by_field_name("arguments")
        if arguments is None or arguments.type != "arguments":
            return [], []
        nodes = named(arguments)
        values = []
        for item in nodes:
            value = self.ev(item)
            if refine and value.taint.tainted and value.obj != "source-object" and any(origin.root for origin in value.taint.origins):
                value = Value(taint=self._refine(value.taint, short_text(item, 100), line_of(item)), kind=value.kind,
                              literal=value.literal, pre=value.pre, obj=value.obj, props=value.props, items=value.items,
                              text=value.text, function=value.function, sql_text=value.sql_text,
                              shell_option=value.shell_option, is_html=value.is_html)
            values.append(value)
        return values, nodes

    def _new(self, node: Any) -> Value:
        constructor = node.child_by_field_name("constructor")
        name = self.file.callee(constructor) or (txt(constructor) if constructor is not None else "")
        last = name.split(".")[-1]
        values, nodes = self._arguments(node, refine=last not in ("URL", "URLSearchParams", "Request"))
        if last == "URL":
            first = values[0] if values else UNKNOWN
            rooted = any(origin.root for origin in first.taint.origins)
            return Value(taint=first.taint, kind="url", pre=first.pre if first.taint.tainted else (
                first.literal if first.literal is not None else first.pre), text=short_text(node, 100),
                obj="source-object" if rooted else "url", literal=first.literal)
        if last == "URLSearchParams":
            first = values[0] if values else UNKNOWN
            rooted = any(origin.root for origin in first.taint.origins)
            return Value(taint=first.taint, text=short_text(node, 100), obj="source-object" if rooted else None)
        if last == "Function":
            if values:
                self.sink("code_injection", "polaris.js.code_injection.eval", values[-1], node, "new Function(…)",
                          dynamic=True)
            return Value(kind="function")
        if name in ("vm.Script",) or name.endswith(".Script") and "vm" in name:
            if values:
                self.sink("code_injection", "polaris.js.code_injection.eval", values[0], node, "new vm.Script(…)",
                          dynamic=True)
            return UNKNOWN
        if name in RESPONSE_SECRET_SINKS or last in ("Response", "NextResponse"):
            if values:
                self.sink("secret_exposure", "polaris.js.secret_exposure.output", values[0], node, f"new {last}(…)")
                headers = values[1].props.get("headers") if len(values) > 1 and values[1].props else None
                html = headers is not None and "text/html" in (headers.sql_text + " ".join(
                    (item.literal or "") for item in (headers.props or {}).values()))
                if html and values[0].is_html:
                    self.sink("xss", "polaris.js.xss.html_response", values[0], node, f"new {last}(html)")
            return Value(kind="response", obj="response")
        if last == "Request":
            first = values[0] if values else UNKNOWN
            return Value(taint=first.taint, pre=first.pre, text=short_text(node, 80))
        return Value(kind="object", text=short_text(node, 80))

    def _call(self, node: Any) -> Value:
        function = unwrap(node.child_by_field_name("function"))
        arguments = node.child_by_field_name("arguments")
        line = line_of(node)
        if arguments is not None and arguments.type == "template_string":
            for child in named(arguments):
                if child.type == "template_substitution":
                    self.ev(next(iter(named(child)), None))
            return Value(kind="sql_tagged", text=short_text(node, 80))
        if function is None:
            return UNKNOWN
        if function.type == "import":
            values, _ = self._arguments(node)
            if values:
                self.sink("code_injection", "polaris.js.code_injection.dynamic_module", values[0], node, "import(…)")
            return UNKNOWN
        name = self.file.callee(function) or ""
        receiver: Value | None = None
        if function.type == "member_expression":
            receiver = self.ev(function.child_by_field_name("object"))
        values, nodes = self._arguments(node)
        method = name.split(".")[-1] if name else (txt(function.child_by_field_name("property"))
                                                  if function.type == "member_expression" and function.child_by_field_name("property") is not None else "")
        if name and self.project.is_guard(name):
            self.guards.append(name)
        if values and SSRF_GUARD.search(method or name):
            self._ssrf_checked(values)
        if name and RATE_LIMIT.search(name):
            self.rate_limited = True
        local_label = short_text(function, 60)
        self._data_operation(name, method, function, line, local_label)
        self._sinks(node, name, method, receiver, values, nodes, line, local_label)
        # Route registrations: app.get("/path", handler)
        if method in ROUTER_METHODS and nodes and (string_value(nodes[0]) or "").startswith("/") \
                and function.type == "member_expression" and len(nodes) > 1 \
                and ROUTER_RECEIVER.match(name.split(".")[-2] if name.count(".") >= 1 else "") \
                and any(unwrap(item) is not None and (unwrap(item).type in FUNCTION_TYPES or unwrap(item).type == "identifier")
                        for item in nodes[1:]):
            for argument in nodes[1:]:
                target = unwrap(argument)
                handler = target if target is not None and target.type in FUNCTION_TYPES else (
                    self.file.functions.get(txt(target)) if target is not None and target.type == "identifier" else None)
                if handler is not None:
                    self.registered.append(Entry(handler, "express_handler", f"{method.upper()} {string_value(nodes[0])}",
                                                 method.upper(), [self.file.callee(item) or "" for item in nodes[1:-1]]))
            return UNKNOWN
        # Iterator callbacks: items.map(item => fetch(item))
        if method in ITERATORS and receiver is not None and receiver.taint.tainted:
            for argument in nodes:
                target = unwrap(argument)
                if target is not None and target.type in FUNCTION_TYPES and self.depth <= MAX_SUMMARY_DEPTH:
                    element = Value(taint=receiver.taint, text="item")
                    nested = FunctionAnalysis(self.project, self.file, target, report=self.report, depth=self.depth + 1,
                                              env=self.env, symbol=self.symbol, bindings=[element, element])
                    nested.run()
                    self.sink_count += nested.sink_count
                    self._absorb(nested)
        # Sources
        last = method
        if name in ("next/navigation.useSearchParams", "useSearchParams"):
            return Value(taint=Taint(frozenset({Origin("url_input", "useSearchParams()", line, root=True)})),
                         text="useSearchParams()", obj="source-object")
        if name in ("next/navigation.useParams", "useParams", "react-router-dom.useParams", "react-router.useParams"):
            return Value(taint=Taint(frozenset({Origin("route_param", "useParams()", line, root=True)})),
                         text="useParams()", obj="source-object")
        if name in ("next/headers.headers", "next/headers.cookies", "next/headers.draftMode"):
            return Value(taint=Taint(frozenset({Origin("request", f"{last}()", line, root=True)})), text=f"{last}()",
                         obj="source-object")
        if name in ("next/navigation.useRouter", "next/router.useRouter", "useRouter", "react-router-dom.useNavigate",
                    "useNavigate"):
            return Value(text=f"{last}()", obj="router")
        # Sanitizers
        if name in SANITIZE_ALL or last in ("parseInt", "parseFloat", "isNaN", "isFinite") or name.startswith("Math."):
            return Value(kind="number", text=short_text(node, 60))
        sanitizer = SANITIZERS.get(name) or SANITIZERS.get(last) if (name in SANITIZERS or last in SANITIZERS) else None
        if sanitizer and values:
            return Value(taint=values[0].taint.sanitize(sanitizer), kind="sanitized", text=short_text(node, 80), pre="\x00")
        if last in ("parse", "safeParse", "parseAsync", "safeParseAsync") and receiver is not None \
                and function.type == "member_expression" and values and not receiver.taint.tainted:
            schema = self._schema_text(function.child_by_field_name("object"))
            if schema and SAFE_SCHEMA.search(schema):
                return Value(kind="validated", text=short_text(node, 80))
            # Schema parsing keeps the input's origin unless the schema constrains it to safe values.
            return Value(taint=values[0].taint.with_step(line, short_text(node, 80)) if values[0].taint.tainted
                         else values[0].taint, text=short_text(node, 80), pre="", props=values[0].props)
        if last in ("replace", "replaceAll") and nodes and receiver is not None and self._allowlist_regex(nodes[0]):
            return Value(taint=receiver.taint.sanitize(ALL_CHECKS), kind="sanitized", text=short_text(node, 80), pre="\x00")
        if name in ("String", "JSON.parse", "decodeURIComponent", "decodeURI", "Buffer.from", "atob", "btoa",
                    "path.join", "path.resolve", "path.normalize", "path.posix.join", "path.win32.join",
                    "url.format", "Object.assign", "Object.values", "Object.entries", "Object.fromEntries",
                    "Array.from", "structuredClone", "String.raw", "url.resolve", "querystring.stringify",
                    "qs.stringify", "path.relative", "upath.join"):
            taint = join(*(item.taint for item in values))
            return Value(taint=taint.with_step(line, short_text(node, 80)) if taint.tainted else taint,
                         kind="path" if name.startswith("path.") else "derived",
                         pre=values[0].pre if values and name.startswith("path.") and not values[0].taint.tainted else "",
                         text=short_text(node, 80), sql_text=" ".join(item.sql_text for item in values))
        if name == "JSON.stringify":
            taint = join(*(item.taint for item in values[:1]))
            if not taint.real():
                # JSON-LD and serialized server data: only attacker input can break out of the script.
                taint = taint.sanitize(frozenset({"xss"}))
            return Value(taint=taint, kind="json", text=short_text(node, 80))
        # Calls into analyzable functions (same file, imports, local closures).
        local = self.env.get(txt(function)) if function.type == "identifier" else None
        resolved = self.project.function_for(self.file, function)
        if resolved is None and local is not None and local.function is not None:
            resolved = (self.file, local.function)
        if resolved is not None:
            return self._apply(resolved[0], resolved[1], local_label or name or "function", values, node, line)
        # A fixed-length prefix/suffix of a secret (key.slice(0, 4)) is a masked display, not the secret.
        if receiver is not None and receiver.taint.secrets() and last in ("slice", "substring", "substr") and nodes \
                and all(self._numeric(item) for item in nodes):
            return Value(taint=receiver.taint.sanitize(frozenset({"secret_exposure"})), kind="sanitized",
                         text=short_text(node, 80))
        # Propagation through methods on tainted receivers.
        if receiver is not None and receiver.taint.tainted:
            if any(origin.root for origin in receiver.taint.origins) or last in PROPAGATING_METHODS:
                return Value(taint=self._refine(receiver.taint, short_text(node, 100), line), text=short_text(node, 100),
                             pre="", obj="url" if receiver.obj == "url" else None)
        if receiver is not None and receiver.obj == "url" and last in ("toString", "toJSON"):
            return receiver
        return Value(kind="call", text=short_text(node, 80), obj="response" if last in ("json", "redirect") and
                     name.endswith(("NextResponse.json", "Response.json")) else None)

    @staticmethod
    def _numeric(node: Any) -> bool:
        node = unwrap(node)
        if node is not None and node.type == "unary_expression":
            node = unwrap(next(iter(named(node)), None))
        return node is not None and node.type == "number"

    def _ssrf_checked(self, values: list[Value]) -> None:
        """A recognized SSRF guard was called on this input: later uses are treated as checked."""
        checked = frozenset().union(*(value.taint.origins for value in values if value.taint.tainted))
        if not checked:
            return
        for name, value in list(self.env.items()):
            if value.taint.tainted and value.taint.origins & checked:
                self.env[name] = replace(value, taint=value.taint.sanitize(frozenset({"ssrf"})))

    def _schema_text(self, node: Any) -> str:
        node = unwrap(node)
        if node is None:
            return ""
        if node.type == "identifier":
            constant = self.file.constants.get(txt(node))
            return txt(constant) if constant is not None else ""
        return txt(node)

    @staticmethod
    def _allowlist_regex(node: Any) -> bool:
        node = unwrap(node)
        return node is not None and node.type == "regex" and bool(re.search(r"\[\^[^\]]*\]", txt(node))) and txt(node).rstrip("gimsuy").endswith("/") is True

    def _apply(self, file: JsFile, function: Any, name: str, values: list[Value], node: Any, line: int) -> Value:
        summary = self.project.summary(file, function, self.depth)
        key = self.project.key(file, function)
        if summary.guarded:
            self.guards.append(name)
        self.writes.extend(summary.writes[:3])
        self.reads.extend(summary.reads[:3])
        if self.report:
            kinds = ",".join("real" if value.taint.real() else "param" if value.taint.params() else "clean"
                             for value in values)
            self.project.call_records.setdefault(key, []).append((self.file.path, line, kinds))
        other = file.path if file.path != self.file.path else None
        for index, hits in summary.param_hits.items():
            if index >= len(values):
                continue
            argument = values[index]
            if not argument.taint.tainted:
                continue
            for hit in hits:
                relevant = argument.taint.secrets() if hit.check == "secret_exposure" else [
                    origin for origin in argument.taint.origins if origin.kind in REAL_KINDS or origin.kind == "param"]
                if not relevant or argument.taint.safe_for(hit.check):
                    continue
                if hit.leading and (fixed_origin(argument.pre) if hit.check == "ssrf" else
                                    relative_redirect(argument.pre) if hit.check == "open_redirect" else False):
                    continue  # the caller fixes the origin (or keeps the redirect relative)
                inner_path = hit.sink_path or (hit.path if hit.path != self.file.path else None)
                steps = (*argument.taint.steps, (line, f"{name}(…)", None),
                         *((step_line, label, step_path or other) for step_line, label, step_path in hit.taint.steps
                           if not label.startswith("{")))
                taint = Taint(frozenset(relevant), steps[-8:], argument.taint.sanitized)
                derived = Hit(hit.check, hit.rule_id, line, self.file.column(node), hit.sink, taint,
                              self.file.path, self.symbol,
                              detail=f"via {name}() at {inner_path or self.file.path}:{hit.sink_line or hit.line}",
                              sink_line=hit.sink_line or hit.line, sink_path=inner_path,
                              leading=hit.leading and leads(argument))
                self._record(derived)
        returned = []
        for index in summary.returns_params:
            if index >= len(values):
                continue
            taint = values[index].taint
            if values[index].kind == "object" and values[index].props and taint.secrets():
                # An options object carrying a credential ({ apiKey, model }) configures the helper;
                # what it returns (model output, an API result) is not the credential itself.
                kept = frozenset(origin for origin in taint.origins if origin.kind != SECRET_KIND)
                taint = Taint(kept, taint.steps, taint.sanitized) if kept else CLEAN
            returned.append(taint)
        taint = join(summary.returns, *returned)
        return Value(taint=taint.with_step(line, f"{name}(…)") if taint.tainted else taint, kind="call",
                     text=short_text(node, 80), pre="")

    def _data_operation(self, name: str, method: str, function: Any, line: int, label: str) -> None:
        if not method or function.type != "member_expression":
            return
        receivers = [part.removesuffix("()") for part in label.split(".")[:-1]]
        if method in UNAMBIGUOUS_WRITES or (method in WRITE_METHODS and any(DATA_RECEIVER.match(part) for part in receivers)):
            self.writes.append((line, label))
        elif method in UNAMBIGUOUS_READS or (method in READ_METHODS and any(DATA_RECEIVER.match(part) for part in receivers)):
            self.reads.append((line, label))

    # ---- sinks ------------------------------------------------------------------------------

    def sink(self, check: str, rule_id: str, value: Value, node: Any, label: str, *, dynamic: bool = False,
             edit_column: int = -1, edit_text: str = "", replace_old: str = "", replace_new: str = "") -> None:
        self.sink_count += 1
        taint = self._refine(value.taint, value.text, line_of(node)) if value.taint.tainted else value.taint
        if check == "secret_exposure":
            relevant = taint.secrets()
        else:
            relevant = [origin for origin in taint.origins if origin.kind in REAL_KINDS or origin.kind == "param"]
        if relevant and not taint.safe_for(check):
            hit = Hit(check, rule_id, line_of(node), self.file.column(node), label,
                      Taint(frozenset(relevant), taint.steps, taint.sanitized), self.file.path, self.symbol,
                      edit_column=edit_column, edit_text=edit_text, replace_old=replace_old, replace_new=replace_new,
                      leading=check in ("ssrf", "open_redirect") and leads(value))
            self._record(hit)
        elif dynamic and not taint.tainted and value.kind in ("unknown", "call", "join", "concat", "template", "derived") \
                and value.literal is None and check != "secret_exposure":
            self._record(Hit(check, rule_id, line_of(node), self.file.column(node), label, CLEAN, self.file.path,
                             self.symbol, detail=value.text, dynamic=True))

    def _record(self, hit: Hit) -> None:
        params = hit.taint.params()
        real = [origin for origin in hit.taint.origins if origin.kind != "param"]
        if real or hit.dynamic:
            # Context files are not reviewed, except where their input reaches a sink inside a
            # reviewed file (a caller passing request input into the changed helper).
            into_review = (real and not hit.dynamic and hit.sink_path is not None
                           and self.project.is_reviewed(hit.sink_path))
            if self.report and (self.file.role == "review" or into_review):
                self.project.report(hit)
        for origin in params:
            self.summary.param_hits.setdefault(origin.index, []).append(hit)

    def _sinks(self, node: Any, name: str, method: str, receiver: Value | None, values: list[Value],
               nodes: list[Any], line: int, local: str = "") -> None:
        first = values[0] if values else UNKNOWN
        last_segment = method
        server = not self.file.client
        shown = local or name
        # Command execution
        if name in SHELL_CALLS and values:
            self.sink("command_injection", "polaris.js.command_injection.shell", first, node, f"{name.split('.')[-1]}(…)")
        elif name in SPAWN_CALLS and values:
            program = first
            arguments = values[1] if len(values) > 1 and values[1].kind == "array" else None
            options = next((item for item in values[1:] if item.kind == "object"), None)
            if name.startswith("Bun.") and first.kind == "array" and first.items:
                program, arguments = first.items[0], Value(kind="array", items=first.items[1:], taint=join(*(item.taint for item in first.items[1:])))
            self.sink("command_injection", "polaris.js.command_injection.executable", program, node,
                      f"{name.split('.')[-1]}(program, …)")
            if options is not None and options.shell_option and arguments is not None:
                self.sink("command_injection", "polaris.js.command_injection.shell_option", arguments, node,
                          f"{name.split('.')[-1]}(…, {{ shell: true }})")
            elif arguments is not None and arguments.items and program.literal is not None:
                binary = posixpath.basename(program.literal)
                if binary in OPTION_PROGRAMS:
                    self._argument_injection(node, nodes, arguments, binary)
        # Code evaluation
        if name in CODE_CALLS and not self._local_shadow(name):
            if name in ("setTimeout", "setInterval", "setImmediate"):
                if first.kind not in ("function",) and (first.taint.tainted):
                    self.sink("code_injection", "polaris.js.code_injection.eval", first, node, f"{name}(string)")
            elif name == "Function":
                if values:
                    self.sink("code_injection", "polaris.js.code_injection.eval", values[-1], node, "Function(…)", dynamic=True)
            elif values:
                self.sink("code_injection", "polaris.js.code_injection.eval", first, node, f"{name}(…)", dynamic=True)
        if name == "require" and values and first.literal is None:
            self.sink("code_injection", "polaris.js.code_injection.dynamic_module", first, node, "require(…)")
        # SSRF (server code only)
        if server and values:
            client = name in HTTP_CLIENTS or (name.split(".")[0] in ("axios", "got", "ky", "superagent", "needle", "undici")
                                              and last_segment in HTTP_CLIENT_METHODS)
            if client and not self._local_shadow(name.split(".")[0]):
                target = first
                if first.kind == "object" and first.props and "url" in first.props:
                    target = first.props["url"]
                if not fixed_origin(target.pre):
                    self.sink("ssrf", "polaris.js.ssrf.request", target, node, f"{shown}(url)")
        # Redirects
        if values and (name in REDIRECT_CALLS or (last_segment in ("redirect", "permanentRedirect")
                                                  and name.split(".")[0] in REDIRECT_RECEIVERS | {"NextResponse", "Response"})):
            target = values[-1] if name.split(".")[0] in ("res", "response") and len(values) > 1 and first.kind == "number" else first
            if not relative_redirect(target.pre):
                self.sink("open_redirect", "polaris.js.open_redirect.redirect", target, node, f"{shown}(destination)")
        if values and last_segment in NAVIGATION_METHODS and receiver is not None and receiver.obj == "router":
            if not relative_redirect(first.pre):
                self.sink("open_redirect", "polaris.js.open_redirect.client_navigation", first, node, f"router.{last_segment}(…)")
        if values and name in ("window.location.assign", "location.assign", "window.location.replace", "location.replace",
                               "window.open", "document.location.assign", "document.location.replace"):
            if not relative_redirect(first.pre):
                self.sink("open_redirect", "polaris.js.open_redirect.client_navigation", first, node, f"{shown}(…)")
        # Filesystem paths
        module = name.rsplit(".", 1)[0] if "." in name else ""
        if values and last_segment in FS_PATH_FUNCTIONS and module in FS_MODULES:
            self.sink("path_traversal", "polaris.js.path_traversal.fs", first, node, f"{shown}(path)")
            if last_segment in ("rename", "renameSync", "copyFile", "copyFileSync", "cp", "cpSync", "symlink", "symlinkSync",
                                "move", "copy") and len(values) > 1:
                self.sink("path_traversal", "polaris.js.path_traversal.fs", values[1], node, f"{shown}(…, path)")
        if values and last_segment in SEND_FILE_METHODS and name.split(".")[0] in ("res", "response", "reply", "ctx"):
            self.sink("path_traversal", "polaris.js.path_traversal.send_file", first, node, f"{shown}(path)")
        # SQL
        if values:
            self._sql(node, name, last_segment, first, nodes)
        # XSS
        if values and last_segment == "insertAdjacentHTML" and len(values) > 1:
            self.sink("xss", "polaris.js.xss.dom_html", values[1], node, "insertAdjacentHTML(…)", dynamic=True)
        if values and name in ("document.write", "document.writeln"):
            self.sink("xss", "polaris.js.xss.dom_html", first, node, f"{shown}(…)", dynamic=True)
        if values and last_segment in ("send", "end", "html", "write") and name.split(".")[0] in ("res", "response", "c", "ctx", "reply") \
                and (first.is_html or last_segment == "html") and first.taint.tainted:
            self.sink("xss", "polaris.js.xss.html_response", first, node, f"{shown}(html)")
        # Secrets written to logs or responses
        if values and ((last_segment in LOG_CALLS and name.split(".")[0] in LOG_RECEIVERS)
                       or name in RESPONSE_SECRET_SINKS
                       or (last_segment in ("json", "send", "end", "text") and name.split(".")[0] in ("res", "response", "c", "ctx", "reply"))):
            for value in values:
                self.sink("secret_exposure", "polaris.js.secret_exposure.output", value, node, f"{shown}(…)")

    def _local_shadow(self, name: str) -> bool:
        root = name.split(".")[0]
        return (root in self.file.functions and root not in self.file.imports) or (
            root in self.env and self.env[root].kind == "function")

    def _argument_injection(self, node: Any, nodes: list[Any], arguments: Value, binary: str) -> None:
        if not arguments.items:
            return
        array_node = unwrap(nodes[1]) if len(nodes) > 1 else None
        elements = named(array_node) if array_node is not None and array_node.type == "array" else []
        for index, item in enumerate(arguments.items):
            if item.literal == "--":
                return
            if item.taint.tainted and not item.taint.safe_for("command_injection"):
                column = self.file.column(elements[index]) if index < len(elements) else -1
                same_line = index < len(elements) and line_of(elements[index]) == line_of(node)
                self.sink("command_injection", "polaris.js.command_injection.argument_injection", item, node,
                          f"{binary} argument", edit_column=column if same_line else -1, edit_text='"--", ')
                return

    def _sql(self, node: Any, name: str, method: str, first: Value, nodes: list[Any]) -> None:
        if method in RAW_SQL_METHODS and (method != "unsafe" or name.split(".")[0] in ("sql", "db", "postgres", "pg")):
            replace_old = replace_new = ""
            argument = unwrap(nodes[0]) if nodes else None
            if method == "$queryRawUnsafe" and argument is not None and argument.type == "template_string" and len(nodes) == 1:
                replace_old = f"$queryRawUnsafe({txt(argument)})"
                replace_new = f"$queryRaw{txt(argument)}"
            elif method == "$executeRawUnsafe" and argument is not None and argument.type == "template_string" and len(nodes) == 1:
                replace_old = f"$executeRawUnsafe({txt(argument)})"
                replace_new = f"$executeRaw{txt(argument)}"
            self.sink("sql_injection", "polaris.js.sql_injection.raw_query", first, node, f"{method}(sql)",
                      replace_old=replace_old, replace_new=replace_new)
            return
        if name in ("drizzle-orm.sql.raw", "sql.raw", "Prisma.raw", "@prisma/client.Prisma.raw", "Prisma.sql.raw",
                    "sequelize.literal", "literal", "sequelize.Sequelize.literal", "Sequelize.literal") \
                or (method == "raw" and name.split(".")[0] in ("knex", "db", "trx", "sql")):
            self.sink("sql_injection", "polaris.js.sql_injection.raw_query", first, node, f"{name}(sql)")
            return
        if method in SQL_TEXT_METHODS and first.taint.tainted and first.kind in ("template", "concat", "join") \
                and len(SQL_KEYWORDS.findall(first.sql_text)) >= 2:
            self.sink("sql_injection", "polaris.js.sql_injection.query_text", first, node, f"{method}(sql)")
            return
        if method in ("or", "filter", "not") and first.taint.tainted and first.kind in ("template", "concat") \
                and re.search(r"\.(eq|neq|ilike|like|in|is|gt|lt|gte|lte|cs|cd)\.", first.sql_text):
            self.sink("sql_injection", "polaris.js.sql_injection.postgrest_filter", first, node, f".{method}(filter)")

    # ---- results ----------------------------------------------------------------------------

    def auth_facts(self) -> AuthFacts:
        entry = self.entry
        assert entry is not None
        guards = [name for name in self.guards if name]
        return AuthFacts(entry=entry, path=self.file.path, line=line_of(entry.node), guarded=bool(guards),
                         guard_names=guards[:5], writes=self.writes[:10], reads=self.reads[:10], sinks=self.sink_count,
                         rate_limited=self.rate_limited)


def iter_nodes(root: Any, limit: int = MAX_NODES) -> Iterator[Any]:
    stack = [root]
    count = 0
    while stack and count < limit:
        node = stack.pop()
        count += 1
        yield node
        stack.extend(reversed(node.children))

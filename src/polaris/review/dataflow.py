"""Machine-generated static facts about values reaching SQL and process-execution calls.

The analyzer reports facts only (where values come from, how arguments are built, whether a
shell is used), never a verdict. The model, or the separate rule baseline, decides. Submitted
code is parsed into a syntax tree; it is never imported or executed.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Literal

ANALYZER_VERSION = "polaris-static-notes/0.1.0"
SinkKind = Literal["sql", "process", "ssrf", "redirect", "xss", "path", "code", "secret"]
CHECK_FOR_KIND: dict[str, str] = {
    "sql": "sql_injection", "process": "command_injection", "ssrf": "ssrf", "redirect": "open_redirect",
    "xss": "xss", "path": "path_traversal", "code": "code_injection", "secret": "secret_exposure",
}
SINK_LABEL = {
    "sql": "SQL execution", "process": "process execution", "ssrf": "outbound HTTP request",
    "redirect": "redirect", "xss": "HTML output", "path": "filesystem access", "code": "code evaluation",
    "secret": "log or response output",
}
HTTP_CALLS = frozenset(
    f"{module}.{method}"
    for module in ("requests", "httpx")
    for method in ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")
) | frozenset({"urllib.request.urlopen", "urllib.request.Request", "urllib3.request", "aiohttp.request"})
REDIRECT_CALLS = frozenset({
    "flask.redirect", "werkzeug.utils.redirect", "django.shortcuts.redirect", "django.http.HttpResponseRedirect",
    "django.http.HttpResponsePermanentRedirect", "starlette.responses.RedirectResponse",
    "fastapi.responses.RedirectResponse", "quart.redirect",
})
HTML_CALLS = frozenset({
    "markupsafe.Markup", "flask.Markup", "jinja2.Markup", "django.utils.safestring.mark_safe",
    "fastapi.responses.HTMLResponse", "starlette.responses.HTMLResponse",
})
CODE_CALLS = frozenset({
    "eval", "exec", "compile", "builtins.eval", "builtins.exec", "pickle.loads", "pickle.load",
    "cPickle.loads", "marshal.loads", "dill.loads", "jsonpickle.decode", "yaml.load", "yaml.unsafe_load",
    "yaml.load_all", "flask.render_template_string", "jinja2.Template", "importlib.import_module",
    "__import__", "shelve.open",
})
PATH_CALLS = frozenset({
    "open", "io.open", "builtins.open", "codecs.open", "os.remove", "os.unlink", "os.rmdir",
    "os.removedirs", "os.listdir", "os.scandir", "os.makedirs", "os.mkdir", "os.rename", "os.replace",
    "os.chmod", "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move",
    "shutil.copytree", "flask.send_file", "fastapi.responses.FileResponse", "starlette.responses.FileResponse",
    "aiofiles.open",
})
OUTPUT_CALLS = frozenset({
    "print", "logging.info", "logging.warning", "logging.error", "logging.debug", "logging.critical",
    "logging.exception", "flask.jsonify", "django.http.JsonResponse", "django.http.HttpResponse",
    "fastapi.responses.JSONResponse", "starlette.responses.JSONResponse",
})
LOGGER_NAMES = frozenset({"logger", "log", "LOGGER", "LOG", "_logger", "_log"})
# Workflow (web) analysis only. Request methods of HTTP client objects are SSRF sinks.
HTTP_CLIENT_TYPES = frozenset({
    "httpx.Client", "httpx.AsyncClient", "requests.Session", "requests.session", "requests.sessions.Session",
    "aiohttp.ClientSession", "urllib3.PoolManager",
})
HTTP_CLIENT_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "urlopen"})
# pathlib reads and writes: the first four exist only on paths; the rest need a visible path.
PATH_IO_METHODS = frozenset({"read_text", "read_bytes", "write_text", "write_bytes"})
PATH_METHODS = frozenset({"open", "unlink", "rmdir", "mkdir", "touch", "iterdir", "symlink_to", "hardlink_to", "chmod"})
PATH_TYPES = frozenset({
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePosixPath",
    "pathlib.PureWindowsPath",
})
PATH_DERIVING = frozenset({"joinpath", "with_name", "with_suffix", "with_stem", "resolve", "absolute", "expanduser"})
# These remove ".." (resolve/realpath also symlinks), so a prefix check afterwards is a containment check.
NORMALIZERS = frozenset({
    "os.path.realpath", "os.path.abspath", "os.path.normpath", "posixpath.realpath", "posixpath.abspath",
    "posixpath.normpath",
})
# Return a bare file name, or refuse paths that leave the base directory.
WEB_SANITIZERS = frozenset({
    "werkzeug.utils.secure_filename", "werkzeug.utils.safe_join", "werkzeug.security.safe_join",
    "django.utils._os.safe_join",
})
EXIT_CALLS = frozenset({"abort", "flask.abort", "werkzeug.exceptions.abort", "quart.abort", "sys.exit"})
SECRET_ENV = re.compile(r"(?i)(secret|token|password|passwd|private|api_?key|access_?key|credential)")
NOT_SECRET_ENV = re.compile(r"(?i)(public|publishable|anon|_url$|_uri$|_host$|_name$|_id$|_region$|_path$)")
WEB_KINDS = frozenset({"ssrf", "redirect", "xss", "path", "code", "secret"})

SQL_METHODS = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "mogrify",
        "raw",
        "read_sql",
        "read_sql_query",
        "exec_driver_sql",
        "execute_sql",
    }
)
# Only treated as SQL when the first argument is built as a string.
SQL_STRING_METHODS = frozenset({"query", "fetch", "fetchrow", "fetchval"})
# asyncpg's fetch methods share names with HTTP clients, so their string must also read as SQL.
SQL_KEYWORD_METHODS = frozenset({"fetch", "fetchrow", "fetchval"})
SQL_KEYWORDS = re.compile(r"\b(select|insert|update|delete|from|where|values|returning|join|into)\b", re.IGNORECASE)
SQL_TEXT_FUNCTIONS = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"})
DJANGO_EXTRA_KEYWORDS = ("where", "select", "tables", "order_by")

SHELL_ALWAYS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "commands.getoutput",
        "commands.getstatusoutput",
        "asyncio.create_subprocess_shell",
    }
)
PROCESS_CALLS = (
    frozenset(
        {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "asyncio.create_subprocess_exec",
            "pty.spawn",
        }
    )
    | frozenset(
        f"os.{name}"
        for name in (
            "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
            "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        )
    )
    | SHELL_ALWAYS
)
SANITIZERS = frozenset(
    {"int", "float", "bool", "len", "abs", "round", "shlex.quote", "pipes.quote", "uuid.UUID"}
)
REQUEST_ATTRIBUTES = frozenset(
    {
        "args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST",
        "FILES", "COOKIES", "META", "body", "query_params", "path_params", "get_json", "query_string",
    }
)
PLACEHOLDER = re.compile(r"\?|%s|%\(\w+\)s|(?<![:\w]):[A-Za-z_]\w*|\$\d+")
MAX_NOTE_ITEMS = 6
SHORT_LITERAL = 24
# Methods that add values to the container they are called on.
MUTATORS = frozenset({"append", "extend", "insert", "add", "update", "appendleft", "setdefault"})
# Builtins whose result keeps the origin of their arguments.
TRANSPARENT = frozenset(
    {"str", "repr", "format", "list", "tuple", "sorted", "reversed", "min", "max", "sum", "set",
     "frozenset", "dict", "enumerate", "zip", "map", "filter", "iter", "next", "any", "all", "range"}
)
# Standard-library helpers whose result is derived only from their arguments.
PURE = frozenset(
    {"shlex.split", "shlex.join", "os.path.join", "os.path.basename", "os.path.dirname", "os.path.abspath",
     "os.path.normpath", "os.path.expanduser", "os.path.splitext", "os.fspath", "pathlib.Path",
     "pathlib.PurePath", "json.dumps", "json.loads", "textwrap.dedent", "re.escape", "posixpath.join",
     "shutil.which"}
)


@dataclass(frozen=True)
class ArgInfo:
    """How a query or command argument is built, stated as facts."""

    form: str
    text: str
    tainted: tuple[str, ...] = ()
    sanitized: tuple[str, ...] = ()
    visible: bool = True
    elements: tuple[ArgInfo, ...] = ()
    via: str | None = None
    value: str | None = None  # short string literals only
    prefix: str | None = None  # constant leading text of a built string (URL scheme/host checks)
    identifier_position: bool = False  # an untrusted part follows FROM/JOIN/INTO/ORDER BY/...


@dataclass(frozen=True)
class Sink:
    kind: SinkKind
    line: int
    call: str
    argument: ArgInfo | None
    parameters: bool | None = None
    shell: Literal["yes", "no", "always", "expression"] | None = None
    # Expanded origins: source descriptions, "request input X" (entry-point arguments) or "parameter X".
    origins: tuple[str, ...] = ()
    edit_line: int = 0  # argument injection: where `"--", ` would be inserted
    edit_column: int = -1


@dataclass
class FlowFacts:
    sources: list[str] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)

    def kinds(self) -> set[str]:
        return {sink.kind for sink in self.sinks}

    def sinks_for(self, check_id: str) -> list[Sink]:
        return [sink for sink in self.sinks if CHECK_FOR_KIND[sink.kind] == check_id]

    def render(self) -> str:
        lines = [f"Static notes from {ANALYZER_VERSION} (machine-generated; may be incomplete)."]
        sources = self.sources[:MAX_NOTE_ITEMS]
        more = len(self.sources) - len(sources)
        lines.append(
            "Untrusted sources: "
            + ("; ".join(sources) + (f"; and {more} more" if more > 0 else "") if sources else "none identified")
            + "."
        )
        lines.append("Calls of interest:")
        for sink in self.sinks[:MAX_NOTE_ITEMS]:
            lines.append("- " + describe_sink(sink))
        if len(self.sinks) > MAX_NOTE_ITEMS:
            lines.append(f"- and {len(self.sinks) - MAX_NOTE_ITEMS} more similar calls")
        return "\n".join(lines)


def describe_sink(sink: Sink) -> str:
    label = SINK_LABEL.get(sink.kind, sink.kind)
    text = f"line {sink.line} {sink.call}: {label}."
    noun = {"sql": "Query", "process": "Command"}.get(sink.kind, "Value")
    text += f" {noun}: {sink.argument.text if sink.argument else 'not visible in this call'}."
    if sink.kind == "sql" and sink.parameters is not None:
        text += f" Separate parameters: {'yes' if sink.parameters else 'no'}."
    if sink.kind == "process" and sink.shell is not None:
        text += {
            "yes": " Shell: yes (shell=True).",
            "no": " Shell: no.",
            "always": " Shell: always (this call runs a shell).",
            "expression": " Shell: set by an expression.",
        }[sink.shell]
    return text


def module_imports(tree: ast.AST) -> dict[str, str]:
    """Map local names to qualified imports, e.g. {'sp': 'subprocess', 'run': 'subprocess.run'}."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def module_http_clients(tree: ast.Module, imports: dict[str, str]) -> frozenset[str]:
    """Module-level names bound to HTTP client objects, e.g. `session = requests.Session()`."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call) \
                and dotted(node.value.func, imports) in HTTP_CLIENT_TYPES:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(target.id for target in targets if isinstance(target, ast.Name))
    return frozenset(names)


def dotted(node: ast.expr, imports: dict[str, str]) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return ".".join([imports.get(node.id, node.id), *reversed(parts)])
    if isinstance(node, ast.Call):
        inner = dotted(node.func, imports)
        return ".".join([f"{inner}()" if inner else "call()", *reversed(parts)])
    return None


def _short(name: str) -> str:
    """Readable callee: keep at most the last three dotted parts."""
    parts = name.split(".")
    return ".".join(parts[-3:]) if len(parts) > 3 else name


def _is_stringish(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Name) and node.id.isupper():
        return True  # module-level string templates such as QUERY_TEMPLATE % value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _is_stringish(node.left) or _is_stringish(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in ("format", "join") and isinstance(node.func.value, (ast.Constant, ast.JoinedStr))
    return False


def _reads_as_sql(node: ast.expr) -> bool:
    """Do the literal parts of this string contain at least two SQL keywords?"""
    text = " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    return len({match.lower() for match in SQL_KEYWORDS.findall(text)}) >= 2


class _Analyzer:
    def __init__(self, imports: dict[str, str], params: list[str], entry: bool = False, web: bool = False,
                 clients: frozenset[str] = frozenset()) -> None:
        self.imports = imports
        self.params = params
        self.web = web
        # Web analysis: names bound to HTTP client objects, to paths, and to normalized paths.
        self.clients: set[str] = set(clients)
        self.paths: set[str] = set()
        self.normalized: set[str] = set()
        # Arguments of request handlers (Flask/FastAPI/Django routes) come from the client.
        self.entry_params = frozenset(params) if entry else frozenset()
        self.tainted: dict[str, str] = {name: "parameter" for name in params}
        self.values: dict[str, ArgInfo] = {}
        self.sources: dict[str, None] = {
            (f"request input {name}" if entry else f"parameter {name}"): None for name in params
        }
        self.sinks: list[Sink] = []

    # ---- expressions -------------------------------------------------------------------------

    def _source(self, node: ast.expr) -> str | None:
        name = dotted(node, self.imports) if isinstance(node, (ast.Attribute, ast.Name, ast.Call)) else None
        if isinstance(node, ast.Call):
            called = dotted(node.func, self.imports)
            if called in ("input", "builtins.input", "raw_input"):
                return "input()"
            if called in ("os.getenv", "os.environ.get"):
                key = node.args[0] if node.args else None
                name = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else ""
                if name and SECRET_ENV.search(name) and not NOT_SECRET_ENV.search(name):
                    return f"secret environment value ({name})"
                return "environment variable"
            if called and called.endswith((".parse_args", ".parse_known_args")):
                return "command-line arguments"
            if called:
                parts = called.split(".")
                if "request" in parts[:-1] and parts[-1] in ("get_json", "get_data", "json", "body", "text"):
                    return f"request data ({'.'.join(parts[-3:])}())"
            if called and called.endswith((".read", ".readline", ".readlines", ".recv", ".recvfrom")):
                return "file or network data"
            if called and called.split(".")[0] == "requests" and called.split(".")[-1] in (
                "get", "post", "put", "request",
            ):
                return "network response"
            return None
        if name is None:
            return None
        if name == "sys.argv" or name.startswith("sys.argv."):
            return "command-line arguments"
        if name.startswith("os.environ"):
            return "environment variable"
        if isinstance(node, ast.Subscript) and dotted(node.value, self.imports) == "os.environ":
            key = node.slice
            env_name = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else ""
            if env_name and SECRET_ENV.search(env_name) and not NOT_SECRET_ENV.search(env_name):
                return f"secret environment value ({env_name})"
            return "environment variable"
        parts = name.split(".")
        if len(parts) >= 2 and parts[-2] == "request" or (len(parts) >= 2 and parts[0] == "request"):
            if any(part in REQUEST_ATTRIBUTES for part in parts[1:]):
                return f"request data ({'.'.join(parts[:3])})"
        return None

    def visible(self, name: str) -> bool:
        """Is this name's origin visible inside the unit (local value, parameter, constant, import)?"""
        if name in self.values:
            return self.values[name].visible
        return name in self.params or name.isupper() or name in self.imports

    def _passes_origin(self, expr: ast.Call) -> bool:
        """Transparent builtins, and methods called on a visible local value or string literal."""
        func = expr.func
        if dotted(func, self.imports) in PURE:
            return True
        if isinstance(func, ast.Name):
            return func.id in TRANSPARENT and func.id not in self.imports
        if isinstance(func, ast.Attribute):
            base: ast.expr = func.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Constant | ast.JoinedStr):
                return True
            if isinstance(base, ast.Name):
                if self._source(func.value) is not None:
                    return True
                return base.id in self.values or base.id in self.params
        return False

    def _web_sanitizer(self, called: str | None) -> bool:
        return self.web and called in WEB_SANITIZERS

    def _client_object(self, expr: ast.expr | None) -> bool:
        return isinstance(expr, ast.Call) and dotted(expr.func, self.imports) in HTTP_CLIENT_TYPES

    def _client_request(self, call: ast.Call) -> bool:
        """`client.get(url)` on an httpx/requests/aiohttp client object."""
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in HTTP_CLIENT_METHODS:
            return False
        receiver = call.func.value
        return (isinstance(receiver, ast.Name) and receiver.id in self.clients) or self._client_object(receiver)

    def _pathish(self, expr: ast.expr | None) -> bool:
        """Visibly a pathlib path: `base / name`, `Path(...)`, or derived from one."""
        if isinstance(expr, ast.BinOp):
            return isinstance(expr.op, ast.Div)
        if isinstance(expr, ast.Name):
            return expr.id in self.paths
        if isinstance(expr, ast.Attribute):
            return expr.attr == "parent" and self._pathish(expr.value)
        if isinstance(expr, ast.Call):
            if dotted(expr.func, self.imports) in PATH_TYPES:
                return True
            return isinstance(expr.func, ast.Attribute) and expr.func.attr in PATH_DERIVING and self._pathish(expr.func.value)
        return False

    def _normalizes(self, expr: ast.expr | None) -> bool:
        """The value's last step is os.path.realpath/abspath/normpath or Path.resolve()."""
        if isinstance(expr, ast.Name):
            return expr.id in self.normalized
        if not isinstance(expr, ast.Call):
            return False
        called = dotted(expr.func, self.imports) or ""
        if called in NORMALIZERS:
            return True
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "resolve":
            return self._pathish(expr.func.value)
        return called in ("str", "os.fspath") and bool(expr.args) and self._normalizes(expr.args[0])

    def _track(self, target: ast.expr, value: ast.expr) -> None:
        """Web analysis: remember which names hold HTTP clients, paths and normalized paths."""
        if not self.web or not isinstance(target, ast.Name):
            return
        for names, holds in ((self.clients, self._client_object(value)), (self.paths, self._pathish(value)),
                             (self.normalized, self._normalizes(value))):
            if holds:
                names.add(target.id)
            else:
                names.discard(target.id)

    def _exits(self, body: list[ast.stmt]) -> bool:
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
            return True
        # Web analysis: `abort(404)` ends the request just like raising.
        return self.web and isinstance(last, ast.Expr) and isinstance(last.value, ast.Call) \
            and dotted(last.value.func, self.imports) in EXIT_CALLS

    @staticmethod
    def _constant_lookup(expr: ast.Call) -> bool:
        func = expr.func
        return (
            isinstance(func, ast.Attribute) and func.attr == "get"
            and isinstance(func.value, ast.Name) and func.value.id.isupper()
        )

    def names_in(self, node: ast.expr) -> tuple[list[str], list[str], list[str], list[str]]:
        """Return (referenced, tainted, sanitized, hidden) labels inside an expression.

        Labels are names or attribute chains (`self.table`, `payload.name`). Hidden labels have
        an origin that isn't visible in this unit.
        """
        referenced: list[str] = []
        tainted: list[str] = []
        sanitized: list[str] = []
        hidden: list[str] = []

        def visit(expr: ast.AST, clean: bool) -> None:
            if isinstance(expr, (ast.GeneratorExp, ast.ListComp, ast.SetComp)) and isinstance(expr.elt, ast.Constant):
                # Every element is the same literal (for example "?" placeholders); input only sets the count.
                return
            if isinstance(expr, ast.expr):
                source = self._source(expr)
                if source is not None:
                    self.sources.setdefault(f"{source} (line {getattr(expr, 'lineno', '?')})", None)
                    (sanitized if clean else tainted).append(source)
                    return
            if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
                referenced.append(expr.id)
                if expr.id in self.tainted:
                    (sanitized if clean else tainted).append(expr.id)
                elif not self.visible(expr.id):
                    hidden.append(expr.id)
                return
            if isinstance(expr, ast.Subscript) and dotted(expr.value, self.imports) == "os.environ":
                source = self._source(expr)
                if source is not None:
                    (sanitized if clean else tainted).append(source)
                    return
            if isinstance(expr, ast.Attribute):
                base: ast.expr = expr
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    label = dotted(expr, {}) or base.id
                    referenced.append(label)
                    if base.id in self.tainted:
                        (sanitized if clean else tainted).append(label)
                    elif base.id in ("self", "cls") or not self.visible(base.id):
                        hidden.append(label)
                    return
            if isinstance(expr, ast.Call):
                called = dotted(expr.func, self.imports)
                lookup = self._constant_lookup(expr)
                is_clean = clean or (called in SANITIZERS if called else False) or lookup or self._web_sanitizer(called)
                if not is_clean and not self._passes_origin(expr):
                    # The result of an unknown function could be anything: its origin isn't visible.
                    label = f"{_short(called or 'call')}()"
                    referenced.append(label)
                    hidden.append(label)
                if isinstance(expr.func, ast.Attribute) and not lookup:
                    visit(expr.func.value, is_clean)
                for argument in expr.args:
                    visit(argument, is_clean)
                for keyword in expr.keywords:
                    visit(keyword.value, is_clean)
                return
            for child in ast.iter_child_nodes(expr):
                visit(child, clean)

        visit(node, False)
        unique = lambda items: list(dict.fromkeys(items))  # noqa: E731
        tainted = unique(tainted)
        return (unique(referenced), tainted, unique(item for item in sanitized if item not in tainted),
                unique(item for item in hidden if item not in tainted))

    def describe(self, node: ast.expr) -> ArgInfo:
        referenced, tainted, sanitized, hidden = self.names_in(node)

        def using(prefix: str) -> str:
            shown = []
            for name in referenced[:4]:
                if name in tainted:
                    shown.append(f"{name} (untrusted)")
                elif name in hidden:
                    shown.append(f"{name} (origin not visible)")
                else:
                    shown.append(name)
            shown += [label for label in tainted if label not in referenced][:2]
            if sanitized:
                shown.append("sanitized: " + ", ".join(sanitized[:3]))
            return prefix + (" using " + ", ".join(shown) if shown else "")

        def built(form: str, prefix: str) -> ArgInfo:
            return ArgInfo(form, using(prefix), tuple(tainted), tuple(sanitized), not hidden,
                           prefix=_leading_text(node), identifier_position=_identifier_position(node, set(tainted)))

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if PLACEHOLDER.search(node.value):
                return ArgInfo("literal with placeholders", "string literal with placeholders", prefix=node.value)
            if len(node.value) <= SHORT_LITERAL:
                return ArgInfo("literal", f"string literal {node.value!r}", value=node.value, prefix=node.value)
            return ArgInfo("literal", "string literal", prefix=node.value)
        if isinstance(node, ast.Constant):
            return ArgInfo("literal", "literal value")
        if isinstance(node, ast.JoinedStr):
            return built("f-string", "f-string")
        if isinstance(node, ast.Call) and "sql.SQL" in (dotted(node.func, self.imports) or ""):
            return ArgInfo("composed", using("psycopg sql composition"), (), tuple(tainted + sanitized))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_stringish(node.left):
            return built("%-formatting", "%-formatted string")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return built("concatenation", "concatenation")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return built(".format()", ".format() string")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            return built("join", "joined string")
        if isinstance(node, (ast.List, ast.Tuple)):
            elements = tuple(self.describe(item) for item in node.elts[:8])
            listed = ", ".join(element.text for element in elements)
            if len(node.elts) > 8:
                listed += ", ..."
            kind = "list" if isinstance(node, ast.List) else "tuple"
            return ArgInfo(
                kind,
                f"{kind} [{listed}]",
                tuple(dict.fromkeys(t for element in elements for t in element.tainted)),
                tuple(dict.fromkeys(s for element in elements for s in element.sanitized)),
                all(element.visible for element in elements),
                elements,
            )
        if isinstance(node, ast.Name):
            if node.id in self.values:
                known = self.values[node.id]
                return ArgInfo(
                    known.form,
                    f"variable {node.id} ({known.text})",
                    known.tainted,
                    known.sanitized,
                    known.visible,
                    known.elements,
                    via=node.id,
                    value=known.value,
                    prefix=known.prefix,
                    identifier_position=known.identifier_position,
                )
            if node.id in self.entry_params:
                label = f"request input {node.id}"
                return ArgInfo("source", f"{label} (untrusted)", (label,), (), True, via=node.id)
            if node.id in self.params:
                return ArgInfo("parameter", f"parameter {node.id} (untrusted)", (node.id,), (), True, via=node.id)
            if node.id.isupper():
                return ArgInfo("constant", f"constant {node.id} (defined outside this function)", via=node.id)
            return ArgInfo(
                "outside",
                f"{node.id} (assigned outside this function; origin not visible)",
                visible=False,
                via=node.id,
            )
        source = self._source(node)
        if source is not None:
            return ArgInfo("source", f"{source} (untrusted)", (source,))
        if isinstance(node, ast.Call) and self._constant_lookup(node):
            container = node.func.value.id  # type: ignore[attr-defined]
            return ArgInfo("lookup", using(f"lookup in constant {container}"), (), tuple(tainted + sanitized))
        if isinstance(node, ast.Call):
            called = dotted(node.func, self.imports) or "call"
            if called in SANITIZERS or self._web_sanitizer(called):
                return ArgInfo("sanitized", using(f"result of {_short(called)}()"), (), tuple(tainted + sanitized))
            if (called in SQL_TEXT_FUNCTIONS or (called == "text" and self.imports.get("text", "").startswith("sqlalchemy"))) and node.args:
                inner = self.describe(node.args[0])
                return ArgInfo(inner.form, f"text() of {inner.text}", inner.tainted, inner.sanitized, inner.visible,
                               inner.elements, inner.via, inner.value)
            if called in ("shlex.split",):
                inner_via = None
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in self.params:
                    inner_via = node.args[0].id
                return ArgInfo("split", using("shlex.split() of a string"), tuple(tainted), tuple(sanitized),
                               not hidden, via=inner_via)
            if self._passes_origin(node):
                return built("expression", f"result of {_short(called)}()")
            if called.split(".")[-1] in ("SQL", "Identifier", "Literal", "Composed") and "sql" in called:
                return ArgInfo("composed", using("psycopg sql composition"), (), tuple(tainted + sanitized))
            return ArgInfo(
                "call",
                using(f"result of {_short(called)}(...)") + " (defined elsewhere; result not visible)",
                tuple(tainted),
                tuple(sanitized),
                visible=False,
            )
        if isinstance(node, ast.Attribute):
            label = dotted(node, {}) or "value"
            if tainted:
                return ArgInfo("attribute", f"attribute {label} (untrusted)", tuple(tainted), tuple(sanitized))
            if hidden:
                return ArgInfo("attribute", f"attribute {label} (origin not visible)", visible=False)
            return ArgInfo("attribute", f"attribute {label}", (), tuple(sanitized))
        if isinstance(node, ast.Subscript):
            container = node.value
            if isinstance(container, ast.Name) and container.id.isupper():
                return ArgInfo("lookup", using(f"lookup in constant {container.id}"), (), tuple(tainted))
            return built("subscript", "subscript")
        if isinstance(node, ast.IfExp):
            left, right = self.describe(node.body), self.describe(node.orelse)
            return ArgInfo(
                "conditional",
                f"conditional: {left.text} or {right.text}",
                tuple(dict.fromkeys(left.tainted + right.tainted)),
                tuple(dict.fromkeys(left.sanitized + right.sanitized)),
                left.visible and right.visible,
            )
        return built("expression", "expression")

    # ---- statements ----------------------------------------------------------------------------

    def assign(self, target: ast.expr, info: ArgInfo) -> None:
        if isinstance(target, ast.Name):
            self.values[target.id] = info
            if info.tainted:
                self.tainted[target.id] = "derived"
            else:
                self.tainted.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.assign(item, info)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, info)

    def statements(self, body: list[ast.stmt]) -> None:
        for statement in body:
            self.statement(statement)

    def statement(self, node: ast.stmt) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                if argument.arg not in ("self", "cls"):
                    self.tainted[argument.arg] = "parameter"
            self.statements(node.body)
            return
        if isinstance(node, ast.ClassDef):
            return
        if isinstance(node, ast.Assign):
            self.calls(node.value)
            info = self.describe(node.value)
            for target in node.targets:
                self.assign(target, info)
                self._track(target, node.value)
            return
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            self.calls(node.value)
            self.assign(node.target, self.describe(node.value))
            self._track(node.target, node.value)
            return
        if isinstance(node, ast.AugAssign):
            self.calls(node.value)
            if isinstance(node.target, ast.Name):
                previous = self.values.get(node.target.id)
                added = self.describe(node.value)
                tainted = tuple(dict.fromkeys((previous.tainted if previous else ()) + added.tainted))
                if node.target.id in self.tainted and node.target.id not in tainted:
                    tainted = (*tainted, node.target.id)
                form = "concatenation" if isinstance(node.op, ast.Add) else "expression"
                shown = ", ".join(f"{name} (untrusted)" for name in tainted[:4])
                self.assign(
                    node.target,
                    ArgInfo(form, f"{form} built with +=" + (f" using {shown}" if shown else ""), tainted,
                            added.sanitized, previous.visible if previous else False),
                )
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self.calls(node.iter)
            self.assign(node.target, self.describe(node.iter))
            self.statements(node.body)
            self.statements(node.orelse)
            return
        if isinstance(node, ast.If):
            self.calls(node.test)
            guarded = self._guarded(node.test)
            exits = self._exits(node.body)
            # Web analysis reads the check's direction from the test; otherwise a body that exits
            # is taken as the failure branch.
            polarity = self._polarity(node.test) if self.web and guarded else None
            if polarity == "positive" or (polarity is None and guarded and not exits):
                saved = {name: (self.tainted.get(name), self.values.get(name)) for name in guarded}
                self._allowlisted(guarded)  # positive form: `if table in ALLOWED: use(table)`
                self.statements(node.body)
                for name, (taint, value) in saved.items():
                    if taint is not None:
                        self.tainted[name] = taint
                    if value is not None:
                        self.values[name] = value
                    else:
                        self.values.pop(name, None)
            else:
                self.statements(node.body)
            self.statements(node.orelse)
            if guarded and exits and polarity != "positive":
                self._allowlisted(guarded)  # negative form: `if table not in ALLOWED: raise`
            return
        if isinstance(node, ast.Assert):
            self.calls(node.test)
            self._allowlisted(self._guarded(node.test))
            return
        if isinstance(node, ast.While):
            self.calls(node.test)
            self.statements(node.body)
            self.statements(node.orelse)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.calls(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, self.describe(item.context_expr))
                    self._track(item.optional_vars, item.context_expr)
            self.statements(node.body)
            return
        if isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            self.statements(node.body)  # type: ignore[attr-defined]
            for handler in node.handlers:  # type: ignore[attr-defined]
                self.statements(handler.body)
            self.statements(node.orelse)  # type: ignore[attr-defined]
            self.statements(node.finalbody)  # type: ignore[attr-defined]
            return
        if isinstance(node, ast.Match):
            self.calls(node.subject)
            for case in node.cases:
                self.statements(case.body)
            return
        if (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute) and node.value.func.attr in MUTATORS
            and isinstance(node.value.func.value, ast.Name)
        ):
            # `clauses.append(value)` puts value's origin into `clauses`.
            self.calls(node.value)
            container: str = node.value.func.value.id
            earlier = self.values.get(container)
            pieces = [self.describe(argument) for argument in node.value.args]
            pieces += [self.describe(keyword.value) for keyword in node.value.keywords]
            merged_tainted = tuple(dict.fromkeys(
                (earlier.tainted if earlier else ()) + tuple(t for piece in pieces for t in piece.tainted)))
            merged_sanitized = tuple(dict.fromkeys(
                (earlier.sanitized if earlier else ()) + tuple(s for piece in pieces for s in piece.sanitized)))
            merged_visible = (earlier.visible if earlier else self.visible(container)) and all(
                piece.visible for piece in pieces)
            kind = earlier.form if earlier else "expression"
            listed = ", ".join(f"{name} (untrusted)" for name in merged_tainted[:4])
            self.assign(
                ast.Name(id=container, ctx=ast.Store()),
                ArgInfo(kind, f"{kind} extended with {node.value.func.attr}()" + (f" using {listed}" if listed else ""),
                        merged_tainted, merged_sanitized, merged_visible, earlier.elements if earlier else ()),
            )
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.calls(child)

    # ---- guards -------------------------------------------------------------------------------

    def _constant_container(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id.isupper()
        if isinstance(node, ast.Attribute):
            return node.attr.isupper()
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            return all(isinstance(item, ast.Constant) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(isinstance(key, ast.Constant) for key in node.keys if key is not None)
        if isinstance(node, ast.Call) and dotted(node.func, self.imports) in ("set", "frozenset", "tuple", "list"):
            return all(self._constant_container(argument) for argument in node.args)
        return False

    def _guarded(self, test: ast.expr) -> set[str]:
        """Untrusted names an allowlist/format check constrains (membership, equality, fullmatch)."""
        names: set[str] = set()
        for node in ast.walk(test):
            if isinstance(node, ast.Compare):
                operands = [node.left, *node.comparators]
                if any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops) and self._constant_container(operands[-1]):
                    names.update(item.id for item in ast.walk(node.left) if isinstance(item, ast.Name))
                if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops) and any(
                        isinstance(item, ast.Constant) and isinstance(item.value, str) for item in operands):
                    names.update(item.id for operand in operands for item in ast.walk(operand) if isinstance(item, ast.Name))
                if self.web and any(isinstance(item, ast.Call) and dotted(item.func, self.imports) in (
                        "os.path.commonpath", "posixpath.commonpath") for item in operands):
                    # os.path.commonpath([BASE, real]) == BASE, on a normalized path.
                    names.update(item.id for operand in operands for item in ast.walk(operand)
                                 if isinstance(item, ast.Name) and item.id in self.normalized)
            elif isinstance(node, ast.Call):
                called = dotted(node.func, self.imports) or ""
                if self.web and isinstance(node.func, ast.Attribute) and node.func.attr in ("is_relative_to", "startswith") \
                        and any(isinstance(item, ast.Name) and item.id in self.normalized for item in ast.walk(node.func.value)):
                    # Containment: real.is_relative_to(BASE) / real.startswith(BASE) after resolve/realpath.
                    # On an unnormalized path these checks are lexical and ".." passes them.
                    names.update(item.id for item in ast.walk(node.func.value)
                                 if isinstance(item, ast.Name) and item.id in self.normalized)
                elif called in ("re.fullmatch", "re.match") and len(node.args) >= 2:
                    names.update(item.id for item in ast.walk(node.args[1]) if isinstance(item, ast.Name))
                elif isinstance(node.func, ast.Attribute) and node.func.attr in (
                        "isalnum", "isidentifier", "isdigit", "isdecimal", "isnumeric", "isalpha", "fullmatch"):
                    target = node.func.value if node.func.attr != "fullmatch" else (node.args[0] if node.args else node.func.value)
                    names.update(item.id for item in ast.walk(target) if isinstance(item, ast.Name))
                elif called.split(".")[-1].startswith(("is_valid", "is_allowed", "validate_", "is_safe", "allowed_")):
                    names.update(item.id for argument in node.args for item in ast.walk(argument) if isinstance(item, ast.Name))
        return {name for name in names if name in self.tainted}

    @staticmethod
    def _polarity(test: ast.expr) -> str | None:
        """"negative" when the branch runs if the check fails (`not ok(x)`, `x not in ALLOWED`),
        "positive" when it runs if the check passes (`ok(x)`, `x in ALLOWED`), None if unclear."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return "negative"
        if isinstance(test, ast.Compare):
            if all(isinstance(op, (ast.NotIn, ast.NotEq)) for op in test.ops):
                return "negative"
            if all(isinstance(op, (ast.In, ast.Eq)) for op in test.ops):
                return "positive"
            return None  # `is None` comparisons can go either way
        return "positive" if isinstance(test, ast.Call) else None

    def _allowlisted(self, names: set[str]) -> None:
        for name in names:
            self.tainted.pop(name, None)
            self.values[name] = ArgInfo("sanitized", f"{name} (checked against an allowlist)", (), (name,), True,
                                        via=name)

    def _origins(self, labels: tuple[str, ...], seen: frozenset[str] = frozenset()) -> tuple[str, ...]:
        """Expand variable names to where their values came from."""
        found: list[str] = []
        for label in labels:
            base = label.split(".")[0]
            if " " in label:
                found.append(label)
            elif base in self.entry_params:
                found.append(f"request input {base}")
            elif base in self.values and base not in seen:
                found.extend(self._origins(self.values[base].tainted, seen | {base}))
            elif base in self.params:
                found.append(f"parameter {base}")
            elif base in self.tainted:
                found.append(f"parameter {base}")
        return tuple(dict.fromkeys(found))

    def _web_sink(self, call: ast.Call, name: str | None, line: int) -> None:
        """SSRF, redirects, HTML/template output, file paths, code loading and secret output."""
        method = call.func.attr if isinstance(call.func, ast.Attribute) else None
        if isinstance(call.func, ast.Attribute) and (
                call.func.attr in PATH_IO_METHODS or (call.func.attr in PATH_METHODS and self._pathish(call.func.value))):
            # pathlib: the path the method is called on is what gets read or written. Helpers and
            # tools call these on paths they were handed all the time, so only request input in
            # the same function is reported (not parameters or command-line arguments).
            info = self.describe(call.func.value)
            origins = tuple(origin for origin in self._origins(info.tainted)
                            if origin.startswith(("request data", "request input")))
            if origins:
                self.sinks.append(Sink("path", line, f"Path.{call.func.attr}", info, origins=origins))
            return
        logger = (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                  and call.func.value.id in LOGGER_NAMES and method in ("info", "warning", "error", "debug", "critical", "exception"))
        if name is None and not logger:
            return
        targets: list[tuple[SinkKind, ast.expr | None]] = []
        if name in HTTP_CALLS:
            index = 1 if name.endswith(".request") and name.split(".")[0] in ("requests", "httpx") else 0
            targets.append(("ssrf", self.argument(call, index, "url")))
        elif self._client_request(call):
            index = 1 if method in ("request", "stream", "urlopen") else 0
            targets.append(("ssrf", self.argument(call, index, "url")))
        elif name in REDIRECT_CALLS:
            targets.append(("redirect", self.argument(call, 0, "location", "url", "redirect_to", "to")))
        elif name in HTML_CALLS:
            targets.append(("xss", self.argument(call, 0, "content", "base")))
        elif name in CODE_CALLS:
            if name in ("yaml.load", "yaml.load_all"):
                loader = next((k.value for k in call.keywords if k.arg == "Loader"), call.args[1] if len(call.args) > 1 else None)
                if loader is not None and "Safe" in (dotted(loader, self.imports) or ""):
                    return
            targets.append(("code", self.argument(call, 0, "source", "data", "name")))
        elif name in PATH_CALLS:
            targets.append(("path", self.argument(call, 0, "file", "path", "path_or_file", "src")))
            if name in ("os.rename", "os.replace", "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move", "shutil.copytree"):
                targets.append(("path", self.argument(call, 1, "dst")))
        elif name in OUTPUT_CALLS or logger:
            targets.extend(("secret", value) for value in [*call.args, *(k.value for k in call.keywords)])
        for kind, target in targets:
            if target is None:
                continue
            info = self.describe(target)
            origins = self._origins(info.tainted)
            self.sinks.append(Sink(kind, line, _short(name or f"logger.{method}"), info, origins=origins))

    # ---- sinks ---------------------------------------------------------------------------------

    def calls(self, node: ast.expr) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.assign(child.target, self.describe(child.value))
            if isinstance(child, ast.Call):
                self.sink(child)

    def argument(self, call: ast.Call, index: int, *keywords: str) -> ast.expr | None:
        for keyword in call.keywords:
            if keyword.arg in keywords:
                return keyword.value
        return call.args[index] if len(call.args) > index else None

    def sink(self, call: ast.Call) -> None:
        name = dotted(call.func, self.imports)
        method = call.func.attr if isinstance(call.func, ast.Attribute) else None
        line = call.lineno
        if self.web:
            self._web_sink(call, name, line)
        if name in PROCESS_CALLS:
            target: ast.expr | None = None
            if name.startswith("os.exec") or name.startswith("os.spawn"):
                start = 1 if name.startswith("os.spawn") else 0
                pieces = call.args[start:]
                argument = self.describe(ast.List(elts=list(pieces), ctx=ast.Load())) if pieces else None
                shell: Literal["yes", "no", "always", "expression"] = "no"
            else:
                target = self.argument(call, 0, "args", "cmd", "command")
                argument = self.describe(target) if target is not None else None
                if name in SHELL_ALWAYS:
                    shell = "always"
                else:
                    flag = next((k.value for k in call.keywords if k.arg == "shell"), None)
                    if flag is None or (isinstance(flag, ast.Constant) and not flag.value):
                        shell = "no"
                    elif isinstance(flag, ast.Constant) and flag.value:
                        shell = "yes"
                    else:
                        shell = "expression"
            edit_line, edit_column = 0, -1
            if target is not None and isinstance(target, ast.List) and not name.startswith(("os.exec", "os.spawn")):
                for element in target.elts[1:]:
                    if isinstance(element, ast.Constant) and element.value == "--":
                        break
                    described = self.describe(element)
                    if described.tainted and element.lineno == element.end_lineno:
                        edit_line, edit_column = element.lineno, element.col_offset
                        break
            origins = self._origins(argument.tainted) if argument is not None else ()
            self.sinks.append(Sink("process", line, _short(name), argument, shell=shell, origins=origins,
                                   edit_line=edit_line, edit_column=edit_column))
            return
        if name in SQL_TEXT_FUNCTIONS or (name == "text" and self.imports.get("text", "").startswith("sqlalchemy")):
            target = self.argument(call, 0, "text")
            text_argument = self.describe(target) if target is not None else None
            self.sinks.append(
                Sink("sql", line, "sqlalchemy text()", text_argument,
                     origins=self._origins(text_argument.tainted) if text_argument is not None else ())
            )
            return
        if method is None:
            return
        if method == "extra":
            values = [k.value for k in call.keywords if k.arg in DJANGO_EXTRA_KEYWORDS]
            if values:
                argument = self.describe(ast.List(elts=values, ctx=ast.Load()))
                parameters = any(k.arg in ("params", "select_params") for k in call.keywords)
                self.sinks.append(Sink("sql", line, _short(name or "extra"), argument, parameters))
            return
        if not call.args and not call.keywords:
            # Query builders (Supabase/PostgREST, peewee, ...) run what they built: no SQL text here.
            return
        target = self.argument(call, 0, "sql", "statement", "query", "operation")
        if method in SQL_STRING_METHODS and (target is None or not _is_stringish(target)):
            return
        if method in SQL_KEYWORD_METHODS and (target is None or not _reads_as_sql(target)):
            return
        if method in SQL_METHODS or method in SQL_STRING_METHODS:
            if isinstance(target, ast.Call):
                inner = dotted(target.func, self.imports)
                if inner in SQL_TEXT_FUNCTIONS or (
                    inner == "text" and self.imports.get("text", "").startswith("sqlalchemy")
                ):
                    return  # the text() call is reported as the SQL construction point
            argument = self.describe(target) if target is not None else None
            keyworded = any(k.arg in ("params", "parameters", "args", "vars") for k in call.keywords)
            # pandas takes the connection second; only `params=` separates values there.
            parameters = keyworded if method in ("read_sql", "read_sql_query") else len(call.args) > 1 or keyworded
            self.sinks.append(Sink("sql", line, _short(name or method), argument, parameters,
                                   origins=self._origins(argument.tainted) if argument is not None else ()))


def analyze(unit: ast.AST, imports: dict[str, str], *, entry: bool = False, web: bool = False,
            clients: frozenset[str] = frozenset()) -> FlowFacts:
    """Analyze a function (or module statements) and return facts about risky calls.

    `entry=True` marks a request handler: its arguments are client input, not caller-supplied.
    `clients` names module-level HTTP client objects (web analysis).
    """
    params: list[str] = []
    if isinstance(unit, (ast.FunctionDef, ast.AsyncFunctionDef)):
        params = [
            argument.arg
            for argument in [*unit.args.posonlyargs, *unit.args.args, *unit.args.kwonlyargs]
            if argument.arg not in ("self", "cls")
        ]
        for extra in (unit.args.vararg, unit.args.kwarg):
            if extra is not None:
                params.append(extra.arg)
        body = unit.body
    elif isinstance(unit, ast.Module):
        body = unit.body
    else:
        raise TypeError("analyze expects a function definition or module")
    analyzer = _Analyzer(imports, params, entry=entry and bool(params), web=web, clients=clients)
    # One forward pass in source order: a later reassignment (for example `name = int(name)`)
    # never changes what an earlier call received.
    analyzer.statements(body)
    return FlowFacts(sources=list(analyzer.sources), sinks=analyzer.sinks)


def _leading_text(node: ast.expr) -> str | None:
    """Constant text at the start of an f-string/concatenation (for fixed-origin URL checks)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        value = node.values[0].value
        return value if isinstance(value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leading_text(node.left)
    return None


IDENTIFIER_CONTEXT = re.compile(r"(?i)(\bfrom|\bjoin|\binto|\bupdate|\btable|order\s+by|group\s+by|\.)\s*[\"'`\[]?$")


def _identifier_position(node: ast.expr, tainted: set[str]) -> bool:
    """Does an untrusted part follow FROM/JOIN/INTO/ORDER BY (a table/column name position)?"""
    if not tainted or not isinstance(node, ast.JoinedStr):
        return False
    text = ""
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            text += value.value
        elif isinstance(value, ast.FormattedValue):
            names = {item.id for item in ast.walk(value.value) if isinstance(item, ast.Name)}
            if names & tainted and IDENTIFIER_CONTEXT.search(text):
                return True
            text += "?"
    return False


def has_candidate_call(tree: ast.AST, imports: dict[str, str], *, web: bool = False,
                       clients: frozenset[str] = frozenset()) -> bool:
    """Cheap prefilter: does this code contain any SQL or process-execution call at all?

    `web=True` also accepts the workflow's HTTP/redirect/HTML/path/code/output sinks.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func, imports)
        if name in PROCESS_CALLS or name in SQL_TEXT_FUNCTIONS:
            return True
        if web and (name in HTTP_CLIENT_TYPES or (isinstance(node.func, ast.Attribute) and (
                node.func.attr in PATH_IO_METHODS or node.func.attr in PATH_METHODS or (
                    node.func.attr in HTTP_CLIENT_METHODS and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in clients)))):
            return True
        if web and (name in HTTP_CALLS or name in REDIRECT_CALLS or name in HTML_CALLS or name in CODE_CALLS
                    or name in PATH_CALLS or name in OUTPUT_CALLS or (
                        isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                        and node.func.value.id in LOGGER_NAMES)):
            return True
        if name == "text" and imports.get("text", "").startswith("sqlalchemy"):
            return True
        if isinstance(node.func, ast.Attribute) and (node.args or node.keywords) and (
            node.func.attr in SQL_METHODS or node.func.attr in SQL_STRING_METHODS or node.func.attr == "extra"
        ):
            return True
    return False

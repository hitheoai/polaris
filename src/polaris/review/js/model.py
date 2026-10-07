"""Facts the TypeScript/JavaScript engine tracks: where untrusted data comes from and where it goes.

Values carry their origins (request input, route params, URL/client input, server-action
arguments, CLI arguments, secret-named environment values, or a function's own parameters for
summaries), a short propagation path, and the checks for which they were sanitized or validated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from polaris.review.catalog import rule

INJECTION_CHECKS = frozenset({
    "sql_injection", "command_injection", "code_injection", "xss", "ssrf", "open_redirect",
    "path_traversal",
})
ALL_CHECKS = INJECTION_CHECKS | {"secret_exposure"}
# Origins that represent attacker-controlled input (vs. a symbolic function parameter).
REAL_KINDS = frozenset({
    "request", "route_param", "url_input", "client_input", "action_input", "argv", "message_data",
    "page_prop",
    # A public function builds a shell command or regular expression from its own argument. Callers
    # cannot make that safe; the argument is attacker-controlled at the library boundary.
    "library_input",
})
SECRET_KIND = "secret_env"
MAX_STEPS = 6


@dataclass(frozen=True)
class Origin:
    kind: str
    label: str
    line: int
    index: int = -1          # parameter index for kind == "param"
    root: bool = False       # an unrefined root object (request, params, searchParams hook)
    path: str | None = None  # file of origin when it differs from the sink's file


@dataclass(frozen=True)
class Taint:
    origins: frozenset[Origin] = frozenset()
    steps: tuple[tuple[int, str, str | None], ...] = ()
    sanitized: frozenset[str] = frozenset()

    @property
    def tainted(self) -> bool:
        return bool(self.origins)

    def real(self) -> list[Origin]:
        return sorted((item for item in self.origins if item.kind in REAL_KINDS),
                      key=lambda item: (item.line, item.label))

    def params(self) -> list[Origin]:
        return sorted((item for item in self.origins if item.kind == "param"), key=lambda item: item.index)

    def secrets(self) -> list[Origin]:
        return sorted((item for item in self.origins if item.kind == SECRET_KIND), key=lambda item: item.line)

    def with_step(self, line: int, label: str, path: str | None = None) -> Taint:
        if not self.origins or (self.steps and self.steps[-1][:2] == (line, label)):
            return self
        return Taint(self.origins, (*self.steps, (line, label, path))[-MAX_STEPS:], self.sanitized)

    def sanitize(self, checks: frozenset[str]) -> Taint:
        return Taint(self.origins, self.steps, self.sanitized | checks) if self.origins else self

    def safe_for(self, check: str) -> bool:
        return check in self.sanitized


CLEAN = Taint()


def join(*taints: Taint) -> Taint:
    """Union of origins; a value is sanitized for a check only if every tainted part is."""
    tainted = [item for item in taints if item.origins]
    if not tainted:
        return CLEAN
    if len(tainted) == 1:
        return tainted[0]
    origins: frozenset[Origin] = frozenset().union(*(item.origins for item in tainted))
    sanitized = frozenset.intersection(*(item.sanitized for item in tainted))
    steps = max((item.steps for item in tainted), key=len)
    return Taint(origins, steps, sanitized)


@dataclass
class Value:
    taint: Taint = CLEAN
    kind: str = "unknown"            # literal, template, concat, call, object, array, function, number, url, json
    literal: str | None = None       # full constant text when known
    pre: str = "\x00"                # text before the first tainted part ("\x00" = unknown untainted part)
    obj: str | None = None           # special objects: router, request, url, set, response
    props: dict[str, Value] | None = None
    items: list[Value] | None = None
    text: str = ""                   # short source text for labels
    function: object | None = None   # a function node for local callbacks
    sql_text: str = ""               # literal fragments (for SQL keyword detection)
    shell_option: bool = False       # object literal containing shell: true
    is_html: bool = False            # literal fragments look like HTML markup


def literal(text: str, label: str = "") -> Value:
    return Value(kind="literal", literal=text, pre=text, text=label or repr(text), sql_text=text,
                 is_html="<" in text and ">" in text)


UNKNOWN = Value()


@dataclass(frozen=True)
class Hit:
    """A sink reached by a tainted (or unknown dynamic) value."""

    check: str
    rule_id: str
    line: int
    column: int
    sink: str
    taint: Taint
    path: str
    symbol: str
    detail: str = ""
    edit_column: int = -1    # suggested insertion point for argument-injection edits
    edit_text: str = ""
    replace_old: str = ""
    replace_new: str = ""
    dynamic: bool = False    # value not tainted but dynamic and unsanitized (needs context)
    sink_line: int = 0       # where the sink really is when reached through a helper
    sink_path: str | None = None
    # URL sinks: the tainted value starts the URL, so a caller that passes a fixed origin
    # (or a relative path, for redirects) makes this helper's sink safe.
    leading: bool = False


@dataclass
class Summary:
    param_hits: dict[int, list[Hit]] = field(default_factory=dict)
    returns_params: set[int] = field(default_factory=set)
    returns: Taint = CLEAN
    guarded: bool = False
    writes: list[tuple[int, str]] = field(default_factory=list)
    reads: list[tuple[int, str]] = field(default_factory=list)


# ---- tables -------------------------------------------------------------------------------------

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ROUTER_METHODS = frozenset({"get", "post", "put", "patch", "delete", "all", "options", "head"})
REQUEST_PARAM_NAMES = frozenset({"req", "request", "_req", "_request", "r"})
CONTEXT_PARAM_NAMES = frozenset({"c", "ctx", "context"})
ITERATORS = frozenset({"map", "forEach", "filter", "flatMap", "some", "every", "find", "findIndex", "reduce", "then"})

SHELL_CALLS = frozenset({
    "child_process.exec", "child_process.execSync", "shelljs.exec", "execa.execaCommand",
    "execa.execaCommandSync", "execa.$", "zx.$",
})
SPAWN_CALLS = frozenset({
    "child_process.spawn", "child_process.spawnSync", "child_process.execFile",
    "child_process.execFileSync", "child_process.fork", "cross-spawn", "cross-spawn.sync",
    "cross-spawn.spawn", "execa", "execa.execa", "execa.execaSync", "execa.execaNode", "Bun.spawn",
    "Bun.spawnSync",
})
# Programs that interpret leading-dash arguments in dangerous ways (option/argument injection).
OPTION_PROGRAMS = frozenset({
    "git", "ssh", "scp", "sftp", "rsync", "curl", "wget", "tar", "zip", "unzip", "7z", "find",
    "xargs", "sed", "awk", "gpg", "openssl", "ffmpeg", "convert", "magick", "npm", "npx", "pnpm",
    "yarn", "pip", "docker", "kubectl", "helm", "aws", "gcloud", "az", "hg", "svn", "less",
    "man", "chmod", "chown", "cp", "mv", "rm", "ln", "mount", "nc", "ncat", "socat", "psql",
    "mysql", "sqlite3", "node", "python", "python3", "ruby", "perl", "bash", "sh", "zsh",
})
CODE_CALLS = frozenset({
    "eval", "Function", "vm.runInNewContext", "vm.runInThisContext", "vm.runInContext",
    "vm.compileFunction", "vm.Script", "setTimeout", "setInterval", "setImmediate",
})
HTTP_CLIENTS = frozenset({
    "fetch", "node-fetch", "cross-fetch", "undici.fetch", "undici.request", "axios", "got", "ky",
    "superagent", "needle", "http.get", "http.request", "https.get", "https.request",
    "isomorphic-fetch", "ofetch", "ofetch.ofetch", "ofetch.$fetch", "$fetch",
})
HTTP_CLIENT_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
REDIRECT_CALLS = frozenset({
    "next/navigation.redirect", "next/navigation.permanentRedirect",
    "next/server.NextResponse.redirect", "Response.redirect", "NextResponse.redirect",
})
REDIRECT_RECEIVERS = frozenset({"res", "response", "reply", "ctx", "c", "context", "h"})
NAVIGATION_METHODS = frozenset({"push", "replace", "prefetch"})
FS_MODULES = frozenset({"fs", "fs/promises", "fs-extra", "graceful-fs", "fs.promises"})
FS_PATH_FUNCTIONS = frozenset({
    name + suffix
    for name in (
        "readFile", "writeFile", "appendFile", "createReadStream", "createWriteStream", "unlink",
        "rm", "rmdir", "mkdir", "readdir", "stat", "lstat", "access", "open", "opendir",
        "copyFile", "cp", "rename", "symlink", "chmod", "chown", "truncate", "utimes",
        "readJson", "writeJson", "outputFile", "outputJson", "remove", "ensureDir", "ensureFile",
        "pathExists", "move", "copy", "emptyDir", "exists", "realpath",
    )
    for suffix in ("", "Sync")
})
SEND_FILE_METHODS = frozenset({"sendFile", "download", "attachment"})
LOG_CALLS = frozenset({"log", "info", "warn", "error", "debug", "trace"})
LOG_RECEIVERS = frozenset({"console", "logger", "log", "Sentry", "pino"})
RESPONSE_SECRET_SINKS = frozenset({
    "Response.json", "NextResponse.json", "next/server.NextResponse.json", "Response",
    "NextResponse", "next/server.NextResponse",
})
RAW_SQL_METHODS = frozenset({
    "$queryRawUnsafe", "$executeRawUnsafe", "whereRaw", "orWhereRaw", "andWhereRaw", "havingRaw",
    "orHavingRaw", "orderByRaw", "groupByRaw", "joinRaw", "fromRaw", "selectRaw", "unsafe",
})
SQL_TEXT_METHODS = frozenset({"query", "execute", "exec", "prepare", "raw", "all", "get", "run", "sql"})
SQL_KEYWORDS = re.compile(
    r"\b(select|insert|update|delete|from|where|values|returning|join|into|order\s+by|group\s+by|limit|create\s+table|drop\s+table)\b",
    re.IGNORECASE,
)
SANITIZE_ALL = frozenset({
    "Number", "parseInt", "parseFloat", "Boolean", "Math.floor", "Math.ceil", "Math.round",
    "Math.trunc", "Math.abs", "Math.min", "Math.max", "Number.parseInt", "Number.parseFloat",
    "BigInt", "Date.parse", "crypto.randomUUID", "uuid.v4", "uuidv4", "nanoid", "cuid",
})
SANITIZERS: dict[str, frozenset[str]] = {
    "encodeURIComponent": frozenset({"ssrf", "open_redirect", "path_traversal", "xss"}),
    "path.basename": frozenset({"path_traversal"}),
    "basename": frozenset({"path_traversal"}),
    "DOMPurify.sanitize": frozenset({"xss"}),
    "dompurify.sanitize": frozenset({"xss"}),
    "isomorphic-dompurify.sanitize": frozenset({"xss"}),
    "sanitize-html": frozenset({"xss"}),
    "sanitizeHtml": frozenset({"xss"}),
    "sanitize": frozenset({"xss"}),
    "xss": frozenset({"xss"}),
    "escape": frozenset({"xss"}),
    "escapeHtml": frozenset({"xss"}),
    "escapeHTML": frozenset({"xss"}),
    "he.encode": frozenset({"xss"}),
    "he.escape": frozenset({"xss"}),
    # These escape regular-expression metacharacters. A bare `escape()` is not one of them:
    # that name is also used for HTML, and HTML escaping does not make a pattern safe.
    "escapeStringRegexp": frozenset({"code_injection"}),
    "escape-string-regexp": frozenset({"code_injection"}),
    "escapeRegExp": frozenset({"code_injection"}),
    "lodash.escapeRegExp": frozenset({"code_injection"}),
    "_.escapeRegExp": frozenset({"code_injection"}),
    "validator.escape": frozenset({"xss"}),
    "lodash.escape": frozenset({"xss"}),
    "_.escape": frozenset({"xss"}),
    "shell-quote.quote": frozenset({"command_injection"}),
    "quote": frozenset({"command_injection"}),
    "shellEscape": frozenset({"command_injection"}),
    "shell-escape": frozenset({"command_injection"}),
    "sqlstring.escape": frozenset({"sql_injection"}),
    "mysql.escape": frozenset({"sql_injection"}),
    "SqlString.escape": frozenset({"sql_injection"}),
    "pg-format": frozenset({"sql_injection"}),
    "format": frozenset(),
}
PROPAGATING_METHODS = frozenset({
    "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "toLocaleLowerCase",
    "toLocaleUpperCase", "slice", "substring", "substr", "concat", "padStart", "padEnd",
    "normalize", "toString", "valueOf", "split", "join", "at", "charAt", "repeat", "replace",
    "replaceAll", "get", "getAll", "json", "text", "formData", "arrayBuffer", "blob",
    "flat", "values", "entries", "keys", "pop", "shift", "first", "toJSON", "href", "then",
})
GUARD_METHODS = frozenset({
    "includes", "has", "test", "startsWith", "endsWith", "match", "matches", "some", "every",
    "indexOf", "safeParse", "isValid", "exec",
})
GUARD_NAME = re.compile(r"^(is|has|can|validate|verify|check|ensure|assert)[A-Z_]")
EXIT_CALLS = frozenset({
    "notFound", "redirect", "unauthorized", "forbidden", "permanentRedirect", "abort", "process.exit",
})
# Validation schemas whose parse() output is constrained to safe values.
SAFE_SCHEMA = re.compile(
    r"\b(z\.(enum|nativeEnum|literal|number|boolean|coerce\.number|bigint|date)|\.uuid\(|\.cuid2?\(|\.regex\(|"
    r"\.int\(|\.email\(|v\.(picklist|number|boolean|literal))"
)

_GUARD_WORDS = (
    r"(Auth|Authed|Authenticated|Authorized|Authorization|User|Session|Admin|Role|Roles|Permission|"
    r"Permissions|Access|Token|Jwt|JWT|ApiKey|APIKey|Api_Key|Key|Signature|Owner|Ownership|Org|"
    r"Organization|Team|Member|Membership|Login|LoggedIn|Account|Caller|Principal|Identity|Staff|"
    r"Superuser|Workspace|Tenant|Scope|Scopes|Cron|Internal|Bearer|Secret|Webhook|Credentials|Me|"
    r"Request|Plan|Subscription|Entitlement|Ability)"
)
_GUARD_SUFFIX = (
    r"(OrThrow|OrRedirect|OrFail|OrNull|OrError|FromRequest|FromHeaders?|FromCookies?|FromToken|FromSession|"
    r"Context|Server|Api|Middleware|Access|Guard|Check|Id|Info)?"
)
AUTH_GUARD = re.compile(
    # Strong verbs: requireUser, verifyAdmin, assertTeamMember, withAuth, hasPermission, isOwner...
    r"^(require|verify|check|ensure|assert|validate|authenticate|authorize|with|protect|guard|"
    r"enforce|must|is|has)" + _GUARD_WORDS + _GUARD_WORDS + r"?" + _GUARD_SUFFIX + r"$"
    # Current-identity accessors: getCurrentUser, getServerSession, getUserFromRequest...
    r"|^(get|fetch|load|read|use)(Current|Server|Auth|LoggedIn|Verified|Signed|Session)?"
    r"(User|Session|Auth|Me|Account|Token|Jwt|JWT|Caller|Principal|Identity|Viewer|Claims)" + _GUARD_SUFFIX + r"$"
    # Permission predicates: canEdit, canDeleteProject...
    r"|^can[A-Z][A-Za-z]*$"
)
# A handler that builds 401/403 responses has an authorization branch.
AUTH_RESPONSE = re.compile(r"^(unauthori[sz]ed|forbidden|unauthenticated)(Response|Error|Json)?$", re.IGNORECASE)
# Callers authenticated another way: webhook signatures, OAuth state, constant-time secret checks.
VERIFIER_GUARD = re.compile(
    r"(?i)^(verify|validate|check|assert|authenticate)\w*(webhook|signature|signed|hmac|svix)\w*$"
    r"|^(consume|verify|validate|check)\w*oauth\w*$|^(verify|validate|check)(oauth)?state$"
    r"|(timing_?safe|constant_?time|secure_?compare|safe_?compare)"
)
# Rate limiting an unauthenticated write suggests the endpoint is public by design.
RATE_LIMIT = re.compile(r"(?i)(rate_?limit|throttle|limiter)")
AUTH_GUARD_EXACT = frozenset({
    "auth", "getServerSession", "getSession", "currentUser", "getUser", "getAuth", "getToken",
    "verifyJWT", "verifyJwt", "jwtVerify", "verifyAuth", "requireAuth", "withAuth", "authenticate",
    "authorize", "validateRequest", "getKindeServerSession", "unstable_getServerSession",
    "isAuthenticated", "ensureLoggedIn", "requireUser", "requireAdmin", "requireSession",
    "getCurrentUser", "getLoggedInUser", "protect", "withApiAuth", "withAdmin", "authMiddleware",
    "constructEvent", "constructEventAsync", "verifyWebhook", "verifySignature", "timingSafeEqual",
    "verifyKey", "verifyRequest", "verifyRequestSignature", "checkApiKey", "validateApiKey",
    "verifyApiKey", "requirePermission", "requireRole", "assertAdmin", "assertUser",
})
DATA_RECEIVER = re.compile(
    r"(?i)^(db|prisma|supabase\w*|admin\w*|databases?|storage|bucket|knex|sql|pool|redis|kv|"
    r"collection|repo|repository|stripe|users?|orm|mongoose|firestore|firebase|appwrite|tables?|"
    r"drizzle|tx|trx|s3|ses|resend|mailer|sendgrid|models?|documents?|teams|functions|messaging|"
    r"accounts?|client|\w*(Service|Repository|Repo|Client|Db|DB|Store|Table|Collection|Model))$"
)
WRITE_METHODS = frozenset({
    "create", "createMany", "update", "updateMany", "upsert", "delete", "deleteMany", "remove",
    "destroy", "insert", "insertOne", "insertMany", "updateOne", "deleteOne", "findOneAndUpdate",
    "findOneAndDelete", "findByIdAndUpdate", "findByIdAndDelete", "save", "createDocument",
    "updateDocument", "deleteDocument", "createFile", "deleteFile", "upload", "charge", "refund",
    "transfer", "executeRaw", "$executeRaw", "$executeRawUnsafe", "bulkWrite", "replaceOne",
    "createUser", "deleteUser", "updateUser", "createRow", "updateRow", "deleteRow", "rpc",
    "sendEmail", "createCheckoutSession", "createPaymentIntent",
})
READ_METHODS = frozenset({
    "findMany", "findFirst", "findUnique", "findOne", "find", "findById", "findAll", "select",
    "listDocuments", "getDocument", "getFile", "listFiles", "from", "query", "execute", "count",
    "aggregate", "$queryRaw", "$queryRawUnsafe", "listRows", "getRow", "listUsers", "getUserById",
})
UNAMBIGUOUS_WRITES = frozenset({
    "createMany", "updateMany", "upsert", "deleteMany", "insertOne", "insertMany", "updateOne",
    "deleteOne", "findOneAndUpdate", "findOneAndDelete", "findByIdAndUpdate", "findByIdAndDelete",
    "createDocument", "updateDocument", "deleteDocument", "createFile", "deleteFile",
    "$executeRaw", "$executeRawUnsafe", "bulkWrite", "createRow", "updateRow", "deleteRow",
    "createCheckoutSession", "createPaymentIntent", "deleteUser", "createUser", "updateUser",
})
UNAMBIGUOUS_READS = frozenset({
    "findMany", "findFirst", "findUnique", "findById", "listDocuments", "getDocument",
    "$queryRaw", "$queryRawUnsafe", "listRows", "getRow", "listUsers", "getUserById",
})


# ---- rules --------------------------------------------------------------------------------------

def _rules() -> None:
    js = "polaris.js."
    rule(js + "sql_injection.raw_query", "sql_injection", "Unsafe raw SQL",
         "Untrusted input is built into a raw SQL string.",
         "Use the tagged-template form ($queryRaw`... ${value}`, sql`...`) or bound parameters "
         "instead of building SQL text; allowlist identifiers.")
    rule(js + "sql_injection.query_text", "sql_injection", "SQL text built from input",
         "Untrusted input is concatenated or interpolated into SQL text.",
         "Keep the SQL text fixed and pass values separately, e.g. db.query(\"... WHERE id = $1\", [id]).")
    rule(js + "sql_injection.postgrest_filter", "sql_injection", "PostgREST filter built from input",
         "Untrusted input is interpolated into a Supabase/PostgREST filter string.", 
         "Use the typed filter helpers (.eq(column, value), .in(...)) instead of building .or() strings, "
         "or strictly validate the value first.", severity="medium")
    rule(js + "command_injection.shell", "command_injection", "Shell command built from input",
         "Untrusted input reaches a shell command string.",
         "Use execFile/spawn with a fixed program and an argument array (no shell), and validate "
         "the value; put \"--\" before user-supplied arguments.", severity="critical")
    rule(js + "command_injection.executable", "command_injection", "Program chosen by input",
         "Untrusted input chooses which program runs.",
         "Map the user's choice to a fixed allowlist of programs instead of running the value.",
         severity="critical")
    rule(js + "command_injection.shell_option", "command_injection", "Shell enabled with untrusted arguments",
         "Untrusted arguments reach a process started with shell: true.",
         "Remove shell: true and pass a fixed program with an argument array.", severity="critical")
    rule(js + "command_injection.argument_injection", "command_injection", "Argument injection",
         "An untrusted value is passed to the program where it can be read as an option (e.g. --upload-pack=...).",
         "Insert \"--\" before user-supplied arguments and validate them (e.g. reject values starting with \"-\").",
         severity="medium", cwe="CWE-88")
    rule(js + "code_injection.eval", "code_injection", "Dynamic code evaluation",
         "Untrusted input is evaluated as JavaScript.",
         "Don't evaluate input: parse data with JSON.parse and dispatch to fixed functions.",
         severity="critical", cwe="CWE-95")
    rule(js + "code_injection.dynamic_module", "code_injection", "Module path chosen by input",
         "Untrusted input chooses which module is loaded.",
         "Load modules from a fixed allowlist map instead of a user-supplied path.", severity="high")
    rule(js + "code_injection.regexp", "code_injection", "Regular expression built from input",
         "Untrusted input is interpolated into a regular expression.",
         "Escape the value (or reject metacharacters) before building the pattern, or use a fixed expression.",
         severity="high", cwe="CWE-730")
    rule(js + "xss.dangerously_set_inner_html", "xss", "Unsanitized dangerouslySetInnerHTML",
         "A value that isn't sanitized is rendered as raw HTML with dangerouslySetInnerHTML.",
         "Render the text as children, or sanitize it with DOMPurify.sanitize(html) right before rendering.")
    rule(js + "xss.dom_html", "xss", "HTML written to the DOM",
         "Untrusted input is written to the DOM as HTML (innerHTML/outerHTML/insertAdjacentHTML/document.write).",
         "Use textContent / createTextNode, or sanitize with DOMPurify before inserting HTML.")
    rule(js + "xss.jquery_html", "xss", "jQuery HTML interpretation",
         "A dynamic string is passed to $() / jQuery(), which interprets a string that starts with < as HTML.",
         "Use $(document).find(selector) or a DOM API for an element, and never pass an attribute value to $().")
    rule(js + "xss.html_response", "xss", "Reflected HTML response",
         "Untrusted input is embedded in an HTML response.",
         "Escape values for HTML (or use a template engine that escapes by default) and set a strict CSP.")
    rule(js + "ssrf.request", "ssrf", "Server request to a user-controlled URL",
         "The server makes an HTTP request to a URL derived from request input.",
         "Keep scheme and host fixed, or parse with new URL() and check url.hostname against an "
         "allowlist before fetching; never let input choose the host.")
    rule(js + "open_redirect.redirect", "open_redirect", "Redirect to a user-controlled destination",
         "A redirect destination comes from request input.",
         "Only redirect to relative paths starting with a single \"/\" (reject \"//\" and \"/\\\\\"), "
         "or to an allowlist of destinations.")
    rule(js + "open_redirect.client_navigation", "open_redirect", "Client navigation to a user-controlled URL",
         "Client-side navigation uses a destination taken from the URL.",
         "Validate the destination is a same-origin relative path before navigating.")
    rule(js + "path_traversal.fs", "path_traversal", "File path built from input",
         "Untrusted input chooses a filesystem path.",
         "Resolve against a fixed base (path.resolve(BASE, name)) and reject unless the result "
         "starts with BASE + path.sep; or use path.basename / an ID-to-file map.")
    rule(js + "path_traversal.send_file", "path_traversal", "File response chosen by input",
         "A file sent to the client is chosen by request input.",
         "Use the root option of sendFile/download with a validated basename, or map IDs to files.")
    rule(js + "secret_exposure.hardcoded", "secret_exposure", "Hardcoded credential",
         "A credential appears to be hardcoded in source.",
         "Move it to a server-side environment variable or secret manager and rotate the exposed key.")
    rule(js + "secret_exposure.public_env", "secret_exposure", "Secret exposed through NEXT_PUBLIC_",
         "A secret-looking variable uses the NEXT_PUBLIC_ prefix, so Next.js inlines it into the browser bundle.",
         "Rename it without NEXT_PUBLIC_, read it only in server code (route handlers, server actions), "
         "and rotate the key.", severity="high")
    rule(js + "secret_exposure.output", "secret_exposure", "Secret written to logs or a response",
         "A secret-named environment value reaches a log statement or an HTTP response.",
         "Never log or return credentials; log a fixed redaction instead.")
    rule(js + "missing_authorization.handler", "missing_authorization", "Handler without an auth check",
         "This request handler reaches data access or side effects without calling an auth guard.",
         "Call your guard (e.g. requireUser/getServerSession/auth()) first and return 401/403 when it "
         "fails; list intentionally public routes and custom guard names in .polaris.toml [workflow].")
    rule(js + "insecure_auth_crypto.weak_random", "insecure_auth_crypto", "Predictable security token",
         "Math.random() is used to create a security-sensitive value.",
         "Use crypto.randomUUID() or crypto.randomBytes(32).toString(\"hex\") for tokens, IDs and codes.",
         cwe="CWE-338")
    rule(js + "insecure_auth_crypto.weak_password_hash", "insecure_auth_crypto", "Weak password hash",
         "A password is hashed with a fast, unsalted hash (MD5/SHA-1/SHA-256).",
         "Use bcrypt, scrypt or argon2 with a per-user salt for passwords.", severity="high", cwe="CWE-916")
    rule(js + "insecure_auth_crypto.jwt_none", "insecure_auth_crypto", "JWT verification accepts 'none'",
         "JWT verification allows the 'none' algorithm, so unsigned tokens are accepted.",
         "Pass an explicit algorithms list (e.g. ['HS256'] or ['RS256']) that excludes 'none'.",
         severity="critical", cwe="CWE-347")
    rule(js + "insecure_auth_crypto.jwt_decode", "insecure_auth_crypto", "JWT decoded without verification",
         "jwt.decode() reads token claims without verifying the signature.",
         "Use jwt.verify(token, key, { algorithms: [...] }) before trusting claims.", severity="medium",
         cwe="CWE-347")
    rule(js + "insecure_auth_crypto.weak_cipher", "insecure_auth_crypto", "Weak or deprecated cipher",
         "A deprecated cipher API or ECB mode is used.",
         "Use crypto.createCipheriv with AES-256-GCM, a random IV and authentication tag.", cwe="CWE-327")
    rule(js + "unsafe_security_configuration.tls_disabled", "unsafe_security_configuration",
         "TLS certificate verification disabled",
         "TLS certificate verification is turned off, allowing man-in-the-middle interception.",
         "Remove rejectUnauthorized: false, strictSSL: false or NODE_TLS_REJECT_UNAUTHORIZED=0 and trust the right CA instead.")
    rule(js + "unsafe_security_configuration.cleartext_download", "unsafe_security_configuration",
         "Installer downloaded over cleartext HTTP",
         "An installer or package URL uses http://, so the download can be replaced in transit.",
         "Use https:// for the download, and check a checksum before running what was downloaded.",
         cwe="CWE-829")
    rule(js + "unsafe_security_configuration.cors_credentials", "unsafe_security_configuration",
         "Credentialed CORS for any origin",
         "CORS allows credentials together with a wildcard or reflected origin.",
         "Allow credentials only for an explicit allowlist of trusted origins.", severity="medium",
         cwe="CWE-942")
    rule(js + "unsafe_security_configuration.cookie_flags", "unsafe_security_configuration",
         "Session cookie without httpOnly/secure",
         "A session/auth cookie is set with httpOnly or secure disabled.",
         "Set httpOnly: true, secure: true and sameSite: 'lax' (or 'strict') on session cookies.",
         severity="medium", cwe="CWE-1004")


_rules()

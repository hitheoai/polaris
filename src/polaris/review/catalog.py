"""What each workflow check and rule means, why it matters, and how to fix it.

One catalog feeds every analyzer, the text/SARIF renderers and the `explain_finding` tool, so
an agent sees the same concrete guidance whichever surface it uses. Entries describe bounded
static patterns; a matching rule is evidence to review, not proof of exploitability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from polaris.review.analyzers.base import source_kind
from polaris.review.models import Category

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class CheckInfo:
    """One check. `domains` are the source-kind domains it applies to (program code by default):
    files of other domains get no coverage rows for it, so they can't be incomplete for it."""

    check_id: str
    title: str
    cwe: str
    severity: Severity
    summary: str
    why: str
    fix: str
    example_bad: str = ""
    example_good: str = ""
    category: Category = "security"
    domains: tuple[str, ...] = ("code",)


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    check_id: str
    title: str
    message: str
    fix: str
    severity: Severity | None = None
    cwe: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)


CHECKS: dict[str, CheckInfo] = {
    item.check_id: item
    for item in (
        CheckInfo(
            "sql_injection", "SQL injection", "CWE-89", "high",
            "Untrusted input is built into SQL text.",
            "An attacker can change the query: read or modify other users' data, or drop tables.",
            "Keep SQL text fixed and pass values as bound parameters. Identifiers (table/column "
            "names) can't be parameters: map user choices to a fixed allowlist first.",
            'db.query(`SELECT * FROM users WHERE id = ${id}`)',
            'db.query("SELECT * FROM users WHERE id = $1", [id])',
        ),
        CheckInfo(
            "command_injection", "Command injection", "CWE-78", "critical",
            "Untrusted input reaches a shell command, chooses the program, or becomes an option.",
            "An attacker can run arbitrary programs on the server (remote code execution).",
            "Run a fixed program with an argument list and no shell; put \"--\" before "
            "user-supplied values so they can't be read as options; validate values.",
            "exec(`git log ${branch}`)",
            'execFile("git", ["log", "--", branch])',
        ),
        CheckInfo(
            "code_injection", "Code injection", "CWE-94", "critical",
            "Untrusted input is evaluated as code or deserialized into objects.",
            "An attacker can run arbitrary code inside the application process.",
            "Never evaluate or unsafely deserialize untrusted data; parse data formats "
            "(JSON) instead and dispatch to fixed functions.",
            "eval(req.body.expression)",
            "const fn = OPERATIONS[req.body.op]; // fixed allowlist",
        ),
        CheckInfo(
            "xss", "Cross-site scripting (XSS)", "CWE-79", "high",
            "Untrusted input is rendered as HTML.",
            "An attacker can run script in other users' browsers and act as them.",
            "Render text, not HTML. If HTML is required, sanitize it with a maintained "
            "sanitizer such as DOMPurify immediately before rendering.",
            "<div dangerouslySetInnerHTML={{ __html: comment }} />",
            "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment) }} />",
        ),
        CheckInfo(
            "ssrf", "Server-side request forgery (SSRF)", "CWE-918", "high",
            "The server requests a URL that the user controls.",
            "An attacker can make the server reach internal services or cloud metadata "
            "endpoints and read the responses.",
            "Keep the scheme and host fixed (or check the parsed hostname against an allowlist) "
            "and only put user input into encoded path/query parts.",
            "await fetch(searchParams.get(\"url\"))",
            "const target = new URL(input); if (!ALLOWED_HOSTS.has(target.hostname)) return bad();",
        ),
        CheckInfo(
            "open_redirect", "Open redirect", "CWE-601", "medium",
            "The app redirects to a destination the user controls.",
            "Attackers use your domain to send victims to phishing pages or leak tokens.",
            "Only redirect to relative paths that start with a single \"/\" (not \"//\"), or "
            "to an allowlist of known destinations.",
            "return NextResponse.redirect(new URL(next, request.url))",
            'const safe = next?.startsWith("/") && !next.startsWith("//") ? next : "/";',
        ),
        CheckInfo(
            "path_traversal", "Path traversal", "CWE-22", "high",
            "Untrusted input chooses a filesystem path.",
            "An attacker can read or overwrite files outside the intended folder "
            "(\"../../.env\").",
            "Resolve the path against a fixed base folder and reject it unless the resolved "
            "path stays inside that folder; or use path.basename / an ID-to-file mapping.",
            "fs.readFile(path.join(UPLOADS, req.query.name))",
            "const file = path.resolve(UPLOADS, name); if (!file.startsWith(UPLOADS + path.sep)) throw ...",
        ),
        CheckInfo(
            "secret_exposure", "Secret exposure", "CWE-798", "high",
            "A credential is hardcoded, shipped to browsers, or written to logs/responses.",
            "Anyone with the code, the browser bundle or the logs can use the credential.",
            "Load secrets from server-side environment or a secret manager, never prefix "
            "them with NEXT_PUBLIC_, never log or return them, and rotate any exposed key.",
            'const stripe = new Stripe("sk_live_...")',
            "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)",
            # Also CI workflows (secrets printed to logs) and container images (secrets in layers).
            domains=("code", "ci", "container"),
        ),
        CheckInfo(
            "missing_authorization", "Missing authorization", "CWE-862", "high",
            "A request handler or server action reaches data or side effects without an auth check.",
            "Anyone who can reach the endpoint can read or change data that should be protected.",
            "Call your auth guard (session/user/role check) at the start of the handler and "
            "return 401/403 before any data access. Configure guard names and intentionally "
            "public routes in .polaris.toml.",
            "export async function DELETE(req) { await db.project.delete(...) }",
            "export async function DELETE(req) { const user = await requireUser(req); ... }",
        ),
        CheckInfo(
            "insecure_auth_crypto", "Insecure auth or crypto", "CWE-330", "medium",
            "Security values use weak randomness, weak hashing, or unverified tokens.",
            "Predictable tokens and weak password hashes let attackers guess or forge credentials.",
            "Use crypto.randomBytes/randomUUID (or secrets in Python) for tokens, bcrypt/scrypt/"
            "argon2 for passwords, and verify JWT signatures with an explicit algorithm.",
            "const resetToken = Math.random().toString(36)",
            'const resetToken = crypto.randomBytes(32).toString("hex")',
        ),
        CheckInfo(
            "unsafe_security_configuration", "Unsafe security configuration", "CWE-295", "high",
            "A security control is explicitly turned off (TLS verification, CORS, cookie flags).",
            "Disabled controls expose traffic to interception or let other sites use your users' sessions.",
            "Keep TLS verification on (configure the right CA instead), never combine wildcard "
            "or reflected CORS origins with credentials, and set httpOnly/secure on session cookies.",
            "new https.Agent({ rejectUnauthorized: false })",
            "new https.Agent({ ca: fs.readFileSync(CA_PATH) })",
        ),
        CheckInfo(
            "api_authorization", "Authorization guard regression", "CWE-862", "high",
            "A guard call required by a caller-trusted policy was removed.",
            "Removing a required guard can expose a protected endpoint.",
            "Restore the policy-required guard and have its authorization behavior verified.",
        ),
        # CI workflows (GitHub Actions) and container builds (Dockerfiles).
        CheckInfo(
            "workflow_injection", "Workflow expression injection", "CWE-94", "high",
            "Untrusted event data is expanded into a workflow script before the script runs.",
            "Whoever writes the issue, pull request, branch name or comment can run commands in the "
            "workflow, with its token and secrets.",
            "Pass the value through an environment variable (env: TITLE: ${{ github.event.issue.title }}) "
            "and use it quoted in the script (\"$TITLE\"). In actions/github-script, read "
            "context.payload or process.env instead of expanding ${{ }} into the script.",
            'run: echo "${{ github.event.issue.title }}"',
            'env: {TITLE: "${{ github.event.issue.title }}"}, run: echo "$TITLE"',
            domains=("ci",),
        ),
        CheckInfo(
            "untrusted_checkout", "Untrusted checkout in a privileged workflow", "CWE-829", "high",
            "A privileged workflow (pull_request_target, workflow_run, issue_comment) checks out "
            "or builds the pull request's code.",
            "Build scripts, dependencies and tools from the pull request run with the base "
            "repository's token, secrets and caches, so anyone who opens a pull request can take "
            "them over.",
            "Build and test pull requests under pull_request (read-only token, no secrets). If a "
            "privileged job needs the change, fetch it as data only (git fetch, no checkout) or "
            "split the work: build under pull_request and only publish results from workflow_run, "
            "without running anything from the pull request.",
            "on: pull_request_target … uses: actions/checkout with ref: "
            "${{ github.event.pull_request.head.sha }}, then run: npm ci",
            "on: pull_request … uses: actions/checkout, then run: npm ci",
            domains=("ci",),
        ),
        CheckInfo(
            "excessive_privileges", "Excessive privileges", "CWE-250", "low",
            "A workflow token or a container runs with more privileges than it needs.",
            "Any bug, injection or compromised dependency in that job or container gets the extra "
            "privileges too.",
            "Grant each job only the token permissions it needs (permissions: contents: read plus "
            "specific writes), and run containers as a non-root user (USER app after creating it).",
            "permissions: write-all",
            "permissions: {contents: read, pull-requests: write}",
            domains=("ci", "container"),
        ),
        CheckInfo(
            "unpinned_dependency", "Unpinned dependency", "CWE-1357", "low",
            "A third-party action or container image is referenced by a mutable tag or branch "
            "instead of an immutable commit SHA or digest.",
            "Whoever controls the tag (or takes over the publisher's account) can change what runs "
            "in your build without any change to this repository.",
            "Pin actions to a full commit SHA (uses: owner/action@<40-hex sha> # v1.2.3) and images "
            "to a digest (FROM node:20@sha256:<digest>), and let Dependabot or Renovate update the pins.",
            "uses: some-org/deploy-action@v2",
            "uses: some-org/deploy-action@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v2.1.0",
            domains=("ci", "container"),
        ),
        CheckInfo(
            "unverified_download", "Download without integrity check", "CWE-494", "low",
            "A remote script or file is downloaded and used without checking a checksum or signature.",
            "If the server or the download path is compromised (or, over plain HTTP, anyone on the "
            "network), attacker code runs in the build.",
            "Download over HTTPS to a file, verify a pinned SHA-256 (sha256sum -c) or signature, then "
            "run it; for ADD use --checksum=sha256:<digest>.",
            "RUN curl -fsSL https://example.com/install.sh | sh",
            "RUN curl -fsSLo install.sh https://example.com/install.sh && "
            "echo \"<sha256>  install.sh\" | sha256sum -c - && sh install.sh",
            domains=("ci", "container"),
        ),
    )
}


@dataclass(frozen=True)
class PlainText:
    """A check in everyday words, for people who have never written security code.

    `title` names the problem, `why` says what could happen, `fix` says what to do, and
    `question` is what to find out when Polaris can't see enough to be sure. `route_title`, when
    set, names the page or API route instead (`{route}` is replaced, for example "DELETE /api/users").
    These texts are trusted catalog text: they never include anything read from a repository.
    """

    title: str
    why: str
    fix: str
    question: str
    route_title: str = ""


PLAIN: dict[str, PlainText] = {
    "sql_injection": PlainText(
        "Users could read or change your database",
        "Someone could type special text that makes your database show, change or delete data.",
        "Send user input to the database as query parameters, never as part of the query text.",
        "Could the text used in this database query come from a user?",
        "Users of {route} could read or change your database",
    ),
    "command_injection": PlainText(
        "Users could run commands on your server",
        "Someone could take over the computer your app runs on.",
        "Don't build commands from user input: run a fixed program with a list of arguments.",
        "Could this command, or anything added to it, come from a user?",
        "Users of {route} could run commands on your server",
    ),
    "code_injection": PlainText(
        "Users could run their own code inside your app",
        "Someone could make your app do anything it is able to do.",
        "Never run code made from user input; pick from a fixed list of allowed actions instead.",
        "Could the code being run here come from a user?",
        "Users of {route} could run their own code inside your app",
    ),
    "xss": PlainText(
        "Attackers could run scripts in your users' browsers",
        "Someone could take over your users' accounts or act as them.",
        "Show user content as text, not HTML. If you must allow HTML, clean it with a sanitizer "
        "such as DOMPurify first.",
        "Could a user put their own HTML or script on this page?",
    ),
    "ssrf": PlainText(
        "Your server could be tricked into visiting other addresses",
        "Someone could reach your private services or cloud passwords through your server.",
        "Only let your server visit addresses from a fixed list you trust, never an address a user sends.",
        "Could the address your server visits here come from a user?",
        "Users of {route} could make your server visit other addresses",
    ),
    "open_redirect": PlainText(
        "Links on your site could send people to fake sites",
        "Scammers could use your site's name to trick people.",
        "Only send people to pages on your own site (paths that start with a single /), or to a fixed list.",
        "Could the page people are sent to come from a user?",
        "{route} could send people to fake sites",
    ),
    "path_traversal": PlainText(
        "Users could read or overwrite files on your server",
        "Someone could read private files, such as your .env passwords, or change files.",
        "Keep file access inside one folder and reject names that try to leave it, or look files up by ID.",
        "Could this file name come from a user?",
        "Users of {route} could read or overwrite files on your server",
    ),
    "secret_exposure": PlainText(
        "A password or API key is visible in your code",
        "Anyone who sees the code, the website or the logs could use it.",
        "Move it to an environment variable or a secret manager, and replace the exposed key with a new one.",
        "Is this a real password or key? If it is, move it out of the code and replace it.",
    ),
    "missing_authorization": PlainText(
        "This code runs without checking who is asking",
        "Anyone on the internet could do this, even without an account.",
        "Check that the person is logged in, and allowed to do this, at the very start.",
        "Should anyone be able to do this without logging in? If not, add a login check at the start.",
        "Anyone can use {route} without logging in",
    ),
    "insecure_auth_crypto": PlainText(
        "Passwords or login codes could be guessed",
        "Weak random numbers or weak password storage let attackers guess or fake logins.",
        "Use a secure random generator for tokens, and bcrypt or argon2 to store passwords.",
        "Is this value used for logging in or for security?",
    ),
    "unsafe_security_configuration": PlainText(
        "A security protection is turned off",
        "With the protection off, attackers could read or change traffic, or use your users' sessions.",
        "Turn the protection back on (for example, keep certificate checks on).",
        "Does this protection really need to be off? If not, turn it back on.",
    ),
    "api_authorization": PlainText(
        "A required login check was removed",
        "A page that used to be protected may now be open to anyone.",
        "Put the removed login check back.",
        "Was this login check removed on purpose?",
    ),
    "workflow_injection": PlainText(
        "A pull request or issue could take over your GitHub workflow",
        "Someone could run commands in your GitHub Actions, with your secrets.",
        "Pass the value through an environment variable and quote it, instead of writing ${{ }} inside "
        "the script.",
        "Can people outside your team trigger this workflow?",
    ),
    "untrusted_checkout": PlainText(
        "Your workflow runs strangers' code with your secrets",
        "A pull request from anyone could steal your secrets or tokens.",
        "Don't check out or run pull request code in workflows that have your secrets.",
        "Does this workflow run code from pull requests?",
    ),
    "excessive_privileges": PlainText(
        "Something runs with more power than it needs",
        "If it is ever tricked, the damage is much bigger than it has to be.",
        "Give it only the permissions it needs, and don't run containers as the root user.",
        "Does this really need these permissions?",
    ),
    "unpinned_dependency": PlainText(
        "A tool or image version could change without you knowing",
        "If that tool is ever hacked, your project picks up the hacked version automatically.",
        "Pin it to an exact version: a full commit ID for GitHub Actions, or an image digest.",
        "Do you trust whoever can change this version?",
    ),
    "unverified_download": PlainText(
        "You download and run a script without checking it",
        "If the download is tampered with, you run someone else's code.",
        "Download a fixed version and check its checksum before running it.",
        "Do you trust this download source to never change?",
    ),
}


def plain(check_id: str) -> PlainText:
    """The everyday wording for a check (a neutral fallback for checks without one)."""
    return PLAIN.get(check_id) or PlainText(
        f"Possible problem: {check_title(check_id)}",
        "This could make your app less safe.",
        "Read the technical details and fix it, or ask your AI to.",
        "Could this be a problem in your app?",
    )


RULES: dict[str, RuleInfo] = {}


def rule(
    rule_id: str, check_id: str, title: str, message: str, fix: str, *,
    severity: Severity | None = None, cwe: str | None = None,
) -> RuleInfo:
    """Register (or fetch) a rule description; analyzers declare their rules at import time."""
    existing = RULES.get(rule_id)
    if existing is not None:
        return existing
    if check_id not in CHECKS:
        raise ValueError(f"unknown check for rule {rule_id}")
    info = RuleInfo(rule_id, check_id, title, message, fix, severity, cwe)
    RULES[rule_id] = info
    return info


def check_title(check_id: str) -> str:
    info = CHECKS.get(check_id)
    return info.title if info else check_id.replace("_", " ")


def check_cwe(check_id: str) -> str | None:
    info = CHECKS.get(check_id)
    return info.cwe if info else None


def check_category(check_id: str) -> Category | None:
    info = CHECKS.get(check_id)
    return info.category if info else None


def applies(check_id: str, language: str) -> bool:
    """Whether a check is meaningful for files of this source kind. Files no analyzer reads
    ("unsupported") are program code in an unsupported language, so code checks apply."""
    info = CHECKS.get(check_id)
    if info is None:
        return True
    kind = source_kind(language)
    return (kind.domain if kind is not None else "code") in info.domains


def default_severity(check_id: str) -> Severity:
    info = CHECKS.get(check_id)
    return info.severity if info else "medium"


def load_all() -> None:
    """Register every built-in analyzer's rules (they register on import)."""
    import polaris.review.analyzers.python
    import polaris.review.analyzers.registry
    import polaris.review.analyzers.rust
    import polaris.review.js.model  # noqa: F401


def explain(identifier: str) -> dict[str, str] | None:
    """Plain-language explanation for a check id or a rule id (for the explain_finding tool)."""
    load_all()
    rule_info = RULES.get(identifier.strip())
    identifier = identifier.strip()
    check = CHECKS.get(rule_info.check_id if rule_info else identifier)
    if check is None:
        return None
    result = {
        "check_id": check.check_id, "title": check.title, "cwe": rule_info.cwe if rule_info and rule_info.cwe else check.cwe,
        "category": check.category,
        "severity": (rule_info.severity if rule_info and rule_info.severity else check.severity),
        "what": rule_info.message if rule_info else check.summary,
        "why_it_matters": check.why,
        "how_to_fix": rule_info.fix if rule_info else check.fix,
    }
    if rule_info:
        result["rule_id"] = rule_info.rule_id
        result["rule_title"] = rule_info.title
    if check.example_bad:
        result["vulnerable_example"] = check.example_bad
    if check.example_good:
        result["safer_example"] = check.example_good
    return result

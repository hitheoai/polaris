"""Built-in GitHub Actions analyzer: workflow YAML is composed into nodes, never constructed or run.

Reads `.github/workflows/*.yml|yaml` and reports expression injection of untrusted event data
into `run:` scripts and `actions/github-script`, privileged workflows that check out or run a
pull request's code (or run files from the triggering run's artifacts), write-all or broad write
tokens on untrusted triggers, third-party actions and images not pinned to a commit SHA or
digest, download-and-run scripts, hardcoded credentials and secrets printed to the job log.

Severity follows the trigger. An outsider controls the data of pull_request_target, issues,
issue_comment, discussion, commit_comment, gollum and workflow_run runs, which get the
repository's secrets and a token that may write; push runs see commit text that arrives through
merged pull requests; pull_request runs from forks get a read-only token and no secrets.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml  # type: ignore[import-untyped,unused-ignore]

from polaris.jsonio import digest_json
from polaris.review import catalog, secrets
from polaris.review.analyzers import shellwords
from polaris.review.analyzers.base import AnalysisInput, AnalyzerResult, language_for_path
from polaris.review.analyzers.evidence import line_text, make_finding, mask_values, step
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    Confidence,
    CoverageStatus,
    Severity,
    SourceFile,
    SuggestedEdit,
    WorkflowFinding,
)

ANALYZER_ID = "polaris-gha"
VERSION = "polaris-gha/0.1.0"
KIND = "github_actions"
CHECKS = ("workflow_injection", "untrusted_checkout", "excessive_privileges", "unpinned_dependency",
          "unverified_download", "secret_exposure")
LIMITATIONS = [
    "Reads the workflows GitHub runs (.github/workflows/*.yml|yaml at the repository root); composite "
    "actions (action.yml) and workflows called from other repositories are not followed.",
    "Untrusted data is a fixed list of event fields (titles, bodies, comments, branch names, commit "
    "messages and authors); step outputs, inputs and matrix values are not traced.",
    "Severity assumes each trigger's documented token and secret access; repository settings (default "
    "token permissions, fork approval, environment reviewers) are not visible.",
    "Shell in run: steps is tokenized for commands, pipes and redirections, never executed or fully parsed.",
]
MAX_BYTES = 1_000_000
MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_STEP_VISITS = 5_000
MAX_EXPRESSION = 4_096
MAX_HITS = 500

PR_EVENTS = frozenset({"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment"})
# Untrusted data and a privileged token/secrets in the same run.
PRIVILEGED = frozenset({"pull_request_target", "issues", "issue_comment", "discussion", "discussion_comment",
                        "commit_comment", "workflow_run", "gollum"})
# Runs that check out or run a pull request's code count only under these triggers.
CHECKOUT_TRIGGERS = frozenset({"pull_request_target", "workflow_run", "issue_comment"})
FIRST_PARTY = frozenset({"actions", "github"})
# The SLSA generator verifies its own reusable workflow by tag; a SHA reference breaks provenance.
_TAG_ONLY = ("slsa-framework/slsa-github-generator/",)
_SEMVER = re.compile(r"v\d+\.\d+\.\d+")
# Token scopes whose write access matters most if an untrusted run is taken over.
BROAD_SCOPES = frozenset({"contents", "actions", "packages", "deployments", "id-token", "pages", "attestations"})
_SHA = re.compile(r"(?i)[0-9a-f]{40}(?:[0-9a-f]{24})?")
_DIGEST = re.compile(r"(?i)@sha256:[0-9a-f]{64}$")
_SECRET_ENV = re.compile(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class Untrusted:
    path: tuple[str, ...]
    triggers: frozenset[str]
    label: str
    who: str
    multiline: bool = False


def _u(path: str, triggers: frozenset[str] | set[str], label: str, who: str, multiline: bool = False) -> Untrusted:
    return Untrusted(tuple(path.split(".")), frozenset(triggers), label, who, multiline)


_ISSUE = {"issues", "issue_comment"}
_COMMENTS = {"issue_comment", "pull_request_review_comment", "commit_comment", "discussion_comment"}
_DISCUSSION = {"discussion", "discussion_comment"}
UNTRUSTED: tuple[Untrusted, ...] = (
    _u("github.event.issue.title", _ISSUE, "issue title", "whoever opens or edits the issue"),
    _u("github.event.issue.body", _ISSUE, "issue body", "whoever opens or edits the issue", True),
    _u("github.event.pull_request.title", PR_EVENTS, "pull request title", "whoever opens the pull request"),
    _u("github.event.pull_request.body", PR_EVENTS, "pull request body", "whoever opens the pull request", True),
    _u("github.event.pull_request.head.ref", PR_EVENTS, "pull request branch name", "whoever opens the pull request"),
    _u("github.event.pull_request.head.label", PR_EVENTS, "pull request head label", "whoever opens the pull request"),
    _u("github.event.pull_request.head.repo.default_branch", PR_EVENTS, "fork's default branch name",
       "whoever opens the pull request"),
    _u("github.event.pull_request.head.repo.description", PR_EVENTS, "fork description",
       "whoever opens the pull request", True),
    _u("github.event.pull_request.head.repo.homepage", PR_EVENTS, "fork homepage", "whoever opens the pull request"),
    _u("github.head_ref", {"pull_request", "pull_request_target"}, "pull request branch name",
       "whoever opens the pull request"),
    _u("github.event.changes.*.from", {*_ISSUE, *PR_EVENTS, *_DISCUSSION}, "previous title or body",
       "whoever edited it", True),
    _u("github.event.comment.body", _COMMENTS, "comment body", "whoever writes the comment", True),
    _u("github.event.review.body", {"pull_request_review"}, "review body", "whoever writes the review", True),
    _u("github.event.discussion.title", _DISCUSSION, "discussion title", "whoever starts the discussion"),
    _u("github.event.discussion.body", _DISCUSSION, "discussion body", "whoever starts the discussion", True),
    _u("github.event.pages.*.page_name", {"gollum"}, "wiki page name", "whoever edits the wiki"),
    _u("github.event.pages.*.title", {"gollum"}, "wiki page title", "whoever edits the wiki"),
    _u("github.event.head_commit.message", {"push"}, "commit message", "whoever wrote the commit", True),
    _u("github.event.head_commit.author.name", {"push"}, "commit author name", "whoever wrote the commit"),
    _u("github.event.head_commit.author.email", {"push"}, "commit author email", "whoever wrote the commit"),
    _u("github.event.head_commit.committer.name", {"push"}, "committer name", "whoever wrote the commit"),
    _u("github.event.head_commit.committer.email", {"push"}, "committer email", "whoever wrote the commit"),
    _u("github.event.commits.*.message", {"push"}, "commit message", "whoever wrote the commit", True),
    _u("github.event.commits.*.author.name", {"push"}, "commit author name", "whoever wrote the commit"),
    _u("github.event.commits.*.author.email", {"push"}, "commit author email", "whoever wrote the commit"),
    _u("github.event.commits.*.committer.name", {"push"}, "committer name", "whoever wrote the commit"),
    _u("github.event.commits.*.committer.email", {"push"}, "committer email", "whoever wrote the commit"),
    _u("github.event.workflow_run.head_branch", {"workflow_run"}, "triggering run's branch name",
       "whoever opened the pull request behind the triggering run"),
    _u("github.event.workflow_run.display_title", {"workflow_run"}, "triggering run's title",
       "whoever opened the pull request behind the triggering run"),
    _u("github.event.workflow_run.head_commit.message", {"workflow_run"}, "triggering run's commit message",
       "whoever opened the pull request behind the triggering run", True),
    _u("github.event.workflow_run.head_commit.author.name", {"workflow_run"}, "triggering run's commit author",
       "whoever opened the pull request behind the triggering run"),
    _u("github.event.workflow_run.head_commit.author.email", {"workflow_run"}, "triggering run's commit author",
       "whoever opened the pull request behind the triggering run"),
    _u("github.event.workflow_run.pull_requests.*.head.ref", {"workflow_run"}, "triggering pull request's branch",
       "whoever opened the pull request behind the triggering run"),
    _u("github.event.workflow_run.head_repository.description", {"workflow_run"}, "fork description",
       "whoever opened the pull request behind the triggering run", True),
)
# Paths that name the pull request's own revision (checking these out runs its code).
_PR_HEAD_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "pull_request_target": tuple(tuple(path.split(".")) for path in (
        "github.event.pull_request.head.sha", "github.event.pull_request.head.ref", "github.head_ref",
        "github.event.pull_request.merge_commit_sha", "github.event.pull_request.head.repo.full_name",
        "github.event.pull_request.head.repo.clone_url", "github.event.pull_request.head.repo.ssh_url")),
    "workflow_run": tuple(tuple(path.split(".")) for path in (
        "github.event.workflow_run.head_sha", "github.event.workflow_run.head_branch",
        "github.event.workflow_run.head_commit.id", "github.event.workflow_run.pull_requests.*.head.sha",
        "github.event.workflow_run.pull_requests.*.head.ref", "github.event.workflow_run.head_repository.full_name")),
    "issue_comment": (),
}
_PULL_REF = re.compile(r"(?i)\brefs/pull/|(?:^|[\s:/])pull/[^/\s]+/(?:head|merge)\b|\bFETCH_HEAD\b")
_BUILD_TOOLS = frozenset({
    "npm", "npx", "yarn", "pnpm", "bun", "node", "deno", "make", "cmake", "ninja", "gradle", "gradlew", "mvn",
    "mvnw", "ant", "sbt", "pip", "pip3", "python", "python3", "pytest", "tox", "nox", "poetry", "uv", "pipenv",
    "hatch", "go", "cargo", "dotnet", "msbuild", "bundle", "rake", "ruby", "gem", "composer", "php", "docker",
    "docker-compose", "bazel", "bazelisk", "lerna", "nx", "turbo", "tsc", "jest", "vitest", "mix", "swift",
    "xcodebuild", "flutter", "dart", "terraform", "pre-commit", "sh", "bash", "source", ".",
})
_EXECUTING_ACTIONS = frozenset({"docker/build-push-action", "cypress-io/github-action", "github/codeql-action/autobuild",
                                "gradle/gradle-build-action", "pre-commit/action"})
# What a write scope lets a taken-over job do.
_SCOPE_EFFECT = {"contents": "push code and releases", "actions": "cancel or re-run workflows and edit caches",
                 "packages": "publish packages", "deployments": "create deployments",
                 "id-token": "request cloud credentials through OIDC", "pages": "publish GitHub Pages",
                 "attestations": "sign build attestations"}


def _runs_workspace_code(words: list[shellwords.Word]) -> bool:
    """Whether a command runs or builds code from the working directory."""
    name = shellwords.basename(words[0].text)
    if name == "docker":
        return len(words) > 1 and words[1].text in ("build", "buildx", "compose")
    return name in _BUILD_TOOLS or words[0].text.startswith("./")
_DOWNLOAD_ACTIONS = frozenset({"actions/download-artifact", "dawidd6/action-download-artifact"})


def _rules() -> None:
    gha = "polaris.gha."
    catalog.rule(gha + "workflow_injection.run", "workflow_injection", "Untrusted expression in a run script",
                 "Untrusted event data is expanded into a run: script before the shell starts.",
                 "Pass the value through env: (for example env: TITLE: ${{ github.event.issue.title }}) and use it "
                 "quoted in the script (\"$TITLE\"), so it stays data instead of becoming shell code.")
    catalog.rule(gha + "workflow_injection.github_script", "workflow_injection",
                 "Untrusted expression in actions/github-script",
                 "Untrusted event data is expanded into actions/github-script JavaScript before it runs.",
                 "Read the value from context.payload (or from process.env after passing it through env:) "
                 "instead of expanding ${{ }} into the script.")
    catalog.rule(gha + "untrusted_checkout.pr_head", "untrusted_checkout",
                 "Pull request code checked out in a privileged workflow",
                 "A privileged workflow checks out the pull request's code.",
                 "Build pull requests under pull_request; in the privileged workflow, fetch the change as data only "
                 "(git fetch, no checkout) or use only artifacts as data, and never run anything from them.")
    catalog.rule(gha + "untrusted_checkout.artifact", "untrusted_checkout",
                 "Artifact of the triggering run executed in a privileged workflow",
                 "A workflow_run job runs files from an artifact of the triggering run, which a pull request "
                 "from a fork can produce.",
                 "Treat artifacts from the triggering run as data: read and validate them, never execute them or "
                 "extract them over the workspace before running build tools.")
    catalog.rule(gha + "excessive_privileges.write_all", "excessive_privileges", "write-all token permissions",
                 "permissions: write-all grants the job token write access to every scope.",
                 "List only the scopes the jobs need (for example permissions: contents: read, pull-requests: write).")
    catalog.rule(gha + "excessive_privileges.untrusted_trigger_write", "excessive_privileges",
                 "Broad write token on an untrusted trigger",
                 "A job triggered by outside data gets a token that can write code, releases, packages or deployments.",
                 "Grant this job only the narrow scopes it needs (pull-requests, issues), and move writes that need "
                 "contents/packages/id-token to a workflow that untrusted events can't trigger.")
    catalog.rule(gha + "excessive_privileges.default_permissions", "excessive_privileges",
                 "Default token permissions on an untrusted trigger",
                 "A workflow that outside events trigger sets no permissions, so its jobs get the repository's "
                 "default token, which is read/write in older repositories and organizations.",
                 "Add a top-level permissions block (permissions: {} or contents: read) and grant writes per job.")
    catalog.rule(gha + "unpinned_dependency.action", "unpinned_dependency", "Third-party action not pinned to a SHA",
                 "A third-party action is referenced by a tag or branch its owner can move.",
                 "Pin the action to the full 40-character commit SHA of the reviewed release (keep the tag in a "
                 "comment) and let Dependabot or Renovate update it.")
    catalog.rule(gha + "unpinned_dependency.image", "unpinned_dependency", "Container image not pinned to a digest",
                 "A container image used by the workflow is referenced by a mutable tag.",
                 "Reference the image by digest (image@sha256:<digest>) and update the digest deliberately.")
    catalog.rule(gha + "unverified_download.pipe_to_shell", "unverified_download", "Remote script piped to a shell",
                 "A script downloaded in a run: step is executed without verifying it.",
                 "Download to a file, check a pinned SHA-256 (sha256sum -c) or signature, then run it; prefer a "
                 "pinned release or a setup action pinned to a SHA.")
    catalog.rule(gha + "secret_exposure.hardcoded", "secret_exposure", "Credential hardcoded in a workflow",
                 "A credential appears to be written directly in the workflow file.",
                 "Store it as an encrypted secret (${{ secrets.NAME }}), rotate the exposed value, and remove it "
                 "from the history.")
    catalog.rule(gha + "secret_exposure.log", "secret_exposure", "Secret printed to the job log",
                 "A secret is printed to the job log.",
                 "Don't print secrets; pass them to the tool that needs them on stdin or in env. GitHub masks only "
                 "exact values, so encoded or transformed secrets appear in clear text.")


_rules()


def capability() -> AnalyzerCapability:
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability="available", version=VERSION, expected_version=VERSION,
        rule_pack_version=VERSION,
        rule_pack_digest=digest_json({"version": VERSION,
                                      "rules": sorted(rule for rule in catalog.RULES if rule.startswith("polaris.gha."))}),
        languages=[KIND], checks=list(CHECKS),
        provenance="Original Polaris rules; workflow YAML composed with PyYAML (MIT), never constructed",
        license="Apache-2.0", reason="builtin_in_process", limitations=list(LIMITATIONS),
    )


# ----------------------------------------------------------------------------------- bounded YAML


class _Problem(Exception):
    """A fixed coverage reason; never carries input text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Loader(yaml.SafeLoader):
    """SafeLoader that only composes nodes, with nesting and node budgets (aliases count each time
    they are composed, so anchor bombs exhaust the budget instead of memory)."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.depth = 0
        self.nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        self.depth += 1
        self.nodes += 1
        if self.depth > MAX_DEPTH or self.nodes > MAX_NODES:
            raise _Problem("analysis_limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1


def compose(text: str) -> Any:
    """The document's root node. Invalid YAML, several documents, duplicate keys or a non-mapping
    root raise `_Problem("parse_error")`; budgets raise `_Problem("analysis_limit")`."""
    loader = _Loader(text)
    try:
        root = loader.get_single_node()
    except yaml.YAMLError:
        raise _Problem("parse_error") from None
    except RecursionError:
        raise _Problem("analysis_limit") from None
    finally:
        loader.dispose()
    if not isinstance(root, yaml.MappingNode):
        raise _Problem("parse_error")
    seen: set[int] = set()
    stack: list[Any] = [root]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            keys: set[str] = set()
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode):
                    if key.value in keys:
                        raise _Problem("parse_error")
                    keys.add(key.value)
                stack.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return root


def _get(node: Any, key: str) -> Any:
    if isinstance(node, yaml.MappingNode):
        for item, value in node.value:
            if isinstance(item, yaml.ScalarNode) and item.value == key:
                return value
    return None


def _key(node: Any, key: str) -> Any:
    if isinstance(node, yaml.MappingNode):
        for item, _ in node.value:
            if isinstance(item, yaml.ScalarNode) and item.value == key:
                return item
    return None


def _items(node: Any) -> Iterator[tuple[str, Any, Any]]:
    if isinstance(node, yaml.MappingNode):
        for item, value in node.value:
            if isinstance(item, yaml.ScalarNode):
                yield item.value, item, value


def _text(node: Any) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) and isinstance(node.value, str) else None


def _line(node: Any) -> int:
    return int(node.start_mark.line) + 1


def _content_line(node: Any) -> int:
    """First line of a scalar's content (block scalars start on the line after `|` or `>`)."""
    return _line(node) + (1 if node.style in ("|", ">") else 0)


# ----------------------------------------------------------------------------------- expressions


class _ExprError(ValueError):
    pass


_TOKEN = re.compile(r"""\s*(?:
    (?P<string>'(?:[^']|'')*')
  | (?P<number>-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][-+]?\d+)?))
  | (?P<op>&&|\|\||==|!=|<=|>=|[<>!()\[\],.*])
  | (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
)""", re.X)

Ast = tuple[Any, ...]


def _tokens(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    index = 0
    while index < len(text):
        match = _TOKEN.match(text, index)
        if match is None or match.end() == index:
            if text[index:].strip():
                raise _ExprError("token")
            break
        kind = match.lastgroup or ""
        found.append((kind, match.group(kind)))
        index = match.end()
    return found


class _Parser:
    def __init__(self, text: str) -> None:
        if len(text) > MAX_EXPRESSION:
            raise _ExprError("size")
        self.tokens = _tokens(text)
        self.index = 0
        self.depth = 0

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.index] if self.index < len(self.tokens) else ("end", "")

    def take(self) -> tuple[str, str]:
        token = self.peek()
        self.index += 1
        return token

    def expect(self, value: str) -> None:
        if self.take() != ("op", value):
            raise _ExprError("syntax")

    def parse(self) -> Ast:
        node = self.either()
        if self.peek()[0] != "end":
            raise _ExprError("syntax")
        return node

    def either(self) -> Ast:
        node = self.both()
        while self.peek() == ("op", "||"):
            self.take()
            node = ("or", node, self.both())
        return node

    def both(self) -> Ast:
        node = self.equality()
        while self.peek() == ("op", "&&"):
            self.take()
            node = ("and", node, self.equality())
        return node

    def equality(self) -> Ast:
        node = self.relation()
        while self.peek() in (("op", "=="), ("op", "!=")):
            operator = self.take()[1]
            node = ("cmp", operator, node, self.relation())
        return node

    def relation(self) -> Ast:
        node = self.unary()
        while self.peek() in (("op", "<"), ("op", "<="), ("op", ">"), ("op", ">=")):
            operator = self.take()[1]
            node = ("cmp", operator, node, self.unary())
        return node

    def unary(self) -> Ast:
        if self.peek() == ("op", "!"):
            self.take()
            return ("not", self.unary())
        return self.postfix()

    def postfix(self) -> Ast:
        self.depth += 1
        if self.depth > 64:
            raise _ExprError("depth")
        try:
            return self._postfix()
        finally:
            self.depth -= 1

    def _postfix(self) -> Ast:
        kind, value = self.take()
        node: Ast
        if (kind, value) == ("op", "("):
            node = self.either()
            self.expect(")")
        elif kind in ("string", "number"):
            node = ("lit", value[1:-1].replace("''", "'") if kind == "string" else value)
        elif kind == "name":
            lowered = value.lower()
            if lowered in ("true", "false", "null"):
                node = ("lit", lowered)
            elif self.peek() == ("op", "("):
                self.take()
                args: list[Ast] = []
                if self.peek() != ("op", ")"):
                    args.append(self.either())
                    while self.peek() == ("op", ","):
                        self.take()
                        args.append(self.either())
                self.expect(")")
                node = ("call", lowered, tuple(args))
            else:
                node = ("path", (lowered,))
        else:
            raise _ExprError("syntax")
        while True:
            if self.peek() == ("op", "."):
                self.take()
                kind, value = self.take()
                if kind == "name":
                    node = _extend(node, value.lower())
                elif (kind, value) == ("op", "*"):
                    node = _extend(node, "*")
                else:
                    raise _ExprError("syntax")
            elif self.peek() == ("op", "["):
                self.take()
                if self.peek() == ("op", "*"):
                    self.take()
                    segment = "*"
                else:
                    index = self.either()
                    segment = (index[1].lower() if index[0] == "lit" and not _number(index[1]) else
                               "*" if index[0] == "lit" else "?")
                self.expect("]")
                node = _extend(node, segment)
            else:
                return node


def _number(value: str) -> bool:
    return bool(re.fullmatch(r"-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][-+]?\d+)?)", value))


def _extend(node: Ast, segment: str) -> Ast:
    if node[0] == "path":
        return ("path", (*node[1], segment))
    return ("index", node, segment)


def parse_expression(text: str) -> Ast | None:
    try:
        return _Parser(text).parse()
    except _ExprError:
        return None


def expressions(text: str) -> list[tuple[int, int, str]]:
    """`${{ … }}` spans as (start, end, inner text); string literals may contain braces."""
    found: list[tuple[int, int, str]] = []
    index = text.find("${{")
    while index >= 0 and len(found) < 1_000:
        cursor = index + 3
        end = -1
        while cursor < len(text) and cursor - index <= MAX_EXPRESSION:
            if text[cursor] == "'":
                close = cursor + 1
                while close < len(text):
                    if text[close] == "'" and text.startswith("''", close):
                        close += 2
                        continue
                    if text[close] == "'":
                        break
                    close += 1
                cursor = close + 1
                continue
            if text.startswith("}}", cursor):
                end = cursor + 2
                break
            cursor += 1
        if end < 0:
            break
        found.append((index, end, text[index + 3:end - 2]))
        index = text.find("${{", end)
    return found


def _segments_match(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    return all(left in ("*", "?") or right == "*" or left == right for left, right in zip(path, pattern, strict=False))


@dataclass(frozen=True)
class Taint:
    source: Untrusted
    via: tuple[str, int] | None = None  # env variable name and the line binding it


EnvLookup = Callable[[str], list[Taint]]


def _path_taint(path: tuple[str, ...], ancestor: bool, env: EnvLookup) -> list[Taint]:
    if len(path) >= 2 and path[0] == "env":
        return env(path[1])
    found = []
    for item in UNTRUSTED:
        if not _segments_match(path, item.path):
            continue
        if len(path) >= len(item.path) or ancestor:
            found.append(Taint(item))
    return found


def taint(node: Ast, env: EnvLookup, *, ancestor: bool = False) -> list[Taint]:
    """Untrusted data that can reach the expression's string value (booleans never carry it)."""
    kind = node[0]
    if kind == "path":
        return _path_taint(node[1], ancestor, env)
    if kind == "and":
        return taint(node[2], env)
    if kind == "or":
        return [*taint(node[1], env), *taint(node[2], env)]
    if kind == "index":
        return taint(node[1], env, ancestor=ancestor)
    if kind == "call":
        name, args = node[1], node[2]
        if name in ("contains", "startswith", "endswith", "success", "failure", "always", "cancelled", "hashfiles"):
            return []
        return [found for arg in args for found in taint(arg, env, ancestor=name == "tojson")]
    return []  # literals, comparisons and negations are not strings an attacker writes


def _references(node: Ast) -> Iterator[tuple[str, ...]]:
    if node[0] == "path":
        yield node[1]
    elif node[0] in ("and", "or"):
        yield from _references(node[1])
        yield from _references(node[2])
    elif node[0] in ("not", "index"):
        yield from _references(node[1])
    elif node[0] == "cmp":
        yield from _references(node[2])
        yield from _references(node[3])
    elif node[0] == "call":
        for arg in node[2]:
            yield from _references(arg)


def _conjuncts(node: Ast) -> list[Ast]:
    if node[0] == "and":
        return [*_conjuncts(node[1]), *_conjuncts(node[2])]
    return [node]


def condition(text: str | None) -> Ast | None:
    """An `if:` value as an expression (bare or a single `${{ }}`); a value mixing `${{ }}` with other
    text is a non-empty string, which GitHub treats as always true."""
    if text is None:
        return None
    stripped = text.strip()
    spans = expressions(stripped)
    if spans:
        if len(spans) != 1 or spans[0][0] != 0 or spans[0][1] != len(stripped):
            return ("lit", "true")
        stripped = spans[0][2]
    return parse_expression(stripped)


def _is(node: Ast, *path: str) -> bool:
    return node[0] == "path" and node[1] == path


def _literal(node: Ast) -> str | None:
    return node[1].lower() if node[0] == "lit" and isinstance(node[1], str) else None


def _compares(node: Ast, operator: str, test: Callable[[Ast], bool], value: Callable[[Ast], bool]) -> bool:
    return node[0] == "cmp" and node[1] == operator and (
        (test(node[2]) and value(node[3])) or (test(node[3]) and value(node[2])))


_REPOSITORY = (("github", "repository"), ("github", "event", "repository", "full_name"),
               ("github", "event", "pull_request", "base", "repo", "full_name"))
_HEAD_REPOSITORY = (("github", "event", "pull_request", "head", "repo", "full_name"),
                    ("github", "event", "workflow_run", "head_repository", "full_name"))
_FORK_FLAG = (("github", "event", "pull_request", "head", "repo", "fork"),
              ("github", "event", "workflow_run", "head_repository", "fork"))
_TRUSTED_ASSOCIATIONS = frozenset({"owner", "member", "collaborator"})


@dataclass(frozen=True)
class Gate:
    """What an `if:` condition requires before a privileged job runs."""

    trusted: str | None = None  # why outsiders can't trigger it (same repository, association, merged)
    approval: str | None = None  # a maintainer step (label) that limits but doesn't close the hole
    events: frozenset[str] | None = None  # the event names the condition allows, when it restricts them


def gate(node: Ast | None) -> Gate:
    if node is None:
        return Gate()
    trusted = approval = None
    events: set[str] | None = None
    for part in _conjuncts(node):
        if part[0] == "lit" and part[1] == "false":
            trusted = "never runs"
        if _compares(part, "==", lambda item: any(item == ("path", path) for path in _HEAD_REPOSITORY),
                     lambda item: any(item == ("path", path) for path in _REPOSITORY)):
            trusted = "same-repository pull requests only"
        if (_compares(part, "==", lambda item: any(item == ("path", path) for path in _FORK_FLAG),
                      lambda item: _literal(item) == "false")
                or (part[0] == "not" and any(part[1] == ("path", path) for path in _FORK_FLAG))
                or _compares(part, "!=", lambda item: any(item == ("path", path) for path in _FORK_FLAG),
                             lambda item: _literal(item) == "true")):
            trusted = "pull requests from forks are excluded"
        if _is(part, "github", "event", "pull_request", "merged") or _compares(
                part, "==", lambda item: _is(item, "github", "event", "pull_request", "merged"),
                lambda item: _literal(item) == "true"):
            trusted = "merged pull requests only"
        if _compares(part, "==", lambda item: item[0] == "path" and item[1][-1:] == ("author_association",),
                     lambda item: (_literal(item) or "") in _TRUSTED_ASSOCIATIONS):
            trusted = "trusted authors only"
        if (part[0] == "call" and part[1] == "contains" and len(part[2]) == 2
                and part[2][1][0] == "path" and part[2][1][1][-1:] == ("author_association",)):
            container = part[2][0]
            literal = _literal(container[2][0]) if container[0] == "call" and container[2] else _literal(container)
            words = set(re.findall(r"[a-z_]+", literal or ""))
            if words and words <= _TRUSTED_ASSOCIATIONS:
                trusted = "trusted authors only"
        if _compares(part, "==", lambda item: _is(item, "github", "event", "workflow_run", "event"),
                     lambda item: _literal(item) in ("push", "schedule", "workflow_dispatch", "release")):
            trusted = "runs triggered by pushes only"
        if (part[0] == "call" and part[1] == "contains" and len(part[2]) == 2 and part[2][0][0] == "path"
                and part[2][0][1][-2:] == ("*", "name") and "labels" in part[2][0][1]):
            approval = "a maintainer-applied label"
        if _compares(part, "==", lambda item: _is(item, "github", "event", "label", "name"),
                     lambda item: _literal(item) is not None):
            approval = "a maintainer-applied label"
        if _compares(part, "==", lambda item: _is(item, "github", "event_name"), lambda item: _literal(item) is not None):
            named = next(_literal(item) for item in part[2:] if _literal(item) is not None)
            events = {named or ""} if events is None else events & {named or ""}
    return Gate(trusted, approval, frozenset(events) if events is not None else None)


# ----------------------------------------------------------------------------------- workflow model


@dataclass(frozen=True)
class Binding:
    name: str
    node: Any
    line: int


@dataclass
class Permissions:
    line: int
    kind: str  # write-all, read-all, none, map, other
    scopes: dict[str, tuple[str, int]] = field(default_factory=dict)


def _permissions(node: Any) -> Permissions | None:
    if node is None:
        return None
    if isinstance(node, yaml.ScalarNode):
        value = (node.value or "").strip()
        return Permissions(_line(node), value if value in ("write-all", "read-all") else "other")
    if isinstance(node, yaml.MappingNode):
        scopes = {name: ((_text(value) or "").strip(), _line(key)) for name, key, value in _items(node)}
        return Permissions(_line(node), "map" if scopes else "none", scopes)
    return Permissions(_line(node), "other")


def _env(node: Any) -> dict[str, Binding]:
    return {name: Binding(name, value, _line(key)) for name, key, value in _items(node)}


@dataclass
class Step:
    node: Any
    index: int
    line: int
    uses: str | None
    uses_node: Any
    run: Any
    shell: str | None
    env: dict[str, Binding]
    inputs: Any
    condition: str | None


@dataclass
class Job:
    name: str
    node: Any
    line: int
    permissions: Permissions | None
    env: dict[str, Binding]
    condition: str | None
    steps: list[Step]
    uses: str | None
    uses_node: Any
    environment: bool
    shell: str | None
    runs_on: list[str] | None


@dataclass
class Workflow:
    triggers: dict[str, int]
    trigger_nodes: dict[str, Any]
    permissions: Permissions | None
    env: dict[str, Binding]
    shell: str | None
    jobs: list[Job]


def _shell_of(defaults: Any) -> str | None:
    return _text(_get(_get(defaults, "run"), "shell"))


def _strings(node: Any) -> list[str] | None:
    if isinstance(node, yaml.ScalarNode):
        return [node.value]
    if isinstance(node, yaml.SequenceNode) and all(isinstance(item, yaml.ScalarNode) for item in node.value):
        return [item.value for item in node.value]
    if isinstance(node, yaml.MappingNode):
        return _strings(_get(node, "labels"))
    return None


def workflow_model(root: Any) -> Workflow:
    on = _get(root, "on")
    triggers: dict[str, int] = {}
    trigger_nodes: dict[str, Any] = {}
    if isinstance(on, yaml.ScalarNode):
        triggers[on.value] = _line(on)
    elif isinstance(on, yaml.SequenceNode):
        for item in on.value:
            if isinstance(item, yaml.ScalarNode):
                triggers[item.value] = _line(item)
    for name, key, value in _items(on):
        triggers[name] = _line(key)
        trigger_nodes[name] = value
    jobs: list[Job] = []
    visits = 0
    for name, key, node in _items(_get(root, "jobs")):
        steps = []
        step_nodes = _get(node, "steps")
        for index, item in enumerate(step_nodes.value if isinstance(step_nodes, yaml.SequenceNode) else []):
            visits += 1
            if visits > MAX_STEP_VISITS:
                raise _Problem("analysis_limit")
            if not isinstance(item, yaml.MappingNode):
                continue
            uses_node = _get(item, "uses")
            steps.append(Step(item, index, _line(item), _text(uses_node), uses_node, _get(item, "run"),
                              _text(_get(item, "shell")), _env(_get(item, "env")), _get(item, "with"),
                              _text(_get(item, "if"))))
        uses_node = _get(node, "uses")
        jobs.append(Job(name, node, _line(key), _permissions(_get(node, "permissions")), _env(_get(node, "env")),
                        _text(_get(node, "if")), steps, _text(uses_node), uses_node,
                        _get(node, "environment") is not None, _shell_of(_get(node, "defaults")),
                        _strings(_get(node, "runs-on"))))
    return Workflow(triggers, trigger_nodes, _permissions(_get(root, "permissions")), _env(_get(root, "env")),
                    _shell_of(_get(root, "defaults")), jobs)


# ----------------------------------------------------------------------------------- findings


@dataclass
class Hit:
    check: str
    rule: str
    line: int
    message: str
    severity: Severity
    symbol: str = "<module>"
    trace: list[tuple[str, int, str]] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    edit: SuggestedEdit | None = None
    confidence: Confidence = "high"
    reason: str = "pattern_match"
    secret: str | None = None  # the literal to mask in every finding's snippet


_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_LOWER: dict[str, Severity] = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}


def _quote(text: str, limit: int = 90) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed if len(collapsed) <= limit else collapsed[:limit - 1] + "…"


class _File:
    def __init__(self, source: SourceFile, checks: set[str]) -> None:
        self.source = source
        self.text = source.after or ""
        self.checks = checks
        self.hits: list[Hit] = []
        self.secrets: set[str] = set()  # masked in every finding, whichever checks run

    def add(self, hit: Hit) -> None:
        if hit.secret:
            self.secrets.add(hit.secret)
        if hit.check in self.checks and len(self.hits) < MAX_HITS:
            self.hits.append(hit)

    # ---- positions ---------------------------------------------------------------------------

    def raw(self, node: Any) -> str:
        return self.text[node.start_mark.index:node.end_mark.index]

    def value_line(self, node: Any, value: str, offset: int, needle: str = "") -> int:
        """File line of `offset` in a scalar's value. Literal block scalars map line by line; other
        styles fold lines, so the k-th occurrence of `needle` in the raw text is used."""
        if node.style == "|":
            return _line(node) + 1 + value.count("\n", 0, offset)
        if needle:
            occurrence = value.count(needle, 0, offset)
            raw = self.raw(node)
            position = -1
            for _ in range(occurrence + 1):
                position = raw.find(needle, position + 1)
                if position < 0:
                    break
            if position >= 0:
                return _line(node) + raw.count("\n", 0, position)
        return _content_line(node)

    # ---- environment -------------------------------------------------------------------------

    def env_lookup(self, scopes: list[dict[str, Binding]], depth: int = 0) -> EnvLookup:
        def lookup(name: str) -> list[Taint]:
            if depth > 2:
                return []
            for scope in scopes:
                binding = next((item for key, item in scope.items() if key.lower() == name), None)
                if binding is None:
                    continue
                value = _text(binding.node) or ""
                found: list[Taint] = []
                for _, _, inner in expressions(value):
                    parsed = parse_expression(inner)
                    if parsed is not None:
                        found.extend(Taint(item.source, (binding.name, binding.line))
                                     for item in taint(parsed, self.env_lookup(scopes[1:], depth + 1)))
                return found
            return []
        return lookup


def _severity(triggers: set[str], workflow_call: bool) -> Severity | None:
    if triggers & PRIVILEGED:
        return "critical"
    if "push" in triggers or workflow_call:
        return "high"
    return "medium" if triggers else None


def _trigger_text(triggers: set[str]) -> str:
    privileged = sorted(triggers & PRIVILEGED)
    if privileged:
        return f"{', '.join(privileged)} run{'s' if len(privileged) == 1 else ''} with the repository's secrets and token"
    if "push" in triggers:
        return "push runs with the repository's secrets and token after the commit is merged"
    return "fork pull requests get a read-only token and no secrets here, which limits the damage"


class Analysis:
    def __init__(self, file: _File, workflow: Workflow) -> None:
        self.file = file
        self.workflow = workflow
        self.triggers = set(workflow.triggers)
        self.workflow_call = "workflow_call" in self.triggers

    def first_trigger_line(self, names: set[str]) -> int:
        lines = [line for name, line in self.workflow.triggers.items() if name in names]
        return min(lines) if lines else 1

    # ---- expression injection ----------------------------------------------------------------

    def injection(self, job: Job, item: Step, scopes: list[dict[str, Binding]], allowed: set[str]) -> None:
        sinks: list[tuple[Any, str, str]] = []
        if isinstance(item.run, yaml.ScalarNode):
            sinks.append((item.run, "run script", "polaris.gha.workflow_injection.run"))
        if item.uses and item.uses.lower().startswith("actions/github-script@"):
            script = _get(item.inputs, "script")
            if isinstance(script, yaml.ScalarNode):
                sinks.append((script, "github-script", "polaris.gha.workflow_injection.github_script"))
        lookup = self.file.env_lookup(scopes)
        for node, sink, rule in sinks:
            value = node.value if isinstance(node.value, str) else ""
            spans = expressions(value)
            heredocs = self.heredocs(job, item, value, spans) if node is item.run else None
            by_line: dict[int, list[tuple[int, int, str, list[Taint]]]] = {}
            for start, end, inner in spans:
                parsed = parse_expression(inner)
                found = taint(parsed, lookup) if parsed is not None else []
                supplied = [entry for entry in found if self.workflow_call or entry.source.triggers & allowed]
                if supplied and heredocs is not None:
                    body = shellwords.data_heredoc(*heredocs, start)
                    # A quoted heredoc that is only data expands nothing; a value without newlines
                    # (a title, a branch name, toJSON output) can't end it early, so it stays data.
                    if body is not None and body.quoted and (
                            (parsed is not None and parsed[:2] == ("call", "tojson"))
                            or not any(entry.source.multiline for entry in supplied)):
                        continue
                if supplied:
                    line = self.file.value_line(node, value, start, "${{")
                    by_line.setdefault(line, []).append((start, end, inner, supplied))
            for line, occurrences in by_line.items():
                triggers = {name for _, _, _, found in occurrences for entry in found
                            for name in entry.source.triggers & allowed}
                severity = _severity(triggers, self.workflow_call)
                if severity is None:
                    continue
                first = occurrences[0][3][0]
                expression = _quote("${{ " + occurrences[0][2].strip() + " }}")
                via = first.via
                label = first.source.label
                if re.match(r"(?i)\s*tojson\s*\(", occurrences[0][2]):
                    label = f"event data, including the {label}"
                who = first.source.who + (" (through env " + via[0] + ")" if via else "")
                message = (f"{expression} ({label}) is expanded into this {sink} before it runs, so "
                           f"{who} can inject code; {_trigger_text(triggers)}.")
                trace = [("source", self.first_trigger_line(triggers or allowed),
                          f"on: {', '.join(sorted(triggers)) or 'workflow_call'} ({label})")]
                if via is not None:
                    trace.append(("step", via[1], f"env {via[0]}"))
                trace.append(("sink", line, f"{sink}: {expression}"))
                details = [self.token_detail(job)]
                if len(occurrences) > 1:
                    details.append(f"{len(occurrences)} untrusted expressions on this line.")
                edit = self.injection_edit(job, item, node, value, line, occurrences, allowed)
                self.file.add(Hit("workflow_injection", rule, line, message, severity, f"jobs.{job.name}", trace,
                                  details, edit, reason="tainted_flow"))

    def heredocs(self, job: Job, item: Step, value: str, spans: list[tuple[int, int, str]],
                 ) -> tuple[list[shellwords.Command], list[shellwords.HeredocBody]] | None:
        """The run script's commands and heredoc bodies (expressions masked), for POSIX shells."""
        if self.shell(job, item) in ("pwsh", "powershell", "cmd", "python", "node", "perl", "ruby") or "<<" not in value:
            return None
        masked = value
        for start, end, _ in spans:
            masked = masked[:start] + "X" * (end - start) + masked[end:]
        return shellwords.tokenize_with_heredocs(masked)

    def token_detail(self, job: Job) -> str:
        permissions = job.permissions or self.workflow.permissions
        if permissions is None:
            return "Job token: the repository's default permissions (no permissions block)."
        if permissions.kind in ("write-all", "read-all"):
            return f"Job token: {permissions.kind}."
        writes = sorted(scope for scope, (level, _) in permissions.scopes.items() if level == "write")
        return "Job token writes: " + (", ".join(writes) if writes else "none") + "."

    def shell(self, job: Job, item: Step) -> str | None:
        explicit = item.shell or job.shell or self.workflow.shell
        if explicit:
            name = shellwords.basename(explicit.split()[0]).lower() if explicit.split() else ""
            return name
        labels = [label.lower() for label in job.runs_on or []]
        if not labels or any("${{" in label for label in labels):
            return None
        if any("windows" in label for label in labels):
            return "pwsh"
        if any(word in label for label in labels for word in ("ubuntu", "macos", "linux")):
            return "bash"
        return None

    def injection_edit(self, job: Job, item: Step, node: Any, value: str, line: int,
                       occurrences: list[tuple[int, int, str, list[Taint]]],
                       allowed: set[str]) -> SuggestedEdit | None:
        """An exact one-line replacement, only where the value is available without expansion:
        $GITHUB_HEAD_REF in bash, context.payload in github-script."""
        if len(occurrences) != 1 or node.style not in ("|", None):
            return None
        start, end, inner, found = occurrences[0]
        expression = inner.strip()
        original = value[start:end]
        source_line = line_text(self.file.source.after, line)
        if source_line.count(original) != 1 or len(source_line) > 1_500:
            return None
        if node is item.run:
            if expression.lower() != "github.head_ref" or self.shell(job, item) not in ("bash", "sh"):
                return None
            masked = value
            for span_start, span_end, _ in expressions(value):
                masked = masked[:span_start] + "X" * (span_end - span_start) + masked[span_end:]
            context = shellwords.quote_context(masked, start)
            replacement = {"double": "${GITHUB_HEAD_REF}", "unquoted": '"${GITHUB_HEAD_REF}"',
                           "single": "'\"${GITHUB_HEAD_REF}\"'"}.get(context)
            if replacement is None or (node.style is None and source_line.strip().endswith(": " + original)):
                return None
            return SuggestedEdit(line=line, original=source_line, replacement=source_line.replace(original, replacement),
                                 note="GitHub sets GITHUB_HEAD_REF to the same branch name; the shell reads it as data.")
        if node.style != "|":
            return None
        path = expression.lower()
        if path == "github.head_ref":
            target = "context.payload.pull_request.head.ref"
        elif re.fullmatch(r"github\.event(?:\.[a-z_][a-z0-9_]*|\[\d+\])+", path):
            target = "context.payload" + expression.strip()[len("github.event"):]
        else:
            return None
        if not all(found[0].source.triggers >= {name} for name in allowed):
            return None
        for quote in ('"', "'"):
            quoted = quote + original + quote
            if value[start - 1:end + 1] == quoted and source_line.count(quoted) == 1:
                return SuggestedEdit(line=line, original=source_line, replacement=source_line.replace(quoted, target),
                                     note="context.payload holds the same event data as a JavaScript value.")
        return None

    # ---- untrusted checkout ------------------------------------------------------------------

    def head_paths(self, triggers: set[str]) -> list[tuple[str, ...]]:
        return [path for name in triggers & CHECKOUT_TRIGGERS for path in _PR_HEAD_PATHS.get(name, ())]

    def refers_to_head(self, text: str, triggers: set[str], scopes: list[dict[str, Binding]], depth: int = 0) -> bool:
        if _PULL_REF.search(text) and expressions(text) and triggers & CHECKOUT_TRIGGERS:
            return True
        heads = self.head_paths(triggers)
        for _, _, inner in expressions(text):
            parsed = parse_expression(inner)
            if parsed is None:
                continue
            for reference in _references(parsed):
                if any(_segments_match(reference, head) and len(reference) >= len(head) for head in heads):
                    return True
                if reference[:1] == ("env",) and len(reference) >= 2 and depth < 2:
                    binding = self.binding(reference[1], scopes)
                    if binding is not None and self.refers_to_head(_text(binding.node) or "", triggers, scopes,
                                                                   depth + 1):
                        return True
        return False

    @staticmethod
    def binding(name: str, scopes: list[dict[str, Binding]], *, exact: bool = False) -> Binding | None:
        for scope in scopes:
            for key, item in scope.items():
                if key == name or (not exact and key.lower() == name.lower()):
                    return item
        return None

    def checkout(self, item: Step, triggers: set[str], scopes: list[dict[str, Binding]]) -> tuple[int, str] | None:
        """(line, description) when this step puts the pull request's code in the workspace."""
        uses = (item.uses or "").lower()
        if uses.startswith("actions/checkout@"):
            for name in ("ref", "repository"):
                value = _get(item.inputs, name)
                text = _text(value)
                if text and self.refers_to_head(text, triggers, scopes):
                    return _line(value), f"actions/checkout with {name}: {_quote(text, 70)}"
            return None
        if not isinstance(item.run, yaml.ScalarNode) or not isinstance(item.run.value, str):
            return None
        script = item.run.value
        fetched: set[str] = set()
        for command in shellwords.tokenize(script):
            words = shellwords.argv(command)
            names = [word.text for word in words]
            if names[:3] == ["gh", "pr", "checkout"] and triggers & CHECKOUT_TRIGGERS:
                return (self.file.value_line(item.run, script, words[0].start, "gh"),
                        _quote("gh pr checkout " + " ".join(names[3:]), 70))
            if not names or names[0] != "git" or len(names) < 2:
                continue
            arguments = [word for word in words[2:] if not word.text.startswith("-")]
            if names[1] == "fetch":
                for word in arguments:
                    source, _, destination = word.text.lstrip("+").partition(":")
                    if destination and self.head_word(source, word, script, triggers, scopes):
                        fetched.add(destination.removeprefix("refs/heads/"))
                continue
            if names[1] not in ("checkout", "switch", "reset", "merge", "rebase", "cherry-pick", "worktree", "pull",
                                "restore"):
                continue
            for word in arguments:
                text = word.text.removeprefix("--source=")
                if text in fetched or self.head_word(text, word, script, triggers, scopes):
                    return (self.file.value_line(item.run, script, words[0].start, "git"),
                            _quote(" ".join(names), 70))
        return None

    def head_word(self, text: str, word: shellwords.Word, script: str, triggers: set[str],
                  scopes: list[dict[str, Binding]]) -> bool:
        if not triggers & CHECKOUT_TRIGGERS:
            return False
        if _PULL_REF.search(text):
            return True
        raw = script[word.start:word.end]
        if self.refers_to_head(raw, triggers, scopes):
            return True
        for name in _SECRET_ENV.findall(raw):
            binding = self.binding(name, scopes, exact=True)
            if binding is not None and self.refers_to_head(_text(binding.node) or "", triggers, scopes):
                return True
        return False

    def executes(self, item: Step, after_offset: int | None = None) -> tuple[int, str] | None:
        """(line, description) when a step runs code from the workspace."""
        uses = (item.uses or "").strip()
        if uses.startswith("./"):
            return _line(item.uses_node), f"local action {_quote(uses, 60)}"
        if uses.split("@", 1)[0].lower() in _EXECUTING_ACTIONS:
            return _line(item.uses_node), _quote(uses.split("@", 1)[0], 60)
        if not isinstance(item.run, yaml.ScalarNode) or not isinstance(item.run.value, str):
            return None
        script = item.run.value
        for command in shellwords.tokenize(script):
            if after_offset is not None and command.start <= after_offset:
                continue
            words = shellwords.argv(command)
            if words and _runs_workspace_code(words):
                return (self.file.value_line(item.run, script, words[0].start, words[0].text),
                        _quote(" ".join(word.text for word in words), 60))
        return None

    def untrusted_checkout(self, job: Job, allowed: set[str], job_gate: Gate, scopes_for: Callable[[Step], list]) -> None:
        triggers = allowed & CHECKOUT_TRIGGERS
        if not triggers or job_gate.trusted:
            return
        for position, item in enumerate(job.steps):
            step_gate = gate(condition(item.condition))
            if step_gate.trusted:
                continue
            found = self.checkout(item, triggers, scopes_for(item))
            if found is None:
                continue
            line, description = found
            runner = None
            for later in job.steps[position:]:
                offset = None
                if later is item:
                    offset = self.checkout_offset(item)
                    if offset is None:
                        continue
                runner = self.executes(later, offset)
                if runner is not None:
                    break
            severity: Severity = "critical" if runner else "high"
            approval = job_gate.approval or step_gate.approval or ("environment approval" if job.environment else None)
            if approval:
                severity = _LOWER[severity]
            names = ", ".join(sorted(triggers))
            message = (f"This {names} workflow checks out the pull request's code ({description})"
                       + (f" and then runs {runner[1]}" if runner else "")
                       + ": code from the pull request runs with the base repository's token, secrets and caches.")
            trace = [("source", self.first_trigger_line(triggers), f"on: {names}"),
                     ("step", line, description)]
            if runner:
                trace.append(("sink", runner[0], runner[1]))
            details = [self.token_detail(job)]
            if approval:
                details.append(f"Gated on {approval}: commits pushed after approval can still run.")
            self.file.add(Hit("untrusted_checkout", "polaris.gha.untrusted_checkout.pr_head", line, message, severity,
                              f"jobs.{job.name}", trace, details))
            return

    def checkout_offset(self, item: Step) -> int | None:
        if not isinstance(item.run, yaml.ScalarNode) or not isinstance(item.run.value, str):
            return None
        for command in shellwords.tokenize(item.run.value):
            names = [word.text for word in shellwords.argv(command)]
            if names[:3] == ["gh", "pr", "checkout"] or (names[:1] == ["git"] and len(names) > 1 and names[1] in (
                    "checkout", "switch", "reset", "merge", "rebase", "cherry-pick", "worktree", "pull", "restore")):
                return command.start
        return None

    def artifacts(self, job: Job, allowed: set[str], job_gate: Gate) -> None:
        """workflow_run jobs that execute files downloaded from the triggering run's artifacts."""
        if "workflow_run" not in allowed or job_gate.trusted:
            return
        downloads: list[tuple[str, int]] = []
        for item in job.steps:
            name = (item.uses or "").split("@", 1)[0].lower()
            if name in _DOWNLOAD_ACTIONS:
                run_id = _text(_get(item.inputs, "run-id")) or _text(_get(item.inputs, "run_id")) or ""
                if name == "actions/download-artifact" and "workflow_run" not in run_id:
                    continue
                path = (_text(_get(item.inputs, "path")) or ".").strip().removeprefix("./").rstrip("/") or "."
                downloads.append((path, _line(item.node)))
                continue
            if not downloads or not isinstance(item.run, yaml.ScalarNode) or not isinstance(item.run.value, str):
                continue
            script = item.run.value
            for command in shellwords.tokenize(script):
                words = shellwords.argv(command)
                if not words:
                    continue
                tool = shellwords.basename(words[0].text)
                for path, download_line in downloads:
                    target = None
                    if path not in (".", "${{ github.workspace }}"):
                        candidates = [words[0].text]
                        if tool in ("bash", "sh", "source", ".", "python", "python3", "node", "ruby", "perl") \
                                and len(words) > 1:
                            candidates.append(words[1].text)
                        target = next((text for text in candidates
                                       if text.removeprefix("./").startswith(path + "/")), None)
                    elif tool not in ("sh", "bash", "source", ".") and _runs_workspace_code(words):
                        target = " ".join(word.text for word in words)
                    if target is None:
                        continue
                    line = self.file.value_line(item.run, script, words[0].start, words[0].text)
                    if path == ".":
                        message = (f"This workflow_run job extracts an artifact of the triggering run into the workspace "
                                   f"(line {download_line}) and then runs {_quote(target, 60)}: if a pull request from "
                                   "a fork can produce that artifact, files it adds can change what the build runs.")
                    else:
                        message = (f"This workflow_run job downloads an artifact of the triggering run to {path} "
                                   f"(line {download_line}) and then runs {_quote(target, 60)}: a pull request from a "
                                   "fork can produce that artifact, so its content runs with the repository's token "
                                   "and secrets.")
                    # Direct execution of artifact files is explicit; a build reading planted files is not.
                    severity: Severity = "critical" if path != "." else "medium"
                    self.file.add(Hit(
                        "untrusted_checkout", "polaris.gha.untrusted_checkout.artifact", line, message, severity,
                        f"jobs.{job.name}",
                        [("source", self.first_trigger_line({"workflow_run"}), "on: workflow_run"),
                         ("step", download_line, "artifact from the triggering run"), ("sink", line, _quote(target, 60))],
                        [self.token_detail(job)]))
                    return

    # ---- permissions -------------------------------------------------------------------------

    def permissions(self) -> None:
        untrusted = self.triggers & PRIVILEGED
        workflow = self.workflow
        for permissions, symbol in [(workflow.permissions, "<module>"),
                                    *((job.permissions, f"jobs.{job.name}") for job in workflow.jobs)]:
            if permissions is not None and permissions.kind == "write-all":
                severity: Severity = "medium" if untrusted else "low"
                where = f" on a workflow that {', '.join(sorted(untrusted))} trigger{'s' if len(untrusted) == 1 else ''}" \
                    if untrusted else ""
                self.file.add(Hit("excessive_privileges", "polaris.gha.excessive_privileges.write_all", permissions.line,
                                  f"permissions: write-all gives the job token write access to every scope{where}.",
                                  severity, symbol))
        if not untrusted:
            return
        open_jobs = [job for job in workflow.jobs if not gate(condition(job.condition)).trusted]
        inheriting = [job for job in open_jobs if job.permissions is None]
        if workflow.permissions is not None and workflow.permissions.kind == "map" and inheriting:
            self.broad(workflow.permissions, "<module>", untrusted)
        for job in open_jobs:
            if job.permissions is not None and job.permissions.kind == "map":
                self.broad(job.permissions, f"jobs.{job.name}", untrusted)
        if workflow.permissions is None and inheriting:
            line = self.first_trigger_line(untrusted)
            self.file.add(Hit(
                "excessive_privileges", "polaris.gha.excessive_privileges.default_permissions", line,
                f"This {', '.join(sorted(untrusted))} workflow sets no permissions, so "
                f"{'its jobs get' if len(inheriting) > 1 else 'job ' + inheriting[0].name + ' gets'} the repository's "
                "default token, which can write in older repositories and organizations.", "low"))

    def broad(self, permissions: Permissions, symbol: str, untrusted: set[str]) -> None:
        writes = sorted((line, scope) for scope, (level, line) in permissions.scopes.items()
                        if level == "write" and scope in BROAD_SCOPES)
        if not writes:
            return
        names = ", ".join(f"{scope}: write" for _, scope in writes)
        effects = ", ".join(dict.fromkeys(_SCOPE_EFFECT[scope] for _, scope in writes))
        self.file.add(Hit(
            "excessive_privileges", "polaris.gha.excessive_privileges.untrusted_trigger_write", writes[0][0],
            f"{names} on a workflow that outside events trigger ({', '.join(sorted(untrusted))}): if anything in the "
            f"job is taken over, the token can {effects}.", "low", symbol))

    # ---- unpinned actions and images ---------------------------------------------------------

    def own_repositories(self) -> set[str]:
        """Repositories this workflow names as its own (`if: github.repository == 'owner/name'`)."""
        conditions = [job.condition for job in self.workflow.jobs]
        conditions.extend(item.condition for job in self.workflow.jobs for item in job.steps)
        names: set[str] = set()
        for text in conditions:
            parsed = condition(text)
            for part in _conjuncts(parsed) if parsed is not None else []:
                if part[0] != "cmp" or part[1] != "==":
                    continue
                sides = (part[2], part[3])
                if any(side in (("path", ("github", "repository")),
                                ("path", ("github", "event", "repository", "full_name"))) for side in sides):
                    names.update(literal for side in sides if (literal := _literal(side)) and "/" in literal)
        return names

    def unpinned(self, job: Job) -> None:
        own = self.own_repositories()
        references = [(job.uses, job.uses_node)] + [(item.uses, item.uses_node) for item in job.steps]
        for uses, node in references:
            if not uses or node is None:
                continue
            text = uses.strip()
            if text.startswith(("./", "../")) or "${{" in text:
                continue
            if text.lower().startswith("docker://"):
                image = text[len("docker://"):]
                if not _DIGEST.search(image):
                    self.file.add(Hit("unpinned_dependency", "polaris.gha.unpinned_dependency.image", _line(node),
                                      f"docker://{_quote(image, 80)} is a mutable tag: whoever controls it can change "
                                      "the code this step runs.", "low", f"jobs.{job.name}"))
                continue
            name, separator, ref = text.partition("@")
            if not separator or "/" not in name:
                continue
            if name.split("/", 1)[0].lower() in FIRST_PARTY or _SHA.fullmatch(ref.strip()):
                continue
            if name.lower().startswith(_TAG_ONLY) and _SEMVER.fullmatch(ref.strip()):
                continue
            if "/".join(name.lower().split("/", 2)[:2]) in own:
                continue  # the repository's own reusable workflow or action, not third-party code
            kind = "branch" if ref in ("main", "master", "develop", "dev", "trunk") else "tag"
            self.file.add(Hit("unpinned_dependency", "polaris.gha.unpinned_dependency.action", _line(node),
                              f"{_quote(name, 80)}@{_quote(ref, 40)} is a {kind} its owner can move, so the code this "
                              "job runs (with its token and secrets) can change without a change here.",
                              "low", f"jobs.{job.name}"))
        container = _get(job.node, "container")
        image_node = _get(container, "image") if isinstance(container, yaml.MappingNode) else container
        container_image = _text(image_node)
        if container_image and "${{" not in container_image and not _DIGEST.search(container_image.strip()):
            self.file.add(Hit("unpinned_dependency", "polaris.gha.unpinned_dependency.image", _line(image_node),
                              f"Job container {_quote(container_image, 80)} is a mutable tag: every step of this job "
                              "runs inside whatever image the tag points to.", "low", f"jobs.{job.name}"))

    # ---- scripts: downloads and printed secrets ----------------------------------------------

    def scripts(self, job: Job, item: Step, scopes: list[dict[str, Binding]]) -> None:
        if not isinstance(item.run, yaml.ScalarNode) or not isinstance(item.run.value, str):
            return
        if self.shell(job, item) in ("python", "node", "cmd", "perl", "ruby"):
            return
        script = item.run.value
        masked = script
        spans = expressions(script)
        for start, end, _ in spans:
            masked = masked[:start] + "X" * (end - start) + masked[end:]
        for found in shellwords.remote_scripts(masked):
            if not shellwords.is_remote(found.url):
                continue
            insecure = bool(found.url and re.match(r"(?i)(?:http|ftp)://", found.url))
            line = self.file.value_line(item.run, script, found.start, masked[found.start:found.start + 4])
            target = _quote(found.url, 80) if found.url else "a remote script"
            message = (f"{target} is downloaded and piped into {found.interpreter} without verification"
                       + (" over an unencrypted connection, so anyone on the network path can replace it."
                          if insecure else "; whoever controls that server or URL controls this job."))
            self.file.add(Hit("unverified_download", "polaris.gha.unverified_download.pipe_to_shell", line, message,
                              "high" if insecure else "low", f"jobs.{job.name}",
                              [("source", line, target), ("sink", line, found.interpreter)]))
        secret_names = {binding.name for scope in scopes for binding in scope.values() if self.secret_value(binding)}

        def carries(word: shellwords.Word) -> bool:
            if any(name in secret_names for name in _SECRET_ENV.findall(word.raw)):
                return True
            for start, end, inner in spans:
                if start < word.end and word.start < end:
                    parsed = parse_expression(inner)
                    if parsed is not None and self.secret_expression(parsed, scopes):
                        return True
            return False

        for found_print in shellwords.printed(masked, carries):
            line = self.file.value_line(item.run, script, found_print.start, masked[found_print.start:found_print.start + 4])
            if found_print.transformer:
                message = (f"A secret is printed to the job log through {found_print.transformer}; GitHub masks only "
                           "the exact secret value, so the transformed value is readable by anyone who can see the log.")
                severity: Severity = "high"
            else:
                message = ("A secret is printed to the job log. GitHub masks exact secret values, but masking is "
                           "best-effort (structured or multi-line values, later transformations).")
                severity = "low"
            self.file.add(Hit("secret_exposure", "polaris.gha.secret_exposure.log", line, message, severity,
                              f"jobs.{job.name}"))

    @staticmethod
    def secret_value(binding: Binding) -> bool:
        for _, _, inner in expressions(_text(binding.node) or ""):
            parsed = parse_expression(inner)
            if parsed is not None and any(reference[:1] == ("secrets",) or reference[:2] == ("github", "token")
                                          for reference in _references(parsed)):
                return True
        return False

    def secret_expression(self, node: Ast, scopes: list[dict[str, Binding]]) -> bool:
        for reference in _references(node):
            if reference[:1] == ("secrets",) or reference[:2] == ("github", "token"):
                return True
            if reference[:1] == ("env",) and len(reference) > 1:
                binding = self.binding(reference[1], scopes)
                if binding is not None and self.secret_value(binding):
                    return True
        return False

    # ---- driver ------------------------------------------------------------------------------

    def run(self) -> None:
        workflow = self.workflow
        self.permissions()
        for job in workflow.jobs:
            job_gate = gate(condition(job.condition))
            allowed = set(self.triggers)
            if job_gate.events is not None:
                allowed &= job_gate.events
            self.unpinned(job)

            def scopes_for(item: Step, job: Job = job) -> list[dict[str, Binding]]:
                return [item.env, job.env, workflow.env]

            for item in job.steps:
                step_gate = gate(condition(item.condition))
                step_allowed = allowed & step_gate.events if step_gate.events is not None else allowed
                self.injection(job, item, scopes_for(item), step_allowed)
                self.scripts(job, item, scopes_for(item))
            self.untrusted_checkout(job, allowed, job_gate, scopes_for)
            self.artifacts(job, allowed, job_gate)


# ----------------------------------------------------------------------------------- hardcoded secrets

_SECRET_KEY = re.compile(r"(?i)(?:^|[_-])(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
                         r"private[_-]?key|client[_-]?secret|credentials?)(?:$|[_-])")


def hardcoded(file: _File, root: Any) -> None:
    """Credential formats anywhere in the workflow, and long random literals under secret-named keys."""
    seen: set[int] = set()
    stack: list[tuple[Any, str | None]] = [(root, None)]
    reported: set[int] = set()
    while stack:
        node, key = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            stack.extend((value, name) for name, _, value in _items(node))
            continue
        if isinstance(node, yaml.SequenceNode):
            stack.extend((item, None) for item in node.value)
            continue
        value = _text(node)
        if not value or len(value) > 200_000:
            continue
        for pattern in secrets.PATTERNS:
            if pattern.literals and not any(item in value for item in pattern.literals):
                continue
            for match in pattern.regex.finditer(value):
                literal = match.group(0)
                if secrets.PLACEHOLDER.search(literal) or "${{" in value[max(0, match.start() - 4):match.start()]:
                    continue
                line = file.value_line(node, value, match.start(), literal)
                if line in reported:
                    continue
                reported.add(line)
                file.add(Hit("secret_exposure", "polaris.gha.secret_exposure.hardcoded", line,
                             f"A credential appears to be hardcoded in the workflow ({pattern.label}, "
                             f"{secrets.mask(literal)}).", pattern.severity, secret=literal))
        if (key and _SECRET_KEY.search(key) and not secrets.NON_SECRET_NAMES.search(key) and "${{" not in value
                and 16 <= len(value) <= 200 and not re.search(r"\s", value) and secrets.entropy(value) >= 3.5
                and re.search(r"[0-9]", value) and re.search(r"[A-Za-z]", value)
                and not secrets.PLACEHOLDER.search(value) and not any(p.regex.search(value) for p in secrets.PATTERNS)):
            line = _content_line(node)
            if line not in reported:
                reported.add(line)
                file.add(Hit("secret_exposure", "polaris.gha.secret_exposure.hardcoded", line,
                             f"A long random value is hardcoded under {_quote(key, 60)} ({secrets.mask(value)}).",
                             "medium", confidence="medium", secret=value))


def analyze_workflow(source: SourceFile, checks: set[str]) -> tuple[list[Hit], set[str]]:
    """Hits for one workflow file and the credential values it contains (to mask); raises
    `_Problem` with a fixed reason when the file can't be analyzed."""
    text = source.after or ""
    if len(text) > MAX_BYTES or len(text.encode("utf-8")) > MAX_BYTES:
        raise _Problem("file_too_large")
    root = compose(text)
    file = _File(source, checks)
    try:
        Analysis(file, workflow_model(root)).run()
        hardcoded(file, root)
    except shellwords.ShellLimit:
        raise _Problem("analysis_limit") from None
    file.hits.sort(key=lambda hit: (_RANK[hit.severity], hit.line, hit.rule))
    unique: dict[tuple[int, str], Hit] = {}
    for hit in file.hits:
        unique.setdefault((hit.line, hit.rule), hit)
    return list(unique.values()), file.secrets


class GitHubActionsAnalyzer:
    analyzer_id = ANALYZER_ID

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        checks = [check for check in request.checks if check in CHECKS]
        findings: list[WorkflowFinding] = []
        coverage: list[CheckCoverage] = []
        if not checks:
            return AnalyzerResult(capability=capability())
        for source in request.sources:
            if source.role != "review" or source.skip or source.after is None or language_for_path(source.path) != KIND:
                continue
            status: CoverageStatus = "checked"
            reason = "builtin_rules_completed"
            detected: set[str] = set()
            try:
                hits, detected = analyze_workflow(source, set(checks))
            except _Problem as problem:
                status, reason, hits = "not_checked", problem.reason, []
            except (RecursionError, MemoryError):
                status, reason, hits = "not_checked", "analysis_error", []
            for hit in hits:
                findings.append(mask_values(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                    rule_id=hit.rule, result="flagged", start_line=hit.line, symbol=hit.symbol, message=hit.message,
                    severity=hit.severity, confidence=hit.confidence, reason=hit.reason,
                    trace=[step(kind, line, label) for kind, line, label in hit.trace], details=hit.details,
                    suggested_edit=hit.edit, evidence=request.config.evidence,
                ), detected))
            coverage.extend(CheckCoverage(path=source.path, language=KIND, check_id=check, analyzer_id=ANALYZER_ID,
                                          status=status, reason=reason) for check in checks)
        return AnalyzerResult(findings=tuple(findings), coverage=tuple(coverage), capability=capability())

"""Publish a review plan to a GitHub pull request with the job's token.

Only the repository, pull request and head commit passed by the trusted workflow, never values
inside the plan, choose where anything is written. The plan is validated again, every anchor is
checked against GitHub's own diff of the pull request, and Polaris's hidden state markers are
trusted only in comments written by the configured bot account. Nothing is executed, and the
token is sent only to the configured API origin, never echoed or written anywhere.
"""

from __future__ import annotations

import http.client
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol
from urllib.parse import urlencode, urlsplit

from pydantic import ValidationError

from polaris import __version__
from polaris.errors import PolarisInputError
from polaris.integrations.forge.markdown import (
    SUMMARY_MARKER,
    code,
    escape,
    finding_marker,
    imported_tag,
    is_summary,
    read_finding_marker,
    without_marker,
)
from polaris.integrations.forge.models import (
    MAX_PLAN_BYTES,
    PlannedComment,
    PublishReceipt,
    ReviewPlan,
)
from polaris.jsonio import load_json

API_VERSION = "2022-11-28"
DEFAULT_API = "https://api.github.com"
MAX_RESPONSE_BYTES = 16_000_000
MAX_ERROR_BYTES = 65_536
MAX_PAGES = 30
REVIEW_BATCH = 30
MOVED_LISTED = 20
ORIGINAL_LIMIT = 50_000
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
_THREADS = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes { id isResolved comments(first: 1) { nodes { databaseId } } }
      }
    }
  }
}
"""
_RESOLVE = "mutation($threadId: ID!) { resolveReviewThread(input: {threadId: $threadId}) { thread { id } } }"


class GitHubProblem(Exception):
    """A fixed, credential-free diagnostic code (with the HTTP status when there was one)."""

    def __init__(self, code: str, status: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


class Transport(Protocol):
    def __call__(
        self, method: str, url: str, *, headers: Mapping[str, str], body: bytes | None, timeout: float,
    ) -> HTTPResponse: ...


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could carry the token to another origin: refuse every redirect."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def urllib_transport(
    method: str, url: str, *, headers: Mapping[str, str], body: bytes | None, timeout: float,
) -> HTTPResponse:
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    opener = urllib.request.build_opener(_NoRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            status = int(response.status)
            received = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        data = error.read(MAX_ERROR_BYTES) if error.fp is not None else b""
        status = int(error.code)
        received = {key.lower(): value for key, value in error.headers.items()} if error.headers else {}
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
        raise GitHubProblem("transport_error") from None
    if len(data) > MAX_RESPONSE_BYTES:
        raise GitHubProblem("response_too_large")
    return HTTPResponse(status, received, data)


# The transport used by `polaris pr publish`; tests replace it with an offline double.
TRANSPORT: Transport = urllib_transport


def api_base(value: str | None) -> str:
    url = (value or DEFAULT_API).rstrip("/")
    try:
        parts = urlsplit(url)
        valid = (
            not any(character.isspace() or ord(character) < 32 for character in url)
            and parts.hostname is not None and parts.username is None and parts.password is None
            and not parts.query and not parts.fragment
            and (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in _LOOPBACK))
        )
    except ValueError:
        valid = False
    if not valid:
        raise GitHubProblem("invalid_api_url")
    return url


def graphql_url(api: str) -> str:
    """GitHub.com serves GraphQL at /graphql; GitHub Enterprise Server at /api/graphql."""
    return api[: -len("/v3")] + "/graphql" if api.endswith("/api/v3") else api + "/graphql"


def _status_code(status: int) -> str:
    return {401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
            422: "validation_failed", 429: "rate_limited"}.get(status, "server_error" if status >= 500 else "unexpected_status")


class GitHubClient:
    """Minimal REST/GraphQL client. The token is held privately and never logged or echoed."""

    def __init__(
        self, api_url: str | None, token: str, *, transport: Transport | None = None, timeout: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api = api_base(api_url)
        if (not token or len(token) > 4_096 or not token.isascii() or not token.isprintable()
                or any(character.isspace() for character in token)):
            raise GitHubProblem("invalid_token")
        self._token = token
        self._transport = transport or TRANSPORT
        self._timeout = timeout
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"GitHubClient(api={self.api!r})"

    def _wait(self, response: HTTPResponse, attempt: int) -> float | None:
        if attempt >= 2:
            return None
        limited = response.status == 429 or (response.status == 403 and (
            "retry-after" in response.headers or response.headers.get("x-ratelimit-remaining") == "0"))
        if limited:
            try:
                return float(min(max(int(response.headers.get("retry-after", "5")), 1), 30))
            except ValueError:
                return 5.0
        if response.status in (502, 503, 504) and attempt == 0:
            return 2.0
        return None

    def call(self, method: str, path: str, *, query: Mapping[str, str | int] | None = None,
             body: Any = None, url: str | None = None) -> Any:
        target = url or self.api + path + ("?" + urlencode(query) if query else "")
        payload = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8") if body is not None else None
        headers = {
            "Accept": "application/vnd.github+json", "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": API_VERSION, "User-Agent": f"polaris-pr/{__version__}",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(3):
            response = self._transport(method, target, headers=headers, body=payload, timeout=self._timeout)
            if response.status in (200, 201):
                try:
                    return json.loads(response.body) if response.body else None
                except (ValueError, UnicodeError):
                    raise GitHubProblem("invalid_response", response.status) from None
            if response.status == 204:
                return None
            wait = self._wait(response, attempt)
            if wait is None:
                raise GitHubProblem(_status_code(response.status), response.status)
            self._sleep(wait)
        raise GitHubProblem("rate_limited", 429)

    def paginate(self, path: str, *, per_page: int = 100, max_pages: int = MAX_PAGES) -> list[dict[str, Any]]:
        """Every item, or an error: acting on a partial listing could duplicate or misplace comments."""
        items: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            batch = self.call("GET", path, query={"per_page": per_page, "page": page})
            if not isinstance(batch, list):
                raise GitHubProblem("invalid_response")
            items.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < per_page:
                return items
        raise GitHubProblem("pagination_limit")

    def graphql(self, query: str, variables: Mapping[str, Any]) -> Any:
        data = self.call("POST", "", url=graphql_url(self.api), body={"query": query, "variables": dict(variables)})
        if not isinstance(data, dict) or data.get("errors") or not isinstance(data.get("data"), dict):
            raise GitHubProblem("graphql_error")
        return data["data"]


@dataclass(frozen=True)
class PublishOptions:
    bot_login: str = "github-actions[bot]"
    resolve: bool = True
    dry_run: bool = False

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?", self.bot_login):
            raise GitHubProblem("invalid_bot_login")


@dataclass(frozen=True)
class _Existing:
    comment_id: int
    key: str
    path: str
    body: str


def load_plan(data: bytes) -> ReviewPlan:
    """Validate an untrusted plan file: size, JSON structure (no duplicate keys), then schema."""
    if len(data) > MAX_PLAN_BYTES:
        raise GitHubProblem("plan_too_large")
    try:
        load_json(data, max_bytes=MAX_PLAN_BYTES)
        return ReviewPlan.model_validate_json(data)
    except (PolarisInputError, ValidationError, ValueError, UnicodeError):
        raise GitHubProblem("invalid_plan") from None


def check_binding(plan: ReviewPlan, *, repository: str, pull_request: int, head_sha: str) -> None:
    """The trusted event, not the plan, decides the repository, pull request and commit."""
    if (plan.repository.lower() != repository.lower() or plan.pull_request != pull_request
            or plan.head_sha != head_sha.lower()):
        raise GitHubProblem("plan_mismatch")


def commentable_lines(patch: object) -> frozenset[int]:
    """Right-side lines GitHub shows in a file's patch (added and context lines)."""
    if not isinstance(patch, str):
        return frozenset()
    lines: set[int] = set()
    current = 0
    active = False
    for raw in patch.split("\n"):
        match = _HUNK.match(raw)
        if match:
            current, active = int(match.group(1)), True
            continue
        if not active or raw.startswith(("-", "\\")):
            continue
        if raw.startswith(("+", " ")):
            lines.add(current)
            current += 1
    return frozenset(lines)


def _trusted(item: Mapping[str, Any], bot_login: str) -> bool:
    user = item.get("user")
    return isinstance(user, dict) and user.get("login") == bot_login and user.get("type") == "Bot"


def _comment_body(comment: PlannedComment) -> str:
    return comment.body.rstrip() + "\n\n" + finding_marker(comment.key)


def _review_body(count: int) -> str:
    return (f"Polaris: {count} new finding(s) on changed lines. Coverage, other findings and anything not "
            "reviewed are in the Polaris summary comment.")


def _moved(comments: Sequence[PlannedComment]) -> str:
    if not comments:
        return ""
    lines = ["", "", f"**Not placed inline ({len(comments)}):** GitHub does not show these lines in this pull "
                     "request's diff."]
    for comment in comments[:MOVED_LISTED]:
        lines.append(f"- **{SEVERITY_LABEL[comment.severity]}** · {escape(comment.title, 120)} · "
                     f"{code(f'{comment.path}:{comment.line}', 300)}")
    if len(comments) > MOVED_LISTED:
        lines.append(f"- … and {len(comments) - MOVED_LISTED} more")
    return "\n".join(lines)


def _resolved_body(existing: _Existing, head_sha: str) -> str:
    original = without_marker(existing.body)
    if len(original) > ORIGINAL_LIMIT:
        original = original[:ORIGINAL_LIMIT] + "\n\n_Original comment truncated._"
    if imported_tag(existing.key) is not None:
        status = (f"**Resolved:** the tool that reported this result no longer reports it at {code(head_sha[:12])} "
                  "(imported SARIF; Polaris did not verify it).")
    else:
        status = (f"**Resolved:** Polaris no longer detects this finding at {code(head_sha[:12])} "
                  "(static re-review; tests were not run).")
    return (f"{status}\n\n<details><summary>Original comment</summary>\n\n"
            f"{original}\n\n</details>\n\n{finding_marker(existing.key, 'resolved')}")


def _gone(plan: ReviewPlan) -> Callable[[str, str], bool]:
    """Whether an earlier open comment's finding is no longer reported, so it can be resolved.

    Polaris findings: not detected anymore in a file whose required checks all completed.
    Imported results: not reported anymore by a tool whose SARIF this run imported completely,
    in a file that run covered. A missing, rejected or partial import resolves nothing.
    """
    detected, checked = set(plan.detected_keys), set(plan.checked_paths)
    tools, covered = set(plan.imported_tools), set(plan.imported_paths)

    def gone(key: str, path: str) -> bool:
        if key in detected:
            return False
        tag = imported_tag(key)
        return path in checked if tag is None else tag in tools and path in covered

    return gone


def _post(client: GitHubClient, base: str, number: int, comments: Sequence[PlannedComment],
          head_sha: str) -> tuple[int, list[PlannedComment]]:
    """One review per batch; if GitHub rejects a batch, try each comment alone and keep the rest."""
    posted = 0
    failed: list[PlannedComment] = []
    for start in range(0, len(comments), REVIEW_BATCH):
        batch = list(comments[start:start + REVIEW_BATCH])
        payload = {
            "commit_id": head_sha, "event": "COMMENT", "body": _review_body(len(batch)),
            "comments": [{"path": item.path, "line": item.line, "side": "RIGHT", "body": _comment_body(item)}
                         for item in batch],
        }
        try:
            client.call("POST", f"{base}/pulls/{number}/reviews", body=payload)
            posted += len(batch)
            continue
        except GitHubProblem as problem:
            if problem.code != "validation_failed":
                raise
        for item in batch:
            try:
                client.call("POST", f"{base}/pulls/{number}/comments", body={
                    "body": _comment_body(item), "commit_id": head_sha, "path": item.path,
                    "line": item.line, "side": "RIGHT",
                })
                posted += 1
            except GitHubProblem as problem:
                if problem.code != "validation_failed":
                    raise
                failed.append(item)
    return posted, failed


def _thread_ids(client: GitHubClient, repository: str, number: int) -> dict[int, tuple[str, bool]]:
    owner, name = repository.split("/", 1)
    threads: dict[int, tuple[str, bool]] = {}
    cursor: str | None = None
    for _ in range(10):
        data = client.graphql(_THREADS, {"owner": owner, "name": name, "number": number, "cursor": cursor})
        connection = (((data.get("repository") or {}).get("pullRequest") or {}).get("reviewThreads") or {})
        for node in connection.get("nodes") or []:
            first = ((node.get("comments") or {}).get("nodes") or [{}])[0] if isinstance(node, dict) else {}
            if isinstance(first, dict) and isinstance(first.get("databaseId"), int) and isinstance(node.get("id"), str):
                threads[first["databaseId"]] = (node["id"], bool(node.get("isResolved")))
        page = connection.get("pageInfo") or {}
        if not page.get("hasNextPage") or not isinstance(page.get("endCursor"), str):
            return threads
        cursor = page["endCursor"]
    return threads


def _resolve(client: GitHubClient, base: str, repository: str, number: int, stale: Sequence[_Existing],
             head_sha: str) -> tuple[int, int]:
    resolved = 0
    for item in stale:
        client.call("PATCH", f"{base}/pulls/comments/{item.comment_id}", body={"body": _resolved_body(item, head_sha)})
        resolved += 1
    if not stale:
        return resolved, 0
    try:  # Collapsing the conversation is a convenience; the edited comment already says it is resolved.
        threads = _thread_ids(client, repository, number)
    except GitHubProblem:
        return resolved, len(stale)
    errors = 0
    for item in stale:
        thread = threads.get(item.comment_id)
        if thread is None or thread[1]:
            continue
        try:
            client.graphql(_RESOLVE, {"threadId": thread[0]})
        except GitHubProblem:
            errors += 1
    return resolved, errors


def _summary(
    client: GitHubClient, base: str, number: int, body: str, bot_login: str,
) -> Literal["created", "updated", "unchanged"]:
    comments = client.paginate(f"{base}/issues/{number}/comments")
    current = next((item for item in comments if _trusted(item, bot_login) and is_summary(item.get("body"))), None)
    if current is None:
        client.call("POST", f"{base}/issues/{number}/comments", body={"body": body})
        return "created"
    if current.get("body") == body:
        return "unchanged"
    if not isinstance(current.get("id"), int):
        raise GitHubProblem("invalid_response")
    client.call("PATCH", f"{base}/issues/comments/{current['id']}", body={"body": body})
    return "updated"


def publish(
    plan: ReviewPlan, client: GitHubClient, *, repository: str, pull_request: int, head_sha: str,
    options: PublishOptions | None = None,
) -> PublishReceipt:
    options = options or PublishOptions()
    check_binding(plan, repository=repository, pull_request=pull_request, head_sha=head_sha)
    base = f"/repos/{plan.repository}"
    receipt: dict[str, Any] = {"repository": plan.repository, "pull_request": plan.pull_request,
                               "head_sha": plan.head_sha, "gate": plan.gate}
    pull = client.call("GET", f"{base}/pulls/{pull_request}")
    if not isinstance(pull, dict) or not isinstance(pull.get("head"), dict):
        raise GitHubProblem("invalid_response")
    if pull.get("state") != "open":
        return PublishReceipt(status="not_open", **receipt)
    if pull["head"].get("sha") != plan.head_sha:
        # A newer push is being reviewed by its own run; never attach these results to it.
        return PublishReceipt(status="stale_head", **receipt)
    files = client.paginate(f"{base}/pulls/{pull_request}/files")
    placeable = {item["filename"]: commentable_lines(item.get("patch")) for item in files
                 if isinstance(item.get("filename"), str)}
    existing: dict[str, _Existing] = {}
    for item in client.paginate(f"{base}/pulls/{pull_request}/comments"):
        if not _trusted(item, options.bot_login) or item.get("in_reply_to_id") is not None:
            continue
        marker = read_finding_marker(item.get("body"))
        if (marker is None or marker[1] != "open" or not isinstance(item.get("id"), int)
                or not isinstance(item.get("path"), str)):
            continue
        existing.setdefault(marker[0], _Existing(item["id"], marker[0], item["path"], item["body"]))
    new: list[PlannedComment] = []
    moved: list[PlannedComment] = []
    for comment in plan.comments:
        if comment.key in existing:
            continue
        (new if comment.line in placeable.get(comment.path, frozenset()) else moved).append(comment)
    already = sum(1 for comment in plan.comments if comment.key in existing)
    gone = _gone(plan)
    stale = ([item for key, item in sorted(existing.items()) if gone(key, item.path)]
             if options.resolve and plan.review_status in ("complete", "incomplete") else [])
    if options.dry_run:
        return PublishReceipt(status="dry_run", posted=len(new), already_posted=already,
                              moved_to_summary=len(moved), resolved=len(stale), **receipt)
    posted, failed = _post(client, base, pull_request, new, plan.head_sha)
    moved.extend(failed)
    resolved, thread_errors = _resolve(client, base, plan.repository, pull_request, stale, plan.head_sha)
    summary = plan.summary.rstrip() + _moved(moved) + "\n\n" + SUMMARY_MARKER
    summary_state = _summary(client, base, pull_request, summary, options.bot_login)
    return PublishReceipt(
        status="published", posted=posted, already_posted=already, moved_to_summary=len(moved),
        resolved=resolved, thread_resolution_errors=thread_errors, summary=summary_state, **receipt,
    )

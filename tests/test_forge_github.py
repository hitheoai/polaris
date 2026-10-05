"""Publishing to GitHub against an offline, stateful fake API; no network access or real token."""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from polaris import cli
from polaris.integrations.forge import github
from polaris.integrations.forge.github import (
    GitHubClient,
    GitHubProblem,
    HTTPResponse,
    PublishOptions,
    publish,
)
from polaris.integrations.forge.markdown import SUMMARY_MARKER, finding_marker, read_finding_marker
from polaris.integrations.forge.models import PlanCounts, PlannedComment, ReviewPlan

TOKEN = "ghs_SYNTHETIC0TOKEN0FOR0TESTS0ONLY"  # polaris-ignore[secret_exposure]: synthetic, never a real token
HEAD = "b" * 40
BOT = {"login": "github-actions[bot]", "type": "Bot"}
REPO = "/repos/acme/app"
PATCH = "@@ -1 +1,9 @@\n-export const ok = 1;\n" + "".join(f"+line {number}\n" for number in range(1, 10)).rstrip("\n")
KEY_A, KEY_B, KEY_C = "a1" * 12, "b2" * 12, "c3" * 12


def comment(key: str, line: int, *, path: str = "api/route.ts", severity: str = "high") -> PlannedComment:
    return PlannedComment(key=key, finding_id=key[:20], path=path, line=line, severity=severity,  # type: ignore[arg-type]
                          result="flagged", rule_id="polaris.js.ssrf.request", title="Server-side request forgery",
                          body=f"Finding {key[:6]} body")


def make_plan(comments: list[PlannedComment], *, detected: list[str] | None = None,
              checked: list[str] | None = None, gate: str = "fail", status: str = "complete") -> ReviewPlan:
    return ReviewPlan(
        polaris_version="0.3.3", repository="acme/app", pull_request=7, base_sha="a" * 40, head_sha=HEAD,
        merge_base="a" * 40, report_id="sha256:" + "d" * 64, review_status=status,  # type: ignore[arg-type]
        gate=gate,  # type: ignore[arg-type]
        counts=PlanCounts(issues_in_change=len(comments), questions_in_change=0, lower_severity_in_change=0,
                          existing_in_changed_files=0, inline=len(comments), not_reviewed_files=0,
                          suggestions_verified=0, suggestions_withheld=0),
        comments=comments, detected_keys=sorted(detected if detected is not None else [item.key for item in comments]),
        checked_paths=checked if checked is not None else ["api/route.ts"], summary="### Polaris review\n\nsummary",
    )


class FakeGitHub:
    """Just enough of the REST and GraphQL APIs, keeping state between calls."""

    def __init__(self, *, head: str = HEAD, state: str = "open", files: Mapping[str, str] | None = None) -> None:
        self.head, self.state = head, state
        self.files = dict(files if files is not None else {"api/route.ts": PATCH})
        self.review_comments: list[dict[str, Any]] = []
        self.issue_comments: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str, Any]] = []
        self.reject: set[tuple[str, int]] = set()
        self.resolved_threads: list[str] = []
        self.next_id = 1000

    def add_review_comment(self, path: str, line: int, body: str, user: Mapping[str, str] = BOT,
                           reply_to: int | None = None) -> dict[str, Any]:
        self.next_id += 1
        item = {"id": self.next_id, "path": path, "line": line, "body": body, "user": dict(user),
                "in_reply_to_id": reply_to}
        self.review_comments.append(item)
        return item

    def writes(self) -> list[tuple[str, str, Any]]:
        return [request for request in self.requests if request[0] != "GET" and "reviewThreads" not in str(request[2])]

    def __call__(self, method: str, url: str, *, headers: Mapping[str, str], body: bytes | None,
                 timeout: float) -> HTTPResponse:
        assert headers["Authorization"] == f"Bearer {TOKEN}" and url.startswith("https://api.github.com/")
        parts = urlsplit(url)
        query = parse_qs(parts.query)
        payload = json.loads(body) if body else None
        self.requests.append((method, parts.path, payload))

        def ok(value: Any, status: int = 200) -> HTTPResponse:
            return HTTPResponse(status, {}, json.dumps(value).encode())

        def page(items: list[dict[str, Any]]) -> HTTPResponse:
            size, number = int(query["per_page"][0]), int(query["page"][0])
            return ok(items[(number - 1) * size:number * size])

        route = (method, parts.path)
        if route == ("GET", f"{REPO}/pulls/7"):
            return ok({"state": self.state, "head": {"sha": self.head}})
        if route == ("GET", f"{REPO}/pulls/7/files"):
            return page([{"filename": name, "patch": patch} for name, patch in self.files.items()])
        if route == ("GET", f"{REPO}/pulls/7/comments"):
            return page(self.review_comments)
        if route == ("GET", f"{REPO}/issues/7/comments"):
            return page(self.issue_comments)
        if route == ("POST", f"{REPO}/pulls/7/reviews"):
            assert payload["commit_id"] == HEAD and payload["event"] == "COMMENT"
            if any((item["path"], item["line"]) in self.reject for item in payload["comments"]):
                return HTTPResponse(422, {}, b'{"message": "Validation Failed"}')
            for item in payload["comments"]:
                assert item["side"] == "RIGHT"
                self.add_review_comment(item["path"], item["line"], item["body"])
            return ok({"id": 1})
        if route == ("POST", f"{REPO}/pulls/7/comments"):
            if (payload["path"], payload["line"]) in self.reject:
                return HTTPResponse(422, {}, b"{}")
            return ok(self.add_review_comment(payload["path"], payload["line"], payload["body"]), 201)
        if method == "PATCH" and parts.path.startswith(f"{REPO}/pulls/comments/"):
            target = next(item for item in self.review_comments if item["id"] == int(parts.path.rsplit("/", 1)[1]))
            target["body"] = payload["body"]
            return ok(target)
        if route == ("POST", f"{REPO}/issues/7/comments"):
            self.next_id += 1
            self.issue_comments.append({"id": self.next_id, "user": dict(BOT), "body": payload["body"]})
            return ok(self.issue_comments[-1], 201)
        if method == "PATCH" and parts.path.startswith(f"{REPO}/issues/comments/"):
            target = next(item for item in self.issue_comments if item["id"] == int(parts.path.rsplit("/", 1)[1]))
            target["body"] = payload["body"]
            return ok(target)
        if route == ("POST", "/graphql"):
            if "reviewThreads" in payload["query"]:
                nodes = [{"id": f"T{item['id']}", "isResolved": False, "comments": {"nodes": [{"databaseId": item["id"]}]}}
                         for item in self.review_comments]
                return ok({"data": {"repository": {"pullRequest": {"reviewThreads": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": nodes}}}}})
            self.resolved_threads.append(payload["variables"]["threadId"])
            return ok({"data": {"resolveReviewThread": {"thread": {"id": payload["variables"]["threadId"]}}}})
        return HTTPResponse(404, {}, b"")


def run(plan: ReviewPlan, fake: FakeGitHub, **options: Any) -> Any:
    client = GitHubClient("https://api.github.com", TOKEN, transport=fake, sleep=lambda _: None)
    return publish(plan, client, repository="acme/app", pull_request=7, head_sha=HEAD,
                   options=PublishOptions(**options))


def test_first_publish_posts_one_review_and_one_summary():
    fake = FakeGitHub()
    receipt = run(make_plan([comment(KEY_A, 3), comment(KEY_B, 50)]), fake)
    assert (receipt.status, receipt.posted, receipt.moved_to_summary, receipt.summary) == ("published", 1, 1, "created")
    reviews = [request for request in fake.requests if request[1].endswith("/reviews")]
    assert len(reviews) == 1 and [item["line"] for item in reviews[0][2]["comments"]] == [3]
    assert read_finding_marker(fake.review_comments[0]["body"]) == (KEY_A, "open")
    (summary,) = fake.issue_comments
    assert summary["body"].endswith(SUMMARY_MARKER) and "Not placed inline (1)" in summary["body"]
    assert "`api/route.ts:50`" in summary["body"]


def test_republishing_the_same_plan_is_idempotent():
    fake = FakeGitHub()
    plan = make_plan([comment(KEY_A, 3)])
    run(plan, fake)
    second = run(plan, fake)
    assert (second.posted, second.already_posted, second.summary) == (0, 1, "unchanged")
    assert len(fake.review_comments) == 1 and len(fake.issue_comments) == 1


def test_markers_written_by_other_accounts_or_mid_comment_are_not_state():
    fake = FakeGitHub()
    fake.add_review_comment("api/route.ts", 3, "lgtm\n\n" + finding_marker(KEY_A), user={"login": "mallory", "type": "User"})
    fake.add_review_comment("api/route.ts", 3, finding_marker(KEY_A) + "\nedited later", user=BOT)
    fake.add_review_comment("api/route.ts", 3, "reply\n\n" + finding_marker(KEY_A), user=BOT, reply_to=1)
    fake.issue_comments.append({"id": 1, "user": {"login": "mallory", "type": "User"}, "body": "fake\n\n" + SUMMARY_MARKER})
    receipt = run(make_plan([comment(KEY_A, 3)]), fake)
    assert receipt.posted == 1 and receipt.already_posted == 0 and receipt.summary == "created"
    assert fake.issue_comments[0]["body"].startswith("fake"), "another account's comment is never edited"


def test_findings_no_longer_detected_are_resolved_only_in_fully_checked_files():
    fake = FakeGitHub()
    fixed = fake.add_review_comment("api/route.ts", 3, "old finding\n\n" + finding_marker(KEY_A))
    elsewhere = fake.add_review_comment("app/other.ts", 4, "unchecked file\n\n" + finding_marker(KEY_B))
    still = fake.add_review_comment("api/route.ts", 5, "still detected\n\n" + finding_marker(KEY_C))
    receipt = run(make_plan([], detected=[KEY_C], checked=["api/route.ts"], gate="pass"), fake)
    assert receipt.resolved == 1 and receipt.thread_resolution_errors == 0
    assert fixed["body"].startswith("**Resolved:**") and read_finding_marker(fixed["body"]) == (KEY_A, "resolved")
    assert "old finding" in fixed["body"] and fake.resolved_threads == [f"T{fixed['id']}"]
    assert read_finding_marker(elsewhere["body"]) == (KEY_B, "open")
    assert read_finding_marker(still["body"]) == (KEY_C, "open")
    # Resolved comments are no longer state: the same finding reappearing gets a new comment.
    again = run(make_plan([comment(KEY_A, 3)]), fake)
    assert again.posted == 1


def test_stale_or_errored_reviews_never_resolve_anything():
    fake = FakeGitHub()
    fake.add_review_comment("api/route.ts", 3, "old\n\n" + finding_marker(KEY_A))
    for status in ("stale", "error"):
        receipt = run(make_plan([], detected=[], gate="incomplete", status=status), fake)
        assert receipt.resolved == 0
    assert run(make_plan([], detected=[], gate="pass"), fake, resolve=False).resolved == 0


@pytest.mark.parametrize("head,state,expected", [("c" * 40, "open", "stale_head"), (HEAD, "closed", "not_open")])
def test_moved_or_closed_pull_requests_get_no_writes(head, state, expected):
    fake = FakeGitHub(head=head, state=state)
    receipt = run(make_plan([comment(KEY_A, 3)]), fake)
    assert receipt.status == expected and receipt.posted == 0 and fake.writes() == []


def test_a_rejected_batch_falls_back_to_single_comments():
    fake = FakeGitHub()
    fake.reject.add(("api/route.ts", 4))
    receipt = run(make_plan([comment(KEY_A, 3), comment(KEY_B, 4)]), fake)
    assert (receipt.posted, receipt.moved_to_summary) == (1, 1)
    assert [read_finding_marker(item["body"]) for item in fake.review_comments] == [(KEY_A, "open")]
    assert "`api/route.ts:4`" in fake.issue_comments[0]["body"]


def test_dry_run_reads_but_never_writes():
    fake = FakeGitHub()
    receipt = run(make_plan([comment(KEY_A, 3), comment(KEY_B, 60)]), fake, dry_run=True)
    assert (receipt.status, receipt.posted, receipt.moved_to_summary) == ("dry_run", 1, 1)
    assert fake.writes() == []


@pytest.mark.parametrize("repository,number,head", [("acme/other", 7, HEAD), ("acme/app", 8, HEAD),
                                                    ("acme/app", 7, "c" * 40)])
def test_the_trusted_event_not_the_plan_chooses_the_target(repository, number, head):
    fake = FakeGitHub()
    client = GitHubClient(None, TOKEN, transport=fake)
    with pytest.raises(GitHubProblem, match="plan_mismatch"):
        publish(make_plan([comment(KEY_A, 3)]), client, repository=repository, pull_request=number, head_sha=head)
    assert fake.requests == []


def test_untrusted_plan_files_are_validated_before_use():
    good = make_plan([comment(KEY_A, 3)]).model_dump_json().encode()
    assert github.load_plan(good).comments[0].key == KEY_A
    duplicate = b'{"format": "polaris.pr-plan/0.1.0", "format": "polaris.pr-plan/0.1.0"}'
    tampered = good.replace(b"Finding", b"<!-- polaris:summary v1 --> Finding")
    for data, code in ((duplicate, "invalid_plan"), (tampered, "invalid_plan"), (b"x" * 4_000_001, "plan_too_large"),
                       (b"\xff", "invalid_plan")):
        with pytest.raises(GitHubProblem) as caught:
            github.load_plan(data)
        assert caught.value.code == code


def test_patches_define_which_lines_can_hold_comments():
    patch = "@@ -1,3 +1,4 @@\n context\n-removed\n+added\n+added too\n context\n@@ -20 +21,2 @@\n-x\n+y\n+z"
    assert github.commentable_lines(patch) == frozenset({1, 2, 3, 4, 21, 22})
    assert github.commentable_lines(None) == frozenset() and github.commentable_lines("Binary files differ") == frozenset()


def test_api_origins_tokens_and_bot_names_are_validated():
    assert github.api_base(None) == "https://api.github.com"
    assert github.api_base("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert github.graphql_url("https://ghe.example/api/v3") == "https://ghe.example/api/graphql"
    for bad in ("http://example.com", "https://user:pw@example.com", "https://example.com?x=1", "ftp://example.com"):
        with pytest.raises(GitHubProblem, match="invalid_api_url"):
            github.api_base(bad)
    for bad in ("", "has space", "line\nbreak", "x" * 4_097, "tökén"):
        with pytest.raises(GitHubProblem, match="invalid_token"):
            GitHubClient(None, bad)
    assert TOKEN not in repr(GitHubClient(None, TOKEN))
    with pytest.raises(GitHubProblem, match="invalid_bot_login"):
        PublishOptions(bot_login="evil login")


def test_rate_limits_are_retried_with_bounded_waits():
    calls: list[int] = []
    waits: list[float] = []

    def transport(method: str, url: str, *, headers: Mapping[str, str], body: bytes | None,
                  timeout: float) -> HTTPResponse:
        calls.append(1)
        if len(calls) == 1:
            return HTTPResponse(429, {"retry-after": "600"}, b"")
        return HTTPResponse(200, {}, b'{"ok": true}')

    client = GitHubClient(None, TOKEN, transport=transport, sleep=waits.append)
    assert client.call("GET", "/rate") == {"ok": True} and waits == [30.0]
    forbidden = GitHubClient(None, TOKEN, transport=lambda *a, **k: HTTPResponse(403, {}, b""), sleep=waits.append)
    with pytest.raises(GitHubProblem) as caught:
        forbidden.call("GET", "/x")
    assert caught.value.code == "forbidden" and caught.value.status == 403


def test_redirects_are_never_followed_so_the_token_cannot_move(monkeypatch):
    received: list[str | None] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            received.append(self.headers.get("Authorization"))
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/steal")
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("NO_PROXY", "*")
        client = GitHubClient(f"http://127.0.0.1:{server.server_port}", TOKEN)
        with pytest.raises(GitHubProblem) as caught:
            client.call("GET", "/repos/acme/app")
        assert caught.value.status == 302 and len(received) == 1
    finally:
        thread.join(timeout=5)
        server.server_close()


def test_cli_publishes_with_the_environment_token_and_never_prints_it(tmp_path, monkeypatch, capsys):
    plan_path = tmp_path.resolve() / "plan.json"  # plan files are read without following symlinks
    plan_path.write_text(make_plan([comment(KEY_A, 3)]).model_dump_json())
    fake = FakeGitHub()
    monkeypatch.setattr(github, "TRANSPORT", fake)
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    arguments = ["pr", "publish", "--plan", str(plan_path), "--repository", "acme/app", "--pr", "7", "--head", HEAD]
    assert cli.main(arguments) == 1, "a failing gate fails the job by default"
    captured = capsys.readouterr()
    receipt = json.loads(captured.out)
    assert receipt["format"] == "polaris.pr-publish/0.1.0" and receipt["posted"] == 1
    assert TOKEN not in captured.out + captured.err
    assert cli.main([*arguments, "--fail-on", "never"]) == 0
    capsys.readouterr()
    monkeypatch.delenv("GITHUB_TOKEN")
    assert cli.main(arguments) == 2 and json.loads(capsys.readouterr().out)["code"] == "missing_token"
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    assert cli.main([*arguments[:-1], "c" * 40]) == 2
    error = capsys.readouterr().out
    assert json.loads(error)["code"] == "plan_mismatch" and TOKEN not in error


def test_cli_incomplete_reviews_fail_only_when_requested(tmp_path, monkeypatch, capsys):
    plan_path = tmp_path.resolve() / "plan.json"
    plan_path.write_text(make_plan([], detected=[], gate="incomplete", status="incomplete").model_dump_json())
    monkeypatch.setattr(github, "TRANSPORT", FakeGitHub())
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    arguments = ["pr", "publish", "--plan", str(plan_path), "--repository", "acme/app", "--pr", "7", "--head", HEAD]
    assert cli.main(arguments) == 0
    assert cli.main([*arguments, "--fail-on", "incomplete"]) == 2
    capsys.readouterr()

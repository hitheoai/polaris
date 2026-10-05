"""The hosted model (remote mode). A scripted model stands in for the real one: software only.

The central guarantee is checked on the wire: the server records every byte it receives, and code
from functions without SQL or process calls must never appear in it.
"""

import io
import json
import socket
import stat
import threading
import time
from dataclasses import dataclass, field

import pytest
from review_helpers import ScriptedBackend

import polaris.remote as remote
from polaris.api.security import KeyStore, new_key
from polaris.cli import main
from polaris.client import PolarisAPIError
from polaris.fixtures import sample_request
from polaris.integrations import ModelUnavailable, ReviewService
from polaris.remote import (
    BATCH_BYTES,
    Credentials,
    RemoteBackend,
    RemoteUnavailable,
    _chunks,
    connect,
    delete_credentials,
    load_credentials,
    save_credentials,
    use_remote,
)
from polaris.review import Reviewer, SourceFile

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from polaris.api.app import ApiSettings, create_app  # noqa: E402
from polaris.api.models import ModelsResponse  # noqa: E402

SECRET = "zz_never_sent_77"
HEADER = "import os, subprocess\nfrom flask import request\n\n"
CODE = HEADER + (
    "def risky(db, v):\n    # RISKY\n    return db.execute(f'SELECT {v}')\n\n\n"
    "def unsure(db, v):\n    # UNSURE\n    return db.execute(f'SELECT {v}')\n\n\n"
    f"def quiet(x):\n    token = '{SECRET}'\n    return x + len(token)\n\n\n"
    "def ping(host):\n    os.system('ping -c 1 ' + host)\n"
)


def free_port():
    while True:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port not in (8765, 8766, 3025, 3107):
            return port


@dataclass
class Hosted:
    url: str
    key: str
    key_id: str
    received: list[tuple[str, str, bytes]] = field(default_factory=list)

    def bodies(self) -> bytes:
        return b"".join(body for _, _, body in self.received)

    def posts(self) -> list[str]:
        return [path for method, path, _ in self.received if method == "POST"]


def recording(app, log):
    """Wrap an ASGI app and keep (method, path, raw body) of every request it receives."""

    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        chunks = []

        async def spy():
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
            return message

        try:
            await app(scope, spy, send)
        finally:
            log.append((scope["method"], scope["path"], b"".join(chunks)))

    return wrapped


@pytest.fixture
def hosted():
    import uvicorn

    port = free_port()
    raw, record = new_key("remote-test")
    log: list[tuple[str, str, bytes]] = []
    app = create_app(ReviewService(ScriptedBackend()), settings=ApiSettings(port=port), keys=KeyStore([record]))
    server = uvicorn.Server(uvicorn.Config(recording(app, log), host="127.0.0.1", port=port,
                                           log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    yield Hosted(f"http://127.0.0.1:{port}", raw, record.key_id, log)
    server.should_exit = True
    thread.join(15)


@pytest.fixture
def signed_in(hosted, monkeypatch):
    monkeypatch.setenv("POLARIS_API_KEY", hosted.key)
    monkeypatch.setenv("POLARIS_API_URL", hosted.url)
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    return hosted


def comparable(report):
    return ([finding.model_dump(mode="json") for finding in report.findings], report.summary.results,
            report.model.model_dump(mode="json"), report.summary.units_prefiltered)


@pytest.mark.parametrize("engine", ["hybrid", "model"])
def test_hosted_reviews_match_local_ones_and_send_only_candidate_functions(signed_in, engine):
    sources = [SourceFile("svc/db.py", CODE)]
    local = Reviewer(ScriptedBackend(), engine=engine).review_sources(sources)
    remote = Reviewer(connect(), engine=engine).review_sources(sources)
    assert comparable(remote) == comparable(local)
    assert remote.summary.units_prefiltered == 1 and remote.summary.units_assessed == 3
    assert any("ran on the Polaris API" in notice for notice in remote.notices)
    assert not any("ran on the Polaris API" in notice for notice in local.notices)
    # On the wire: one model lookup, then only assessment batches with the three candidate functions.
    assert [path for _, path, _ in signed_in.received] == ["/v1/models", "/v1/assess/batch"]
    sent = json.loads(signed_in.received[-1][2])["requests"]
    assert len(sent) == 3
    assert {item["evidence"][0]["location"]["path"] for item in sent} == {"svc/db.py"}
    assert SECRET.encode() not in signed_in.bodies() and b"def quiet" not in signed_in.bodies()
    assert b"def risky" in signed_in.bodies() and b"def ping" in signed_in.bodies()


def test_nothing_is_sent_when_no_function_has_sql_or_process_calls(signed_in):
    report = Reviewer(connect(), engine="hybrid").review_snippet(f"def quiet(x):\n    return '{SECRET}'\n")
    assert report.summary.units_assessed == 0 and report.findings == []
    assert signed_in.posts() == [] and SECRET.encode() not in signed_in.bodies()


def test_cli_uses_the_hosted_model_when_signed_in_and_local_keeps_everything_here(
        signed_in, tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(CODE)
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "home"))
    base = ["review", "--files", "app.py", "--root", str(tmp_path), "--format", "json", "--no-cache"]
    assert main(base) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["model"]["model_version"] == "scripted-test" and report["model"]["engine"] == "hybrid"
    assert any("ran on the Polaris API" in notice for notice in report["notices"])
    posts = len(signed_in.posts())
    assert posts == 1
    assert main([*base, "--model-source", "local"]) == 1
    local = json.loads(capsys.readouterr().out)
    assert local["model"]["engine"] == "rules" and len(signed_in.posts()) == posts
    assert main(["scan", str(tmp_path), "--root", str(tmp_path), "--quiet", "--no-cache", "--engine", "model",
                 "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["model"]["engine"] == "model"
    assert SECRET.encode() not in signed_in.bodies()


def test_review_cache_skips_functions_the_hosted_model_already_assessed(signed_in, tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(CODE)
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "home"))
    base = ["review", "--files", "app.py", "--root", str(tmp_path), "--format", "json"]
    assert main(base) == 1 and main(base) == 1
    capsys.readouterr()
    assert signed_in.posts() == ["/v1/assess/batch"]


def test_model_source_resolution(monkeypatch, tmp_path):
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    assert not use_remote("auto") and use_remote("remote") and not use_remote("local")
    with pytest.raises(RemoteUnavailable) as missing:
        connect()
    assert missing.value.problem == "not_signed_in" and "polaris login" in str(missing.value)
    monkeypatch.setenv("POLARIS_API_KEY", "plk_test_key")
    assert use_remote("auto") and not use_remote("local")
    assert not use_remote("auto", str(tmp_path)), "an explicit --model folder means local"
    monkeypatch.setenv("POLARIS_MODEL", str(tmp_path))
    assert not use_remote("auto") and use_remote("remote")


def test_not_signed_in_follows_the_no_model_choice(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(CODE)
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "home"))
    base = ["review", "--files", "app.py", "--root", str(tmp_path), "--model-source", "remote", "--no-cache"]
    assert main([*base, "--format", "json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert "Not signed in" in captured.err and report["model"]["engine"] == "rules"
    assert any("Not signed in" in notice for notice in report["notices"])
    assert not any("No Polaris model is installed" in notice for notice in report["notices"])
    assert main([*base, "--engine", "model"]) == 3
    assert "polaris login" in capsys.readouterr().err
    assert main([*base, "--engine", "model", "--no-model", "skip"]) == 0
    assert "NOT reviewed" in capsys.readouterr().err
    assert main([*base, "--engine", "model", "--no-model", "rules"]) == 1
    assert "static rules instead" in capsys.readouterr().err


def test_credentials_are_private_and_the_environment_wins(monkeypatch, tmp_path):
    assert load_credentials() is None
    path = save_credentials("https://api.example", "plk_saved_secret")
    assert path == remote.credentials_path() and stat.S_IMODE(path.stat().st_mode) == 0o600
    saved = load_credentials()
    assert saved == Credentials("https://api.example", "plk_saved_secret", "file")
    assert "plk_saved_secret" not in repr(saved)
    monkeypatch.setenv("POLARIS_API_KEY", "plk_env_secret")
    assert load_credentials() == Credentials("https://api.polaris.theovex.com", "plk_env_secret", "environment")
    monkeypatch.setenv("POLARIS_API_URL", "https://other.example")
    assert load_credentials().api_url == "https://other.example"
    monkeypatch.delenv("POLARIS_API_KEY")
    assert delete_credentials() and load_credentials() is None and not delete_credentials()
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"api_key": "plk_linked"}))
    path.symlink_to(target)
    assert load_credentials() is None, "a symlinked credentials file is ignored"
    with pytest.raises(OSError, match="symbolic link"):
        save_credentials("https://api.example", "plk_new")
    path.unlink()
    path.write_text("not json")
    assert load_credentials() is None


def test_login_whoami_and_logout(hosted, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("plk_wrong_key\n"))
    assert main(["login", "--api-url", hosted.url, "--key-stdin"]) == 1
    assert "didn't accept" in capsys.readouterr().err and load_credentials() is None
    monkeypatch.setattr("sys.stdin", io.StringIO(hosted.key + "\n"))
    assert main(["login", "--api-url", hosted.url, "--key-stdin"]) == 0
    out = capsys.readouterr().out
    assert f"key {hosted.key_id}" in out and "scripted-test" in out and hosted.key not in out
    assert load_credentials() == Credentials(hosted.url, hosted.key, "file")
    assert stat.S_IMODE(remote.credentials_path().stat().st_mode) == 0o600
    assert main(["whoami"]) == 0
    out = capsys.readouterr().out
    assert hosted.key_id in out and hosted.url in out and hosted.key not in out
    assert main(["logout"]) == 0 and "Signed out" in capsys.readouterr().out
    assert main(["whoami"]) == 1 and "Not signed in" in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin", io.StringIO("two words\n"))
    assert main(["login", "--api-url", hosted.url, "--key-stdin"]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO(hosted.key + "\n"))
    assert main(["login", "--api-url", "http://polaris.example", "--key-stdin"]) == 2
    assert "https" in capsys.readouterr().err


def test_service_uses_the_hosted_model_for_editors_and_explains_problems(signed_in, monkeypatch, tmp_path):
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "home"))
    service = ReviewService.load(source="auto")
    status = service.model_status()
    assert service.remote and status.source == "remote" and "runs on the Polaris API" in status.message
    assert status.flag_thresholds == {"command_injection": 0.5, "sql_injection": 0.5}
    envelope = service.assess(sample_request())
    assert envelope.kind == "assessment" and envelope.runtime.model_version == "scripted-test"
    batch = service.assess_batch([sample_request(), {"contract_version": "polaris.assessment/0.1.0"}])
    assert [item.kind for item in batch] == ["assessment", "error"]
    report = service.run("hybrid", lambda: service.reviewer("hybrid").review_snippet(CODE))
    assert report.model.model_version == "scripted-test"
    monkeypatch.setenv("POLARIS_API_KEY", "plk_revoked")
    refused = ReviewService.load(source="auto")
    assert not refused.remote and refused.problem == "remote_unavailable"
    assert "didn't accept your API key" in refused.model_status().message
    with pytest.raises(ModelUnavailable, match="didn't accept your API key"):
        refused.reviewer("model")
    notices = refused.reviewer("hybrid").review_snippet(CODE).notices
    assert any("didn't accept your API key" in notice and "static rules reviewed this alone" in notice
               for notice in notices)
    monkeypatch.delenv("POLARIS_API_KEY")
    local = ReviewService.load(source="auto")
    assert local.problem == "no_model" and not local.remote


def test_the_server_reports_flag_thresholds_and_identity(signed_in):
    status = RemoteBackend(Credentials(signed_in.url, signed_in.key)).client.models().model
    assert status.source == "local" and status.identity is not None
    assert status.identity.model_version == "scripted-test"
    assert status.flag_thresholds == {"command_injection": 0.5, "sql_injection": 0.5}


def batch_client(service=None):
    app = create_app(service or ReviewService(ScriptedBackend()), settings=ApiSettings(port=18781))
    return TestClient(app, base_url="http://127.0.0.1:18781")


def test_batch_endpoint_answers_each_request_and_counts_usage():
    client = batch_client()
    body = {"requests": [sample_request(), sample_request("command_injection"),
                         {"contract_version": "polaris.assessment/0.1.0"}]}
    response = client.post("/v1/assess/batch", json=body)
    assert response.status_code == 200
    results = response.json()["results"]
    assert [item["kind"] for item in results] == ["assessment", "assessment", "error"]
    assert results[2]["code"] == "invalid_input"
    assert client.get("/v1/usage").json()["usage"]["assessments"] == 3
    for count in (0, 65):
        refused = client.post("/v1/assess/batch", json={"requests": [sample_request()] * count})
        assert refused.status_code == 422 and refused.json()["code"] == "invalid_request"
    missing = batch_client(ReviewService()).post("/v1/assess/batch", json={"requests": [sample_request()]})
    assert missing.status_code == 503 and missing.json()["code"] == "model_unavailable"


class FakeClient:
    """Stands in for PolarisClient: answers from a scripted model, after scripted failures."""

    def __init__(self, failures=(), *, loaded=True, short=False):
        self.service = ReviewService(ScriptedBackend() if loaded else None)
        self.failures = list(failures)
        self.short = short
        self.chunks: list[int] = []

    def models(self):
        return ModelsResponse(model=self.service.model_status(), engines=[])

    def assess_batch(self, chunk):
        self.chunks.append(len(chunk))
        if self.failures:
            raise self.failures.pop(0)
        results = self.service.assess_batch(chunk)
        return results[:-1] if self.short else results


def backend_with(client):
    return RemoteBackend(Credentials("https://api.example", "plk_test"), client=client)


def test_retries_honor_retry_after_then_give_up_with_error_envelopes(monkeypatch):
    waits = []
    monkeypatch.setattr("polaris.remote.time.sleep", waits.append)
    busy = [PolarisAPIError(429, "rate_limited", "Slow down.", retryable=True, retry_after=2.0),
            PolarisAPIError(503, "queue_full", "Busy.", retryable=True)]
    client = FakeClient(busy)
    results = backend_with(client).assess_many([sample_request()])
    assert [item.kind for item in results] == ["assessment"] and waits == [2.0, 2.0] and client.chunks == [1, 1, 1]
    stuck = FakeClient([PolarisAPIError(429, "rate_limited", "Slow down.", retryable=True)] * 3)
    failed = backend_with(stuck).assess_many([sample_request()])
    assert failed[0].kind == "error" and failed[0].retryable and "Slow down." in failed[0].message
    assert failed[0].request_id == sample_request()["request_id"] and len(stuck.chunks) == 3


def test_an_unreachable_api_fails_fast_and_recovers():
    client = FakeClient([PolarisAPIError(0, "connection_failed", "Couldn't reach Polaris.")])
    backend = backend_with(client)
    first = backend.assess_many([sample_request()])
    second = backend.assess_many([sample_request()])
    assert first[0].kind == second[0].kind == "error" and client.chunks == [1]
    assert "a moment ago" in second[0].message
    backend._paused_until = 0.0
    assert backend.assess_many([sample_request()])[0].kind == "assessment" and client.chunks == [1, 1]


def test_invalid_requests_are_answered_locally_and_bad_responses_become_errors():
    client = FakeClient()
    results = backend_with(client).assess_many([{"contract_version": "polaris.assessment/0.1.0"}, sample_request()])
    assert [item.kind for item in results] == ["error", "assessment"] and client.chunks == [1]
    assert results[0].code == "invalid_input"
    short = backend_with(FakeClient(short=True)).assess_many([sample_request(), sample_request("command_injection")])
    assert all(item.kind == "error" and "wrong number" in item.message for item in short)


def test_batches_are_bounded_by_count_and_size():
    small = [(index, {"x": "a" * 10}) for index in range(70)]
    assert [len(chunk) for chunk in _chunks(small)] == [32, 32, 6]
    large = [(index, {"x": "a" * 800_000}) for index in range(5)]
    chunks = _chunks(large)
    assert [len(chunk) for chunk in chunks] == [2, 2, 1]
    assert all(sum(len(json.dumps(item)) for _, item in chunk) <= BATCH_BYTES for chunk in chunks)
    assert [index for chunk in chunks for index, _ in chunk] == list(range(5))


def test_unusable_servers_are_explained():
    with pytest.raises(RemoteUnavailable, match="has no model right now"):
        backend_with(FakeClient(loaded=False))

    class NotPolaris(FakeClient):
        def models(self):
            return ModelsResponse.model_validate({"unexpected": True})

    with pytest.raises(RemoteUnavailable, match="didn't answer like a Polaris API"):
        backend_with(NotPolaris())
    with pytest.raises(RemoteUnavailable, match="https"):
        RemoteBackend(Credentials("http://polaris.example", "plk_test"))

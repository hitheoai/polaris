"""REST API tests. Scripted and fake models exercise software only, never review quality."""

import hashlib
import json
import logging
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
import time
from pathlib import Path

import anyio
import pytest
from review_helpers import ScriptedBackend

from polaris import __version__
from polaris.api.security import (
    KeyFile,
    KeyStore,
    QueueFull,
    RateLimiter,
    WorkQueue,
    new_key,
    write_key_file,
)
from polaris.cli import main
from polaris.fixtures import sample_request
from polaris.integrations import ReviewService

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from polaris.api.app import ApiSettings, create_app, openapi_document  # noqa: E402
from polaris.client import PolarisAPIError, PolarisClient  # noqa: E402

PORT = 18780
BASE = f"http://127.0.0.1:{PORT}"
ROOT = Path(__file__).resolve().parents[1]
MARKER = "zz_private_code_marker_91"
HEADER = "import os, subprocess\nfrom flask import request\n\n"
SHELL = HEADER + "def ping(host):\n    os.system('ping -c 1 ' + host)\n"
SCRIPTED = HEADER + (
    "def risky(db, v):\n    # RISKY\n    return db.execute(f'SELECT {v}')\n\n\n"
    "def unsure(db, v):\n    # UNSURE\n    return db.execute(f'SELECT {v}')\n\n\n"
    "def quiet(x):\n    return x + 1\n"
)
DIFF = ("--- a/svc.py\n+++ b/svc.py\n@@ -40,2 +40,3 @@\n def run(host):\n-    pass\n"
        "+    import os\n+    os.system('ping ' + host)\n")


def client_for(service=None, *, keys=None, base_url=BASE, **settings):
    app = create_app(service or ReviewService(), settings=ApiSettings(port=PORT, **settings), keys=keys)
    return TestClient(app, base_url=base_url)


def bearer(raw):
    return {"Authorization": f"Bearer {raw}"}


def free_port():
    while True:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port not in (8765, 8766):
            return port


def test_without_a_model_health_and_models_say_so_and_rules_still_work():
    client = client_for()
    assert client.get("/health").json() == {
        "status": "ok", "version": __version__, "model_loaded": False, "api_keys_required": False}
    models = client.get("/v1/models").json()
    assert models["model"]["loaded"] is False and "polaris model pull" in models["model"]["message"]
    assert [(item["engine"], item["available"]) for item in models["engines"]] == [
        ("hybrid", True), ("model", False), ("rules", True)]
    refused = client.post("/v1/review", json={"code": SHELL, "engine": "model"})
    assert refused.status_code == 503 and refused.json()["code"] == "model_unavailable"
    assert 'engine "rules"' in refused.json()["message"]
    default = client.post("/v1/review", json={"code": SHELL}).json()
    assert default["model"]["engine"] == "rules" and default["summary"]["results"]["flagged"] == 1
    assert any("No Polaris model is installed" in notice for notice in default["notices"])
    report = client.post("/v1/review", json={"code": SHELL, "path": "net/ping.py", "engine": "rules"}).json()
    assert report["format"] == "polaris.review/0.1.0" and report["model"]["engine"] == "rules"
    assert [(f["path"], f["result"], f["check_id"]) for f in report["findings"]] == [
        ("net/ping.py", "flagged", "command_injection")]
    capabilities = client.get("/v1/capabilities").json()
    assert capabilities["checks"] == ["sql_injection", "command_injection"]
    assert capabilities["limits"]["max_files"] == 500 and capabilities["assessment"]["authorization"] is False


def test_hybrid_review_lets_rules_decide_and_adds_second_opinions():
    client = client_for(ReviewService(ScriptedBackend()))
    report = client.post("/v1/review", json={"files": [{"path": "svc/db.py", "content": SCRIPTED}]}).json()
    assert report["model"]["engine"] == "hybrid" and report["model"]["model_version"] == "scripted-test"
    assert {f["symbol"]: (f["result"], f["engine"], f["second_opinion"]["result"]) for f in report["findings"]} == {
        "risky": ("flagged", "rules", "flagged"), "unsure": ("flagged", "rules", "uncertain")}
    assert any("Static rules decided each result" in notice for notice in report["notices"])


def test_scripted_model_review_maps_results_and_notices():
    backend = ScriptedBackend()
    client = client_for(ReviewService(backend))
    response = client.post("/v1/review", json={"files": [{"path": "svc/db.py", "content": SCRIPTED}],
                                               "engine": "model"})
    report = response.json()
    assert response.status_code == 200 and report["model"]["model_version"] == "scripted-test"
    assert {f["symbol"]: f["result"] for f in report["findings"]} == {"risky": "flagged", "unsure": "uncertain"}
    flagged = next(f for f in report["findings"] if f["result"] == "flagged")
    assert flagged["risk"] > 0.99 and flagged["threshold"] == 0.5 and flagged["guidance"]
    assert flagged["details"] and "SQL execution" in flagged["details"][0]
    assert report["summary"]["units_prefiltered"] == 1 and sum(backend.batches) == 2
    assert any("Experimental model" in notice for notice in report["notices"])


def test_request_settings_override_policy_checks_and_threshold():
    client = client_for(ReviewService(ScriptedBackend()))
    body = {"code": SCRIPTED, "engine": "model", "config": {"policy": ["Only admins call these helpers."],
                                                           "checks": ["sql_injection"], "flag_threshold": 1}}
    report = client.post("/v1/review", json=body).json()
    assert report["policy_source"] == "request" and report["checks"] == ["sql_injection"]
    assert report["summary"]["results"].get("flagged", 0) == 0
    unchanged = client.post("/v1/review", json={"code": SCRIPTED, "engine": "model",
                                                "config": {"flag_threshold": 0.5}}).json()
    assert unchanged["policy_source"] == "default"
    bad = client.post("/v1/review", json={"code": SHELL, "engine": "rules", "config": {"checks": ["made_up"]}})
    assert bad.status_code == 422 and bad.json()["code"] == "invalid_request"
    assert bad.json()["fields"] == ["config"] and "made_up" not in bad.text


def test_diff_files_and_sarif_inputs():
    client = client_for()
    diff = client.post("/v1/review", json={"diff": DIFF, "engine": "rules"}).json()
    assert diff["findings"][0]["start_line"] == 40
    assert any("diff hunks only" in notice for notice in diff["notices"])
    files = [
        {"path": "app/views.py", "content": SHELL, "before": HEADER + "def ping(host):\n    return host\n"},
        {"path": "README.txt", "content": "not python"},
        {"path": "big.py", "content": "x = 1\n" * 400_000},
    ]
    report = client.post("/v1/review", json={"files": files, "engine": "rules"}).json()
    assert report["summary"]["files_skipped"] == {"file_too_large": 1, "not_python": 1}
    assert [f["path"] for f in report["findings"]] == ["app/views.py"]
    response = client.post("/v1/review", json={"code": SHELL, "engine": "rules", "format": "sarif"})
    assert response.headers["content-type"].startswith("application/sarif+json")
    sarif = response.json()
    result = sarif["runs"][0]["results"][0]
    assert sarif["version"] == "2.1.0" and result["ruleId"] == "polaris/command_injection"
    assert result["level"] == "error" and result["partialFingerprints"]["polarisFinding/v1"]


def test_api_keys_are_required_and_checked():
    raw, record = new_key("ci")
    other, _ = new_key("other")
    client = client_for(keys=KeyStore([record]))
    assert client.get("/health").json()["api_keys_required"] is True
    assert client.get("/openapi.json").status_code == 200
    missing = client.get("/v1/models")
    assert missing.status_code == 401 and missing.json()["code"] == "unauthorized"
    assert missing.headers["www-authenticate"] == "Bearer"
    for header in (f"Bearer {other}", f"Bearer {raw}x", f"Basic {raw}", raw, "Bearer "):
        assert client.get("/v1/models", headers={"Authorization": header}).status_code == 401
    unauthenticated = client.post("/v1/review", json={"code": SHELL, "engine": "rules"})
    assert unauthenticated.status_code == 401
    assert client.post("/v1/review", json={"code": SHELL, "engine": "rules"}, headers=bearer(raw)).status_code == 200
    usage = client.get("/v1/usage", headers=bearer(raw)).json()
    assert usage["key_id"] == record.key_id and usage["usage"]["reviews"] == 1


def test_keys_cli_prints_a_key_once_and_stores_only_salted_hashes(tmp_path, capsys):
    keys = tmp_path / "keys.json"
    assert main(["serve", "keys", "create", "--file", str(keys), "--name", "ci"]) == 0
    raw = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("plk_"))
    stored = keys.read_text()
    assert raw not in stored and raw.split("_", 2)[2] not in stored
    assert hashlib.sha256(raw.encode()).hexdigest() not in stored
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600
    assert KeyStore.read(keys).verify(raw).name == "ci"
    assert main(["serve", "keys", "create", "--file", str(keys), "--name", "deploy", "--rate-limit", "5"]) == 0
    second = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("plk_"))
    records = json.loads(keys.read_text())["keys"]
    assert len({item["salt"] for item in records}) == 2 and records[1]["rate_per_minute"] == 5
    assert main(["serve", "keys", "list", "--file", str(keys)]) == 0
    listing = capsys.readouterr().out
    assert "ci" in listing and "deploy" in listing and "plk_" not in listing
    assert main(["serve", "keys", "revoke", "--file", str(keys), records[0]["key_id"]]) == 0
    store = KeyStore.read(keys)
    assert store.verify(raw) is None and store.verify(second) is not None
    assert main(["serve", "keys", "revoke", "--file", str(keys), "deadbeef"]) == 2


def test_environment_keys_take_hashes_or_a_file_never_raw_keys(tmp_path):
    raw, record = new_key("env")
    assert KeyStore.from_environment(f"{record.key_id}:{record.salt}:{record.digest}").verify(raw)
    with pytest.raises(ValueError, match="never the keys themselves"):
        KeyStore.from_environment(raw)
    path = tmp_path / "keys.json"
    write_key_file(path, KeyFile(keys=[record]))
    assert KeyStore.from_environment(str(path)).verify(raw) is not None
    with pytest.raises(ValueError, match="No key file"):
        KeyStore.from_environment(str(tmp_path / "missing.json"))


def test_serving_other_machines_requires_api_keys(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("POLARIS_API_KEYS", raising=False)
    with pytest.raises(ValueError, match="requires API keys"):
        create_app(ReviewService(), settings=ApiSettings(host="0.0.0.0"))
    assert main(["serve", "--host", "0.0.0.0", "--rules-only"]) == 2
    assert "requires API keys" in capsys.readouterr().err
    assert main(["serve", "--host", "0.0.0.0", "--api-keys", str(tmp_path / "none.json")]) == 2
    assert "No key file" in capsys.readouterr().err
    raw, record = new_key("remote")
    remote = client_for(keys=KeyStore([record]), host="0.0.0.0", base_url="https://polaris.example")
    assert remote.get("/v1/models", headers=bearer(raw)).status_code == 200


def test_remote_banner_points_only_to_public_docs(capsys):
    from polaris.api.cli import _banner

    _, record = new_key("remote")
    _banner(ApiSettings(host="0.0.0.0", port=PORT), ReviewService(problem="not_requested"), KeyStore([record]))
    banner = capsys.readouterr().out
    assert "TLS reverse proxy" in banner and "(see docs/api.md)" in banner
    assert set(re.findall(r"[\w./-]+\.md", banner)) == {"docs/api.md"}  # the only doc it names


def test_serve_explains_a_busy_port(capsys):
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = taken.getsockname()[1]
        assert main(["serve", "--port", str(port), "--rules-only"]) == 2
    assert "already in use" in capsys.readouterr().err


def test_rate_limits_are_per_key_and_tell_when_to_retry():
    first_raw, first = new_key("a")
    second_raw, second = new_key("b")
    unlimited_raw, unlimited = new_key("c", rate_per_minute=0)
    client = client_for(keys=KeyStore([first, second, unlimited]), rate_per_minute=2, burst=2)
    codes = [client.get("/v1/models", headers=bearer(first_raw)).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    limited = client.get("/v1/models", headers=bearer(first_raw))
    assert limited.json()["code"] == "rate_limited" and limited.json()["retryable"] is True
    assert int(limited.headers["retry-after"]) >= 1
    assert client.get("/v1/models", headers=bearer(second_raw)).status_code == 200
    assert all(client.get("/v1/models", headers=bearer(unlimited_raw)).status_code == 200 for _ in range(5))


def test_token_bucket_refills_over_time():
    now = [0.0]
    limiter = RateLimiter(60, 1, clock=lambda: now[0])
    assert limiter.acquire("key") == 0
    assert limiter.acquire("key") == pytest.approx(1.0)
    now[0] = 1.0
    assert limiter.acquire("key") == 0
    assert RateLimiter(0, 1).acquire("key") == 0


def test_work_queue_bounds_running_and_waiting_jobs():
    started, release = threading.Event(), threading.Event()
    results = []

    def slow():
        started.set()
        release.wait(5)
        return "slow"

    async def scenario():
        queue = WorkQueue(workers=1, depth=1)

        async def submit(job):
            results.append(await queue.run(job))

        async with anyio.create_task_group() as group:
            group.start_soon(submit, slow)
            await anyio.to_thread.run_sync(started.wait, 5)
            group.start_soon(submit, lambda: "waited")
            await anyio.sleep(0.05)
            with pytest.raises(QueueFull):
                await queue.run(lambda: "rejected")
            release.set()
        assert queue.admitted == 0

    anyio.run(scenario)
    assert results == ["slow", "waited"]


def test_a_busy_server_answers_429_instead_of_queueing_forever():
    started, release = threading.Event(), threading.Event()

    class SlowService(ReviewService):
        def run(self, engine, work):
            started.set()
            release.wait(10)
            return super().run(engine, work)

    app = create_app(SlowService(), settings=ApiSettings(port=PORT, workers=1, queue_depth=0))
    outcome = {}
    with TestClient(app, base_url=BASE) as client:
        first = threading.Thread(target=lambda: outcome.update(
            first=client.post("/v1/review", json={"code": SHELL, "engine": "rules"})))
        first.start()
        assert started.wait(10)
        busy = client.post("/v1/review", json={"code": SHELL, "engine": "rules"})
        release.set()
        first.join(10)
    assert busy.status_code == 429 and busy.json()["code"] == "queue_full"
    assert busy.headers["retry-after"] == "1" and outcome["first"].status_code == 200


def test_body_and_file_count_limits():
    client = client_for(max_body_bytes=2000, max_files=2)
    large = client.post("/v1/review", json={"code": "x = 1\n" * 1000, "engine": "rules"})
    assert large.status_code == 413 and large.json()["code"] == "payload_too_large"

    def chunks():
        yield b'{"code": "'
        for _ in range(50):
            yield b"x" * 100
        yield b'", "engine": "rules"}'

    streamed = client.post("/v1/review", content=chunks(), headers={"content-type": "application/json"})
    assert streamed.status_code == 413
    files = [{"path": f"f{index}.py", "content": "x = 1\n"} for index in range(3)]
    too_many = client.post("/v1/review", json={"files": files, "engine": "rules"})
    assert too_many.status_code == 413 and too_many.json()["code"] == "too_many_files"


@pytest.mark.parametrize("body", [
    b'{"code": "a", "code": "b"}', b'{"code": NaN}', b'{"code": "\xff"}', b"not json", b"",
    b'{"code": "a"} trailing',
])
def test_strict_json_parsing(body):
    response = client_for().post("/v1/review", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 400 and response.json()["code"] == "invalid_json"


def test_content_type_nesting_and_unknown_routes_get_typed_envelopes():
    client = client_for()
    plain = client.post("/v1/review", content=b'{"code": "x"}', headers={"content-type": "text/plain"})
    assert plain.status_code == 415 and plain.json()["code"] == "unsupported_media_type"
    deep = b'{"code": ' + b"[" * 40 + b"]" * 40 + b"}"
    assert client.post("/v1/review", content=deep, headers={"content-type": "application/json"}).status_code == 413
    assert client.get("/v1/nothing").json()["code"] == "not_found"
    wrong = client.get("/v1/review")
    assert wrong.status_code == 405 and wrong.json()["code"] == "method_not_allowed"
    for response in (plain, wrong):
        assert response.json()["kind"] == "api_error" and "Traceback" not in response.text


def test_invalid_requests_name_fields_but_never_echo_values():
    client = client_for()
    response = client.post("/v1/review", json={"code": MARKER, "engine": MARKER, "surprise": MARKER})
    assert response.status_code == 422 and set(response.json()["fields"]) == {"engine", "surprise"}
    assert MARKER not in response.text
    both = client.post("/v1/review", json={"code": "x", "diff": "y"})
    assert "exactly one of diff, files or code" in both.json()["message"]
    duplicate = client.post("/v1/review", json={"files": [{"path": "a.py", "content": ""}] * 2})
    assert "unique" in duplicate.json()["message"]
    control = client.post("/v1/review", json={"code": "x", "path": "a\nb.py"})
    assert control.status_code == 422 and control.json()["fields"] == ["path"]


def test_unexpected_errors_are_typed_and_hide_details(monkeypatch, caplog):
    import polaris.api.app as api_app

    def explode(reviewer, payload):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(api_app, "_review", explode)
    caplog.set_level(logging.DEBUG)
    response = client_for().post("/v1/review", json={"code": SHELL, "engine": "rules"})
    assert response.status_code == 500 and response.json()["code"] == "internal_error"
    assert MARKER not in response.text and MARKER not in caplog.text
    assert "RuntimeError" in caplog.text


def test_request_bodies_are_never_logged(caplog, capsys):
    caplog.set_level(logging.DEBUG)
    client = client_for(ReviewService(ScriptedBackend()))
    code = SCRIPTED + f"\n# {MARKER}\n"
    assert client.post("/v1/review", json={"code": code}).status_code == 200
    assert client.post("/v1/review", json={"code": code, "engine": "bogus"}).status_code == 422
    broken = b'{"code": "' + MARKER.encode() + b'", "code": 1}'
    assert client.post("/v1/review", content=broken, headers={"content-type": "application/json"}).status_code == 400
    captured = capsys.readouterr()
    assert MARKER not in caplog.text + captured.out + captured.err


def test_usage_counts_and_the_usage_log_never_contain_code(tmp_path, capsys):
    log = tmp_path / "usage.jsonl"
    raw, record = new_key("ci")
    client = client_for(keys=KeyStore([record]), usage_log=log)
    files = [{"path": f"secret_{MARKER}.py", "content": SHELL + f"# {MARKER}\n"}]
    assert client.post("/v1/review", json={"files": files, "engine": "rules"}, headers=bearer(raw)).status_code == 200
    assert client.post("/v1/assess", json=sample_request(), headers=bearer(raw)).status_code == 503
    assert client.get(f"/v1/{MARKER}", headers=bearer(raw)).status_code == 404
    assert client.get("/v1/models").status_code == 401
    usage = client.get("/v1/usage", headers=bearer(raw)).json()["usage"]
    assert usage == {"requests": 3, "reviews": 1, "assessments": 1, "files_reviewed": 1,
                     "functions_total": 1, "functions_assessed": 1, "rejected": 2}
    text = log.read_text()
    assert MARKER not in text and "secret_" not in text
    entries = [json.loads(line) for line in text.splitlines()]
    assert {entry["endpoint"] for entry in entries} == {
        "/v1/review", "/v1/assess", "/v1/models", "/v1/usage", "other"}
    assert {entry["key_id"] for entry in entries} == {record.key_id, "anonymous"}
    assert main(["serve", "usage", str(log)]) == 0
    assert record.key_id in capsys.readouterr().out


def test_cors_is_off_unless_configured():
    plain = client_for().get("/health", headers={"Origin": "https://app.example"})
    assert "access-control-allow-origin" not in plain.headers
    allowed = client_for(cors_origins=("https://app.example",))
    response = allowed.get("/health", headers={"Origin": "https://app.example"})
    assert response.headers["access-control-allow-origin"] == "https://app.example"
    preflight = allowed.options("/v1/review", headers={
        "Origin": "https://app.example", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"})
    assert preflight.status_code == 200
    other = allowed.get("/health", headers={"Origin": "https://elsewhere.example"})
    assert "access-control-allow-origin" not in other.headers


def test_local_servers_check_the_host_name_and_send_safety_headers():
    client = client_for()
    assert client.get("/health", headers={"Host": "attacker.example"}).json()["code"] == "invalid_host"
    response = client.get("/health", headers={"Host": f"localhost:{PORT}"})
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert "server" not in response.headers or "uvicorn" not in response.headers["server"]


def test_assess_follows_the_contract(backend):
    client = client_for(ReviewService(backend))
    assessed = client.post("/v1/assess", json=sample_request())
    assert assessed.status_code == 200 and assessed.json()["kind"] == "assessment"
    assert assessed.json()["runtime"]["release_status"] == "experimental"
    invalid = client.post("/v1/assess", json={"contract_version": "polaris.assessment/0.1.0"})
    assert invalid.status_code == 400 and invalid.json()["code"] == "invalid_input"
    other = client.post("/v1/assess", json={"contract_version": "polaris.assessment/9.9.9"})
    assert other.json()["code"] == "unsupported_contract"
    missing = client_for().post("/v1/assess", json=sample_request())
    assert missing.status_code == 503 and missing.json()["code"] == "model_unavailable"


def test_openapi_is_published_docs_are_opt_in_and_the_client_snapshot_is_current():
    client = client_for()
    spec = client.get("/openapi.json").json()
    assert {"/health", "/v1/review", "/v1/assess", "/v1/assess/batch", "/v1/models", "/v1/capabilities",
            "/v1/usage", "/v1/workflow/review", "/v1/workflow/propose", "/v1/workflow/action",
            "/v1/workflow/capabilities"} == set(spec["paths"])
    body = spec["paths"]["/v1/assess"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert body == {"$ref": "#/components/schemas/AssessmentRequest"}
    schemas = spec["components"]["schemas"]

    def references(value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield from ([item] if key == "$ref" else references(item))
        elif isinstance(value, list):
            for item in value:
                yield from references(item)

    assert all(ref.removeprefix("#/components/schemas/") in schemas for ref in references(spec))
    assert client.get("/docs").status_code == 404
    assert client_for(docs=True).get("/docs").status_code == 200
    snapshot = json.loads((ROOT / "clients" / "typescript" / "openapi.json").read_text())
    assert snapshot == openapi_document(), "Regenerate: polaris serve openapi > clients/typescript/openapi.json"


@pytest.mark.ml
def test_a_real_tiny_bundle_loads_once_and_reviews_through_the_api(tmp_path):
    pytest.importorskip("torch")
    pytest.importorskip("transformers")
    from ml_helpers import make_tiny_bundle, tiny_request

    service = ReviewService.load(str(make_tiny_bundle(tmp_path / "tiny")), device="cpu")
    client = client_for(service)
    status = client.get("/v1/models").json()["model"]
    assert status["loaded"] is True and status["model_version"] == "tiny-random-unit-test"
    report = client.post("/v1/review", json={"code": SCRIPTED}).json()
    assert report["model"]["model_version"] == "tiny-random-unit-test"
    assert report["summary"]["units_assessed"] == 2 and report["summary"]["results"].get("error", 0) == 0
    assessed = client.post("/v1/assess", json=tiny_request().model_dump(mode="json"))
    assert assessed.status_code == 200 and assessed.json()["kind"] == "assessment"


@pytest.fixture
def live_server():
    import uvicorn

    port = free_port()
    raw, record = new_key("client")
    app = create_app(ReviewService(ScriptedBackend()), settings=ApiSettings(port=port),
                     keys=KeyStore([record]))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                           access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    yield f"http://127.0.0.1:{port}", raw
    server.should_exit = True
    thread.join(15)


def test_python_client_round_trip(live_server):
    url, raw = live_server
    client = PolarisClient(url, api_key=raw)
    assert client.health().model_loaded is True
    assert client.models().model.model_version == "scripted-test"
    report = client.review_code(SCRIPTED, path="svc/db.py")
    assert {finding.symbol for finding in report.findings} == {"risky", "unsure"}
    assert client.review_files({"a.py": SHELL}, before={"a.py": HEADER}, engine="rules").findings[0].result == "flagged"
    assert client.review_diff(DIFF, engine="rules").findings[0].start_line == 40
    assert client.sarif(code=SHELL, engine="rules")["version"] == "2.1.0"
    assert client.usage().usage.reviews == 4
    assert client.capabilities()["review_format"] == "polaris.review/0.1.0"
    envelope = client.assess({"contract_version": "polaris.assessment/0.1.0"})
    assert envelope.kind == "error" and envelope.code == "invalid_input"
    with pytest.raises(PolarisAPIError) as denied:
        PolarisClient(url).models()
    assert denied.value.status == 401 and denied.value.code == "unauthorized"
    with pytest.raises(PolarisAPIError) as invalid:
        client.review_code(SHELL, checks=["made_up"], engine="rules")
    assert invalid.value.code == "invalid_request"
    with pytest.raises(ValueError, match="https"):
        PolarisClient("http://polaris.example", api_key=raw)
    with pytest.raises(PolarisAPIError) as gone:
        PolarisClient(f"http://127.0.0.1:{free_port()}", timeout=2).health()
    assert gone.value.code == "connection_failed"


def test_python_workflow_client_round_trip(live_server):
    from polaris.jsonio import digest_text
    from polaris.workflow.requests import WorkflowReviewRequest

    url, raw = live_server
    client = PolarisClient(url, api_key=raw)
    payload = {"files": [{"path": "app.py", "content": SHELL}], "config": {"checks": ["command_injection"]}}
    report = client.review_workflow(WorkflowReviewRequest.model_validate(payload))
    assert report.format == "polaris.workflow/0.1.0"
    assert report.status == "complete" and report.finding_count == 1
    assert client.workflow_capabilities().format == "polaris.capabilities/0.2.0"
    repaired = "import subprocess\n\ndef ping(host):\n    subprocess.run(['ping', host])\n"
    proposal = client.propose_repair({
        **payload,
        "candidate": {
            "edits": [{
                "path": "app.py", "before_sha256": digest_text(SHELL), "replacement": repaired,
                "finding_refs": [report.review.findings[0].finding_id],
            }],
            "rationale": "Separate the executable from its arguments.",
        },
    })
    assert proposal.snapshot.source_kind == "submitted_content"
    action = client.review_action({
        "action": {"kind": "network", "action_id": "fixture", "method": "POST", "url": "https://example.invalid/upload"},
    })
    assert action.status == "needs_review" and not action.authorized and not action.executed
    with pytest.raises(PolarisAPIError) as denied:
        PolarisClient(url).review_workflow(payload)
    assert denied.value.status == 401


def test_typescript_client_round_trip(live_server):
    node = shutil.which("node")
    dist = ROOT / "clients" / "typescript" / "dist" / "index.js"
    if node is None or not dist.exists():
        pytest.skip("build the TypeScript client first: cd clients/typescript && npm run build")
    url, raw = live_server
    script = f"""
import {{ PolarisClient, PolarisApiError }} from {json.dumps(dist.as_uri())};
const client = new PolarisClient({{ baseUrl: process.env.POLARIS_URL, apiKey: process.env.POLARIS_KEY }});
const report = await client.reviewCode({json.dumps(SHELL)}, {{ engine: "rules", path: "net/ping.py" }});
const models = await client.models();
const assessment = await client.assess({{ contract_version: "polaris.assessment/0.1.0" }});
const batch = await client.assessBatch([{{ contract_version: "polaris.assessment/0.1.0" }}]);
const workflow = await client.reviewWorkflow({{
  files: [{{ path: "app.py", content: {json.dumps(SHELL)} }}],
  config: {{ checks: ["command_injection"] }},
}});
const capabilities = await client.workflowCapabilities();
const action = await client.reviewAction({{
  action: {{ kind: "network", action_id: "fixture", method: "POST", url: "https://example.invalid/upload" }},
}});
let status = 0;
try {{ await new PolarisClient({{ baseUrl: process.env.POLARIS_URL }}).models(); }}
catch (error) {{ status = error instanceof PolarisApiError ? error.status : -1; }}
console.log(JSON.stringify({{ results: report.findings.map((f) => f.result), path: report.findings[0].path,
  model: models.model.model_version, assessment: assessment.kind, unauthorized: status,
  batch: batch.map((item) => item.kind), thresholds: models.model.flag_thresholds,
  workflow: [workflow.format, workflow.finding_count], capabilities: capabilities.format,
  action: [action.status, action.authorized, action.executed] }}));
"""
    done = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True,
                          timeout=60, env={**os.environ, "POLARIS_URL": url, "POLARIS_KEY": raw})
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"results": ["flagged"], "path": "net/ping.py",
                                       "model": "scripted-test", "assessment": "error", "unauthorized": 401,
                                       "batch": ["error"],
                                       "thresholds": {"command_injection": 0.5, "sql_injection": 0.5},
                                       "workflow": ["polaris.workflow/0.1.0", 1],
                                       "capabilities": "polaris.capabilities/0.2.0",
                                       "action": ["needs_review", False, False]}

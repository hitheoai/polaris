"""The replay evaluation of `polaris fix --ai`: scripted answers, offline, deterministic."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest
from test_fix import SQL

from polaris.engineering.transport import HTTPResult
from polaris.refactor.aiconfig import CI_VARIABLES

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "benchmarks" / "refactor_eval"


def load_runner():
    spec = importlib.util.spec_from_file_location("refactor_eval_run", FOLDER / "run.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def runner():
    return load_runner()


@pytest.fixture(scope="module")
def replay(runner):
    return runner.evaluate()


def test_every_scripted_case_behaves_as_expected(replay):
    assert replay["mismatches"] == [] and replay["mode"] == "replay" and replay["scripted"] is True
    assert replay["cases"] == len(replay["results"]) == 16
    assert all(item["result"] == item["expected"] for item in replay["results"])


def test_the_corpus_covers_good_bad_and_failing_answers(replay):
    verified = {item["id"] for item in replay["results"] if item["result"] == "verified"}
    assert {"sql-concatenation", "command-os-system", "tls-verification-off", "debug-mode-on"} <= verified
    assert set(replay["rejections"]) == {
        "finding_still_detected", "edit_adds_findings", "change_outside_scope", "edited_file_not_fully_checked",
        "ai_invalid_candidate", "ai_secret_detected", "ai_provider_error", "ai_timeout"}
    assert replay["new_problem_rate"] > 0 and replay["behavior_unchecked"] is True


def test_the_case_the_checks_cannot_catch_is_shown_not_hidden(replay):
    limit = next(item for item in replay["results"] if item["id"] == "obedient-model-deletes-a-function")
    assert limit["result"] == "verified" and "behavior" in limit["limit"]


def test_only_the_file_asked_about_is_ever_sent(replay):
    assert all(item["sent"] in ([], ["db.py"], ["ping.py"], ["fetch.py"], ["web.py"]) for item in replay["results"])


def test_replay_is_deterministic_and_carries_no_date(runner, replay):
    again = runner.evaluate()
    assert json.dumps(again, sort_keys=True) == json.dumps(replay, sort_keys=True) and "date" not in replay


def test_the_report_does_not_offer_a_quotable_rate_for_scripted_answers(runner, replay):
    text = runner.render(replay)
    assert "scripted answers, not a model" in text and "Behavior is not checked" in text
    assert not re.search(r"verified \d+ \(\d+%\)", text)  # the rate stays in the JSON only


def test_a_case_that_behaves_differently_is_reported_and_fails_the_run(runner):
    cases = [{"id": "x", "files": {"db.py": SQL}, "expect": "finding_still_detected",
              "answer": {"edits": [("name = ", "name = ")]}}]  # changes nothing: not the expected outcome
    report = runner.evaluate(cases=cases)
    assert report["mismatches"] == ["x"] and "DIFFERENT FROM EXPECTED: x" in runner.render(report)


def test_the_command_exits_zero_when_every_case_matches(runner):
    shown: list[str] = []
    assert runner.main([], out=shown.append) == 0 and "ok   sql-concatenation: verified" in shown[0]


def test_live_needs_an_explicit_yes_and_never_runs_in_ci(runner, monkeypatch, capsys):
    for name in ("CI", *CI_VARIABLES):
        monkeypatch.delenv(name, raising=False)
    assert runner.main(["--live"]) == 2 and "--yes-send" in capsys.readouterr().err
    monkeypatch.setenv("CI", "true")
    assert runner.main(["--live", "--yes-send"]) == 2 and "CI" in capsys.readouterr().err


def test_live_uses_the_users_settings_and_labels_the_report(runner, tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    home.chmod(0o700)
    monkeypatch.setenv("POLARIS_HOME", str(home))
    for name in ("CI", *CI_VARIABLES):
        monkeypatch.delenv(name, raising=False)
    settings = home / "ai.toml"
    settings.write_text('endpoint = "http://127.0.0.1:9/v1/chat/completions"\nmodel = "my-model"\n')
    settings.chmod(0o600)
    asked: list[str] = []

    def provider(endpoint, *, body, api_key, timeout_seconds, max_response_bytes):
        asked.append(endpoint)
        return HTTPResult(500, b"")  # every request fails: the report must still be produced and labelled

    monkeypatch.setattr("polaris.engineering.generation.http_transport", provider)
    code = runner.main(["--live", "--yes-send", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 0  # live results are measurements, never a pass or fail
    assert report["mode"] == "live" and report["model"] == "my-model" and re.fullmatch(r"\d{4}-\d\d-\d\d", report["date"])
    assert "scripted" not in report and report["mismatches"] == [] and report["verified"] == 0
    assert len(asked) == 16 and set(asked) == {"http://127.0.0.1:9/v1/chat/completions"}

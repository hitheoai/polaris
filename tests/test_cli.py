import json
import subprocess
import sys

import pytest

from polaris.fixtures import sample_request
from polaris.jsonio import MAX_PAYLOAD_BYTES


def run_cli(*args, content=None):
    return subprocess.run(
        [sys.executable, "-m", "polaris", *args],
        input=content,
        text=True,
        capture_output=True,
        check=False,
    )


def test_capabilities_are_honest():
    result = run_cli("capabilities")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert len(payload["checks"]) == 7
    assert payload["qualified_checks"] == []
    assert payload["authorization"] is False


def test_no_model_is_a_runtime_error():
    result = run_cli("assess", content=json.dumps(sample_request()))
    assert result.returncode == 3
    assert json.loads(result.stdout)["code"] == "model_unavailable"
    assert not result.stderr


def test_invalid_json_is_input_error():
    result = run_cli("assess", content='{"broken":')
    assert result.returncode == 2
    assert json.loads(result.stdout)["kind"] == "error"


def test_jsonl_processes_requests_independently():
    missing = sample_request()
    missing["trusted_context"] = []
    result = run_cli("assess", "--jsonl", content="invalid\n" + json.dumps(missing) + "\n")
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    assert result.returncode == 2
    assert lines[0]["kind"] == "error"
    assert lines[1]["results"][0]["status"] == "abstain"


def test_smoke_fixtures_are_explicitly_unreviewed():
    result = run_cli("fixtures")
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert result.returncode == 0
    assert len(records) == 21
    assert all(record["provenance"]["review_state"] == "unreviewed" for record in records)


# The training commands (train, calibrate, evaluate, export-candidate) ship only with the
# private training tools: tests/test_research_cli.py.
@pytest.mark.parametrize("command", ["benchmark", "benchmark-architecture"])
def test_benchmark_commands_are_discoverable_without_loading_weights(command):
    result = run_cli(command, "--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout


def test_schema_export_never_overwrites_an_existing_file(tmp_path):
    path = tmp_path / "request.schema.json"
    first = run_cli("schema", "request", "--output", str(path))
    assert first.returncode == 0
    original = path.read_bytes()
    second = run_cli("schema", "response", "--output", str(path))
    assert second.returncode == 2
    assert path.read_bytes() == original


def test_jsonl_oversize_whitespace_cannot_hide_a_request():
    request = sample_request()
    request["trusted_context"] = []
    result = run_cli(
        "assess", "--jsonl", content=" " * (MAX_PAYLOAD_BYTES + 1) + json.dumps(request) + "\n"
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["code"] == "payload_limit"


def test_invalid_cold_run_count_is_rejected_before_reading_inputs(tmp_path):
    result = run_cli(
        "benchmark",
        "--bundle",
        str(tmp_path / "absent"),
        "--requests",
        str(tmp_path / "absent.jsonl"),
        "--cold-runs",
        "-1",
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["code"] == "invalid_input"


def test_existing_benchmark_output_is_rejected_before_loading_weights(tmp_path):
    output = tmp_path / "existing.json"
    output.write_text("preserve me", encoding="utf-8")
    result = run_cli(
        "benchmark-architecture",
        "--output",
        str(output),
    )
    assert result.returncode == 2
    assert output.read_text() == "preserve me"

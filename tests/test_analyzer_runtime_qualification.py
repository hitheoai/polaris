"""Exception handling regressions use synthetic cleanup, never live exporters."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("analyzer_runtime_test", ROOT / "scripts/qualify_analyzer_runtime.py")
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


@pytest.mark.parametrize("initial", [None, RuntimeError("original synthetic error"), KeyboardInterrupt()])
@pytest.mark.parametrize("failures", [set(), {0}, {1}, {0, 1}, {0, 2, 4}])
def test_cleanup_tries_every_action_and_preserves_the_original_exception(initial, failures):
    actions, called, errors = [], [], {}
    for number in range(6):
        def cleanup(number=number):
            called.append(number)
            if number in failures:
                errors[number] = RuntimeError("later synthetic cleanup error")
                raise errors[number]
        actions.append((f"action-{number}", cleanup))
    primary, observed, attempted = runtime.finish_actions(actions, initial)
    assert called == list(range(6))
    assert attempted == [f"action-{number}" for number in range(6)]
    assert observed == [(f"action-{number}", errors[number]) for number in sorted(failures)]
    assert primary is (initial if initial is not None else errors[min(failures)] if failures else None)
    record = runtime.outcome((primary, observed, attempted))
    assert "synthetic" not in repr(record)


def test_cleanup_handles_base_exceptions_without_abandoning_later_actions():
    called = []
    original = ValueError("original")

    def interrupted():
        raise SystemExit(3)

    result = runtime.finish_actions([("interrupt", interrupted), ("later", lambda: called.append(True))], original)
    assert result[0] is original
    assert called == [True] and isinstance(result[1][0][1], SystemExit)


def test_output_receipts_are_exclusive_and_private(tmp_path):
    path = tmp_path / "receipt.json"
    runtime.write_json(path, {"fixture": True})
    before = path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        runtime.write_json(path, {"fixture": False})
    assert path.read_bytes() == before


def test_worker_dispatch_uses_the_exact_argument_vector(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(runtime.sys, "argv", [str(runtime.__file__), "_worker", "success", str(tmp_path)])
    monkeypatch.setattr(runtime, "telemetry_worker", lambda root, case: observed.append((root, case)))
    assert runtime.main() == 0
    assert observed == [(tmp_path, "success")]

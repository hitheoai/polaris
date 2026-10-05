"""Opt-in Claude Code/Cursor hooks. Review only: no edits, project tests, or hosted inference.

Documented event adapters: Claude Code PostToolUse/Stop; Cursor afterFileEdit/stop. There is
intentionally no Warp adapter. Stop always re-analyzes rather than trusting a mutable receipt.

Events: `dirty` marks an edit; `check` (what `polaris setup --hooks` installs on Stop) runs
`polaris check` on the changes in an isolated worker and hands the "fix now" items back to the
agent until it is clear, for at most `CHECK_ROUNDS` rounds per turn (Claude Code's
stop_hook_active plus a per-session count; Cursor's loop_count and loop_limit). `stop` is the
earlier one-follow-up review report, kept for configurations installed before.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from polaris.integrations._safe import (
    IntegrationProblem,
    atomic_write,
    module_command,
    no_symlinks,
    offline_environment,
    parent_descriptor,
    read_bytes,
    run_bounded,
    trusted_executable,
)
from polaris.integrations.freshness import (
    RECEIPT_FORMAT,
    ReviewSnapshot,
    _installed_analysis,
    capture_snapshot,
    git_bytes,
    is_fresh,
    repository_identity,
    scoped_limits,
    state_directory,
)
from polaris.integrations.reporting import compact_report, problem_summary, render_summary

MAX_INPUT = 262_144
MAX_OUTPUT = 2_000_000
# Hand-backs per agent turn before the hook lets the agent stop and tells the user instead.
CHECK_ROUNDS = 3
HOST_EVENTS = {"claude-code": {"dirty": "PostToolUse", "stop": "Stop", "check": "Stop"},
               "cursor": {"dirty": "afterFileEdit", "stop": "stop", "check": "stop"}}
FOLLOWUP = (
    "Include this Polaris review outcome in your final response, distinguishing unresolved issues "
    "and unreviewed scope. Do not edit files, execute verification commands, expand scope, or "
    "retry indefinitely to satisfy this hook. Corrections still require the user's original "
    "authorization and normal approvals; re-review any further edits explicitly.\n\n"
)
Runner = Callable[[Path, float], dict[str, Any]]


class LockBusy(IntegrationProblem):
    pass


def add_agent_hook_parsers(commands: Any) -> None:
    parser = commands.add_parser(
        "agent-hook", help="Opt-in local completion-hook adapter; JSON on stdin, never edits code.",
    )
    parser.add_argument("--host", choices=("claude-code", "cursor"), required=True)
    parser.add_argument("--event", choices=("dirty", "check", "stop"), required=True,
                        help="dirty: an edit happened; check: the agent finished, so run `polaris check` and "
                             "hand back what to fix now; stop: the earlier one-time review report.")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--semgrep", "--semgrep-executable", type=Path,
                        help="Explicit trusted absolute Semgrep executable; never inherited from project PATH.")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="Whole isolated review deadline in seconds, 1-30 (default 20).")
    parser.add_argument("--retries", type=int, choices=(0, 1), default=0,
                        help="Optional stale-snapshot retry within the same deadline (default zero).")
    parser.add_argument("--no-followup", action="store_true",
                        help="Report only; never ask the host for one final reporting turn.")


@contextmanager
def review_lock(folder: Path) -> Iterator[None]:
    """OS-owned advisory lock, so a crash cannot leave a permanent lock. One bounded retry."""
    try:
        import fcntl
    except ImportError as exc:
        raise IntegrationProblem("Completion-hook locking requires POSIX support.") from exc
    path = folder / "review.lock"
    with parent_descriptor(path, create=True) as parent:
        descriptor = os.open(path.name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise IntegrationProblem("Hook lock is not a regular file.")
        for attempt in range(2):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if attempt:
                    raise LockBusy("Another review is in progress; this invocation was not reviewed.") from exc
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def _json_state(path: Path) -> dict[str, Any]:
    raw = read_bytes(path, limit=MAX_OUTPUT)
    if raw is None:
        return {}
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return {}
    return result if isinstance(result, dict) else {}


def _write_state(path: Path, value: Mapping[str, Any]) -> None:
    content = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(content) > MAX_OUTPUT:
        raise IntegrationProblem("Hook state exceeds its output bound.")
    atomic_write(path, content + b"\n")


def _validate_payload(root: Path, host: str, event: str, payload: Mapping[str, Any]) -> bool:
    expected = HOST_EVENTS[host][event]
    if payload.get("hook_event_name") != expected:
        raise IntegrationProblem("Unexpected host event; review was not run.")
    cwd = payload.get("cwd")
    if cwd is not None:
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            raise IntegrationProblem("Hook working directory is invalid.")
        candidate = no_symlinks(Path(cwd))
        if not candidate.is_relative_to(root) or repository_identity(candidate).root != root:
            raise IntegrationProblem("Hook working directory differs from the configured worktree.")
    workspaces = payload.get("workspace_roots")
    if workspaces is not None:
        if (not isinstance(workspaces, list) or not workspaces
                or any(not isinstance(value, str) or not Path(value).is_absolute() for value in workspaces)):
            raise IntegrationProblem("Hook workspace roots are invalid.")
        roots = {str(no_symlinks(Path(value))) for value in workspaces}
        if len(roots) != 1 or str(root) not in roots:
            raise IntegrationProblem("This hook reviews one configured worktree, not a different/multi-root workspace.")
    if event in ("stop", "check"):
        if host == "claude-code":
            active = payload.get("stop_hook_active")
            if type(active) is not bool:
                raise IntegrationProblem("Missing recursion state in the Stop event.")
            return not active
        count = payload.get("loop_count")
        if type(count) is not int or count < 0:
            raise IntegrationProblem("Missing recursion count in the stop event.")
        if payload.get("status") != "completed":
            raise IntegrationProblem("Agent was aborted or errored; completion review is unavailable.")
        return count == 0
    return False


def run_review(root: Path, timeout: float, *, semgrep: Path | None = None) -> dict[str, Any]:
    """Isolated trusted-package worker; the process never inherits credentials or project Python."""
    semgrep = trusted_executable(semgrep)
    with tempfile.TemporaryDirectory(prefix="polaris-hook-") as temporary:
        home = Path(temporary).resolve()
        result = run_bounded(
            [*module_command("polaris.integrations.hooks", "_worker_main"), "--root", str(root),
             *(["--semgrep", str(semgrep)] if semgrep is not None else [])],
            cwd=home, env=offline_environment(home), timeout=timeout, max_output_bytes=MAX_OUTPUT,
        )
    if result.returncode != 0:
        raise IntegrationProblem("Local review worker failed; no successful review recorded.")
    try:
        data = json.loads(result.stdout)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IntegrationProblem("Local review worker returned invalid output.") from exc
    if (not isinstance(data, dict) or not isinstance(data.get("summary"), dict)
            or not isinstance(data.get("snapshot"), dict)):
        raise IntegrationProblem("Local review worker returned an incomplete envelope.")
    return data


def run_hook(
    root: Path, *, host: str, event: str, payload: Mapping[str, Any], timeout: float = 20,
    retries: int = 0, no_followup: bool = False, review_runner: Runner | None = None,
    semgrep: Path | None = None,
) -> dict[str, Any]:
    """Return a redacted outcome; protocol serialization is separate for testability."""
    if host not in ("claude-code", "cursor") or event not in ("dirty", "stop"):
        raise IntegrationProblem("Unsupported hook host or event.")
    if not 1 <= timeout <= 30 or retries not in (0, 1):
        raise IntegrationProblem("Hook bounds are invalid.")
    semgrep = trusted_executable(semgrep)
    if os.environ.get("POLARIS_AGENT_HOOK_ACTIVE") == "1":
        return {"summary": problem_summary("unavailable", "Recursive hook invocation suppressed."),
                "followup": False}
    identity = repository_identity(root)
    root = identity.root
    can_followup = _validate_payload(root, host, event, payload)
    folder = state_directory(root)
    if event == "dirty":
        # No transcript, tool_input, edit content, or credential-bearing payload is ever saved.
        _write_state(folder / "dirty.json", {"generation": os.urandom(16).hex()})
        return {"summary": problem_summary("dirty", "Content changed; review is pending."),
                "followup": False}
    runner = review_runner or (lambda project, budget: run_review(project, budget, semgrep=semgrep))
    try:
        with review_lock(folder):
            generation = _json_state(folder / "dirty.json").get("generation")
            started = time.monotonic()
            try:
                result: dict[str, Any] = {}
                for attempt in range(retries + 1):
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise IntegrationProblem("Completion review exhausted its time budget.")
                    result = runner(root, remaining)
                    if result["summary"].get("status") != "stale" or attempt == retries:
                        break
                summary = result["summary"]
                snapshot = result["snapshot"]
                if not isinstance(summary, dict) or not isinstance(snapshot, dict):
                    raise IntegrationProblem("Malformed worker envelope.")
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                summary = problem_summary("unavailable", "Local review failed, timed out, or exceeded its bounds.")
                snapshot = {"complete": False, "worktree_id": identity.worktree_id,
                            "repository_id": identity.repository_id}
            if (snapshot.get("worktree_id") != identity.worktree_id
                    or snapshot.get("repository_id") != identity.repository_id):
                summary = problem_summary("error", "Review belongs to a different worktree.")
                snapshot = {"complete": False}
            if _json_state(folder / "dirty.json").get("generation") != generation:
                summary = {**summary, "status": "stale", "unreviewed": [
                    *summary.get("unreviewed", []), "An edit event arrived during review; review again."
                ]}
            if summary.get("status") != "complete":
                snapshot = {**snapshot, "complete": False}
            _write_state(folder / "review.json", {
                "format": RECEIPT_FORMAT, "trust": "mutable_local_hint_not_ci_evidence",
                "snapshot": snapshot, "summary": summary,
            })
            session = payload.get("session_id", payload.get("conversation_id"))
            key = hashlib.sha256(json.dumps(
                [host, session, payload.get("generation_id"), snapshot.get("digest")],
                sort_keys=True,
            ).encode()).hexdigest()
            previous = _json_state(folder / "followup.json")
            followup = bool(can_followup and not no_followup and isinstance(session, str)
                            and previous.get("key") != key)
            if followup:
                _write_state(folder / "followup.json", {"key": key})
            return {"summary": summary, "followup": followup}
    except LockBusy:
        # Do not overwrite the running worker's receipt.
        return {"summary": problem_summary("busy", "Another completion review is running; this one is incomplete."),
                "followup": False}
    except (OSError, ValueError, KeyError, TypeError):
        return {"summary": problem_summary("unavailable", "Local review state could not be safely stored."),
                "followup": False}


CheckRunner = Callable[[Path, float], Any]


def run_check_worker(root: Path, timeout: float) -> Any:
    """`polaris check --changes --json` in an isolated worker of this trusted package: offline, with a
    temporary HOME, no inherited credentials or project Python, and bounded time and output.
    Returns the validated `CheckResult`; raises IntegrationProblem when there is no result."""
    from pydantic import ValidationError

    from polaris.check.model import CHECK_FORMAT, CheckResult

    with tempfile.TemporaryDirectory(prefix="polaris-hook-") as temporary:
        home = Path(temporary).resolve()
        process = run_bounded(
            [*module_command("polaris.cli"), "check", "--changes", "--json", "--root", str(root)],
            cwd=home, env=offline_environment(home), timeout=timeout, max_output_bytes=MAX_OUTPUT,
        )
    if process.returncode not in (0, 1, 2):
        raise IntegrationProblem("The local check worker failed.")
    try:
        data = json.loads(process.stdout)
        if not isinstance(data, dict) or data.get("format") != CHECK_FORMAT:
            raise IntegrationProblem("The check couldn't finish.")  # includes polaris.check-error/1
        return CheckResult.model_validate(data)
    except (ValueError, UnicodeError, RecursionError, ValidationError) as exc:
        raise IntegrationProblem("The local check worker returned an invalid result.") from exc


def _check_outcome(status: str, message: str, *, handback: str | None = None, rounds: int = 0) -> dict[str, Any]:
    return {"status": status, "message": message, "handback": handback, "rounds": rounds}


def run_check_hook(
    root: Path, *, host: str, payload: Mapping[str, Any], timeout: float = 20, no_followup: bool = False,
    check_runner: CheckRunner | None = None,
) -> dict[str, Any]:
    """The agent finished: run `polaris check` on the changes and decide whether to hand the "fix
    now" items back. Returns status, a plain message for the user, the hand-back text for the
    agent (or None) and the round number. Never edits files; never claims clear without a result.

    Loop guard: at most `CHECK_ROUNDS` hand-backs per turn. Claude Code marks continuations with
    stop_hook_active (the count is kept per session in Git's private folder, hashed); Cursor
    counts them itself (loop_count, capped by the installed loop_limit).
    """
    from polaris.check import brand
    from polaris.check.output import handback

    if host not in HOST_EVENTS or not 1 <= timeout <= 30:
        raise IntegrationProblem("Unsupported hook host or bounds.")
    if os.environ.get("POLARIS_AGENT_HOOK_ACTIVE") == "1":
        return _check_outcome("unavailable", "Polaris didn't check: recursive hook invocation suppressed.")
    root = repository_identity(root).root
    first_stop = _validate_payload(root, host, "check", payload)
    folder = state_directory(root)
    runner = check_runner or run_check_worker
    try:
        with review_lock(folder):
            generation = _json_state(folder / "dirty.json").get("generation")
            try:
                result = runner(root, timeout)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                return _check_outcome("unavailable", "Polaris couldn't finish checking the changes (it failed or ran "
                                                     "out of time). Run `polaris check` to see the result.")
            if _json_state(folder / "dirty.json").get("generation") != generation:
                return _check_outcome("stale", "Files changed while Polaris was checking; run `polaris check` again.")
            session = payload.get("session_id", payload.get("conversation_id"))
            key = hashlib.sha256(json.dumps([host, session], sort_keys=True).encode()).hexdigest()
            if host == "cursor":
                used = payload["loop_count"]
            else:
                record = _json_state(folder / "check-rounds.json")
                stored = record.get("rounds") if record.get("key") == key else 0
                used = 0 if first_stop else stored if type(stored) is int and stored >= 0 else CHECK_ROUNDS
            words = f"Polaris: {brand.STATUS_MARKS[result.status]} {brand.STATUS_WORDS[result.status]}. {result.summary}"
            if result.counts.fix_now and not no_followup and used < CHECK_ROUNDS:
                _write_state(folder / "check-rounds.json", {"key": key, "rounds": used + 1})
                return _check_outcome("fix_needed", words + " Handing them back to the agent "
                                      f"(round {used + 1} of {CHECK_ROUNDS}).",
                                      handback=handback(result, round_number=used + 1, rounds=CHECK_ROUNDS),
                                      rounds=used + 1)
            _write_state(folder / "check-rounds.json", {"key": key, "rounds": used})
            if result.counts.fix_now:
                words += (" Run `polaris check` to see them." if no_followup or used == 0 else
                          f" The agent stopped after {CHECK_ROUNDS} rounds of fixes; run `polaris check` to see "
                          "what is left.")
            return _check_outcome(result.status, words, rounds=used)
    except LockBusy:
        return _check_outcome("busy", "Another Polaris check is running; this one was skipped.")


class _BoundedText(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self._bytes = 0
    def write(self, value: str) -> int:
        self._bytes += len(value.encode("utf-8"))
        if self._bytes > MAX_OUTPUT:
            raise IntegrationProblem("Workflow output exceeded its bound.")
        return super().write(value)


def _review_scope(root: Path) -> list[str]:
    """Paths the default workflow review selects: changes against HEAD plus untracked files."""
    output = git_bytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames",
                       "--ignore-submodules=dirty")
    return sorted({os.fsdecode(entry[3:]) for entry in output.split(b"\0") if len(entry) > 3})


def _review_snapshot(root: Path, semgrep: Path | None, scope: list[str] | None = None) -> ReviewSnapshot:
    """Bind the changed files and project configuration (not the whole repository).

    The scope is part of the snapshot's provenance, so a file that becomes changed, new or
    deleted while the review runs changes the digest and the result is reported stale.
    """
    selected = _review_scope(root) if scope is None else scope
    limits = scoped_limits(len(selected))
    if semgrep is None:
        return capture_snapshot(root, scope=selected, limits=limits)
    path = trusted_executable(semgrep)
    assert path is not None
    content = read_bytes(path, limit=20_000_000)
    if content is None:
        raise IntegrationProblem("Analyzer launcher disappeared during review.")
    versions = {**_installed_analysis(), "semgrep_launcher": str(path),
                "semgrep_launcher_digest": "sha256:" + hashlib.sha256(content).hexdigest()}
    return capture_snapshot(root, analyzer_versions=versions, scope=selected, limits=limits)


def _worker_main(argv: list[str] | None = None) -> int:
    """Internal offline worker: both snapshots and the entire workflow run share one deadline."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--semgrep", type=Path)
    args = parser.parse_args(argv)
    try:
        before = _review_snapshot(args.root, args.semgrep)
        output = _BoundedText()
        with redirect_stdout(output), redirect_stderr(_BoundedText()):
            try:
                from polaris.cli import main as cli

                code = cli(["workflow", "review", "--format", "json", "--root", str(args.root),
                            *(["--semgrep", str(args.semgrep)] if args.semgrep is not None else [])])
            except (ImportError, SystemExit):
                code = 2
        after = _review_snapshot(args.root, args.semgrep)
        if code not in (0, 1):
            summary = problem_summary("unavailable", "Versioned workflow review is unavailable or failed.")
        else:
            try:
                envelope = json.loads(output.getvalue())
                summary = compact_report(envelope) if isinstance(envelope, dict) else problem_summary(
                    "error", "Workflow result isn't an object.")
            except (ValueError, UnicodeError, RecursionError):
                summary = problem_summary("error", "Workflow output is invalid.")
        if before.digest != after.digest:
            summary["status"] = "stale"
            summary["unreviewed"].append("Content or review provenance changed during analysis.")
        elif not is_fresh(before, after):
            summary["status"] = "incomplete"
            summary["unreviewed"].append("Snapshot has omitted, unreadable, or oversized content.")
        snapshot = {key: value for key, value in after.to_dict().items()
                    if key not in ("files", "root", "git_dir")}
        print(json.dumps({"summary": summary, "snapshot": snapshot}, ensure_ascii=True))
        return 0
    except Exception:
        # Reviewed source/configuration can appear in arbitrary exception messages: never emit them.
        return 2


def host_output(host: str, event: str, outcome: Mapping[str, Any]) -> dict[str, Any]:
    if event == "dirty":
        return {}
    if event == "check":
        handed = outcome.get("handback")
        if host == "claude-code":
            return {"decision": "block", "reason": handed} if handed else {"systemMessage": outcome["message"]}
        return {"followup_message": handed} if handed else {}
    text = render_summary(outcome["summary"])
    if host == "claude-code":
        if outcome.get("followup"):
            return {"decision": "block", "reason": FOLLOWUP + text}
        return {"systemMessage": text}
    return {"followup_message": FOLLOWUP + text} if outcome.get("followup") else {}


def run(args: argparse.Namespace) -> int:
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
        if len(raw.encode("utf-8")) > MAX_INPUT:
            raise IntegrationProblem("Hook input exceeded its byte bound.")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise IntegrationProblem("Hook input isn't an object.")
        if args.event == "check":
            outcome = run_check_hook(args.root, host=args.host, payload=payload, timeout=args.timeout,
                                     no_followup=args.no_followup)
        else:
            outcome = run_hook(args.root, host=args.host, event=args.event, payload=payload,
                               timeout=args.timeout, retries=args.retries, no_followup=args.no_followup,
                               semgrep=args.semgrep)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        problem = "Invalid hook input, root, or local state."
        outcome = (_check_outcome("unavailable", f"Polaris didn't check: {problem}") if args.event == "check" else
                   {"summary": problem_summary("unavailable", problem), "followup": False})
        print(_user_text(args.event, outcome), file=sys.stderr)
        print(json.dumps(host_output(args.host, args.event, outcome), ensure_ascii=True))
        return 1
    if args.event != "dirty":
        print(_user_text(args.event, outcome), file=sys.stderr)
    print(json.dumps(host_output(args.host, args.event, outcome), ensure_ascii=True))
    return 0


def _user_text(event: str, outcome: Mapping[str, Any]) -> str:
    return str(outcome["message"]) if event == "check" else render_summary(outcome["summary"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    add_agent_hook_parsers(commands)
    return run(parser.parse_args(["agent-hook", *(argv if argv is not None else sys.argv[1:])]))


if __name__ == "__main__":
    raise SystemExit(main())

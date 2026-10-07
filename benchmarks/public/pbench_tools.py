"""Runners for Polaris and the optional comparison tools.

Polaris runs through its own CLI (`polaris workflow review --format sarif`) with a minimal
environment: no provider keys, no user settings, no external analyzers, no network use.

Semgrep CE and zizmor run only through `uv tool run --from <name>==<pinned version>`, which uses
an isolated, cached environment inside the benchmark cache folder. Nothing is installed globally
and no sudo is used. Their versions and rule sets are pinned here and recorded in every report.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pbench_core import sha256_hex

SEMGREP_VERSION = "1.179.0"
SEMGREP_RULES_URL = "https://github.com/semgrep/semgrep-rules.git"
SEMGREP_RULES_COMMIT = "a84ff9cc2453ca91d581380de4b8b3f272f6f4be"
SEMGREP_RULE_DIRS = ("javascript", "typescript")
ZIZMOR_TOOL_VERSION = "1.30.1"
RUN_TIMEOUT_SECONDS = 600


class ToolUnavailable(RuntimeError):
    """A tool could not be run (not installed in the cache, no network, timed out)."""


@dataclass
class RunResult:
    exit_code: int
    seconds: float
    sarif_path: Path
    sarif_sha256: str
    document: dict[str, Any] | None
    note: str = ""


def clean_environment(home: Path, **extra: str) -> dict[str, str]:
    """Only what a subprocess needs: PATH, an isolated HOME and fixed locale. No keys, no config."""
    home.mkdir(parents=True, exist_ok=True)
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
            "PYTHONHASHSEED": "0", **extra}


def _read(path: Path) -> tuple[dict[str, Any] | None, str]:
    if not path.exists():
        return None, ""
    data = path.read_bytes()
    try:
        document = json.loads(data)
    except ValueError:
        return None, sha256_hex(data)
    return (document if isinstance(document, dict) else None), sha256_hex(data)


def run_polaris(root: Path, files: list[str], out: Path, home: Path, *, timeout: float = RUN_TIMEOUT_SECONDS) -> RunResult:
    """Review `files` of the Git worktree `root` with the Polaris CLI and write SARIF to `out`.

    Exit code 0 (clean), 1 (flagged) and 2 (incomplete coverage) all produce a report; any other
    exit code, a timeout or an unreadable report is returned with `document=None`.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    command = [sys.executable, "-P", "-m", "polaris", "workflow", "review", "--root", str(root), "--files", *files,
               "--format", "sarif", "--output", str(out), "--no-external-analyzers"]
    started = time.perf_counter()
    try:
        # cwd is the isolated home, not the reviewed project, and -P keeps the cwd off sys.path, so a
        # project folder named `polaris` can never shadow the installed package.
        done = subprocess.run(command, cwd=home, env=clean_environment(home), capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return RunResult(-1, time.perf_counter() - started, out, "", None, f"timed out after {timeout:.0f}s")
    seconds = time.perf_counter() - started
    document, digest = _read(out)
    note = ""
    if done.returncode not in (0, 1, 2) or document is None:
        document = None
        note = f"exit {done.returncode}: {(done.stderr or done.stdout).strip()[-200:]}"
    return RunResult(done.returncode, seconds, out, digest, document, note)


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        raise ToolUnavailable("uv is not on PATH; it is needed to run Semgrep CE or zizmor in an isolated environment")
    return uv


def _tool_run(package: str, version: str, program: str, arguments: list[str], *, cwd: Path, cache: Path,
              timeout: float) -> subprocess.CompletedProcess[str]:
    """`uv tool run --from package==version program ...` with uv's cache kept inside the benchmark cache."""
    env = clean_environment(cache / "home", UV_CACHE_DIR=str(cache / "uv-cache"), UV_NO_CONFIG="1",
                            SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    command = [_uv(), "tool", "run", "--from", f"{package}=={version}", program, *arguments]
    try:
        return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as problem:
        raise ToolUnavailable(f"{program} timed out after {timeout:.0f}s") from problem


def tool_version(package: str, version: str, program: str, cache: Path) -> str:
    done = _tool_run(package, version, program, ["--version"], cwd=cache, cache=cache, timeout=900)
    if done.returncode != 0:
        raise ToolUnavailable(f"{program} --version failed: {(done.stderr or done.stdout).strip()[-200:]}")
    return done.stdout.strip().splitlines()[-1] if done.stdout.strip() else ""


def run_semgrep(root: Path, files: list[str], out: Path, rules: Path, cache: Path, *,
                timeout: float = RUN_TIMEOUT_SECONDS) -> RunResult:
    """Semgrep CE with the pinned rule folders, on the given files only, SARIF to `out`."""
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    configs: list[str] = []
    for folder in SEMGREP_RULE_DIRS:
        configs += ["--config", str(rules / folder)]
    arguments = ["scan", *configs, "--sarif", "--output", str(out), "--metrics=off", "--disable-version-check",
                 "--quiet", "--no-git-ignore", "--timeout", "30", *files]
    started = time.perf_counter()
    done = _tool_run("semgrep", SEMGREP_VERSION, "semgrep", arguments, cwd=root, cache=cache, timeout=timeout)
    seconds = time.perf_counter() - started
    document, digest = _read(out)
    note = ""
    if done.returncode not in (0, 1) or document is None:
        document = None
        note = f"exit {done.returncode}: {(done.stderr or done.stdout).strip()[-200:]}"
    return RunResult(done.returncode, seconds, out, digest, document, note)


def run_zizmor(root: Path, out: Path, cache: Path, *, timeout: float = RUN_TIMEOUT_SECONDS) -> RunResult:
    """zizmor, offline (its network audits need a GitHub token and are skipped), on `root`."""
    out.parent.mkdir(parents=True, exist_ok=True)
    arguments = ["--format", "sarif", "--offline", "--no-exit-codes", "--no-progress", str(root)]
    started = time.perf_counter()
    done = _tool_run("zizmor", ZIZMOR_TOOL_VERSION, "zizmor", arguments, cwd=root, cache=cache, timeout=timeout)
    seconds = time.perf_counter() - started
    if done.stdout.strip():
        out.write_text(done.stdout)
    document, digest = _read(out)
    note = ""
    if done.returncode != 0 or document is None:
        document = None
        note = f"exit {done.returncode}: {(done.stderr or done.stdout).strip()[-200:]}"
    return RunResult(done.returncode, seconds, out, digest, document, note)


def fetch_semgrep_rules(cache: Path, home: Path) -> Path:
    """The pinned rule repository, checked out under the cache (sparse: only the rule folders used)."""
    from pbench_datasets import checkout, fetch_commit, run_git

    destination = cache / "datasets" / "semgrep-rules"
    fetch_commit(SEMGREP_RULES_URL, SEMGREP_RULES_COMMIT, destination, home, blobless=True)
    run_git(["sparse-checkout", "set", "--no-cone", *(f"/{name}/" for name in SEMGREP_RULE_DIRS), "/LICENSE"],
            destination, home)
    checkout(destination, SEMGREP_RULES_COMMIT, home)
    return destination

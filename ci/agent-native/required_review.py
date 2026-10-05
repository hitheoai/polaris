"""CI launcher template: provision an audited copy OUTSIDE the candidate checkout.

Only a protected control plane may provision the installation, request, policy, and
read-only Git input. These templates do not install or authenticate that control plane.
No third-party imports, shell execution, downloads, or candidate scripts are used here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

INSTALL = Path("/opt/polaris-ci")
CONTROL = Path("/etc/polaris-ci")
INPUT = Path("/var/lib/polaris-ci/input")
PYTHON = INSTALL / "reviewer/bin/python"
SEMGREP = INSTALL / "semgrep/bin/semgrep"
GIT = Path("/usr/bin/git")
CHECKS = "sql_injection,command_injection,secret_exposure,path_traversal,unsafe_security_configuration"
SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMGREP_VERSION = "1.178.0"
SEMGREP_DISTRIBUTION = "1.178.0+theovex.1"
ANALYZER_CONTRACT_DIGEST = "sha256:d47d50c73ed61f8f62cdeaf48497a52c063c429aa22b37ddfd25f105ae8f975d"


class Refused(Exception):
    """Only constant, non-sensitive error codes may leave this launcher."""


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def root_owned(path: Path) -> None:
    """The job is non-root; every component must be non-link, root-owned, and non-writable."""
    if not path.is_absolute():
        raise Refused("untrusted_control_path")
    for component in reversed((path, *path.parents)):
        info = component.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode)
                or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
            raise Refused("untrusted_control_path")


def bounded_bytes(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Refused("input_limit")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise Refused("input_limit")
    return content


def control_json(name: str) -> dict[str, Any]:
    path = CONTROL / name
    root_owned(path)
    value = json.loads(bounded_bytes(path, 262_144))
    if not isinstance(value, dict):
        raise Refused("invalid_control_record")
    return value


def tree_digest(root: Path) -> str:
    """Pin complete non-editable installation trees, not just a mutable version label.

    This intentionally rejects symlink-based environments: provision copied/dereferenced
    immutable trees. The system interpreter/stdlib/OS are separately trusted runner inputs.
    """
    root_owned(root)
    entries: list[tuple[str, str]] = []
    total = 0
    started = time.monotonic()
    pending = [root]
    visited = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                visited += 1
                if visited > 50_000 or time.monotonic() - started > 60:
                    raise Refused("installation_inventory_limit")
                path = Path(child.path)
                root_owned(path)
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                remaining = 2_000_000_000 - total
                content = bounded_bytes(path, min(remaining, 250_000_000))
                total += len(content)
                entries.append((path.relative_to(root).as_posix(), digest(content)))
    return digest(canonical(sorted(entries)))


def validate_installation(pins: dict[str, Any]) -> None:
    if (pins.get("format") != "polaris.ci-installation/0.1.0"
            or pins.get("approved") is not True
            or pins.get("semgrep_version") != SEMGREP_VERSION
            or pins.get("semgrep_distribution_version") != SEMGREP_DISTRIBUTION
            or pins.get("analyzer_contract_digest") != ANALYZER_CONTRACT_DIGEST
            or pins.get("setuptools_version") != "83.0.0"):
        raise Refused("unapproved_installation")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise Refused("qualified_analyzer_platform_unavailable")
    for field, root in (("reviewer_tree_digest", INSTALL / "reviewer"),
                        ("semgrep_tree_digest", INSTALL / "semgrep")):
        expected = pins.get(field)
        if not isinstance(expected, str) or not DIGEST.fullmatch(expected) or tree_digest(root) != expected:
            raise Refused("installation_digest_mismatch")
    for executable in (PYTHON, SEMGREP, GIT):
        root_owned(executable)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise Refused("trusted_executable_unavailable")
    root_owned(Path(__file__).absolute())
    if digest(bounded_bytes(Path(__file__).absolute(), 262_144)) != pins.get("launcher_digest"):
        raise Refused("launcher_digest_mismatch")
    if not Path("/usr/bin/sandbox-exec").is_file():
        raise Refused("network_sandbox_unavailable")


def validate_request(args: argparse.Namespace, request: dict[str, Any]) -> None:
    for value in (args.base_sha, args.head_sha):
        if not SHA.fullmatch(value) or set(value) == {"0"}:
            raise Refused("invalid_exact_revision")
    if not re.fullmatch(r"[0-9]+:[0-9]+", args.run_id):
        raise Refused("invalid_run_identity")
    if request.get("format") != "polaris.ci-request/0.1.0":
        raise Refused("invalid_control_record")
    for key in ("provider", "repository", "run_id", "base_sha", "head_sha"):
        if request.get(key) != getattr(args, key):
            raise Refused("request_identity_mismatch")
    issued, expires = request.get("issued_at"), request.get("expires_at")
    if (type(issued) is not int or type(expires) is not int
            or not issued <= time.time() <= expires or not 0 < expires - issued <= 3600):
        raise Refused("expired_control_request")
    authorization = request.get("authorization")
    if authorization == "not_requested" and "guard_policy_digest" in request and request["guard_policy_digest"] is None:
        return
    if authorization == "guard_regressions" and isinstance(request.get("guard_policy_digest"), str):
        if DIGEST.fullmatch(request["guard_policy_digest"]):
            return
    raise Refused("explicit_authorization_selection_required")


def environment(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home),
        "POLARIS_HOME": str(home), "XDG_CONFIG_HOME": str(home),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1",
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_ALLOW_PROTOCOL": "",
        "GIT_PAGER": "cat", "LC_ALL": "C",
    }


def git_value(arguments: list[str], home: Path) -> bytes:
    # These commands return only object IDs or config key names, never config values/source.
    command = [str(GIT), "--no-pager", "-C", str(INPUT),
               "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-c", "diff.external=", "-c", "credential.helper=", "-c", "protocol.allow=never",
               *arguments]
    result = subprocess.run(command, cwd=home, env=environment(home), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                            check=False)
    if result.returncode or len(result.stdout) > 65_536:
        raise Refused("git_input_unavailable")
    return result.stdout


def validate_repository(args: argparse.Namespace, home: Path) -> None:
    # Git rejects a root-owned worktree for a non-root reviewer when global config is off.
    # The control plane therefore mounts a job-UID-owned tree read-only at this fixed path.
    root_owned(INPUT.parent)
    for path in (INPUT, INPUT / ".git"):
        if (path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.geteuid()
                or not os.statvfs(path).f_flag & os.ST_RDONLY):
            raise Refused("immutable_input_required")
    info = (INPUT / ".git/config").lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65_536:
        raise Refused("nonminimal_git_configuration")
    keys = git_value(["config", "--local", "--name-only", "--list"], home).decode("ascii").splitlines()
    allowed = {"core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
               "core.ignorecase", "core.precomposeunicode", "extensions.objectformat"}
    if any(key.lower() not in allowed for key in keys):
        raise Refused("nonminimal_git_configuration")
    for name in ("objects/info/alternates", "info/grafts", "shallow"):
        if (INPUT / ".git" / name).exists():
            raise Refused("incomplete_or_redirected_objects")
    for revision in (args.base_sha, args.head_sha):
        resolved = git_value(["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"], home)
        if resolved.strip().decode("ascii") != revision:
            raise Refused("exact_revision_unavailable")
    if git_value(["rev-parse", "--verify", "HEAD"], home).strip().decode("ascii") != args.head_sha:
        raise Refused("head_checkout_mismatch")


def review_command(args: argparse.Namespace, output: Path, *, guard_policy: bool) -> list[str]:
    command = [str(PYTHON), "-I", "-B", "-m", "polaris", "workflow", "review",
               "--root", str(INPUT), "--diff", f"{args.base_sha}..{args.head_sha}",
               "--checks", CHECKS + (",api_authorization" if guard_policy else ""),
               "--require-complete", "--semgrep", str(SEMGREP),
               "--format", "json", "--output", str(output / "review.json")]
    if guard_policy:
        command.extend(("--guard-policy", str(CONTROL / "guard-policy.json")))
    return command


def run_review(command: list[str], home: Path) -> int:
    process = subprocess.Popen(command, cwd=home, env=environment(home), stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        return process.wait(timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise Refused("review_timeout") from exc
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def report_gate(report: dict[str, Any], expected_head: str) -> bool:
    review = report.get("review", {})
    snapshot = report.get("snapshot", {})
    analyzers = review.get("capabilities", {}).get("analyzers", [])
    return bool(
        report.get("format") == "polaris.workflow/0.1.0"
        and report.get("status") == "complete" and report.get("finding_count") == 0
        and snapshot.get("kind") == "git_revision" and snapshot.get("head") == expected_head
        and snapshot.get("complete") is True and snapshot.get("fresh") is True
        and review.get("format") == "polaris.review/0.2.0"
        and review.get("coverage", {}).get("complete") is True
        and all(item.get("result") == "ok" for item in review.get("findings", []))
        and any(item.get("analyzer_id") == "semgrep-ce" and item.get("availability") == "available"
                and item.get("version") == SEMGREP_VERSION
                and item.get("distribution_version") == SEMGREP_DISTRIBUTION
                and item.get("identity_digest") == ANALYZER_CONTRACT_DIGEST for item in analyzers)
    )


def private_json(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical(value) + b"\n")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--provider", choices=("github", "gitlab"), required=True)
    for name in ("repository", "run-id", "base-sha", "head-sha"):
        result.add_argument("--" + name, required=True)
    result.add_argument("--output-dir", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    output = args.output_dir
    if (not output.is_absolute() or output.resolve() != output
            or any(output.is_relative_to(root) for root in (INPUT, INSTALL, CONTROL))):
        return 2
    try:
        output.mkdir(mode=0o700)  # Never overwrite old artifacts or follow candidate links.
    except OSError:
        return 2
    status: dict[str, Any] = {"format": "polaris.ci-status/0.1.0", "status": "unavailable",
                              "behavior": "not_run", "exit_code": 2}
    code = 2
    try:
        if os.geteuid() == 0:
            raise Refused("nonroot_isolated_runner_required")
        request = control_json("request.json")
        validate_request(args, request)
        pins = control_json("installation.json")
        validate_installation(pins)
        guard_policy = request["authorization"] == "guard_regressions"
        policy_digest = None
        if guard_policy:
            policy = CONTROL / "guard-policy.json"
            root_owned(policy)
            policy_digest = digest(bounded_bytes(policy, 256_000))
            if policy_digest != request["guard_policy_digest"]:
                raise Refused("guard_policy_digest_mismatch")
        with tempfile.TemporaryDirectory(prefix="polaris-required-review-") as temporary:
            home = Path(temporary)
            validate_repository(args, home)
            result = run_review(review_command(args, output, guard_policy=guard_policy), home)
            report = json.loads(bounded_bytes(output / "review.json", 16_000_000))
            accepted = isinstance(report, dict) and report_gate(report, args.head_sha)
            code = 0 if result == 0 and accepted else 1 if result == 1 else 2
        status.update(status="complete" if code == 0 else "failed", exit_code=code,
                      base_sha=args.base_sha, head_sha=args.head_sha,
                      request_digest=digest(canonical(request)),
                      installation_digest=digest(canonical(pins)), guard_policy_digest=policy_digest,
                      authorization=request["authorization"],
                      report_digest=digest(bounded_bytes(output / "review.json", 16_000_000)))
    except Refused as exc:
        code = 2
        status["reason"] = str(exc)
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError):
        code = 2
        status["reason"] = "trusted_review_unavailable"
    status["exit_code"] = code
    private_json(output / "status.json", status)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

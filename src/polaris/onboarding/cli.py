"""Theo's customer entry point. The original Polaris CLI remains unchanged."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any, NoReturn

from polaris import __version__
from polaris.integrations._safe import IntegrationProblem, read_bytes
from polaris.onboarding import FORMAT, HOSTS
from polaris.onboarding import state as storage
from polaris.onboarding.auth import DATA_BOUNDARY, activate, endpoint
from polaris.onboarding.errors import OnboardingProblem
from polaris.onboarding.hosts import choose_host
from polaris.onboarding.installation import analyzer, managed_installation
from polaris.onboarding.terminal import Terminal


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse normally echoes unrecognized arguments, which might be a pasted credential.
        raise OnboardingProblem("invalid_arguments", "Invalid Theo arguments. Use `theo --help`; never pass an API key as an argument.")


def _common(command: argparse.ArgumentParser, *, host: bool = True) -> None:
    command.add_argument("--project", type=Path, default=Path.cwd(), help="The existing project folder.")
    if host:
        command.add_argument("--host", choices=("auto", *HOSTS), default="auto")
    command.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="One JSON result; no banner or progress.")


def _authentication(command: argparse.ArgumentParser) -> None:
    command.add_argument("--auth", choices=("auto", "terminal", "browser"), default="auto",
                         help="Private key input; auto opens a local browser form without a TTY.")
    command.add_argument("--auth-timeout", type=float, default=180, help="Private browser form lifetime in seconds (1–600).")


def parser() -> Parser:
    root = Parser(prog="theo", description="Theo connects Polaris to your coding host, without changing its permissions.")
    root.add_argument("--version", action="version", version=f"Theo {__version__}")
    root.add_argument("--json", action="store_true", help="Machine-readable output.")
    commands = root.add_subparsers(dest="command", required=True, parser_class=Parser)
    setup = commands.add_parser("setup", help="Activate and configure Polaris for this project (or --global).")
    _common(setup)
    mode = setup.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true", help="Explicit rules-only mode; no credentials or hosted egress.")
    mode.add_argument("--api-url", help="Explicit approved Polaris API origin; authentication and model readiness are required.")
    setup.add_argument("--global", dest="global_scope", action="store_true",
                       help="One local server for every project (user-level host configuration).")
    setup.add_argument("--with-semgrep", action="store_true",
                       help="Also run the bundled Semgrep CE (optional; built-in analyzers cover all checks).")
    _authentication(setup)
    setup.add_argument("--dry-run", action="store_true", help="Preview project setup; no activation, writes or probes.")
    status = commands.add_parser("status", help="Read the saved setup state without contacting an API or editor.")
    _common(status)
    doctor = commands.add_parser("doctor", help="Run local MCP/rules/analyzer checks; never contact the hosted API.")
    _common(doctor)
    doctor.add_argument("--timeout", type=float, default=20)
    review = commands.add_parser("review", help="Review changed code with local static analysis; no hosted inference.")
    _common(review, host=False)
    scope = review.add_mutually_exclusive_group()
    scope.add_argument("--files", type=Path, nargs="+")
    scope.add_argument("--staged", action="store_true")
    scope.add_argument("--diff")
    review.add_argument("--require-complete", action="store_true")
    review.add_argument("--include", action="append")
    review.add_argument("--exclude", action="append")
    review.add_argument("--with-semgrep", action="store_true",
                        help="Also run the bundled Semgrep CE (optional, slower).")
    auth = commands.add_parser("auth", help="Activate a configured endpoint using private key input.")
    auth.add_argument("--api-url", required=True)
    auth.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    _authentication(auth)
    logout = commands.add_parser("logout", help="Remove the private saved credential, leaving project configuration intact.")
    logout.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    disconnect = commands.add_parser("disconnect", help="Restore only unchanged Theo-owned project edits from private backups.")
    _common(disconnect)
    disconnect.add_argument("--yes", action="store_true", help="Confirm scoped restoration; never deletes a runtime or unrelated settings.")
    installation = commands.add_parser("installation", help="Inspect this CLI package without a project, credentials or network.")
    installation.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    uninstall = commands.add_parser("uninstall", help="Preview removal of this standalone runtime; Homebrew remains brew-managed.")
    uninstall.add_argument("--yes", action="store_true", help="Remove only unchanged owned runtime files and commands.")
    uninstall.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    return root



def _configure(host: str, root: Path, *, semgrep: Path | None, model_source: str,
               dry_run: bool, api_url: str | None = None) -> dict[str, Any]:
    from polaris.integrations import setup

    configure = getattr(setup, "configure_project", None)
    if configure is None:
        raise OnboardingProblem("connector_unavailable", "This installation lacks Theo's structured editor connector. Install the matching complete Theo release.")
    result: dict[str, Any] = configure(
        host, root, semgrep=semgrep, model_source=model_source,
        engine="rules" if model_source == "local" else "hybrid", dry_run=dry_run, api_url=api_url,
    )
    if (result.get("format") != "polaris.setup/1" or result.get("target") != host
            or result.get("project") != str(root) or result.get("host_verified") is not False
            or result.get("status") not in ("preview", "configured", "unchanged")):
        raise OnboardingProblem("connector_scope", "The connector did not confirm this exact project root. Use --project with the worktree root; no host verification is claimed.")
    storage.changed_paths(root, result.get("changed_files"))
    return result


def _mode(args: argparse.Namespace) -> str:
    if args.local:
        return "local"
    if args.api_url:
        endpoint(args.api_url)
        return "remote"
    if sys.stdin.isatty() and not args.json:
        print("No hosted API endpoint is configured. Type 'local' to use rules-only mode, "
              "or cancel and supply your approved --api-url: ", end="", file=sys.stderr, flush=True)
        if sys.stdin.readline(32).strip().lower() == "local":
            return "local"
    raise OnboardingProblem("mode_required", "Choose --local for rules-only setup, or --api-url with your approved hosted endpoint. No public API deployment or silent fallback is assumed.")


def _next_action(result: dict[str, Any]) -> str:
    action = result.get("next_action")
    if isinstance(action, str) and action and len(action) <= 2000 and all(
        character.isprintable() or character == "\n" for character in action
    ):
        return action
    return "Approve or refresh the Polaris server in your coding host using its normal permissions."


def _setup_global(args: argparse.Namespace, terminal: Terminal) -> int:
    """User-level local setup: no project, no prompt, no credentials."""
    from polaris.integrations import setup

    if args.api_url:
        raise OnboardingProblem("global_local_only", "Global setup is local rules-only; configure hosted mode per project with --api-url.")
    host = choose_host(args.host)
    semgrep = analyzer() if args.with_semgrep else None
    result = setup.configure_global(host, semgrep=semgrep, dry_run=args.dry_run)
    terminal.result(
        {**result, "format": FORMAT, "command": "setup", "activation": "not_requested"},
        [
            ("Preview: " if args.dry_run else "") + f"Polaris {result['status']} for {host} in every project "
            "(local static analysis; no credential read).",
            *[f"Changed: {path}" for path in result["changed_files"]],
            *[f"Note: {note}" for note in result.get("notes", [])],
            f"Next: {_next_action(result)}",
        ],
    )
    return 0


def _setup(args: argparse.Namespace, terminal: Terminal) -> int:
    if getattr(args, "global_scope", False):
        return _setup_global(args, terminal)
    source = _mode(args)
    root = storage.project_root(args.project)
    host = choose_host(args.host)
    terminal.banner()
    terminal.stage(1, "Checking your project and local installation")
    # Semgrep is opt-in: the built-in analyzers cover every check on their own.
    semgrep = analyzer() if getattr(args, "with_semgrep", False) else None
    api_url = endpoint(args.api_url) if args.api_url else None
    preview = _configure(host, root, semgrep=semgrep, model_source=source, dry_run=True, api_url=api_url)
    if args.dry_run:
        terminal.result({**preview, "format": FORMAT, "command": "setup", "activation": "not_checked"},
                        ["Theo setup preview. No activation, project changes or health probes were performed.",
                         f"Next: {_next_action(preview)}"])
        return 0
    with storage.project_lock(root, host):
        record = storage.read_record(root, host) or {}
        terminal.stage(2, "Using explicit local rules-only mode" if source == "local" else "Activating Polaris privately")
        activation: dict[str, Any] = {"status": "not_requested", "auth_verified": False, "model_ready": False}
        if source == "remote":
            if not args.json:
                print(DATA_BOUNDARY, file=sys.stderr)
            activation = activate(api_url or "", project=root, method=args.auth,
                                  timeout=args.auth_timeout, notify=terminal.private_handoff)
        paths = storage.changed_paths(root, preview["changed_files"])
        previous = record.get("snapshots", []) if record.get("stage") != "disconnected" else []
        for item in previous:
            current = read_bytes(storage.changed_paths(root, [item["path"]])[0])
            digest = hashlib.sha256(current).hexdigest() if current is not None else None
            expected = item.get("after_sha256") or item.get("before_sha256")
            mode_changed = current is not None and item.get("after_mode") is not None and (
                storage.changed_paths(root, [item["path"]])[0].stat().st_mode & 0o777 != item["after_mode"])
            if digest != expected or mode_changed:
                # Preserve later unrelated edits, including edits during an interrupted setup.
                # Never adopt them into an undo operation that would restore an older whole file.
                item["recoverable"] = False
        snapshots = storage.snapshots(root, host, paths, previous)
        record = {
            **record, "stage": "configuring", "model_source": source, "snapshots": snapshots,
            "activation": activation, "host_verified": False,
        }
        storage.write_record(root, host, record)
        terminal.stage(3, "Connecting the project and checking local MCP health")
        result = _configure(host, root, semgrep=semgrep, model_source=source, dry_run=False, api_url=api_url)
        if not set(storage.changed_paths(root, result["changed_files"])) <= set(paths):
            raise OnboardingProblem("connector_changed", "The connector change set differed from its preview. Run doctor before recovery.")
        record["snapshots"] = storage.seal_snapshots(root, snapshots)
        record["stage"] = "configured"
        record["next_action"] = _next_action(result)
        storage.write_record(root, host, record)
        from polaris.integrations.doctor import diagnose

        health = diagnose(root, target=host, semgrep=semgrep)
        ready = health.get("status") == "ready_for_host_verification"
        record["stage"] = "ready_for_host_verification" if ready else "local_health_incomplete"
        record["local_health"] = health.get("status", "incomplete")
        storage.write_record(root, host, record)
    summary = {
        "format": FORMAT, "command": "setup", "project": str(root), "host": host,
        "status": record["stage"], "model_source": source, "activation": activation,
        "configuration": result["status"], "changed_files": result["changed_files"],
        "local_health": health, "host_verified": False, "next_action": record["next_action"],
    }
    lines = [
        "Polaris is configured. Local MCP checks passed." if ready else
        "Polaris is configured, but local checks need attention. Run `theo doctor` for the precise check.",
        "Mode: local rules only; no credential was read." if source == "local" else
        "Hosted authentication and model availability verified; workflow review remains local static analysis.",
        "Your editor connection is not yet verified; its normal trust and tool permissions are unchanged.",
        f"Next: {record['next_action']}",
    ]
    terminal.result(summary, lines)
    return 0 if ready else 1


def _status(args: argparse.Namespace, terminal: Terminal) -> int:
    root = storage.project_root(args.project)
    host = choose_host(args.host)
    record = storage.read_record(root, host)
    value = {
        "format": FORMAT, "command": "status", "installation": managed_installation(),
        "project": str(root), "host": host, "status": record.get("stage") if record else "not_configured",
        "model_source": record.get("model_source") if record else None,
        "local_health": record.get("local_health") if record else "not_checked",
        "activation": "previously_verified_not_rechecked" if record and record.get("activation", {}).get("auth_verified") else "not_verified",
        "host_verified": False, "network_used": False,
    }
    terminal.result(value, [
        f"Theo: {value['status']}.",
        f"Mode: {value['model_source'] or 'not selected'}. Local health: {value['local_health']}.",
        "Saved state only; no live API or native host connection was checked.",
        f"Next: {record.get('next_action', 'Run theo setup with an explicit mode.')}" if record else
        "Next: run `theo setup --project PATH --host HOST --local`, or supply your approved --api-url.",
    ])
    return 0 if record else 1


def _doctor(args: argparse.Namespace, terminal: Terminal) -> int:
    from polaris.integrations.doctor import diagnose

    root = storage.project_root(args.project)
    host = choose_host(args.host)
    report = diagnose(root, target=host, timeout=args.timeout, semgrep=analyzer())
    terminal.result(
        {"format": FORMAT, "command": "doctor", "host_verified": False, "remote_auth": "not_checked", "local_health": report},
        [f"Theo local health: {report['status']}.", *[
            f"  {name}: {check['status']} — {check['message']}" for name, check in report["checks"].items()
        ], "Hosted activation and native host approval are separate; neither was tested."],
    )
    return 0 if report.get("status") == "ready_for_host_verification" else 1


def _review(args: argparse.Namespace) -> int:
    from polaris.cli import main as polaris

    root = storage.project_root(args.project)
    command = ["workflow", "review", "--root", str(root), "--format", "json" if args.json else "text"]
    if getattr(args, "with_semgrep", False):
        semgrep = analyzer()
        if semgrep is None:
            raise OnboardingProblem("analyzer_unavailable", "--with-semgrep needs the bundled analyzer; reinstall Theo or omit the flag.")
        command += ["--semgrep", str(semgrep)]
    if args.files:
        command += ["--files", *map(str, args.files)]
    if args.staged:
        command += ["--staged"]
    if args.diff:
        command += ["--diff", args.diff]
    if args.require_complete:
        command += ["--require-complete"]
    for option in ("include", "exclude"):
        for value in getattr(args, option) or []:
            command += [f"--{option}", value]
    return polaris(command)


def main(argv: list[str] | None = None) -> int:
    from polaris.integrations.setup import Refused, SetupProblem

    arguments = argv if argv is not None else sys.argv[1:]
    terminal = Terminal(json_output="--json" in arguments)
    try:
        args = parser().parse_args(arguments)
        if args.command == "uninstall":
            from polaris.onboarding.lifecycle import uninstall

            removal = uninstall(confirm=args.yes)
            terminal.result(
                {"format": FORMAT, "command": "uninstall", **removal},
                [f"Theo removal: {removal['status']}.", removal["next_action"],
                 "Projects, editor configuration, credentials, profiles and older releases were not removed."],
            )
            return 0
        if args.command == "installation":
            installation = managed_installation()
            semgrep = analyzer()
            terminal.result(
                {"format": FORMAT, "command": "installation", **installation,
                 "analyzer": str(semgrep) if semgrep else None, "network_used": False},
                [f"Polaris {__version__}: {installation['manager']} installation.",
                 "Bundled analyzer available." if semgrep else
                 "No managed analyzer. Supply your trusted separate analyzer with --semgrep.",
                 "No project, editor, hosted API or native acceptance was checked."],
            )
            return 0
        if args.command == "setup":
            return _setup(args, terminal)
        if args.command == "status":
            return _status(args, terminal)
        if args.command == "doctor":
            return _doctor(args, terminal)
        if args.command == "review":
            return _review(args)
        if args.command == "auth":
            result = activate(args.api_url, method=args.auth, timeout=args.auth_timeout, notify=terminal.private_handoff)
            terminal.result({"format": FORMAT, "command": "auth", **result},
                            ["Polaris authentication and model availability verified.", DATA_BOUNDARY])
            return 0
        if args.command == "logout":
            from polaris.remote import delete_credentials

            removed = delete_credentials()
            terminal.result({"format": FORMAT, "command": "logout", "removed": removed},
                            ["Saved Polaris credential removed." if removed else "No saved Polaris credential to remove.",
                             "Project configuration is unchanged. Environment-provided credentials are not removed."])
            return 0
        if args.command == "disconnect":
            if not args.yes:
                raise OnboardingProblem("confirmation_required", "Rerun with --yes to restore only unchanged Theo-owned project edits. Credentials, runtime and unrelated settings are retained.")
            root, host = storage.project_root(args.project), choose_host(args.host)
            with storage.project_lock(root, host):
                record = storage.read_record(root, host)
                count = storage.restore(root, host, record) if record else 0
            terminal.result({"format": FORMAT, "command": "disconnect", "restored_files": count, "host_verified": False},
                            [f"Restored {count} unchanged Theo-managed project files. Runtime and credentials were retained.",
                             "Refresh the server list in your host; a running host connection was not inspected."])
            return 0
    except OnboardingProblem as exc:
        problem = exc
    except (SetupProblem, Refused):
        problem = OnboardingProblem("connector_refused", "Theo could not safely merge the project configuration. Existing settings were preserved; run `polaris setup HOST --project PATH --dry-run` for the connector's safe diagnostic.")
    except (IntegrationProblem, OSError, ValueError, KeyError, TypeError):
        problem = OnboardingProblem("local_check_failed", "A local safety or compatibility check failed. No completed connection is claimed. Run `theo doctor` or rerun the verified installer; existing files are retained.")
    except KeyboardInterrupt:
        problem = OnboardingProblem("interrupted", "Theo was interrupted. Rerun the same command to resume; no completed connection is claimed.", exit_code=130)
    else:
        return 0
    terminal.result({"format": FORMAT, "status": "error", "code": problem.code, "message": problem.message, "host_verified": False},
                    [f"Theo: {problem.message}"])
    return problem.exit_code

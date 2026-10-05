"""Read-only editor diagnostics. Never execute commands copied from repository configuration."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from polaris.integrations._safe import (
    IntegrationProblem,
    module_command,
    offline_environment,
    run_bounded,
    trusted_executable,
)
from polaris.integrations.setup import (
    EDITOR_SETUP,
    EDITORS,
    RULE_END,
    RULE_START,
    SetupProblem,
    _json_object,
    _project,
    _read,
    _setup_origin,
    _toml_object,
    effective_rule_path,
    is_polaris_entry,
    warp_servers,
)

# Listed by default (what agents see); the advanced workflow tools answer by name either way.
EXPECTED_TOOLS = frozenset({"polaris_check", "polaris_explain", "polaris_fix"})
WORKFLOW_TOOLS = frozenset({"review_workflow", "review_snippet", "explain_finding", "review_details",
                            "propose_repair", "review_action"})
Probe = Callable[[Path, float], dict[str, Any]]
BOOTSTRAP_PACKAGE = re.compile(r"sys\.path\.insert\(0, (['\"])(?P<path>[^'\"\n]{1,4096})\1\)")
MAX_INSPECTED_CONFIG = 8_000_000
# Which configuration files each host reads (Warp: file-based discovery of Claude Code and Codex
# configs, plus servers that may have been imported by hand from the legacy .warp/.mcp.json).
HOST_CONFIGS: dict[str, frozenset[str]] = {
    "warp": frozenset({".mcp.json", ".warp/.mcp.json", ".codex/config.toml", "~/.claude.json",
                       "~/.codex/config.toml"}),
    "claude-code": frozenset({".mcp.json", "~/.claude.json"}),
    "cursor": frozenset({".cursor/mcp.json", "~/.cursor/mcp.json"}),
    "codex": frozenset({".codex/config.toml", "~/.codex/config.toml"}),
    "vscode": frozenset({".vscode/mcp.json"}),
    "windsurf": frozenset(),
}
PROBLEM_TEXT = {
    "command_missing": "its command no longer exists",
    "command_not_on_path": "its command isn't on PATH",
    "package_missing": "it points to a Polaris installation that was removed",
    "root_missing": "its --root folder no longer exists",
    "analyzer_missing": "its --semgrep analyzer no longer exists",
    "ambiguous_options": "it repeats --root/--semgrep",
    "no_command": "it has no command",
}


def _config_locations(root: Path, home: Path) -> list[tuple[str, Path, str, str]]:
    """(label, path, format, scope) of the configurations supported hosts read."""
    return [
        (".mcp.json", root / ".mcp.json", "json", "project"),
        (".warp/.mcp.json", root / ".warp" / ".mcp.json", "json", "project"),
        (".cursor/mcp.json", root / ".cursor" / "mcp.json", "json", "project"),
        (".vscode/mcp.json", root / ".vscode" / "mcp.json", "vscode", "project"),
        (".codex/config.toml", root / ".codex" / "config.toml", "toml", "project"),
        ("~/.claude.json", home / ".claude.json", "json", "user"),
        ("~/.codex/config.toml", home / ".codex" / "config.toml", "toml", "user"),
        ("~/.cursor/mcp.json", home / ".cursor" / "mcp.json", "json", "user"),
    ]


def _servers(data: dict[str, Any], kind: str, root: Path) -> list[tuple[str, Any]]:
    if kind == "toml":
        servers = data.get("mcp_servers")
    elif kind == "vscode":
        servers = data.get("servers")
    else:
        servers = data.get("mcpServers")
        if servers is None and data and all(isinstance(value, dict) and ("command" in value or "url" in value)
                                            for value in data.values()):
            servers = data  # legacy manual-import shape
    found = list(servers.items()) if isinstance(servers, dict) else []
    projects = data.get("projects") if kind == "json" else None
    if isinstance(projects, dict):  # Claude Code local-scope servers live under projects[path]
        local = projects.get(str(root))
        if isinstance(local, dict) and isinstance(local.get("mcpServers"), dict):
            found.extend(local["mcpServers"].items())
    return found


def _entry_problems(entry: dict[str, Any]) -> list[str]:
    """Static checks of a configured launch; nothing in it is executed."""
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        return ["no_command"]
    problems: list[str] = []
    if "/" in command or os.sep in command:
        if not Path(command).exists():
            problems.append("command_missing")
    elif shutil.which(command) is None:
        problems.append("command_not_on_path")
    raw = entry.get("args", [])
    args = [item for item in raw if isinstance(item, str)] if isinstance(raw, list) else []
    for item in args:
        match = BOOTSTRAP_PACKAGE.search(item)
        if match and not Path(match.group("path")).is_dir():
            problems.append("package_missing")
    for names, label in ((("--root",), "root_missing"), (("--semgrep", "--semgrep-executable"), "analyzer_missing")):
        try:
            value = _option(args, *names)
        except ValueError:
            problems.append("ambiguous_options")
            continue
        if value and "${" not in value and not Path(value).exists():
            problems.append(label)
    return list(dict.fromkeys(problems))


def polaris_servers(root: Path, home: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Every Polaris-looking server in host configs, plus files too large or unsafe to inspect.

    Items carry the raw entry under "entry" for internal use only; never print it.
    """
    found: list[dict[str, Any]] = []
    uninspected: list[str] = []
    for label, path, kind, scope in _config_locations(root, home):
        try:
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_INSPECTED_CONFIG:
                uninspected.append(label)
                continue
            text = _read(path)
            data = _toml_object(text, path) if kind == "toml" else _json_object(text, path)
        except (SetupProblem, IntegrationProblem, OSError):
            uninspected.append(label)
            continue
        for server, value in _servers(data, kind, root):
            if not isinstance(value, dict) or not (is_polaris_entry(value) or str(server).lower().startswith("polaris")):
                continue
            found.append({"location": label, "scope": scope, "name": str(server)[:128], "entry": value,
                          "problems": _entry_problems(value)})
    return found, uninspected


def _entries_check(target: str, servers: list[dict[str, Any]], uninspected: list[str]) -> dict[str, str]:
    visible = [item for item in servers if item["location"] in HOST_CONFIGS[target]]
    broken = [item for item in visible if item["problems"]]
    hidden = [label for label in uninspected if label in HOST_CONFIGS[target]]
    described = ", ".join(f"{item['location']} ({item['name']})" for item in visible[:6])
    if broken:
        details = "; ".join(f"{item['location']} ({item['name']}): "
                            + ", ".join(PROBLEM_TEXT.get(problem, problem) for problem in item["problems"])
                            for item in broken[:4])
        return _check("failed", f"Stale Polaris server configuration: {details}. Remove it or rerun setup.")
    if len(visible) > 1:
        return _check("manual", f"Several Polaris servers are visible to this host: {described}. The host may start "
                                "a different one than expected; keep one (project setup, or theo setup --global).")
    if hidden:
        return _check("manual", f"Couldn't inspect {', '.join(hidden)} (too large or not plain JSON/TOML); check it "
                                "for older Polaris servers with the host's own MCP list.")
    return _check("passed", f"One Polaris server is configured ({described})." if visible else
                  "No Polaris server entries were found in this host's configuration files.")


def add_doctor_parsers(commands: Any) -> None:
    parser = commands.add_parser(
        "doctor", help="Check local MCP/rules/configuration offline; never changes editor settings.",
    )
    parser.add_argument("target", choices=EDITORS, nargs="?", default="warp")
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--name", default="polaris")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--semgrep", "--semgrep-executable", type=Path,
                        help="Explicit trusted absolute analyzer for this probe; never execute a path from config.")
    parser.add_argument("--format", choices=("text", "json"), default="text")


def _check(status: str, message: str) -> dict[str, str]:
    return {"status": status, "message": message}


def probe_mcp(root: Path, timeout: float, *, semgrep: Path | None = None) -> dict[str, Any]:
    """Real stdio initialize/list_tools/tool calls; whole probe is bounded in a clean process."""
    semgrep = trusted_executable(semgrep)
    with tempfile.TemporaryDirectory(prefix="polaris-doctor-") as temporary:
        home = Path(temporary).resolve()
        process = run_bounded(
            [*module_command("polaris.integrations.doctor", "_probe_main"), "--root", str(root),
             "--timeout", str(max(0.5, timeout - 1)),
             *(["--semgrep", str(semgrep)] if semgrep is not None else [])],
            cwd=home, env=offline_environment(home), timeout=timeout, max_output_bytes=1_000_000,
        )
    if process.returncode != 0:
        raise IntegrationProblem("MCP diagnostic worker is unavailable or failed.")
    try:
        data = json.loads(process.stdout)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IntegrationProblem("MCP diagnostic worker returned invalid output.") from exc
    if not isinstance(data, dict):
        raise IntegrationProblem("MCP diagnostic worker returned invalid output.")
    return data


def _safe_names(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [item for item in values[:100] if isinstance(item, str)
            and re.fullmatch(r"[A-Za-z0-9_./:+-]{1,100}", item)]

def _option(args: list[str], *names: str) -> str | None:
    """Recognize argparse spellings, rejecting duplicate or incomplete root/source flags."""
    values = []
    for index, item in enumerate(args):
        key, separator, value = item.partition("=")
        if key not in names:
            continue
        if not separator:
            if index + 1 == len(args) or args[index + 1].startswith("--"):
                raise ValueError("Incomplete configured option.")
            value = args[index + 1]
        if not value:
            raise ValueError("Empty configured option.")
        values.append(value)
    if len(values) > 1:
        raise ValueError("Ambiguous configured option.")
    return values[0] if values else None


def _probe_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--semgrep", type=Path)
    args = parser.parse_args(argv)
    try:
        import anyio
        from mcp import Client, StdioServerParameters

        async def probe() -> dict[str, Any]:
            command = module_command("polaris.cli")
            parameters = StdioServerParameters(
                command=command[0],
                args=[*command[1:], "mcp", "--root", str(args.root), "--engine", "rules",
                      "--model-source", "local",
                      *(["--semgrep", str(args.semgrep)] if args.semgrep is not None else [])],
                env=offline_environment(Path.home()), cwd=str(Path.home()),
            )
            with anyio.fail_after(args.timeout):
                async with Client(parameters) as client:
                    tools = _safe_names([item.name for item in (await client.list_tools()).tools])
                    # Advanced tools aren't listed by default but answer by name, as editors' older
                    # rules and integrations still call them.
                    result = await client.call_tool("capabilities", {})
                    capabilities = result.structured_content if not result.is_error else None
                    if not isinstance(capabilities, dict):
                        raise IntegrationProblem("MCP capabilities probe failed.")
                    explained = await client.call_tool("polaris_explain", {"id": "command_injection"})
                    explanation = explained.structured_content if not explained.is_error else None
                    # This is source DATA for an in-memory parser probe, never run/imported.
                    rules = await client.call_tool("review_snippet", {
                        "code": ("import os\nfrom flask import request\n\n\ndef polaris_diagnostic():\n"
                                 "    os.system('probe ' + request.args['value'])\n"),
                        "path": "polaris_diagnostic.py", "checks": ["command_injection"],
                    })
                    report = rules.structured_content if not rules.is_error else None
                    available = isinstance(report, dict) and any(
                        item.get("check_id") == "command_injection" and item.get("result") == "flagged"
                        for item in report.get("findings", []) if isinstance(item, dict)
                    ) and report.get("format") == "polaris.workflow-summary/0.1.0"
                    actual_root = capabilities.get("project_root")
                    root_matches = isinstance(actual_root, str) and Path(actual_root) == args.root
                    from polaris.review.models import CapabilityManifest

                    workflow = CapabilityManifest.model_validate(capabilities["workflow"])
                    return {
                        "handshake": True, "tools": tools, "rules_available": available,
                        "callable_tools": _safe_names(capabilities.get("callable_tools")),
                        "explain_available": isinstance(explanation, dict)
                        and explanation.get("format") == "polaris.explanation/1",
                        "root_reported": isinstance(actual_root, str), "root_matches": root_matches,
                        "languages": _safe_names(capabilities.get("languages")),
                        "checks": _safe_names(capabilities.get("checks")),
                        "model_loaded": bool(capabilities.get("model", {}).get("loaded")),
                        "workflow_capabilities": workflow.model_dump(mode="json"),
                    }

        print(json.dumps(anyio.run(probe)))
        return 0
    except ImportError:
        print(json.dumps({"error": "mcp_dependency_unavailable"}))
        return 0
    except Exception:
        # Tool errors can contain code/settings; diagnostics report only a fixed failure category.
        print(json.dumps({"error": "mcp_handshake_or_probe_failed"}))
        return 0


def diagnose(root: Path, *, target: str = "warp", name: str = "polaris",
             timeout: float = 20, probe: Probe | None = None,
             semgrep: Path | None = None) -> dict[str, Any]:
    if (target not in EDITORS or not 1 <= timeout <= 60 or not name or len(name) > 128
            or any(not (character.isalnum() or character in "-_") for character in name)):
        raise IntegrationProblem("Invalid doctor target or timeout.")
    try:
        root = _project(root, exact=True)
    except SetupProblem as exc:
        raise IntegrationProblem("Doctor requires a safe, bounded project directory.") from exc
    semgrep = trusted_executable(semgrep)
    editor = EDITOR_SETUP[target]
    checks: dict[str, dict[str, str]] = {}
    servers_found, uninspected = polaris_servers(root, Path.home())
    try:
        text = _read(root / editor.project_config)
        data = (_toml_object(text, root / editor.project_config) if target == "codex" else
                _json_object(text, root / editor.project_config))
        container, key = warp_servers(data) if target == "warp" else (data, editor.servers_key)
        servers = container.get(key, {}) if key is not None else container
        entry = servers.get(name) if isinstance(servers, dict) else None
        user_scope = False
        if text is None or not isinstance(entry, dict) or not is_polaris_entry(entry):
            # A user-level server (theo setup --global) serves every project without a fixed root.
            user = next((item["entry"] for item in servers_found
                         if item["scope"] == "user" and item["name"] == name
                         and item["location"] in HOST_CONFIGS[target] and is_polaris_entry(item["entry"])), None)
            entry, user_scope = (user, True) if user is not None else (None, False)
        if not isinstance(entry, dict):
            checks["configuration"] = _check("failed", "No recognized Polaris MCP entry for this project or user.")
        else:
            checks["configuration"] = _check(
                "passed", "Recognized user-level Polaris server (all projects); no values were printed." if user_scope
                else "Recognized project MCP entry; no values were printed.")
            args = entry.get("args", [])
            configured_root = _option(args, "--root")
            if configured_root == "${workspaceFolder}" and target in ("cursor", "vscode"):
                configured_root = str(root)
            if user_scope and configured_root is None:
                checks["configured_root"] = _check(
                    "passed", "No fixed root: the server reviews the project the agent passes (or its working folder).")
            elif configured_root is not None and configured_root != str(root):
                checks["configured_root"] = _check("failed", "Configured root differs from this worktree.")
            elif configured_root is None:
                checks["configured_root"] = _check(
                    "manual", "No explicit root is configured; rerun project setup to bind this directory.")
            else:
                checks["configured_root"] = _check("passed", "Explicit root matches this worktree.")
            if target in ("warp", "codex") and user_scope:
                checks["working_directory"] = _check(
                    "passed", "User-level servers have no fixed working directory; tools take root per call.")
            elif target in ("warp", "codex"):
                directory = entry.get("working_directory" if target == "warp" else "cwd")
                checks["working_directory"] = _check(
                    "passed" if directory == str(root) else "failed",
                    "The host working directory matches this project." if directory == str(root) else
                    "The host working directory must match this project.",
                )
            model_source = _option(args, "--model-source")
            checks["inference_boundary"] = _check(
                "passed" if model_source in ("local", "remote") else "manual",
                "Local-only inference is explicitly configured." if model_source == "local" else
                "Hosted inference is explicitly configured; authentication and model readiness were not "
                "tested by this offline probe." if model_source == "remote" else
                "Model source is not explicit; select local or separately activated remote inference.",
            )
            if model_source == "remote":
                environment = entry.get("env", {})
                expected_origin = environment.get("POLARIS_EXPECTED_API_URL") if isinstance(environment, dict) else None
                pinned = (isinstance(environment, dict)
                          and environment.get("POLARIS_CREDENTIAL_SOURCE") == "file"
                          and isinstance(expected_origin, str)
                          and _setup_origin("remote", expected_origin) == expected_origin)
                checks["hosted_origin"] = _check(
                    "passed" if pinned else "manual",
                    "File credentials and an approved origin are pinned; account access remains untested."
                    if pinned else "Hosted origin and file credentials are not pinned; rerun activation/setup.",
                )
            disabled = entry.get("enabled") is False or entry.get("disabled") is True
            checks["server_enablement"] = _check(
                "manual" if disabled else "passed",
                "The server is disabled in configuration. Enable it in the host when ready; "
                "doctor preserves that choice." if disabled else
                "No disabled flag is present; native host approval remains separate.",
            )
            command = entry.get("command", "")
            local_command = module_command("polaris.cli")
            known = (command == sys.executable and args[:len(local_command) - 1] == local_command[1:]
                     or command == str(Path(sys.executable).parent / "polaris"))
            checks["configured_command"] = _check(
                "passed" if known else "manual",
                "Standard Polaris launch command recognized; this installation is probed below." if known else
                "Custom command was not executed. Doctor probes only this trusted Polaris installation.",
            )
            configured_analyzer = _option(args, "--semgrep", "--semgrep-executable")
            if configured_analyzer is not None:
                checks["analyzer_configuration"] = _check(
                    "passed" if semgrep is not None and configured_analyzer == str(semgrep) else "manual",
                    "Explicit probe analyzer matches the configured launcher." if semgrep is not None
                    and configured_analyzer == str(semgrep) else
                    "Configured analyzer is not executed automatically; pass its trusted path with --semgrep.",
                )
    except (SetupProblem, IntegrationProblem, OSError, ValueError, IndexError, TypeError):
        checks["configuration"] = _check("failed", "Unsafe, invalid, or ambiguous project MCP configuration.")
    checks["server_entries"] = _entries_check(target, servers_found, uninspected)
    try:
        rule_path = effective_rule_path(root, target)
        rule = _read(rule_path)
        managed = True
        if rule is not None and target in ("warp", "codex"):
            managed = (rule.count(RULE_START) == 1 and rule.count(RULE_END) == 1
                       and rule.index(RULE_START) < rule.index(RULE_END))
        ready = rule is not None and "polaris_check" in rule and managed
        outdated = rule is not None and not ready and "review_workflow" in rule
        checks["guidance"] = _check(
            "passed" if ready else "manual",
            "Effective project check guidance is present; rules are not enforcement." if ready else
            f"The project's Polaris rule is from an older version (it tells agents to call review_workflow). "
            f"Run `polaris setup {target}` again to update it to the polaris_check loop." if outdated else
            "Check guidance is missing; use setup --rule or inspect the effective rules file.",
        )
    except (SetupProblem, IntegrationProblem, OSError):
        checks["guidance"] = _check("failed", "Effective rules cannot be read safely.")
    try:
        observed = probe(root, timeout) if probe is not None else probe_mcp(root, timeout, semgrep=semgrep)
    except (OSError, ValueError, KeyError, TypeError):
        observed = {"error": "mcp_probe_unavailable"}
    if not isinstance(observed, dict):
        observed = {"error": "mcp_probe_unavailable"}
    if observed.get("handshake") is not True:
        checks["mcp_handshake"] = _check("failed", "Offline stdio handshake/tool probe failed or MCP extra is missing.")
    else:
        checks["mcp_handshake"] = _check("passed", "A real local stdio MCP client initialized the trusted server.")
        tools = set(_safe_names(observed.get("tools")))
        callable_tools = tools | set(_safe_names(observed.get("callable_tools")))
        listed = EXPECTED_TOOLS <= tools and observed.get("explain_available", True) is True
        checks["mcp_tools"] = _check(
            "passed" if listed else "failed",
            "The check tools (polaris_check, polaris_explain, polaris_fix) are listed." if listed else
            "The check tools (polaris_check, polaris_explain, polaris_fix) are missing; the configured server "
            "is probably an older Polaris. Update it and rerun setup.",
        )
        checks["workflow_tool"] = _check(
            "passed" if WORKFLOW_TOOLS <= callable_tools else "unverified",
            "The advanced workflow tools answer by name (listed with --advanced-tools)."
            if WORKFLOW_TOOLS <= callable_tools else "The advanced workflow tool set is incomplete or unavailable.",
        )
        checks["mcp_root"] = _check(
            "passed" if observed.get("root_matches") is True else
            "failed" if observed.get("root_reported") else "unverified",
            "Root returned over MCP matches this worktree." if observed.get("root_matches") is True else
            "Server root differs or isn't exposed over MCP; do not infer successful root validation.",
        )
        rules = observed.get("rules_available") is True and observed.get("model_loaded") is False
        checks["offline_rules"] = _check(
            "passed" if rules else "failed",
            "Rules identified the controlled parser-only probe with no model loaded." if rules else
            "Rules probe failed or unexpectedly reported a loaded model.",
        )
    from pydantic import ValidationError

    from polaris.review import catalog
    from polaris.review.models import WORKFLOW_DEFAULT_CHECKS, CapabilityManifest

    workflow_data = None
    try:
        manifest = CapabilityManifest.model_validate(observed.get("workflow_capabilities"))
        workflow_data = manifest.model_dump(mode="json")
        # CI-workflow and container checks don't apply to program code (see catalog.applies).
        required = {
            (language, check) for language in ("python", "javascript", "typescript")
            for check in WORKFLOW_DEFAULT_CHECKS if catalog.applies(check, language)
        }
        available = {
            (item.language, item.check_id) for item in manifest.matrix
            if item.availability == "available"
        }
        complete = required <= available
        checks["workflow_analysis"] = _check(
            "passed" if complete else "unavailable",
            "Configured analyzers are available for the default Python/JS/TS matrix; this is not an accuracy claim."
            if complete else
            "Required default workflow checks lack available analysis. Inspect the reported capability matrix.",
        )
    except (ValidationError, ValueError, TypeError):
        checks["workflow_analysis"] = _check(
            "unverified", "No valid expanded capability matrix was returned over MCP.",
        )
    checks["host_permissions"] = _check(
        "manual", editor.next_steps[0].replace('"polaris"', f'"{name}"'))
    if target == "warp":
        checks["warp_completion"] = _check(
            "manual", "No deterministic Warp completion hook is verified. Rules guide but do not enforce review.")
    status = "ready_for_host_verification"
    if any(item["status"] == "failed" for item in checks.values()):
        status = "failed"
    elif any(item["status"] in ("unverified", "unavailable") for item in checks.values()):
        status = "incomplete"
    configuration_checks = ("configuration", "configured_root", "inference_boundary",
                            "server_enablement", "configured_command")
    configuration_ready = all(checks.get(key, {}).get("status") == "passed" for key in configuration_checks)
    if target in ("warp", "codex"):
        configuration_ready = configuration_ready and checks.get("working_directory", {}).get("status") == "passed"
    if "hosted_origin" in checks:
        configuration_ready = configuration_ready and checks["hosted_origin"]["status"] == "passed"
    protocol_ready = all(checks.get(key, {}).get("status") == "passed"
                         for key in ("mcp_handshake", "mcp_tools", "workflow_tool", "mcp_root", "offline_rules"))
    if not configuration_ready and status == "ready_for_host_verification":
        status = "incomplete"
    return {
        "format": "polaris.doctor/0.1.0", "status": status, "target": target, "checks": checks,
        "advertised_languages": _safe_names(observed.get("languages")),
        "advertised_checks": _safe_names(observed.get("checks")), "live_client_verified": False,
        "configuration_ready": configuration_ready, "local_protocol_ready": protocol_ready,
        "host_verified": False, "remote_auth_verified": False,
        "next_action": checks["host_permissions"]["message"],
        "server_entries": [{key: item[key] for key in ("location", "scope", "name", "problems")}
                           for item in servers_found][:32],
        "workflow_capabilities": workflow_data,
        "models_fetched": False, "credentials_used": False, "project_code_executed": False,
        "limitations": [
            "Protocol diagnostics are not verification of a live editor, its policy, or permissions.",
            "Advertised analyzer coverage is not evidence of universal vulnerability detection.",
            "Custom MCP command strings and model/hosted inference are deliberately not executed.",
        ],
    }


def run(args: argparse.Namespace) -> int:
    try:
        report = diagnose(args.project, target=args.target, name=args.name, timeout=args.timeout,
                          semgrep=args.semgrep)
    except (OSError, ValueError, SetupProblem):
        print("Polaris doctor: cannot safely inspect the configured project.", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(f"Polaris doctor: {report['status']}")
        for name, check in report["checks"].items():
            print(f"  {name}: {check['status']} — {check['message']}")
        print("  Legacy coverage advertised: " + ", ".join(report["advertised_languages"]) + " / "
              + ", ".join(report["advertised_checks"]))
        workflow = report["workflow_capabilities"]
        if workflow is not None:
            for analyzer in workflow["analyzers"]:
                print(f"  Workflow analyzer {analyzer['analyzer_id']}: {analyzer['availability']}")
        print("  No models fetched, credentials consumed, project code executed, or client settings changed.")
    return 0 if report["status"] == "ready_for_host_verification" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    add_doctor_parsers(commands)
    return run(parser.parse_args(["doctor", *(argv if argv is not None else sys.argv[1:])]))


if __name__ == "__main__":
    raise SystemExit(main())

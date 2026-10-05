"""A simple, transparent rule baseline over the static facts.

Used to measure whether the model adds anything, and as a model-free fallback
(`--engine rules`). It knows nothing the notes don't state.
"""

from __future__ import annotations

import posixpath
import re

from polaris.review.dataflow import ArgInfo, FlowFacts, Sink, describe_sink

BUILT_STRING = frozenset({"f-string", "concatenation", "%-formatting", ".format()", "join"})
RANK = {"ok": 0, "needs_context": 1, "flagged": 2}
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/env", "cmd", "cmd.exe",
                    "powershell", "pwsh"})
# Programs that pass later arguments to a (remote) shell.
REMOTE_SHELLS = frozenset({"ssh"})
# Programs where a leading-dash argument changes behavior dangerously (git --upload-pack=...,
# curl -o, tar --checkpoint-action, find -exec, rsync -e, ...).
OPTION_PROGRAMS = frozenset({
    "git", "ssh", "scp", "sftp", "rsync", "curl", "wget", "tar", "zip", "unzip", "7z", "find", "xargs",
    "sed", "awk", "gpg", "openssl", "ffmpeg", "convert", "magick", "npm", "npx", "pip", "docker",
    "kubectl", "helm", "aws", "gcloud", "az", "hg", "svn", "psql", "mysql", "sqlite3", "chmod",
    "chown", "cp", "mv", "rm", "ln", "nc", "socat",
})
SAFE_FORMS = frozenset({"literal", "literal with placeholders", "sanitized", "lookup", "composed", "constant"})
ATTACKER_PREFIXES: dict[str, tuple[str, ...]] = {
    "ssrf": ("request data", "request input"),
    "open_redirect": ("request data", "request input"),
    "xss": ("request data", "request input"),
    "path_traversal": ("request data", "request input", "input()", "command-line arguments", "file or network data"),
    "code_injection": ("request data", "request input", "input()", "command-line arguments", "file or network data",
                       "network response"),
    "secret_exposure": ("secret environment value",),
}
FIXED_ORIGIN = re.compile(r"^(https?://[^/?#\s]+[/?#]|/[^/\\])")


def _from_source(argument: ArgInfo) -> bool:
    """Tainted by a known untrusted source (request data, input(), ...) rather than a parameter?

    Source labels are descriptions such as "request data (request.form)"; parameter labels are
    plain names or attribute chains such as `step.command`.
    """
    return any(" " in label for label in argument.tainted)


def _sql(sink: Sink) -> tuple[str, str]:
    argument = sink.argument
    if argument is None:
        return "needs_context", "query_not_visible"
    if argument.form in BUILT_STRING and argument.tainted:
        return "flagged", "untrusted_value_in_sql_text"
    if argument.form == "source" and argument.tainted:
        return "flagged", "untrusted_value_in_sql_text"
    if argument.form == "parameter" and argument.tainted:
        return "needs_context", "query_supplied_by_caller"
    if argument.form in ("attribute", "subscript", "expression", "conditional") and argument.tainted:
        # The whole query is a value handed in from outside, such as `job.sql` or `payload["query"]`.
        if _from_source(argument):
            return "flagged", "untrusted_value_in_sql_text"
        return "needs_context", "query_supplied_by_caller"
    if not argument.visible:
        return "needs_context", "query_origin_not_visible"
    if isinstance(argument.elements, tuple) and any(
        element.form in BUILT_STRING and element.tainted for element in argument.elements
    ):
        return "flagged", "untrusted_value_in_sql_text"
    return "ok", "sql_text_fixed_or_parameterized"


def _stringish_tainted(argument: ArgInfo) -> bool:
    return bool(argument.tainted) and argument.form in (
        BUILT_STRING | {"parameter", "source", "split", "subscript", "expression"}
    )


def _process(sink: Sink) -> tuple[str, str]:
    argument = sink.argument
    if argument is None:
        return "needs_context", "command_not_visible"
    shelled = sink.shell in ("yes", "always", "expression")
    if argument.form in ("list", "tuple"):
        if not argument.elements:
            return "needs_context", "command_not_visible"
        executable = argument.elements[0]
        if executable.tainted and executable.form != "sanitized":
            # The same rule as a whole command: a caller-chosen program needs the call sites,
            # a program chosen by request/CLI input is flagged.
            if executable.form == "source" or _from_source(executable):
                return "flagged", "untrusted_executable"
            return "needs_context", "executable_supplied_by_caller"
        if not executable.visible:
            return "needs_context", "executable_not_visible"
        runs_shell = (executable.value in SHELLS and any(
            element.value in ("-c", "/c", "-Command") for element in argument.elements[1:3]
        )) or executable.value in REMOTE_SHELLS
        if (shelled or runs_shell) and any(_stringish_tainted(element) for element in argument.elements[1:]):
            return "flagged", "untrusted_value_in_shell_command"
        if (shelled or runs_shell) and any(not element.visible for element in argument.elements[1:]):
            return "needs_context", "command_origin_not_visible"
        program = posixpath.basename(executable.value or "")
        if program in OPTION_PROGRAMS:
            for element in argument.elements[1:]:
                if element.value == "--":
                    break
                if _stringish_tainted(element) or (element.tainted and element.form in ("attribute", "conditional")):
                    return "flagged", "untrusted_option_argument"
        return "ok", "fixed_executable_argument_list"
    if shelled:
        if argument.form in BUILT_STRING | {"source"} and argument.tainted:
            return "flagged", "untrusted_value_in_shell_command"
        if argument.form == "parameter" and argument.tainted:
            return "needs_context", "command_supplied_by_caller"
        if argument.tainted and argument.form not in ("sanitized", "lookup", "composed"):
            # The whole command is a value handed in from outside, such as `step.command`.
            if _from_source(argument):
                return "flagged", "untrusted_value_in_shell_command"
            return "needs_context", "command_supplied_by_caller"
        if not argument.visible:
            return "needs_context", "command_origin_not_visible"
        return "ok", "fixed_shell_command"
    # A whole command handed in by the caller: judging it needs the call sites.
    if argument.form == "parameter" or (argument.form == "split" and argument.via is not None):
        return "needs_context", "command_supplied_by_caller"
    # A single string without a shell names the program to run.
    if argument.form == "source" and argument.tainted:
        return "flagged", "untrusted_executable"
    if argument.form == "split" and argument.tainted:
        return "flagged", "untrusted_command_split"
    if argument.tainted and argument.form not in ("sanitized", "lookup", "composed"):
        # A program name (or whole command line) handed in from outside.
        if _from_source(argument):
            return "flagged", "untrusted_executable"
        return "needs_context", "command_supplied_by_caller"
    if not argument.visible:
        return "needs_context", "command_origin_not_visible"
    return "ok", "no_shell_fixed_program"


def rule_result(check_id: str, facts: FlowFacts) -> tuple[str, str, list[str]]:
    """Worst-case result across the check's calls: (result, reason, detail lines)."""
    result, reason, _ = rule_verdict(check_id, facts)
    return result, reason, [describe_sink(sink) for sink in facts.sinks_for(check_id)]


def rule_verdict(check_id: str, facts: FlowFacts) -> tuple[str, str, Sink | None]:
    """Worst-case SQL/process result and the call that produced it."""
    sinks = facts.sinks_for(check_id)
    if not sinks:
        return "ok", "no_candidate_calls", None
    judge = _sql if check_id == "sql_injection" else _process
    verdicts = [(*judge(sink), sink) for sink in sinks]
    worst, reason, sink = max(verdicts, key=lambda verdict: RANK[verdict[0]])
    return worst, reason, sink


def fixed_destination(argument: ArgInfo) -> bool:
    return argument.prefix is not None and FIXED_ORIGIN.match(argument.prefix) is not None


def web_verdict(check_id: str, sink: Sink) -> tuple[str, str]:
    """SSRF / redirect / HTML / path / code-loading / secret-output decision for one call.

    Request input (and, for paths and code, CLI/file input) reaching the sink is flagged; a value
    handed in by the caller needs the call sites; fixed, sanitized or allowlisted values pass.
    """
    argument = sink.argument
    if argument is None:
        return "ok", "value_not_visible"
    if argument.form in SAFE_FORMS and not argument.tainted:
        return "ok", "fixed_or_sanitized_value"
    prefixes = ATTACKER_PREFIXES.get(check_id, ())
    origins = sink.origins
    if check_id in ("ssrf", "open_redirect") and fixed_destination(argument):
        return "ok", "fixed_destination"
    if any(origin.startswith(prefixes) for origin in origins):
        return "flagged", "untrusted_value_reaches_sink"
    if check_id != "secret_exposure" and any(origin.startswith("parameter ") for origin in origins):
        return "needs_context", "value_supplied_by_caller"
    return "ok", "no_untrusted_value"

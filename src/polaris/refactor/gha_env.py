"""Pass an untrusted `${{ ... }}` value to a workflow `run:` script through `env:` instead of pasting it in.

    - run: |                                  - run: |
        echo "${{ github.event.issue.title }}"      echo "${ISSUE_TITLE}"
                                                env:
                                                  ISSUE_TITLE: ${{ github.event.issue.title }}

The shell then reads the value as data, not as code. Two things have to be right, and each one is
checked rather than assumed:

- the shell quoting at the spot: the analyzer's own `quote_context` says whether the expression sits
  unquoted (it becomes `"$NAME"`), inside double quotes (`${NAME}`) or inside single quotes
  (`'"$NAME"'`); a spot inside a command substitution, heredoc, comment or escape is declined;
- the YAML edit: the file is parsed before and after, and the result has to be equal to the original
  data with exactly that one step changed (its `run` text, plus the new `env` entry). An anchor or alias
  shared with another place, a flow-style `env`, odd indentation or anything else that makes the two
  differ is declined.

Only bash/sh `run:` literal block scalars (`run: |` or `|-`) with one untrusted expression on the line
are handled; the expression has to be a plain `github....` property path. A value is passed as one
word, so a script that relied on the value being split into several words changes. Nothing here runs
the workflow.
"""

from __future__ import annotations

import re
from typing import Any

import yaml  # type: ignore[import-untyped,unused-ignore]

from polaris.refactor.fixes import Fix
from polaris.review.analyzers import shellwords
from polaris.review.analyzers.github_actions import (
    Job,
    Step,
    Workflow,
    compose,
    expressions,
    parse_expression,
    taint,
    workflow_model,
)

PATH = re.compile(r"github\.[A-Za-z0-9_.-]+")
RESERVED_PREFIXES = ("GITHUB_", "RUNNER_", "ACTIONS_", "INPUT_")
HEADER = re.compile(r"\|-?\s*(#.*)?")
RATIONALE = (
    "Pass the value to the script through an environment variable (env:) instead of expanding it into "
    "the script text, so the shell reads it as data and not as code (command injection). The script now "
    "reads it as one quoted word; Polaris did not run your workflow."
)


def _shell(workflow: Workflow, job: Job, step: Step) -> str | None:
    explicit = step.shell or job.shell or workflow.shell
    if explicit:
        words = explicit.split()
        return shellwords.basename(words[0]).lower() if words else ""
    labels = [label.lower() for label in job.runs_on or []]
    if not labels or any("${{" in label for label in labels):
        return None
    if any("windows" in label for label in labels):
        return "pwsh"
    if any(word in label for label in labels for word in ("ubuntu", "macos", "linux")):
        return "bash"
    return None


def _variable(path: str) -> str | None:
    parts = [part for part in path.split(".")[1:] if part != "event"][-2:]
    name = "_".join(parts).replace("-", "_").upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name.startswith(RESERVED_PREFIXES) or name == "CI":
        return None
    return name


def _env_names(workflow: Workflow, job: Job, step: Step) -> set[str]:
    return {name.lower() for scope in (step.env, job.env, workflow.env) for name in scope}


def _key_node(mapping: Any, name: str) -> Any:
    for key, _ in mapping.value:
        if isinstance(key, yaml.ScalarNode) and key.value == name:
            return key
    return None


def _walk_data(data: Any, job: str, index: int) -> dict[str, Any] | None:
    try:
        step = data["jobs"][job]["steps"][index]
    except (KeyError, IndexError, TypeError):
        return None
    return step if isinstance(step, dict) else None


def env_indirection(text: str, line: int) -> Fix | None:
    """Rewrite the one untrusted expression on `line` of a `run: |` script to read an env variable.

    See the module notes for the shapes handled; everything else is declined.
    """
    if "\r" in text or "\t" in text:
        return None
    try:
        root = compose(text)
        workflow = workflow_model(root)
        before = yaml.safe_load(text)
    except Exception:
        return None
    lines = text.split("\n")
    found: list[tuple[Job, Step, int, int, str]] = []  # job, step, start, end in the script, original
    for job in workflow.jobs:
        for step in job.steps:
            run = step.run
            if not isinstance(run, yaml.ScalarNode) or run.style != "|" or not isinstance(run.value, str):
                continue
            for start, end, inner in expressions(run.value):
                if run.start_mark.line + 1 + run.value.count("\n", 0, start) != line - 1:
                    continue
                parsed = parse_expression(inner)
                if parsed is None or parsed[0] != "path" or not taint(parsed, lambda _name: []):
                    continue
                found.append((job, step, start, end, run.value[start:end]))
    spans_on_line = sum(
        1 for job in workflow.jobs for step in job.steps
        if isinstance(step.run, yaml.ScalarNode) and step.run.style == "|" and isinstance(step.run.value, str)
        for start, _, _ in expressions(step.run.value)
        if step.run.start_mark.line + 1 + step.run.value.count("\n", 0, start) == line - 1
    )
    if len(found) != 1 or spans_on_line != 1:
        return None
    job, step, start, end, original = found[0]
    run = step.run
    value = run.value
    path = re.sub(r"\s+", "", original[3:-2])
    if not PATH.fullmatch(path) or _shell(workflow, job, step) not in ("bash", "sh"):
        return None
    name = _variable(path)
    if name is None or name.lower() in _env_names(workflow, job, step) or re.search(rf"\b{name}\b", value):
        return None
    masked = value
    for other_start, other_end, _ in expressions(value):
        masked = masked[:other_start] + "X" * (other_end - other_start) + masked[other_end:]
    replacement = {"unquoted": f'"${name}"', "double": f"${{{name}}}", "single": f"'\"${name}\"'"}.get(
        shellwords.quote_context(masked, start))
    if replacement is None:
        return None
    # Where the expression sits in the file: block scalar lines are the file's lines, minus the indent.
    index = run.start_mark.line + 1 + value.count("\n", 0, start)
    header = lines[run.start_mark.line][run.start_mark.column:]
    content = [i for i in range(run.start_mark.line + 1, len(lines)) if lines[i].strip()]
    if not HEADER.fullmatch(header) or not content or index >= len(lines):
        return None
    indent = len(lines[content[0]]) - len(lines[content[0]].lstrip(" "))
    line_start = value.rfind("\n", 0, start) + 1
    column = indent + (start - line_start)
    if lines[index][column:column + len(original)] != original:
        return None
    # The step's keys sit at the column of `run:`; the new `env:` goes in beside them.
    run_key = _key_node(step.node, "run")
    if run_key is None:
        return None
    key_column = run_key.start_mark.column
    entry = f"{name}: {original}"
    env_key = _key_node(step.node, "env")
    inserted: list[str]
    if env_key is not None:
        env_value = next(value_node for key, value_node in step.node.value if key is env_key)
        if not isinstance(env_value, yaml.MappingNode) or env_value.flow_style or not env_value.value:
            return None
        first = env_value.value[0][0]
        position = first.start_mark.line
        inserted = [" " * first.start_mark.column + entry]
        if lines[position][:first.start_mark.column].strip():
            return None
    else:
        inserted = [" " * key_column + "env:", " " * (key_column + 2) + entry]
        if not lines[run_key.start_mark.line][:key_column].strip():
            position = run_key.start_mark.line  # the key starts its line: add `env:` just above it
        else:
            # The key shares the `- ` line: add `env:` right below the script, which ends at the first
            # non-blank line that is indented less than its first line.
            last = run.start_mark.line
            for number in range(run.start_mark.line + 1, len(lines)):
                if lines[number].strip():
                    if len(lines[number]) - len(lines[number].lstrip(" ")) < indent:
                        break
                    last = number
            position = last + 1
    edited_lines = list(lines)
    edited_lines[index] = lines[index][:column] + replacement + lines[index][column + len(original):]
    edited_lines[position:position] = inserted
    edited = "\n".join(edited_lines)
    # Prove the YAML edit: the data must equal the original with only this step changed.
    expected = yaml.safe_load(text)
    target = _walk_data(expected, job.name, step.index)
    if target is None:
        return None
    target["run"] = value[:start] + replacement + value[end:]
    if env_key is None:
        target["env"] = {}
    target_env = target.get("env")
    if not isinstance(target_env, dict):
        return None
    target_env[name] = original
    try:
        after = yaml.safe_load(edited)
    except yaml.YAMLError:
        return None
    if after != expected or before == after:
        return None
    return Fix(edited, RATIONALE, "gha_env_indirection")

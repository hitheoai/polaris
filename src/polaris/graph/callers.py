"""Experiment: turn a Python `needs_context` question into traced caller chains across files.

A `needs_context` finding says "this parameter reaches a sink; judging it needs the callers". This
module walks the graph's resolved call edges upward and reports, for every caller chain, what
the argument at the call site is: a constant, a request-derived value from a known entry point, a
value the existing rules treat as sanitized, or unknown (with the reason). It never changes a
finding, an exit code or a review; it is a library function for the evaluation script.

What it refuses to claim:
- A chain is "request" only when the value is derived from request input in a function that is,
  or is reachable from, a recognized entry point.
- "constant" for a whole finding needs every caller resolved: it is withheld when calls that
  could be callers are unresolved, or the function is also used as a value (callback, decorator).
- Callers outside the repository are never visible; every report says so.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from polaris.graph.model import ArgFact, CallEdge, Definition, Graph
from polaris.review.dataflow import CHECK_FOR_KIND
from polaris.review.models import TraceStep

KIND_FOR_CHECK = {check: kind for kind, check in CHECK_FOR_KIND.items()}
Verdict = Literal["request", "constant", "sanitized", "unknown"]
BLOCKING_NOTES = ("possible_unresolved_callers", "referenced_as_value", "chain_limit", "depth_limit")
NOT_VISIBLE = "Callers outside the repository, dynamic dispatch and framework registration are not visible to the graph."


class FindingLike(Protocol):
    path: str
    symbol: str
    start_line: int
    check_id: str
    result: str


@dataclass(frozen=True, slots=True)
class ParameterFlow:
    """The question: which parameters of which function reach which sink."""

    definition: str
    path: str
    symbol: str
    line: int  # the sink's line
    check_id: str
    sink_call: str
    parameters: tuple[str, ...]
    unsupported: tuple[str, ...] = ()  # parameters of nested functions (not supported yet)


@dataclass(frozen=True, slots=True)
class FlowRefusal:
    """The graph declines to answer, and says why."""

    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Hop:
    caller: str | None  # definition id; None for module-level code
    path: str
    line: int
    callee: str  # definition id
    label: str


@dataclass(frozen=True, slots=True)
class CallerChain:
    parameter: str
    leaf: Verdict
    reason: str | None
    hops: tuple[Hop, ...]  # entry (or outermost caller) first, the flow's function last
    entry_point: str | None
    entry_recognized_by: str | None
    trace: tuple[TraceStep, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter": self.parameter, "leaf": self.leaf, "reason": self.reason,
            "entry_point": self.entry_point, "entry_recognized_by": self.entry_recognized_by,
            "hops": [{"caller": hop.caller, "path": hop.path, "line": hop.line, "callee": hop.callee} for hop in self.hops],
            "trace": [step.model_dump(mode="json", exclude_none=True) for step in self.trace],
        }


@dataclass(frozen=True, slots=True)
class CallerReport:
    flow: ParameterFlow
    verdict: Verdict
    chains: tuple[CallerChain, ...]
    notes: tuple[str, ...]  # why a stronger verdict was withheld, and what is not visible

    def to_dict(self) -> dict[str, Any]:
        return {
            "definition": self.flow.definition, "path": self.flow.path, "line": self.flow.line,
            "check_id": self.flow.check_id, "parameters": list(self.flow.parameters), "verdict": self.verdict,
            "notes": list(self.notes), "chains": [chain.to_dict() for chain in self.chains],
        }


def flow_from_finding(graph: Graph, finding: FindingLike) -> ParameterFlow | FlowRefusal:
    """The parameter-origin flow behind a `needs_context` finding, or a refusal with the reason."""
    if finding.result != "needs_context":
        return FlowRefusal("not_a_needs_context_finding")
    kind = KIND_FOR_CHECK.get(finding.check_id)
    if kind is None:
        return FlowRefusal("check_without_data_flow", finding.check_id)
    if finding.symbol == "<module>":
        return FlowRefusal("module_level_code")
    found = [item for item in graph.definitions_at(finding.path, finding.symbol, finding.start_line) if item.analysis_unit]
    if not found:
        return FlowRefusal("definition_not_in_graph", f"{finding.path}::{finding.symbol}")
    if len(found) > 1:
        return FlowRefusal("ambiguous_definition", f"{finding.path}::{finding.symbol}")
    definition = found[0]
    sinks = [item for item in definition.sinks if item.line == finding.start_line and item.kind == kind]
    if not sinks:
        return FlowRefusal("no_parameter_origin_at_sink", "the question is not about a parameter")
    names = {item.name for item in definition.params if item.kind not in ("vararg", "varkw")}
    wanted = sorted({name for sink in sinks for name in sink.params})
    own = tuple(name for name in wanted if name in names)
    other = tuple(name for name in wanted if name not in names)
    if not own:
        return FlowRefusal("parameter_not_a_plain_parameter", ", ".join(other))
    return ParameterFlow(definition.id, definition.path, definition.qualname, finding.start_line, finding.check_id,
                         sinks[0].call, own, other)


def _unknown(reason: str) -> ArgFact:
    return ArgFact("pos", None, None, "unknown", reason=reason)


def bind_argument(edge: CallEdge, target: Definition, parameter: str) -> ArgFact:
    """The argument a call passes for `parameter`, or an `unknown`/default fact saying why not."""
    params = list(target.params)
    if edge.bound_first:
        first = next((index for index, item in enumerate(params) if item.kind in ("posonly", "pos")), None)
        if first is None:
            return _unknown("no_parameter_for_implicit_first_argument")
        del params[first]
    chosen = next((item for item in params if item.name == parameter), None)
    if chosen is None:
        return _unknown("parameter_not_in_signature")
    if chosen.kind in ("vararg", "varkw"):
        return _unknown("variadic_parameter")
    positional = [item for item in params if item.kind in ("posonly", "pos")]
    position = positional.index(chosen) if chosen.kind in ("posonly", "pos") else None
    for argument in edge.args:
        if argument.kind == "pos" and position is not None and argument.position == position:
            return argument
        if argument.kind == "kw" and argument.keyword == parameter and chosen.kind != "posonly":
            return argument
    if any(argument.kind == "pos" and argument.position is None for argument in edge.args):
        return _unknown("position_unknown_after_star")
    if any(argument.kind in ("star", "dstar") for argument in edge.args):
        return _unknown("star_arguments")
    if chosen.default == "literal":
        return ArgFact("pos", None, None, "constant", reason="default_value")
    if chosen.default == "other":
        return _unknown("default_not_literal")
    return _unknown("argument_not_supplied")


def _name(definition: Definition | None, fallback: str) -> str:
    return definition.qualname if definition is not None else fallback


def trace_callers(graph: Graph, flow: ParameterFlow, *, max_depth: int = 6, max_chains: int = 64) -> CallerReport:
    """Walk callers of the flow's function across files; classify each caller chain."""
    chains: list[CallerChain] = []
    notes: dict[str, None] = {NOT_VISIBLE: None}
    flow_definition = graph.definition(flow.definition)
    if flow_definition is None:
        return CallerReport(flow, "unknown", (), ("definition_not_in_graph",))
    if flow.unsupported:
        notes[f"unsupported_parameters:{','.join(flow.unsupported)}"] = None

    def finish(parameter: str, leaf: Verdict, reason: str | None, hops: list[Hop], *, source_label: str,
               entry: str | None = None, ancestors: list[Hop] | None = None) -> None:
        if len(chains) >= max_chains:
            notes["chain_limit"] = None
            return
        top_down = list(reversed(hops))
        steps: list[TraceStep] = []
        if top_down:
            first = top_down[0]
            steps.append(TraceStep(kind="source", line=first.line, label=source_label[:240], path=first.path))
            steps.extend(TraceStep(kind="call", line=hop.line, label=hop.label[:240], path=hop.path) for hop in top_down)
        steps.append(TraceStep(kind="sink", line=flow.line, label=f"{flow.sink_call}(…)"[:240], path=flow.path))
        recognized = None
        if entry is not None:
            node = graph.entry_point(entry)
            recognized = node.recognized_by if node is not None else None
        chains.append(CallerChain(parameter, leaf, reason, tuple([*(ancestors or []), *top_down]), entry, recognized,
                                  tuple(steps[:16])))

    def entry_ancestors(start: str) -> tuple[str, list[Hop]] | None:
        """The nearest entry point that reaches `start` through resolved calls (breadth first)."""
        seen = {start}
        queue: deque[tuple[str, list[Hop]]] = deque([(start, [])])
        while queue:
            current, below = queue.popleft()
            if graph.entry_point(current) is not None:
                return current, below
            if len(below) >= max_depth:
                continue
            for edge in sorted(graph.callers(current), key=lambda item: (item.caller, item.line, item.column)):
                node = graph.definition(edge.caller)
                if node is None or node.id in seen:
                    continue
                seen.add(node.id)
                hop = Hop(node.id, node.path, edge.line, current, f"{_name(graph.definition(current), current)}(…)")
                queue.append((node.id, [hop, *below]))
        return None

    def walk(target_id: str, parameter: str, hops: list[Hop], visited: frozenset[tuple[str, str]], depth: int,
             original: str) -> None:
        target = graph.definition(target_id)
        if target is None:
            return
        name = target.qualname.rsplit(".", 1)[-1]
        if target.kind == "method" and name == "__init__":
            parent = graph.definition(target.parent) if target.parent else None
            name = parent.qualname.rsplit(".", 1)[-1] if parent is not None else name
        if graph.references(target_id):
            notes[f"referenced_as_value:{target.qualname}"] = None
        if graph.possible_unresolved_callers(name):
            notes[f"possible_unresolved_callers:{target.qualname}"] = None
        edges = [edge for edge in graph.callers(target_id) if edge.target_kind in ("function", "method", "constructor")]
        if not edges:
            finish(original, "unknown", "no_resolved_callers", hops, source_label=f"no resolved caller of {target.qualname}")
            return
        for edge in sorted(edges, key=lambda item: (item.caller, item.line, item.column)):
            caller = graph.definition(edge.caller)
            caller_path = caller.path if caller is not None else edge.caller.split("::", 1)[0]
            hop = Hop(caller.id if caller is not None else None, caller_path, edge.line, target_id,
                      f"{target.qualname}(…) via {edge.callee}")
            here = [*hops, hop]
            if edge.opaque:
                finish(original, "unknown", f"opaque_decorator:{edge.opaque[0]}", here,
                       source_label=f"call through decorator {edge.opaque[0]}")
                continue
            argument = bind_argument(edge, target, parameter)
            if argument.cls == "constant":
                finish(original, "constant", argument.reason, here, source_label=f"constant argument for {parameter}")
            elif argument.cls == "sanitized":
                finish(original, "sanitized", None, here, source_label=f"sanitized argument for {parameter}")
            elif argument.cls == "request":
                label = argument.sources[0] if argument.sources else "request input"
                if caller is None:
                    finish(original, "unknown", "request_data_in_module_level_code", here, source_label=label)
                elif graph.entry_point(caller.id) is not None:
                    finish(original, "request", None, here, source_label=label, entry=caller.id)
                else:
                    found = entry_ancestors(caller.id)
                    if found is None:
                        finish(original, "unknown", "request_data_without_known_entry_point", here, source_label=label)
                    else:
                        finish(original, "request", None, here, source_label=label, entry=found[0], ancestors=found[1])
            elif argument.cls == "param":
                for source_parameter in argument.params:
                    if caller is None:
                        finish(original, "unknown", "module_level_call", here, source_label=f"module-level call passes {parameter}")
                        continue
                    own = {item.name for item in caller.params if item.kind not in ("vararg", "varkw")}
                    if graph.entry_point(caller.id) is not None and source_parameter in own:
                        finish(original, "request", None, here,
                               source_label=f"request input {source_parameter}", entry=caller.id)
                    elif source_parameter not in own:
                        finish(original, "unknown", "not_a_plain_parameter_of_caller", here,
                               source_label=f"{source_parameter} is not a plain parameter of {caller.qualname}")
                    elif depth + 1 >= max_depth:
                        notes["depth_limit"] = None
                        finish(original, "unknown", "depth_limit", here, source_label=f"depth limit at {caller.qualname}")
                    elif (caller.id, source_parameter) in visited:
                        finish(original, "unknown", "recursive_call", here, source_label=f"recursion at {caller.qualname}")
                    else:
                        walk(caller.id, source_parameter, here, visited | {(caller.id, source_parameter)}, depth + 1, original)
            else:
                finish(original, "unknown", argument.reason or "unknown_argument", here,
                       source_label=f"argument not resolved ({argument.reason or 'unknown'})")

    for parameter in flow.parameters:
        if graph.entry_point(flow.definition) is not None:
            finish(parameter, "request", "entry_point_parameter", [], source_label=f"entry point parameter {parameter}",
                   entry=flow.definition)
            continue
        walk(flow.definition, parameter, [], frozenset({(flow.definition, parameter)}), 0, parameter)

    leaves = [chain.leaf for chain in chains]
    blocking = [note for note in notes if note.startswith(BLOCKING_NOTES) or note.startswith("unsupported_parameters")]
    if "request" in leaves:
        verdict: Verdict = "request"
    elif leaves and all(leaf == "constant" for leaf in leaves) and not blocking:
        verdict = "constant"
    elif leaves and all(leaf in ("constant", "sanitized") for leaf in leaves) and not blocking:
        verdict = "sanitized"
    else:
        verdict = "unknown"
    return CallerReport(flow, verdict, tuple(chains), tuple(notes))

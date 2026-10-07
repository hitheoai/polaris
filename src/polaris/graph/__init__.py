"""Experimental deterministic code graph (library only; not wired into reviews).

See docs/graph.md. The graph is built from file texts, holds ids, hashes and symbol names (never
source text), and says explicitly what it could not resolve.
"""

from polaris.graph.build import GraphCache, build_graph, graph_json
from polaris.graph.callers import (
    CallerChain,
    CallerReport,
    FlowRefusal,
    ParameterFlow,
    flow_from_finding,
    trace_callers,
)
from polaris.graph.model import GRAPH_FORMAT, Graph, Incomplete, Limits
from polaris.graph.source import LoadedSources, load_directory

__all__ = [
    "GRAPH_FORMAT", "CallerChain", "CallerReport", "FlowRefusal", "Graph", "GraphCache", "Incomplete",
    "Limits", "LoadedSources", "ParameterFlow", "build_graph", "flow_from_finding", "graph_json",
    "load_directory", "trace_callers",
]

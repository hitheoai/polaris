"""Build the experimental code graph for a directory and measure it (offline, deterministic output).

    uv run python scripts/graph_spike.py PATH [--json] [--check-determinism] [--dump GRAPH.json]

Prints file/node/edge counts, the unresolved-edge ratio with its reasons, build time and peak
memory of this process. Counts and the graph digest are deterministic; times and memory are not.
Run one directory per process: peak memory is the process maximum.
"""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from pathlib import Path

from polaris.graph import Limits, build_graph, graph_json, load_directory


def peak_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def top(reasons: dict[str, int], count: int = 6) -> str:
    ranked = sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:count]
    return ", ".join(f"{name}={number}" for name, number in ranked) or "none"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path)
    parser.add_argument("--json", action="store_true", help="print one JSON object instead of text")
    parser.add_argument("--check-determinism", action="store_true", help="build twice and compare the bytes")
    parser.add_argument("--dump", type=Path, help="write the canonical graph JSON here")
    args = parser.parse_args()

    baseline = peak_mb()
    started = time.perf_counter()
    loaded = load_directory(args.path, limits=Limits())
    load_seconds = time.perf_counter() - started
    started = time.perf_counter()
    graph = build_graph(loaded.files, skipped=loaded.skipped, limits=Limits(), extra_incomplete=loaded.incomplete)
    build_seconds = time.perf_counter() - started
    peak = peak_mb()
    serialized = graph_json(graph)
    stats = graph.stats
    result = {
        "path": str(args.path), "digest": graph.digest, "complete": not graph.incomplete,
        "incomplete": [item.to_dict() for item in graph.incomplete][:20], "incomplete_count": len(graph.incomplete),
        "files": stats["files"], "nodes": stats["nodes"], "edges": stats["edges"],
        "definitions": stats["definitions"], "imports": stats["imports"], "calls": stats["calls"],
        "refs": stats["refs"], "entry_points": stats["entry_points"], "script_imports": stats["script_imports"],
        "unresolved_edge_ratio": stats["unresolved_edge_ratio"],
        "unresolved_non_external_ratio": stats["unresolved_non_external_ratio"],
        "load_seconds": round(load_seconds, 2), "build_seconds": round(build_seconds, 2),
        "peak_mb": round(peak, 1), "baseline_mb": round(baseline, 1), "serialized_mb": round(len(serialized) / 1e6, 2),
    }
    if args.check_determinism:
        again = build_graph(loaded.files, skipped=loaded.skipped, limits=Limits(), extra_incomplete=loaded.incomplete)
        result["deterministic"] = graph_json(again) == serialized
    if args.dump:
        args.dump.write_bytes(serialized)
    if args.json:
        print(json.dumps(result, sort_keys=True))
        return 0
    print(f"graph of {args.path}  digest {graph.digest[:19]}…  complete={result['complete']}")
    print(f"  files {stats['files']}  nodes {stats['nodes']}  edges {stats['edges']}  definitions {stats['definitions']}")
    imports, calls = stats["imports"], stats["calls"]
    print(f"  imports {imports['total']}: unresolved {imports['unresolved']} "
          f"({imports['unresolved_external']} external)  [{top(imports['unresolved_reasons'])}]")
    print(f"  calls {calls['total']}: resolved {calls['resolved']}, unresolved {calls['unresolved']} "
          f"({calls['unresolved_external']} external)  in-repo resolution rate {calls['in_repo_resolution_rate']}")
    print(f"    unresolved reasons: {top(calls['unresolved_reasons'], 10)}")
    print(f"  entry points {stats['entry_points']}  refs {stats['refs']}  script imports {stats['script_imports']['total']}")
    print(f"  unresolved edge ratio {stats['unresolved_edge_ratio']} (without external: {stats['unresolved_non_external_ratio']})")
    print(f"  load {load_seconds:.2f}s  build {build_seconds:.2f}s  peak {peak:.0f} MB (process baseline {baseline:.0f} MB)  "
          f"serialized {len(serialized) / 1e6:.1f} MB")
    if "deterministic" in result:
        print(f"  two builds byte-identical: {result['deterministic']}")
    for item in graph.incomplete[:8]:
        print(f"  incomplete: {item.reason} {item.path or ''} {item.detail or ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

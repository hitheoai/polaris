# Code graph (experimental)

Status: experimental spike. It is a library (`polaris.graph`) and two scripts. No command uses it, no default review reads it, and it changes no finding, severity or exit code.

The graph is a deterministic, local picture of a repository: which file imports which, which functions and classes exist, who calls whom, and which functions are request handlers. It is built from file texts with `ast` (Python) and tree-sitter (TypeScript and JavaScript). Nothing is imported, executed or sent anywhere.

## What it holds

- Files, with a digest of each file's text.
- Python: imports, definitions (functions, methods, nested functions, classes), call edges, references to functions used as values, entry points.
- For every Python call, what each argument is made of: a constant, request-derived, derived from a parameter of the caller, sanitized by the existing rules, or unknown, with the reason.
- For every Python function, the sinks the existing flow rules find whose argument comes from a parameter.
- TypeScript and JavaScript: file-to-file import edges only (static `import`, `export ... from`, `require`, `import()`), resolved with the relative path and the `tsconfig`/`jsconfig` aliases the TypeScript analyzer already reads.

It holds ids, paths, line numbers, symbol names and digests. It never holds source text, string values or comments. The serialized form is canonical JSON (`graph_json`) with a SHA-256 digest.

## What it refuses to guess

An edge is `resolved` only when the target follows from the code without a choice between alternatives. Everything else is an `unresolved` edge with a reason:

- a module name that matches two files (`ambiguous_module`), a name that is bound more than once (`rebound_name`), a module that is in a cycle (`import_cycle`), a relative import that leaves the top package;
- star imports: resolved only when the names can be listed (`__all__` as a literal, or public top-level names); otherwise `star_import`;
- a call on a value of unknown type (`obj.method()`, `self.attr.method()`, a call on a computed expression): `dynamic_receiver`;
- a name that is a parameter or local variable at the call site: `local_binding`;
- `self.method()` when a subclass in the repository overrides the method (`overridden_in_subclass`), or when a base class cannot be resolved (`unresolved_base`, `external_base`);
- decorators other than a short list known not to change how a function is called: the call edge is kept and marked `opaque`, and the consumer refuses to bind arguments through it;
- files that were not analyzed (too large, binary, parse errors, over a limit) stay visible as targets: an import of one is `target_not_analyzed`, never "third party".

Calls that leave the repository (builtins, the standard library, installed packages) are unresolved with `external: true`. They are listed, but they are not gaps. The statistics report the unresolved ratio with and without them.

## Limits

`Limits` bounds files, bytes per file, total bytes, nodes and edges. Hitting a limit never fails silently: the graph lists it in `incomplete` (`file_limit`, `file_too_large`, `total_bytes_limit`, `node_limit`, `edge_limit`, `parse_error`, `invalid_encoding`) and `complete` is false. Files are processed in sorted order and processing stops at the first limit, so the same repository state and limits always give the same graph.

## Determinism and caching

The same repository state always serializes to the same bytes, whatever order the files arrive in. Facts of each file are keyed by (extractor version, file digest, path) in `GraphCache`, an in-memory cache for now. A later persistent cache only has to store those facts under the same key.

## First consumer: caller tracing

`flow_from_finding` and `trace_callers` take a Python `needs_context` finding that asks about a parameter ("this parameter reaches a sink; judging it needs the callers") and walk the resolved callers across files. For every caller chain they report what the argument is: constant, request-derived from a known entry point, sanitized by the existing rules, or unknown. A request-derived chain comes with a cross-file trace in the existing `TraceStep` shape.

What it claims, and what it withholds:

- A request-derived chain needs the value to come from request input in a function that is a recognized entry point, or is reached from one through resolved calls.
- "Constant at every caller" is withheld when a call that could be a caller is unresolved, or when the function is also used as a value (callback, decorator, registry).
- Callers outside the repository, dynamic dispatch and framework registration are never visible. Every report says so.
- Entry points come from the review analyzer's own recognition (route and view decorators, `request` first parameter in `views.py`/`api.py`/`routes.py`). The graph adds one more kind, methods of class-based views, and labels it `recognized_by: graph`.

A request-derived result is a static fact about data flow under the existing taint rules. It is not a proof that the code is exploitable, and it does not account for validation inside the callee that those rules do not recognize.

## Measured so far

Build cost on public repositories, one directory per process, Apple M-series laptop, single process. Peak memory is the process maximum (about 40 MB is the Python and Polaris baseline). Counts are deterministic; times are not.

| Repository (commit) | Python / script files | Nodes | Edges | Unresolved (all / not external) | In-repo call resolution | Build s | Peak MB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| getredash/redash (e170795) | 291 / 581 | 4,061 | 21,010 | 0.70 / 0.31 | 0.32 | 2.2 | 107 |
| healthchecks/healthchecks (e623fa3) | 654 / 42 | 4,094 | 20,407 | 0.87 / 0.28 | 0.21 | 3.0 | 105 |
| CTFd/CTFd (8d32061) | 348 / 169 | 2,593 | 23,298 | 0.62 / 0.40 | 0.40 | 3.4 | 108 |
| indico/indico (d4436e8) | 1,285 / 776 | 14,829 | 80,262 | 0.68 / 0.38 | 0.30 | 7.7 | 264 |
| netbox-community/netbox (a6e0fa0) | 1,289 / 54 | 18,535 | 127,464 | 0.79 / 0.19 | 0.43 | 13.8 | 411 |
| zulip/zulip (494b496) | 2,034 / 692 | 19,201 | 163,822 | 0.50 / 0.17 | 0.71 | 21.0 | 582 |
| sqlalchemy/sqlalchemy (baff8f6) | 673 / 0 | 41,392 | 242,909 | 0.49 / 0.38 | 0.54 | 26.8 | 704 |
| mlflow/mlflow (ff8bb36) | 2,741 / 3,049 | 45,340 | 291,488 | 0.65 / 0.31 | 0.43 | 39.8 | 895 |

Two builds of every repository were byte-identical. Several graphs are incomplete (a file over the size limit, a file that does not parse, a binary `.py`); `complete: false` says so.

What the consumer did with today's Python `needs_context` findings on the same repositories (4,403 findings, 2,554 of them parameter questions): 12 became a request-derived chain from an analyzer-recognized entry point, 42 are methods the graph itself recognizes as class-view entry points (not caller chains), 2 became "constant at every caller", 2,498 stayed unknown. A manual read of the 12 request-derived chains found 2 where a request-controlled value really reaches a sensitive sink, 4 where the value does flow but the code validates or the sink is harmless, and 6 where the taint is an artifact of the existing rules (a value derived through a database lookup, a rendering call, arithmetic, or the whole request object). That is not good enough to feed back into reviews; see the status above.

Reproduce with `scripts/graph_spike.py PATH` (counts, ratios, time, memory) and `scripts/graph_eval.py PATH` (the `needs_context` evaluation). Both are offline and read only the directory they are given.

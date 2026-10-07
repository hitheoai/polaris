"""The experimental code graph, on small synthetic repositories (source is parsed, never run)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from polaris.graph import (
    FlowRefusal,
    GraphCache,
    Limits,
    build_graph,
    flow_from_finding,
    graph_json,
    load_directory,
    trace_callers,
)
from polaris.graph.callers import ParameterFlow
from polaris.graph.model import CallEdge, Graph, ImportEdge
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import SourceFile, WorkflowReviewConfig


def build(files: Mapping[str, str], **kwargs: object) -> Graph:
    return build_graph(dict(files), **kwargs)  # type: ignore[arg-type]


def calls_from(graph: Graph, caller_suffix: str, callee: str) -> list[CallEdge]:
    return [edge for edge in graph.calls if edge.caller.endswith(caller_suffix) and edge.callee == callee]


def one_call(graph: Graph, caller_suffix: str, callee: str) -> CallEdge:
    found = calls_from(graph, caller_suffix, callee)
    assert len(found) == 1, found
    return found[0]


def imports_of(graph: Graph, importer: str) -> list[ImportEdge]:
    return [edge for edge in graph.imports if edge.importer == importer]


# ---- imports ----------------------------------------------------------------------------------


def test_absolute_imports_resolve_to_files_inside_the_repository() -> None:
    graph = build({
        "pkg/__init__.py": "",
        "pkg/mod.py": "def f(x):\n    return x\n",
        "pkg/sub/__init__.py": "",
        "pkg/sub/leaf.py": "def g():\n    return 1\n",
        "main.py": "from pkg.mod import f\nimport pkg.mod as m\nimport pkg.sub.leaf\n\nf(1)\nm.f(2)\npkg.sub.leaf.g()\n",
    })
    edges = {(edge.module, edge.name): edge for edge in imports_of(graph, "main.py")}
    assert edges[("pkg.mod", "f")].status == "resolved" and edges[("pkg.mod", "f")].target == "pkg/mod.py"
    assert edges[("pkg.mod", "")].target == "pkg/mod.py"
    assert edges[("pkg.sub.leaf", "")].target == "pkg/sub/leaf.py"
    assert one_call(graph, "main.py::<module>", "f").target == "pkg/mod.py::f"
    assert one_call(graph, "main.py::<module>", "m.f").target == "pkg/mod.py::f"
    assert one_call(graph, "main.py::<module>", "pkg.sub.leaf.g").target == "pkg/sub/leaf.py::g"


def test_unresolved_imports_say_why_and_external_ones_are_marked() -> None:
    graph = build({
        "util.py": "def one():\n    return 1\n",
        "src/util.py": "def two():\n    return 2\n",
        "pkg/__init__.py": "",
        "main.py": "import os\nimport requests\nimport pkg.missing\nimport util\nfrom pkg import nothing\n",
    })
    by_module = {edge.module + ":" + edge.name: edge for edge in imports_of(graph, "main.py")}
    assert by_module["os:"].reason == "stdlib" and by_module["os:"].external
    assert by_module["requests:"].reason == "third_party" and by_module["requests:"].external
    assert by_module["pkg.missing:"].reason == "missing_submodule" and not by_module["pkg.missing:"].external
    assert by_module["pkg:nothing"].reason == "symbol_not_found"
    # `util` is both ./util.py and src/util.py (src is an import root): the graph does not pick one.
    assert by_module["util:"].reason == "ambiguous_module" and by_module["util:"].status == "unresolved"
    assert all(edge.status == "unresolved" for edge in by_module.values())


def test_relative_imports_follow_the_importing_package() -> None:
    graph = build({
        "pkg/__init__.py": "",
        "pkg/helper.py": "def h():\n    return 1\n",
        "pkg/sub/__init__.py": "from ..helper import h\n",
        "pkg/sub/inner.py": "from . import sibling\nfrom .. import helper\nfrom ... import toofar\n\nsibling.s()\nhelper.h()\n",
        "pkg/sub/sibling.py": "def s():\n    return 2\n",
    })
    edges = {(edge.module, edge.name): edge for edge in imports_of(graph, "pkg/sub/inner.py")}
    assert edges[(".", "sibling")].target == "pkg/sub/sibling.py"
    assert edges[("..", "helper")].target == "pkg/helper.py"
    assert edges[("...", "toofar")].reason == "relative_beyond_root"
    assert one_call(graph, "inner.py::<module>", "sibling.s").target == "pkg/sub/sibling.py::s"
    assert one_call(graph, "inner.py::<module>", "helper.h").target == "pkg/helper.py::h"


def test_import_cycles_do_not_loop_and_unresolvable_reexports_are_explicit() -> None:
    graph = build({
        "a.py": "from b import x\n\ndef fa():\n    return x()\n",
        "b.py": "from a import x\n\ndef fb():\n    return 1\n",
        "c.py": "import d\n\ndef fc():\n    return d.fd()\n",
        "d.py": "import c\n\ndef fd():\n    return c.fc()\n",
    })
    # `x` is only ever re-imported from the other file: it never reaches a definition.
    edge = one_call(graph, "a.py::fa", "x")
    assert edge.status == "unresolved" and edge.reason == "import_cycle"
    # A plain module cycle is fine: both directions resolve.
    assert one_call(graph, "c.py::fc", "d.fd").target == "d.py::fd"
    assert one_call(graph, "d.py::fd", "c.fc").target == "c.py::fc"


def test_star_imports_resolve_only_when_the_names_can_be_listed() -> None:
    graph = build({
        "listed.py": "__all__ = ['visible']\n\ndef visible():\n    return 1\n\ndef hidden():\n    return 2\n",
        "dynamic.py": "__all__ = []\n__all__ += compute()\n\ndef maybe():\n    return 1\n",
        "user.py": "from listed import *\nfrom dynamic import *\n\ndef go():\n    visible()\n    hidden()\n    maybe()\n",
    })
    visible = one_call(graph, "user.py::go", "visible")
    assert visible.status == "resolved" and visible.via_star and visible.target == "listed.py::visible"
    # Not in __all__, and another star import whose names are unknowable could provide it.
    assert one_call(graph, "user.py::go", "hidden").reason == "star_import"
    assert one_call(graph, "user.py::go", "maybe").reason == "star_import"
    stars = {edge.module: edge for edge in imports_of(graph, "user.py")}
    assert stars["listed"].status == "resolved" and stars["listed"].kind == "star"
    assert stars["dynamic"].status == "unresolved" and stars["dynamic"].reason == "star_import"


def test_names_that_are_shadowed_or_rebound_are_not_guessed() -> None:
    graph = build({
        "helpers.py": "def clean(v):\n    return v\n",
        "twice.py": "def pick():\n    return 1\n\ndef pick():\n    return 2\n",
        "main.py": (
            "from helpers import clean\nfrom twice import pick\n\n"
            "def shadow_param(clean):\n    return clean(1)\n\n"
            "def shadow_local():\n    clean = lambda v: v\n    return clean(1)\n\n"
            "def plain():\n    return clean(1)\n\n"
            "def twice_defined():\n    return pick()\n"
        ),
    })
    assert one_call(graph, "main.py::shadow_param", "clean").reason == "local_binding"
    assert one_call(graph, "main.py::shadow_local", "clean").reason == "local_binding"
    assert one_call(graph, "main.py::plain", "clean").target == "helpers.py::clean"
    assert one_call(graph, "main.py::twice_defined", "pick").reason == "rebound_name"
    ids = [item.id for item in graph.definitions if item.path == "twice.py"]
    assert len(ids) == 2 and len(set(ids)) == 2


def test_overload_stubs_and_property_accessors_do_not_make_a_name_ambiguous() -> None:
    graph = build({
        "lib.py": (
            "from typing import overload\n\n@overload\ndef pick(a: int) -> int: ...\n\n@overload\ndef pick(a: str) -> str: ...\n\n"
            "def pick(a):\n    return a\n\nclass Box:\n    @property\n    def size(self):\n        return 1\n\n"
            "    @size.setter\n    def size(self, value):\n        self._size = value\n"
        ),
        "main.py": "from lib import pick\n\ndef go():\n    return pick(1)\n",
    })
    edge = one_call(graph, "main.py::go", "pick")
    assert edge.status == "resolved" and edge.target is not None and edge.target.startswith("lib.py::pick")
    implementation = graph.definition(edge.target)
    assert implementation is not None and implementation.decorators == ()
    assert len([item for item in graph.definitions if item.qualname == "pick"]) == 3


def test_a_package_importing_its_own_submodule_resolves_to_the_submodule() -> None:
    graph = build({
        "pkg/__init__.py": "from pkg import settings\n\nsettings.load()\n",
        "pkg/settings.py": "def load():\n    return 1\n",
    })
    edge = next(item for item in graph.imports if item.importer == "pkg/__init__.py")
    assert edge.status == "resolved" and edge.target == "pkg/settings.py"
    assert one_call(graph, "pkg/__init__.py::<module>", "settings.load").target == "pkg/settings.py::load"


def test_local_imports_and_nested_functions_resolve_in_their_scope() -> None:
    graph = build({
        "lib.py": "def work(v):\n    return v\n",
        "main.py": (
            "def outer():\n    from lib import work\n\n    def inner(v):\n        return work(v)\n\n    return inner(1)\n"
        ),
    })
    assert one_call(graph, "main.py::outer.<locals>.inner", "work").target == "lib.py::work"
    assert one_call(graph, "main.py::outer", "inner").target == "main.py::outer.<locals>.inner"
    assert graph.definition("main.py::outer.<locals>.inner") is not None


# ---- decorators, classes ----------------------------------------------------------------------------


def test_decorators_are_recorded_and_unknown_ones_are_marked_opaque() -> None:
    graph = build({
        "deco.py": "def retry(fn):\n    return fn\n",
        "main.py": (
            "from flask import Flask\nfrom deco import retry\n\napp = Flask(__name__)\n\n"
            "@retry\ndef flaky(a):\n    return a\n\n"
            "@app.route('/x')\ndef view():\n    return flaky(1)\n\n"
            "def plain(a):\n    return a\n\n"
            "def caller():\n    plain(1)\n    flaky(2)\n"
        ),
    })
    assert one_call(graph, "main.py::caller", "flaky").opaque == ("retry",)
    assert one_call(graph, "main.py::caller", "plain").opaque == ()
    view = next(item for item in graph.definitions if item.qualname == "view")
    assert view.decorators == ("app.route",) and view.analyzer_entry == "route"
    assert graph.entry_point("main.py::view") is not None
    assert graph.entry_point("main.py::view").recognized_by == "analyzer"  # type: ignore[union-attr]


def test_methods_constructors_and_overrides() -> None:
    graph = build({
        "shapes.py": (
            "class Base:\n    def __init__(self, size):\n        self.size = size\n\n"
            "    def area(self):\n        return self.helper()\n\n    def helper(self):\n        return 1\n\n"
            "    def other(self):\n        return self.helper()\n\n"
            "    @classmethod\n    def make(cls, size):\n        return cls(size)\n\n"
            "    @staticmethod\n    def util(a):\n        return a\n\n"
            "class Child(Base):\n    def helper(self):\n        return 2\n\n"
            "class Alone:\n    def run(self):\n        return self.step()\n\n    def step(self):\n        return 1\n"
        ),
        "use.py": (
            "from shapes import Base, Alone\n\ndef go():\n    Base(3)\n    Base.make(4)\n    Base.util(5)\n"
            "    Alone().run()\n"
        ),
    })
    # Child overrides helper(): `self.helper()` in Base could run either; not resolved.
    assert one_call(graph, "shapes.py::Base.area", "self.helper").reason == "overridden_in_subclass"
    # Nothing overrides step(): resolved, with `self` supplied implicitly.
    step = one_call(graph, "shapes.py::Alone.run", "self.step")
    assert step.target == "shapes.py::Alone.step" and step.bound_first and step.target_kind == "method"
    constructor = one_call(graph, "use.py::go", "Base")
    assert constructor.target == "shapes.py::Base.__init__" and constructor.target_kind == "constructor" and constructor.bound_first
    make = one_call(graph, "use.py::go", "Base.make")
    assert make.target == "shapes.py::Base.make" and make.bound_first
    util = one_call(graph, "use.py::go", "Base.util")
    assert util.target == "shapes.py::Base.util" and not util.bound_first
    # `Alone().run()`: the receiver is a computed expression, never guessed.
    assert one_call(graph, "use.py::go", "<expr>.run").reason == "dynamic_receiver"


def test_calls_through_unknown_receivers_and_expressions_stay_unresolved() -> None:
    graph = build({
        "main.py": "def go(obj, table):\n    obj.save()\n    table['k']()\n    (lambda: 1)()\n    print(obj)\n",
    })
    assert one_call(graph, "main.py::go", "obj.save").reason == "dynamic_receiver"
    computed = calls_from(graph, "main.py::go", "<expression>")
    assert len(computed) == 2 and {edge.reason for edge in computed} == {"not_a_name"}
    assert one_call(graph, "main.py::go", "print").reason == "builtin"
    assert one_call(graph, "main.py::go", "print").external


# ---- determinism, limits, cache, privacy ----------------------------------------------------------------


FIXTURE = {
    "pkg/__init__.py": "",
    "pkg/a.py": "from pkg.b import g\n\ndef f(x):\n    return g(x)\n",
    "pkg/b.py": "import subprocess\n\ndef g(cmd):\n    return subprocess.run(cmd, shell=True)\n",
    "tool.py": "from pkg.a import f\n\ndef main(argv):\n    return f('ls')\n",
}


def test_two_builds_of_the_same_state_are_byte_identical_regardless_of_input_order() -> None:
    first = build(FIXTURE)
    second = build(dict(reversed(list(FIXTURE.items()))))
    assert graph_json(first) == graph_json(second)
    assert first.digest == second.digest and first.digest.startswith("sha256:")
    changed = build({**FIXTURE, "tool.py": "from pkg.a import f\n\ndef main(argv):\n    return f('ls -l')\n"})
    assert changed.digest != first.digest


def test_serialized_graph_holds_no_source_text() -> None:
    secret = "UNIQUE_LITERAL_7f3a9c"
    graph = build({"m.py": f"TOKEN = '{secret}'\n\ndef f(a):\n    return a + '{secret}'\n\n# comment {secret}\nf('{secret}')\n"})
    assert secret.encode() not in graph_json(graph)


def test_limits_report_what_was_left_out_and_are_deterministic() -> None:
    files = {f"m{index}.py": f"def f{index}():\n    return {index}\n" for index in range(6)}
    limited = build(files, limits=Limits(max_files=3))
    again = build(files, limits=Limits(max_files=3))
    assert [item.path for item in limited.files] == ["m0.py", "m1.py", "m2.py"]
    assert any(item.reason == "file_limit" and item.path == "m3.py" for item in limited.incomplete)
    assert graph_json(limited) == graph_json(again)
    big = build({"big.py": "x = 1\n" * 100, "small.py": "def s():\n    return 1\n"}, limits=Limits(max_file_bytes=200))
    assert any(item.reason == "file_too_large" and item.path == "big.py" for item in big.incomplete)
    assert [item.path for item in big.files if item.status == "ok"] == ["small.py"]
    nodes = build(files, limits=Limits(max_nodes=4))
    assert any(item.reason == "node_limit" for item in nodes.incomplete)
    assert sum(1 for item in nodes.files if item.status == "ok") == 2
    edges = build({"a.py": "def a():\n    return b()\n\ndef b():\n    return 1\n", "c.py": "import a\na.a()\n"},
                  limits=Limits(max_edges=2))
    assert any(item.reason == "edge_limit" for item in edges.incomplete)
    assert build(files).incomplete == ()


def test_files_that_were_not_analyzed_stay_visible_as_targets() -> None:
    graph = build({
        "broken.py": "def oops(:\n",
        "main.py": "import broken\nfrom broken import oops\n\nbroken.oops()\n",
        "big.py": "def huge():\n    return 1\n",
    }, skipped={"big.py": "file_too_large"})
    reasons = {edge.module: edge.reason for edge in imports_of(graph, "main.py")}
    assert reasons["broken"] == "target_not_analyzed"
    assert {item.reason for item in graph.incomplete} >= {"parse_error", "file_too_large"}


def test_facts_are_cached_by_file_digest() -> None:
    cache = GraphCache()
    build(FIXTURE, cache=cache)
    assert cache.misses == 4 and cache.hits == 0
    build(FIXTURE, cache=cache)
    assert cache.hits == 4
    build({**FIXTURE, "tool.py": "def main(argv):\n    return 1\n"}, cache=cache)
    assert cache.misses == 5 and cache.hits == 7


def test_load_directory_reads_sources_and_skips_dependency_folders(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs\n", encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00bad")
    loaded = load_directory(tmp_path)
    assert sorted(loaded.files) == ["pkg/a.py"]
    assert loaded.skipped == {"bad.py": "binary"}
    graph = build_graph(loaded.files, skipped=loaded.skipped)
    assert any(item.reason == "binary" and item.path == "bad.py" for item in graph.incomplete)


# ---- TypeScript / JavaScript ---------------------------------------------------------------------


def test_script_imports_resolve_relative_alias_and_external_specifiers() -> None:
    graph = build({
        "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@lib/*": ["src/lib/*"]}}}',
        "src/app.ts": (
            "import { a } from './util';\nimport { b } from '@lib/thing';\nimport React from 'react';\n"
            "import fs from 'node:fs';\nexport { c } from './util';\nconst d = require('./cjs');\n"
            "const e = await import(name);\nimport './style.css';\n"
        ),
        "src/util.ts": "export const a = 1;\nexport const c = 2;\n",
        "src/lib/thing.ts": "export const b = 1;\n",
        "src/cjs.js": "module.exports = {};\n",
    })
    edges = {(edge.kind, edge.specifier): edge for edge in graph.script_imports if edge.importer == "src/app.ts"}
    assert edges[("import", "./util")].target == "src/util.ts"
    assert edges[("import", "@lib/thing")].target == "src/lib/thing.ts"
    assert edges[("export_from", "./util")].target == "src/util.ts"
    assert edges[("require", "./cjs")].target == "src/cjs.js"
    assert edges[("import", "react")].reason == "external_package" and edges[("import", "react")].external
    assert edges[("import", "node:fs")].reason == "node_builtin"
    assert edges[("dynamic_import", "")].reason == "dynamic_specifier" and not edges[("dynamic_import", "")].external
    assert edges[("import", "./style.css")].reason == "non_script_file"


# ---- the consumer -------------------------------------------------------------------------------


def flow_for(graph: Graph, path: str, symbol: str, kind_line: int | None = None) -> ParameterFlow:
    definition = next(item for item in graph.definitions if item.path == path and item.qualname == symbol)
    sink = next(item for item in definition.sinks if kind_line is None or item.line == kind_line)
    return ParameterFlow(definition.id, path, symbol, sink.line, "sql_injection" if sink.kind == "sql" else "command_injection",
                         sink.call, sink.params)


CROSS_FILE = {
    "lib/__init__.py": "",
    "lib/db.py": (
        "import sqlite3\n\ndef run_query(sql):\n    conn = sqlite3.connect('x.db')\n    return conn.execute(sql)\n\n"
        "def fetch(table, ident):\n    return run_query('select * from ' + table + ' where id=' + ident)\n"
    ),
    "app/__init__.py": "",
    "app/web.py": (
        "from flask import Flask, request\nfrom lib.db import fetch\n\napp = Flask(__name__)\n\n"
        "@app.route('/a')\ndef a():\n    name = request.args['name']\n    return str(fetch('users', name))\n\n"
        "@app.route('/b')\ndef b():\n    return str(fetch('users', '1'))\n"
    ),
}


def test_a_parameter_question_becomes_a_traced_cross_file_flow() -> None:
    graph = build(CROSS_FILE)
    flow = flow_for(graph, "lib/db.py", "run_query")
    assert flow.parameters == ("sql",)
    report = trace_callers(graph, flow)
    assert report.verdict == "request"
    request_chain = next(chain for chain in report.chains if chain.leaf == "request")
    assert request_chain.entry_point == "app/web.py::a" and request_chain.entry_recognized_by == "analyzer"
    paths = [step.path for step in request_chain.trace]
    assert paths[0] == "app/web.py" and paths[-1] == "lib/db.py"
    assert [step.kind for step in request_chain.trace][0] == "source" and request_chain.trace[-1].kind == "sink"
    assert request_chain.trace[-1].line == flow.line
    # Only the `ident` argument of b() is constant; `table` is a constant in both.
    assert {chain.leaf for chain in report.chains} == {"request", "constant"}


def test_flow_from_a_real_needs_context_finding() -> None:
    sources = [SourceFile(path, text) for path, text in CROSS_FILE.items()]
    reviewer = WorkflowReviewer(config=WorkflowReviewConfig(),
                                runtime=AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False))
    report = reviewer.review_sources(sources)
    asked = [item for item in report.findings if item.result == "needs_context" and item.check_id == "sql_injection"]
    assert asked, [(item.path, item.symbol, item.result) for item in report.findings]
    graph = build(CROSS_FILE)
    flow = flow_from_finding(graph, asked[0])
    assert isinstance(flow, ParameterFlow)
    assert flow.path == "lib/db.py" and flow.symbol == "run_query"
    assert trace_callers(graph, flow).verdict == "request"


def test_findings_that_are_not_parameter_questions_are_refused() -> None:
    graph = build(CROSS_FILE)

    class Fake:
        path, symbol, start_line, check_id, result = "lib/db.py", "run_query", 5, "sql_injection", "flagged"

    refusal = flow_from_finding(graph, Fake())
    assert isinstance(refusal, FlowRefusal) and refusal.reason == "not_a_needs_context_finding"
    Fake.result, Fake.start_line = "needs_context", 3  # inside run_query, but no sink on this line
    refusal = flow_from_finding(graph, Fake())
    assert isinstance(refusal, FlowRefusal) and refusal.reason == "no_parameter_origin_at_sink"
    Fake.symbol = "<module>"
    refusal = flow_from_finding(graph, Fake())
    assert isinstance(refusal, FlowRefusal) and refusal.reason == "module_level_code"
    Fake.symbol, Fake.check_id = "nope", "sql_injection"
    refusal = flow_from_finding(graph, Fake())
    assert isinstance(refusal, FlowRefusal) and refusal.reason == "definition_not_in_graph"


def test_all_constant_callers_give_constant_and_a_hidden_caller_withholds_it() -> None:
    files = {
        "db.py": "import sqlite3\n\nTABLE = 'users'\n\ndef run(sql):\n    return sqlite3.connect('x').execute(sql)\n",
        "one.py": "from db import run, TABLE\n\ndef a():\n    return run('select 1')\n\ndef b():\n    return run('select * from ' + TABLE)\n",
    }
    graph = build(files)
    report = trace_callers(graph, flow_for(graph, "db.py", "run"))
    assert [chain.leaf for chain in report.chains] == ["constant", "constant"]
    assert report.verdict == "constant"
    assert any("not visible" in note for note in report.notes)
    # An unresolved call that ends in the same name could be another caller.
    hidden = build({**files, "two.py": "def c(registry):\n    return registry.run(input())\n"})
    withheld = trace_callers(hidden, flow_for(hidden, "db.py", "run"))
    assert withheld.verdict == "unknown"
    assert any(note.startswith("possible_unresolved_callers") for note in withheld.notes)
    # A function used as a value (callback) may be called from anywhere.
    callback = build({**files, "three.py": "from db import run\n\nHANDLERS = [run]\n"})
    assert trace_callers(callback, flow_for(callback, "db.py", "run")).verdict == "unknown"


def test_constants_that_are_rebound_or_computed_are_not_constant() -> None:
    files = {
        "db.py": "import sqlite3\n\ndef run(sql):\n    return sqlite3.connect('x').execute(sql)\n",
        "one.py": (
            "import os\nfrom db import run\n\nMODE = 'a'\nOTHER = os.environ['T']\n\ndef set_mode():\n    global MODE\n    MODE = 'b'\n\n"
            "def a():\n    return run(MODE)\n\ndef b():\n    return run(OTHER)\n"
        ),
    }
    graph = build(files)
    report = trace_callers(graph, flow_for(graph, "db.py", "run"))
    assert [chain.leaf for chain in report.chains] == ["unknown", "unknown"]
    assert {chain.reason for chain in report.chains} == {"constant_not_resolved"}


def test_chains_pass_through_intermediate_parameters_and_stop_at_recursion_and_depth() -> None:
    files = {
        "sink.py": "import os\n\ndef danger(cmd):\n    return os.system(cmd)\n",
        "mid.py": "from sink import danger\n\ndef relay(c):\n    return danger(c)\n\ndef loop(c, n):\n    return loop(c, n - 1) if n else danger(c)\n",
        "top.py": "from flask import Flask, request\nfrom mid import relay\n\napp = Flask(__name__)\n\n@app.route('/')\ndef view():\n    return relay(request.args.get('c'))\n",
    }
    graph = build(files)
    report = trace_callers(graph, flow_for(graph, "sink.py", "danger"))
    assert report.verdict == "request"
    chain = next(item for item in report.chains if item.leaf == "request")
    assert [hop.path for hop in chain.hops] == ["top.py", "mid.py"]
    assert chain.entry_point == "top.py::view"
    assert any(item.reason == "recursive_call" for item in report.chains)
    shallow = trace_callers(graph, flow_for(graph, "sink.py", "danger"), max_depth=1)
    assert shallow.verdict != "request" and "depth_limit" in shallow.notes


def test_request_data_read_in_a_helper_needs_a_known_entry_point() -> None:
    files = {
        "sink.py": "import os\n\ndef danger(cmd):\n    return os.system(cmd)\n",
        "helper.py": "from flask import request\nfrom sink import danger\n\ndef from_request():\n    return danger(request.args['c'])\n",
        "web.py": "from flask import Flask\nfrom helper import from_request\n\napp = Flask(__name__)\n\n@app.route('/')\ndef view():\n    return from_request()\n",
    }
    graph = build(files)
    report = trace_callers(graph, flow_for(graph, "sink.py", "danger"))
    assert report.verdict == "request"
    assert report.chains[0].entry_point == "web.py::view"
    assert [hop.path for hop in report.chains[0].hops] == ["web.py", "helper.py"]
    # The same helper with no route reaching it: request-shaped data, but no known entry point.
    orphan = build({key: value for key, value in files.items() if key != "web.py"})
    answer = trace_callers(orphan, flow_for(orphan, "sink.py", "danger"))
    assert answer.verdict == "unknown"
    assert answer.chains[0].reason == "request_data_without_known_entry_point"


def test_argument_binding_covers_keywords_defaults_methods_and_star_arguments() -> None:
    files = {
        "sink.py": (
            "import os\n\nclass Runner:\n    def go(self, label, cmd='true'):\n        return os.system(cmd)\n\n"
            "def plain(cmd, extra=None):\n    return os.system(cmd)\n"
        ),
        "use.py": (
            "from sink import Runner, plain\n\ndef keyword():\n    return plain(extra=1, cmd='ls')\n\n"
            "def method():\n    return Runner.go(Runner(), 'x')\n\n"
            "def starred(args):\n    return plain(*args)\n\n"
            "def defaulted():\n    return Runner().go('x')\n"
        ),
    }
    graph = build(files)
    plain = trace_callers(graph, flow_for(graph, "sink.py", "plain"))
    leaves = {(chain.hops[-1].line if chain.hops else None): (chain.leaf, chain.reason) for chain in plain.chains}
    assert leaves[4] == ("constant", None)
    assert leaves[10] == ("unknown", "star_arguments")


def test_class_based_view_methods_are_entry_points_found_by_the_graph_only() -> None:
    files = {
        "views.py": (
            "from django.views import View\nfrom sink import danger\n\nclass Thing(View):\n"
            "    def get(self, request, name):\n        return danger(name)\n"
        ),
        "sink.py": "import os\n\ndef danger(cmd):\n    return os.system(cmd)\n",
    }
    graph = build(files)
    node = graph.entry_point("views.py::Thing.get")
    assert node is not None and node.recognized_by == "graph" and node.kind == "class_view"
    report = trace_callers(graph, flow_for(graph, "sink.py", "danger"))
    assert report.verdict == "request"
    assert report.chains[0].entry_recognized_by == "graph"

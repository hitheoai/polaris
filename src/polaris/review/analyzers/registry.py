"""Which analyzers run, on which inputs, and which checks they complete for which languages.

Built-in analyzers are registered here. An operator can also load explicitly named third-party
analyzers from the `polaris.analyzers` entry-point group (`AnalysisRuntime.plugins`, CLI
`--analyzer-plugin NAME`). Plugins are never discovered or loaded implicitly: loading one runs
its installed code in this process, the same trust decision as installing it. A plugin adds
source kinds and an analyzer for checks Polaris already defines; check definitions, severities
and guidance stay in the Polaris catalog, and plugin identity is bound into review digests.
Source kinds a loaded plugin adds stay registered for the rest of the process.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

from polaris.review.analyzers import (
    dockerfile,
    github_actions,
    guards,
    python,
    rust,
    semgrep,
    typescript,
)
from polaris.review.analyzers.base import (
    AnalysisRuntime,
    Analyzer,
    SourceKind,
    _discard_kind,
    register_kind,
    source_kind,
)
from polaris.review.models import WORKFLOW_CHECKS, AnalyzerCapability, TrustedGuardPolicy

PLUGIN_GROUP = "polaris.analyzers"
# analysis: reviewed files plus related context (built-in engines); review: reviewed files only
# (external analyzers never receive context copies); all: every source, including skipped and
# deleted ones (before/after differs).
Inputs = Literal["analysis", "review", "all"]
_ID = re.compile(r"[a-z][a-z0-9_.-]{1,63}")


class PluginProblem(ValueError):
    """A fixed, value-free reason an explicitly requested plugin could not be used."""


PLUGIN_ERRORS = {
    "invalid_plugin_name": "Analyzer plugin names are entry-point names: letters, digits, '.', '_' and '-'.",
    "analyzer_plugin_unavailable": "Exactly one installed `polaris.analyzers` entry point must have the requested name.",
    "analyzer_plugin_failed_to_load": "The requested analyzer plugin failed to load; the review did not run.",
    "invalid_analyzer_plugin": "The requested analyzer plugin does not provide a valid Polaris analyzer.",
    "analyzer_plugin_conflict": "The requested analyzer plugin conflicts with a registered source kind or analyzer.",
}


def _always(runtime: AnalysisRuntime) -> bool:
    return True


@dataclass(frozen=True)
class AnalyzerSpec:
    """How the workflow reviewer runs one analyzer.

    `checks` maps a language to the checks this analyzer completes for it; a missing result for
    one of them is a coverage gap, not a clean file. Supplementary analyzers (Semgrep CE) add
    findings but count toward completeness only when `requested` for this runtime.
    """

    analyzer_id: str
    create: Callable[[AnalysisRuntime, TrustedGuardPolicy | None], Analyzer]
    capability: Callable[[AnalysisRuntime, bool], AnalyzerCapability]
    checks: Mapping[str, tuple[str, ...]]
    inputs: Inputs = "analysis"
    supplementary: bool = False
    requested: Callable[[AnalysisRuntime], bool] = _always
    plugin: str | None = None


@dataclass(frozen=True)
class AnalyzerPlugin:
    """What a `polaris.analyzers` entry point provides (the object itself, or a callable
    returning it): the source kinds it adds and its analyzer."""

    kinds: tuple[SourceKind, ...]
    analyzer: AnalyzerSpec


_SPECS: dict[str, AnalyzerSpec] = {}
_PLUGINS: dict[str, str] = {}  # entry-point name -> analyzer id


def register_analyzer(spec: AnalyzerSpec) -> AnalyzerSpec:
    if not isinstance(spec.analyzer_id, str) or not _ID.fullmatch(spec.analyzer_id):
        raise ValueError("analyzer ids are short lowercase identifiers")
    if (not (callable(spec.create) and callable(spec.capability) and callable(spec.requested))
            or spec.inputs not in ("analysis", "review", "all") or not isinstance(spec.checks, Mapping)):
        raise ValueError("analyzer specs need factories, an input selection and a check mapping")
    current = _SPECS.get(spec.analyzer_id)
    if current is not None:
        if current == spec:
            return spec
        raise ValueError(f"analyzer {spec.analyzer_id!r} is already registered")
    for language, checks in spec.checks.items():
        if not isinstance(language, str) or source_kind(language) is None:
            raise ValueError(f"analyzer {spec.analyzer_id!r} names an unregistered language")
        if not isinstance(checks, tuple) or not all(isinstance(check, str) and check in WORKFLOW_CHECKS
                                                    for check in checks):
            raise ValueError(f"analyzer {spec.analyzer_id!r} names checks outside the Polaris catalog")
    _SPECS[spec.analyzer_id] = spec
    return spec


def analyzer_specs() -> tuple[AnalyzerSpec, ...]:
    """Every registered analyzer, in registration order (built-ins first)."""
    return tuple(_SPECS.values())


def active_specs(runtime: AnalysisRuntime) -> tuple[AnalyzerSpec, ...]:
    """Built-in analyzers plus the plugins this runtime explicitly loads, in a fixed order."""
    load_plugins(runtime.plugins)
    return tuple(spec for spec in _SPECS.values() if spec.plugin is None or spec.plugin in runtime.plugins)


def implemented_checks(language: str, runtime: AnalysisRuntime | None = None) -> frozenset[str]:
    """Checks some non-supplementary active analyzer completes for files of this language."""
    specs = active_specs(runtime) if runtime is not None else tuple(
        spec for spec in _SPECS.values() if spec.plugin is None)
    return frozenset(check for spec in specs if not spec.supplementary for check in spec.checks.get(language, ()))


def _entry_points(name: str) -> list[Any]:
    from importlib.metadata import entry_points

    return [item for item in entry_points(group=PLUGIN_GROUP) if item.name == name]


def load_plugins(names: Iterable[str]) -> tuple[str, ...]:
    """Load explicitly named analyzer plugins once per process; never discovers others."""
    loaded: list[str] = []
    for name in names:
        if name in _PLUGINS:
            loaded.append(name)
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
            raise PluginProblem("invalid_plugin_name")
        found = _entry_points(name)
        if len(found) != 1:
            raise PluginProblem("analyzer_plugin_unavailable")
        try:
            provided = found[0].load()
            plugin = provided() if callable(provided) and not isinstance(provided, AnalyzerPlugin) else provided
        except Exception:
            raise PluginProblem("analyzer_plugin_failed_to_load") from None
        if (
            not isinstance(plugin, AnalyzerPlugin) or not isinstance(plugin.analyzer, AnalyzerSpec)
            or not isinstance(plugin.kinds, tuple) or not all(isinstance(kind, SourceKind) for kind in plugin.kinds)
            # "all" would hand the plugin skipped and deleted sources, which only built-ins need.
            or plugin.analyzer.inputs not in ("analysis", "review") or plugin.analyzer.supplementary
            or plugin.analyzer.analyzer_id in _SPECS
        ):
            raise PluginProblem("invalid_analyzer_plugin")
        added = [kind.name for kind in plugin.kinds if source_kind(kind.name) is None]
        try:
            for kind in plugin.kinds:
                register_kind(kind)
            register_analyzer(replace(plugin.analyzer, plugin=name))
        except ValueError:
            for kind_name in added:  # all or nothing: a refused plugin leaves no source kinds behind
                _discard_kind(kind_name)
            raise PluginProblem("analyzer_plugin_conflict") from None
        _PLUGINS[name] = plugin.analyzer.analyzer_id
        loaded.append(name)
    return tuple(loaded)


def capabilities(runtime: AnalysisRuntime, *, probe: bool = False) -> list[AnalyzerCapability]:
    return [owned_capability(spec, spec.capability(runtime, probe)) for spec in active_specs(runtime)]


def owned_capability(spec: AnalyzerSpec, capability: AnalyzerCapability) -> AnalyzerCapability:
    """An analyzer describes itself under its registered id, never another analyzer's."""
    if capability.analyzer_id == spec.analyzer_id:
        return capability
    return capability.model_copy(update={"analyzer_id": spec.analyzer_id})


def _semgrep_requested(runtime: AnalysisRuntime) -> bool:
    return (runtime.semgrep_executable is not None and runtime.allow_external_analyzers
            and runtime.allow_temporary_source_files)


def _by_language(checks: Sequence[str], *languages: str) -> dict[str, tuple[str, ...]]:
    return {language: tuple(checks) for language in languages}


for _spec in (
    AnalyzerSpec(python.ANALYZER_ID, lambda runtime, policy: python.PythonAnalyzer(),
                 lambda runtime, probe: python.capability(), _by_language(python.SUPPORTED_CHECKS, "python")),
    AnalyzerSpec(typescript.ANALYZER_ID, lambda runtime, policy: typescript.TypeScriptAnalyzer(),
                 lambda runtime, probe: typescript.capability(),
                 _by_language(typescript.CHECKS, "javascript", "typescript")),
    AnalyzerSpec(rust.ANALYZER_ID, lambda runtime, policy: rust.RustAnalyzer(),
                 lambda runtime, probe: rust.capability(), _by_language(rust.CHECKS, "rust")),
    AnalyzerSpec(github_actions.ANALYZER_ID, lambda runtime, policy: github_actions.GitHubActionsAnalyzer(),
                 lambda runtime, probe: github_actions.capability(),
                 _by_language(github_actions.CHECKS, github_actions.KIND)),
    AnalyzerSpec(dockerfile.ANALYZER_ID, lambda runtime, policy: dockerfile.DockerfileAnalyzer(),
                 lambda runtime, probe: dockerfile.capability(), _by_language(dockerfile.CHECKS, dockerfile.KIND)),
    AnalyzerSpec(semgrep.ANALYZER_ID, lambda runtime, policy: semgrep.SemgrepAnalyzer(runtime),
                 lambda runtime, probe: semgrep.SemgrepAnalyzer(runtime).capability(probe=probe), {},
                 inputs="review", supplementary=True, requested=_semgrep_requested),
    # Produces its own (advisory unless requested) api_authorization rows from before/after pairs.
    AnalyzerSpec(guards.ANALYZER_ID, lambda runtime, policy: guards.GuardAnalyzer(policy),
                 lambda runtime, probe: guards.capability(), {}, inputs="all"),
):
    register_analyzer(_spec)

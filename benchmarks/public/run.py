"""Run the public benchmark: Polaris on pinned public datasets, optionally Semgrep CE and zizmor.

    uv run --no-sync python benchmarks/public/run.py --dataset ossf-cve --limit 20 --repeats 3
    uv run --no-sync python benchmarks/public/run.py --dataset all --with-semgrep --with-zizmor
    uv run --no-sync python benchmarks/public/run.py --list-adapters

Fetches pinned public data into a cache folder outside the repository (`--cache`, else
`POLARIS_BENCH_CACHE`, else /tmp/polaris-bench-cache) and writes `report.md` and `report.json`
(see benchmarks/public/README.md). Needs network the first time; never run in CI. No AI is used,
no API key is read, and no repository code is sent anywhere.

Exit codes: 0 report written, 2 setup problem (nothing fetched, pin mismatch, nothing to run).
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pbench_core as core  # noqa: E402
import pbench_datasets as datasets  # noqa: E402
import pbench_report as reports  # noqa: E402
import pbench_tools as tools  # noqa: E402

Say = Callable[[str], object]


class Context:
    def __init__(self, cache: Path, repeats: int, date: str, say: Say) -> None:
        self.cache, self.repeats, self.date, self.say = cache, repeats, date, say
        self.home = cache / "home"
        self.raw_root = cache / "raw" / date
        self.raw_files: list[dict[str, str]] = []
        self.polaris_version = ""
        self.tool_versions: dict[str, str] = {}

    def record(self, result: tools.RunResult, tool: str, label: str) -> None:
        self.raw_files.append({"tool": tool, "run": label, "path": str(result.sarif_path),
                               "sha256": result.sarif_sha256, "exit_code": str(result.exit_code)})


def _polaris_runs(ctx: Context, root: Path, files: list[str], folder: Path, label: str) -> tuple[
        core.Revision, dict[str, Any] | None, list[float], dict[str, Any]]:
    """Run Polaris `ctx.repeats` times on `files`; the first run is scored, the rest check determinism."""
    runs = [tools.run_polaris(root, files, folder / f"run-{index}.sarif", ctx.home) for index in range(1, ctx.repeats + 1)]
    for index, run in enumerate(runs, 1):
        ctx.record(run, "polaris", f"{label}/run-{index}")
    seconds = [round(run.seconds, 2) for run in runs]
    documents = [run.document for run in runs]
    present = {core.normalize_path(name) for name in files}
    if any(document is None for document in documents):
        note = next(run.note for run in runs if run.document is None)
        ctx.say(f"  polaris failed on {label}: {note}")
        return core.Revision(None, None, present), {"error": note}, seconds, {}
    first = documents[0]
    assert first is not None
    version = core.sarif_tool_version(first)
    ctx.polaris_version = ctx.polaris_version or version
    determinism = core.check_determinism([core.results_digest(d) for d in documents if d is not None],
                                         [run.sarif_sha256 for run in runs],
                                         [core.digest_without_report_id(d) for d in documents if d is not None])
    return (core.Revision(core.parse_sarif(first, tool="polaris"), core.analysed_paths(first), present),
            determinism, seconds, core.coverage_summary(first))


def evaluate_ossf(ctx: Context, limit: int, rules: Path | None) -> dict[str, Any]:
    dataset = datasets.OssfCveDataset(ctx.cache)
    labels = dataset.fetch_labels()
    ctx.say(f"ossf-cve-benchmark: {len(labels)} labels verified at the pinned commit")
    cases, skipped = datasets.select_cases(labels.items(), limit, dataset.fetch_case)
    ctx.say(f"  selected {len(cases)} CVEs ({len(skipped)} skipped)")
    records: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    for case in cases:
        repository = dataset.repository_dir(case)
        record: dict[str, Any] = {
            "id": case.id, "repository": case.repository, "pre_commit": case.pre_commit,
            "post_commit": case.post_commit, "cwes": list(case.cwes),
            "weaknesses": [{"file": w.file, "line": w.line, "explanation": w.explanation} for w in case.weaknesses]}
        revisions: dict[str, dict[str, Any]] = {}
        for which, commit in (("vulnerable", case.pre_commit), ("fixed", case.post_commit)):
            datasets.checkout(repository, commit, dataset.home)
            present = [name for name in case.files if (repository / name).is_file() and not (repository / name).is_symlink()]
            label = f"ossf/{case.id}/{which}"
            folder = ctx.raw_root / "ossf" / "polaris" / case.id / which
            if present:
                revision, determinism, seconds, coverage = _polaris_runs(ctx, repository, present, folder, label)
            else:
                revision, determinism, seconds, coverage = core.Revision([], set(), set()), None, [], {}
            revisions[which] = {"revision": revision, "determinism": determinism, "seconds": seconds,
                                "present": present, "coverage": coverage}
            if rules is not None and not present:
                revisions[which]["semgrep"] = core.Revision([], None, set())
            if determinism and "runs" in determinism:
                groups.append(determinism)
            if rules is not None and present:
                semgrep = tools.run_semgrep(repository, present, ctx.raw_root / "ossf" / "semgrep" / case.id / f"{which}.sarif",
                                            rules, ctx.cache)
                ctx.record(semgrep, "semgrep", label)
                revisions[which]["semgrep"] = core.Revision(
                    core.parse_sarif(semgrep.document, tool="semgrep") if semgrep.document else None, None, set(present))
                if semgrep.document is None:
                    ctx.say(f"  semgrep failed on {label}: {semgrep.note}")
        record["polaris"] = _score_pair(case, revisions, "revision")
        record["polaris"]["runs"] = {which: {"determinism": data["determinism"], "seconds": data["seconds"],
                                             "labelled_files_present": data["present"],
                                             "coverage": data["coverage"]}
                                     for which, data in revisions.items()}
        if not revisions["vulnerable"]["present"]:
            record["polaris"]["vulnerable"]["reason"] = "label_file_missing_at_vulnerable_revision"
        if rules is not None:
            record["semgrep"] = _score_pair(case, revisions, "semgrep")
        records.append(record)
        outcome = record["polaris"]["vulnerable"]["outcome"]
        ctx.say(f"  {case.id}: polaris {outcome}" + (f", semgrep {record['semgrep']['vulnerable']['outcome']}" if "semgrep" in record else ""))
    return {"cases": records, "skipped": skipped, "determinism": core.summarize_determinism(groups),
            "description": dataset.describe()}


def _score_pair(case: datasets.CveCase, revisions: dict[str, dict[str, Any]], key: str) -> dict[str, Any]:
    vulnerable = revisions["vulnerable"].get(key)
    fixed = revisions["fixed"].get(key)
    if vulnerable is None:
        vulnerable = core.Revision(None)
    if fixed is None:
        fixed = core.Revision(None)
    result = {"vulnerable": core.score_vulnerable(vulnerable, case.weaknesses, case.cwes)}
    if result["vulnerable"]["outcome"] == "detected":
        result["fixed"] = core.score_fixed(fixed, case.weaknesses, result["vulnerable"]["matched_rules"])
    return result


def evaluate_fixtures(ctx: Context, with_zizmor: bool) -> dict[str, Any]:
    dataset = datasets.ZizmorFixtures(ctx.cache)
    fixtures = dataset.fetch()
    ctx.say(f"github-actions-fixtures: {len(fixtures)} workflows verified at the pinned commit")
    names = sorted(f".github/workflows/{name}" for name in fixtures)
    folder = ctx.raw_root / "fixtures" / "polaris"
    revision, determinism, seconds, coverage = _polaris_runs(ctx, dataset.project_dir, names, folder, "fixtures")
    zizmor_findings: list[core.Finding] | None = None
    zizmor_note = "not requested; no comparison was run"
    if with_zizmor:
        try:
            result = tools.run_zizmor(dataset.project_dir, ctx.raw_root / "fixtures" / "zizmor" / "zizmor.sarif", ctx.cache)
            ctx.record(result, "zizmor", "fixtures")
            if result.document is None:
                zizmor_note = f"zizmor failed: {result.note}; no comparison was run"
            else:
                zizmor_findings = core.parse_sarif(result.document, tool="zizmor", root=str(dataset.project_dir))
                zizmor_note = (f"zizmor {tools.ZIZMOR_TOOL_VERSION} via `uv tool run`, --offline (audits that need the GitHub API "
                               "did not run), default persona, no config file; raw SARIF listed in report.json")
        except tools.ToolUnavailable as problem:
            zizmor_note = f"zizmor unavailable: {problem}; no comparison was run"
    comparison = reports.compare_fixtures(revision.findings or [], zizmor_findings, names)
    comparison["polaris_coverage"] = coverage
    if revision.findings is None:
        comparison["polaris_run_failed"] = True
    return {"comparison": comparison, "determinism": core.summarize_determinism(
        [determinism] if determinism and "runs" in determinism else []),
        "zizmor_note": zizmor_note, "seconds": seconds, "description": dataset.describe(),
        "polaris_files_analysed": len((revision.analysed or set()) & set(names))}


def _source_commit() -> str:
    try:
        done = subprocess.run(["git", "-C", str(HERE), "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
                              timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def build(args: argparse.Namespace, say: Say) -> dict[str, Any]:
    cache = datasets.cache_root(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    date = args.date or datetime.datetime.now(datetime.UTC).date().isoformat()
    ctx = Context(cache, args.repeats, date, say)
    ctx.home.mkdir(parents=True, exist_ok=True)
    section_lines: list[tuple[str, list[str]]] = []
    data: list[dict[str, Any]] = []
    described: list[dict[str, Any]] = []
    determinism: dict[str, Any] = {}
    tool_rows: list[dict[str, str]] = []
    extra: list[str] = []
    commands = ["uv sync --extra api --extra mcp --extra tui"]
    base = "uv run --no-sync python benchmarks/public/run.py"
    flags = f"--repeats {args.repeats}"
    rules: Path | None = None
    if args.with_semgrep:
        try:
            rules = tools.fetch_semgrep_rules(cache, ctx.home)
            ctx.tool_versions["semgrep"] = tools.tool_version("semgrep", tools.SEMGREP_VERSION, "semgrep", cache)
        except (datasets.DatasetUnavailable, tools.ToolUnavailable) as problem:
            say(f"semgrep skipped: {problem}")
            extra.append(f"Semgrep CE was requested but could not run ({problem}); no Semgrep comparison was run.")
            rules = None
    if args.with_zizmor:
        try:
            ctx.tool_versions["zizmor"] = tools.tool_version("zizmor", tools.ZIZMOR_TOOL_VERSION, "zizmor", cache).removeprefix("zizmor ")
        except tools.ToolUnavailable as problem:
            say(f"zizmor skipped: {problem}")
            args.with_zizmor = False
            extra.append(f"zizmor was requested but could not run ({problem}); no zizmor comparison was run.")
    if args.dataset in ("ossf-cve", "all"):
        ossf = evaluate_ossf(ctx, args.limit, rules)
        tool_names = ["polaris"] + (["semgrep"] if rules is not None else [])
        section, lines = reports.cve_section("OpenSSF CVE Benchmark (JavaScript and TypeScript)", ossf["cases"],
                                             ossf["skipped"], tool_names, args.repeats)
        section["cases"] = ossf["cases"]
        section_lines.append((section["title"], lines))
        data.append(section)
        described.append(ossf["description"])
        determinism["ossf-cve-benchmark (Polaris)"] = ossf["determinism"]
        commands.append(f"{base} --dataset ossf-cve --limit {args.limit} {flags}" + (" --with-semgrep" if rules is not None else ""))
    if args.dataset in ("fixtures", "all"):
        fixtures = evaluate_fixtures(ctx, args.with_zizmor)
        section, lines = reports.fixtures_section(fixtures["comparison"], fixtures["determinism"], args.repeats,
                                                  fixtures["zizmor_note"])
        section["files_analysed_by_polaris"] = fixtures["polaris_files_analysed"]
        section_lines.append((section["title"], lines))
        data.append(section)
        described.append(fixtures["description"])
        determinism["github-actions-fixtures (Polaris)"] = fixtures["determinism"]
        commands.append(f"{base} --dataset fixtures {flags}" + (" --with-zizmor" if args.with_zizmor else ""))
    described.append(datasets.OwaspPythonStub().describe())
    tool_rows.append({"name": "Polaris", "version": ctx.polaris_version or "unknown",
                      "how": "`polaris workflow review --root <checkout> --files <labelled files> --format sarif "
                             "--no-external-analyzers` through `python -m polaris`, built-in analyzers only, a minimal "
                             "environment, no AI, no network"})
    if rules is not None:
        tool_rows.append({"name": "Semgrep CE", "version": ctx.tool_versions.get("semgrep", tools.SEMGREP_VERSION),
                          "how": f"`uv tool run --from semgrep=={tools.SEMGREP_VERSION} semgrep scan --config <rules>/"
                                 f"{{{','.join(tools.SEMGREP_RULE_DIRS)}}}` on the labelled files, rules from "
                                 f"{tools.SEMGREP_RULES_URL.removesuffix('.git')} at `{tools.SEMGREP_RULES_COMMIT}` (not "
                                 "redistributed; run locally only; the rules are under the Semgrep Rules License v1.0), "
                                 "metrics off, run once per revision, the rule folders above only (no other rule sets, "
                                 "no registry, no custom rules)"})
    if args.with_zizmor and any(row["tool"] == "zizmor" for row in ctx.raw_files):
        tool_rows.append({"name": "zizmor", "version": ctx.tool_versions.get("zizmor", tools.ZIZMOR_TOOL_VERSION),
                          "how": "`uv tool run --from zizmor==" + tools.ZIZMOR_TOOL_VERSION + " zizmor --format sarif "
                                 "--offline --no-exit-codes --no-progress <project>`, run once"})
    for name in ("Semgrep CE", "zizmor"):
        if not any(row["name"] == name for row in tool_rows):
            tool_rows.append({"name": name, "version": "not run", "how": "adapter documented in the README; no comparison was run"})
    return reports.build_report(
        date=date, generated_at=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        polaris_version=ctx.polaris_version or "unknown", tools=tool_rows, datasets=described, sections=data,
        section_lines=section_lines, determinism=determinism, repeats=args.repeats, raw_root=str(ctx.raw_root),
        raw_files=ctx.raw_files, reproduce=commands, polaris_source_commit=_source_commit(), extra_not_shown=extra)


def main(argv: list[str] | None = None, out: Say = print) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", choices=("ossf-cve", "fixtures", "all"), default="all")
    parser.add_argument("--limit", type=int, default=20, help="CVEs to run (the first N in id order that fetch cleanly).")
    parser.add_argument("--repeats", type=int, default=3, help="Polaris runs per revision, for the determinism check.")
    parser.add_argument("--cache", help="Cache folder outside the repository (default $POLARIS_BENCH_CACHE or /tmp/polaris-bench-cache).")
    parser.add_argument("--report-dir", help="New folder for report.md and report.json (default <cache>/results/<date>).")
    parser.add_argument("--date", help="Date label (YYYY-MM-DD); default is today (UTC).")
    parser.add_argument("--with-semgrep", action="store_true", help="Also run pinned Semgrep CE (about 600 MB download).")
    parser.add_argument("--with-zizmor", action="store_true", help="Also run pinned zizmor on the workflow fixtures.")
    parser.add_argument("--list-adapters", action="store_true", help="Show the adapters and their licences, then exit.")
    args = parser.parse_args(argv)
    if args.list_adapters:
        for item in (datasets.OssfCveDataset(datasets.cache_root(args.cache)).describe(),
                     datasets.ZizmorFixtures(datasets.cache_root(args.cache)).describe(),
                     datasets.OwaspPythonStub().describe()):
            out(json.dumps(item, indent=2))
        return 0
    if args.limit < 1 or args.repeats < 1:
        print("run.py: --limit and --repeats must be at least 1.", file=sys.stderr)
        return 2
    try:
        report = build(args, out)
    except (datasets.DatasetUnavailable, core.PinMismatch) as problem:
        print(f"run.py: {problem}", file=sys.stderr)
        return 2
    directory = Path(args.report_dir) if args.report_dir else datasets.cache_root(args.cache) / "results" / report["date"]
    markdown, document = reports.write_report(report, directory)
    out(f"wrote {markdown} and {document}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

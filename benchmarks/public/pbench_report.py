"""Build the Markdown and JSON reports of a public benchmark run (pure: no I/O except `write_report`)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pbench_core import (
    FORMAT,
    MATCHING_RULES,
    NOT_SHOWN,
    Finding,
    format_ratio,
    render_markdown,
    summarize_cves,
)

# Pairs of (zizmor audit, Polaris check) that look at the same kind of problem. This is the
# author's judgement, listed in every report; checks without a clear counterpart are left out and
# reported on their own rather than forced into a pair.
ZIZMOR_TO_POLARIS = {
    "template-injection": "workflow_injection",
    "excessive-permissions": "excessive_privileges",
    "unpinned-uses": "unpinned_dependency",
}

OUTCOME_ORDER = ("detected", "abstained", "missed", "not_analyzed", "error")


def cve_row(case: Mapping[str, Any], tools: Sequence[str]) -> str:
    first = case["weaknesses"][0]
    label = f"{first['file']}:{first['line']}" + (f" (+{len(case['weaknesses']) - 1})" if len(case["weaknesses"]) > 1 else "")
    cells = [case["id"], f"`{label}`"]
    for tool in tools:
        result = case.get(tool)
        if not result:
            cells.append("-")
            continue
        outcome = result["vulnerable"]["outcome"]
        fixed = (result.get("fixed") or {}).get("fix")
        cells.append(outcome + (f", fix {fixed}" if outcome == "detected" and fixed else ""))
    return "| " + " | ".join(cells) + " |"


def cve_section(title: str, cases: Sequence[Mapping[str, Any]], skipped: Sequence[Mapping[str, str]],
                tools: Sequence[str], repeats: int) -> tuple[dict[str, Any], list[str]]:
    """Per-tool summaries and the Markdown lines of the CVE section."""
    summaries = {tool: summarize_cves([case[tool] for case in cases if case.get(tool)]) for tool in tools}
    lines = [f"Cases: {len(cases)} CVEs, the first {len(cases)} in id order whose labelled commits fetched cleanly. "
             f"Each Polaris run was repeated {repeats} times; scores use the first run."]
    for tool in tools:
        summary = summaries[tool]
        outcomes = summary["outcomes"]
        lines += ["", f"### {tool}", "",
                  "- Outcomes at the vulnerable revision: " + ", ".join(f"{name} {outcomes[name]}" for name in OUTCOME_ORDER),
                  f"- Detected, of all {summary['cves']} CVEs: {format_ratio(summary['detected_of_all'])}",
                  f"- Detected, of the CVEs whose labelled file was analysed: {format_ratio(summary['detected_of_analyzed'])}",
                  f"- Abstained (questions to the user, not detections): {format_ratio(summary['abstained_of_all'])}",
                  f"- Detected or abstained, of all CVEs: {format_ratio(summary['detected_or_abstained_of_all'])}",
                  f"- Any detection in the labelled file, wherever it is: {format_ratio(summary['file_level_detection_of_all'])}",
                  f"- CWE agrees with the label, among detected: {format_ratio(summary['cwe_agrees_among_detected'])}",
                  f"- Fix: matched rule stopped firing, among detected: {format_ratio(summary['fixed_cleared_of_detected'])}"
                  f" (outcomes {summary['fixed_outcomes']})",
                  f"- Findings in labelled files at the vulnerable revision: "
                  f"{summary['labelled_file_flags']['flagged_in_labelled_files_at_vulnerable']}, of which "
                  f"{summary['labelled_file_flags']['of_which_matching_a_label']} at a label. Not a precision: "
                  "findings elsewhere in the file are not necessarily false positives."]
    incomplete = [case["id"] for case in cases if case.get("polaris")
                  and any((run.get("coverage") or {}).get("complete") is False
                          for run in case["polaris"].get("runs", {}).values())]
    if "polaris" in tools:
        lines += ["", f"Polaris reported its own coverage as incomplete for {len(incomplete)} of {len(cases)} CVEs"
                  + (": " + ", ".join(incomplete) if incomplete else "") + ". The per-run coverage statement is in report.json."]
    lines += ["", "### Per CVE", "", "| CVE | label | " + " | ".join(tools) + " |",
              "|---|---|" + "---|" * len(tools)]
    lines += [cve_row(case, tools) for case in cases]
    if skipped:
        lines += ["", "### Skipped while choosing the cases", ""]
        lines += [f"- {item['id']}: {item['reason']}" for item in skipped]
    return {"title": title, "summaries": summaries, "skipped": list(skipped)}, lines


def fixture_positive_sets(findings: Sequence[Finding], key: str) -> dict[str, dict[str, set[str]]]:
    """For each check or audit name, the fixtures with a detection and the fixtures with an abstention."""
    table: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"detection": set(), "abstention": set()})
    for finding in findings:
        name = finding.check if key == "check" else finding.rule_id.removeprefix("zizmor/")
        if name:
            table[name][finding.kind].add(finding.path)
    return table


def compare_fixtures(polaris: Sequence[Finding], zizmor: Sequence[Finding] | None, fixtures: Sequence[str],
                     mapping: Mapping[str, str] = ZIZMOR_TO_POLARIS) -> dict[str, Any]:
    """Agreement between Polaris and zizmor per mapped pair, over the fixtures reviewed.

    Polaris questions (`needs_context`) are shown separately and are not positives. With no
    ground truth, this is agreement, not accuracy.
    """
    polaris_sets = fixture_positive_sets(polaris, "check")
    result: dict[str, Any] = {
        "fixtures": len(fixtures),
        "polaris": {name: {"fixtures_with_detection": len(item["detection"]),
                           "fixtures_with_abstention": len(item["abstention"])}
                    for name, item in sorted(polaris_sets.items())},
        "polaris_any_detection": len({f.path for f in polaris if f.kind == "detection"}),
        "polaris_any_abstention": len({f.path for f in polaris if f.kind == "abstention"}),
    }
    if zizmor is None:
        result["comparison"] = "not run"
        return result
    zizmor_sets = fixture_positive_sets(zizmor, "audit")
    total = set(fixtures)
    pairs = []
    for audit, check in mapping.items():
        ours = polaris_sets.get(check, {"detection": set(), "abstention": set()})["detection"] & total
        asked = polaris_sets.get(check, {"detection": set(), "abstention": set()})["abstention"] & total
        theirs = zizmor_sets.get(audit, {"detection": set()})["detection"] & total
        pairs.append({
            "zizmor_audit": audit, "polaris_check": check, "both": len(ours & theirs),
            "only_polaris": len(ours - theirs), "only_zizmor": len(theirs - ours),
            "neither": len(total - ours - theirs),
            "polaris_asked_where_zizmor_flagged": len((asked - ours) & theirs),
        })
    result["comparison"] = {
        "pairs": pairs,
        "zizmor_audits_without_a_paired_polaris_check": {
            name: len(item["detection"] & total) for name, item in sorted(zizmor_sets.items())
            if name not in mapping},
        "polaris_checks_without_a_paired_zizmor_audit": {
            name: len(item["detection"] & total) for name, item in sorted(polaris_sets.items())
            if name not in mapping.values()},
        "zizmor_fixtures_with_any_finding": len({f.path for f in zizmor} & total),
    }
    return result


def fixtures_section(comparison: Mapping[str, Any], determinism: Mapping[str, Any], repeats: int,
                     zizmor_note: str) -> tuple[dict[str, Any], list[str]]:
    lines = [f"Fixtures reviewed: {comparison['fixtures']} workflow files. No machine-readable labels exist for them, so "
             "these numbers describe what each tool reported and where the tools agree. They are not accuracy.",
             "",
             f"- Polaris: {comparison['polaris_any_detection']} of {comparison['fixtures']} fixtures with at least one "
             f"detection; {comparison['polaris_any_abstention']} of {comparison['fixtures']} with at least one question "
             "(abstention).",
             "- Polaris per check (fixtures with a detection / fixtures with a question): "
             + ", ".join(f"{name} {row['fixtures_with_detection']}/{row['fixtures_with_abstention']}"
                         for name, row in comparison["polaris"].items()) + ".",
             f"- Polaris repeats: {repeats}; identical normalised results in {determinism['groups_with_identical_results']} "
             f"of {determinism['comparable_groups']} comparable groups."]
    coverage = comparison.get("polaris_coverage") or {}
    if coverage:
        lines.append(f"- Polaris coverage statement: review {coverage.get('status')}; {coverage.get('files_analyzed')} of "
                     f"{coverage.get('files_total')} files analysed, {coverage.get('files_not_fully_checked')} not fully "
                     f"checked; required rows not checked: {coverage.get('required_rows_not_checked_count')}"
                     + (" (" + "; ".join(coverage['required_rows_not_checked'][:5]) + ")"
                        if coverage.get("required_rows_not_checked") else "") + ".")
    compared = comparison["comparison"]
    if compared == "not run":
        lines.append(f"- zizmor: no comparison was run ({zizmor_note}).")
    else:
        lines += [f"- zizmor: {compared['zizmor_fixtures_with_any_finding']} of {comparison['fixtures']} fixtures with at "
                  f"least one finding ({zizmor_note}).", "",
                  "Agreement on paired checks (fixtures; pairs are the author's judgement and approximate):", "",
                  "| zizmor audit | Polaris check | both | only Polaris | only zizmor | neither | Polaris asked, zizmor flagged |",
                  "|---|---|---|---|---|---|---|"]
        lines += [f"| {p['zizmor_audit']} | {p['polaris_check']} | {p['both']} | {p['only_polaris']} | {p['only_zizmor']} "
                  f"| {p['neither']} | {p['polaris_asked_where_zizmor_flagged']} |" for p in compared["pairs"]]
        lines += ["", "zizmor audits with no paired Polaris check (fixtures with a finding): "
                  + (", ".join(f"{k} {v}" for k, v in compared["zizmor_audits_without_a_paired_polaris_check"].items()) or "none")
                  + ".", "Polaris checks with no paired zizmor audit (fixtures with a detection): "
                  + (", ".join(f"{k} {v}" for k, v in compared["polaris_checks_without_a_paired_zizmor_audit"].items()) or "none")
                  + "."]
    return {"title": "GitHub Actions workflow fixtures", "comparison": comparison}, lines


def build_report(*, date: str, generated_at: str, polaris_version: str, tools: list[dict[str, str]],
                 datasets: list[dict[str, Any]], sections: list[dict[str, Any]], section_lines: list[tuple[str, list[str]]],
                 determinism: Mapping[str, Any], repeats: int, raw_root: str, raw_files: list[dict[str, str]],
                 reproduce: list[str], polaris_source_commit: str = "", extra_not_shown: Sequence[str] = ()) -> dict[str, Any]:
    return {
        "format": FORMAT, "date": date, "generated_at": generated_at, "polaris_version": polaris_version,
        "polaris_source_commit": polaris_source_commit, "tools": tools, "datasets": datasets, "repeats": repeats,
        "matching_rules": list(MATCHING_RULES), "sections": [
            {"title": title, "lines": lines} for title, lines in section_lines],
        "data": sections, "determinism": dict(determinism), "not_shown": [*NOT_SHOWN, *extra_not_shown],
        "reproduce": reproduce, "raw_root": raw_root, "raw_files": raw_files,
    }


def write_report(report: Mapping[str, Any], directory: Path) -> tuple[Path, Path]:
    """Write `report.md` and `report.json` into a new directory; existing files are never overwritten."""
    directory.mkdir(parents=True, exist_ok=True)
    markdown, document = directory / "report.md", directory / "report.json"
    for path in (markdown, document):
        if path.exists():
            raise FileExistsError(f"{path} exists; choose a new report directory")
    markdown.write_text(render_markdown(report), encoding="utf-8")
    document.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return markdown, document


def count_outcomes(cases: Sequence[Mapping[str, Any]], tool: str) -> Counter[str]:
    return Counter(case[tool]["vulnerable"]["outcome"] for case in cases if case.get(tool))

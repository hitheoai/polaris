"""Pure parts of the public benchmark: SARIF reading, matching rules, scoring, digests, pins.

Nothing here touches the network, runs a tool or reads a file outside what the caller passes in,
so every function can be tested with small synthetic data.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

FORMAT = "polaris.public-bench/0.1.0"

# A finding matches a label when the label's line lies inside the finding's own line span widened
# by this many lines on each side. Recorded in every report.
LOCATION_WINDOW = 5

MATCHING_RULES = (
    "Location match: a finding matches a labelled weakness when it is in the same file (paths "
    "compared after removing `file://`, `./` and the SARIF base, and with `/` separators) and the "
    f"labelled line lies within [start_line - {LOCATION_WINDOW}, end_line + {LOCATION_WINDOW}] of "
    "the finding. The check, the rule and the weakness type are not part of this rule; the CWE "
    "agreement is counted separately for information.",
    "File match: any finding in the labelled file, wherever it is. It is reported as a looser, "
    "secondary figure and is never counted as a detection.",
    "A Polaris `flagged` finding is a detection. A Polaris `needs_context` finding is a question "
    "to the user and is counted as an ABSTENTION, never as a detection. Other tools have no such "
    "state, so every result they report is counted as a detection.",
    "A CVE counts as detected when at least one of its labelled weaknesses has a detection at the "
    "vulnerable revision. It counts as abstained when none has a detection but at least one has a "
    "question. It counts as missed when the labelled file was analysed and neither exists. It "
    "counts as not analysed when the tool did not analyse any labelled file (unsupported file "
    "type or no coverage); that is a scope limit, not a miss, and is reported on its own.",
    "Fixed revision: only for detected CVEs, the fix is `cleared` when the fixed revision has no "
    "detection in the same file with the same rule id as a detection that matched at the "
    "vulnerable revision (lines may have moved, so the line is not compared). `file_absent` means "
    "the labelled file does not exist in the fixed revision (moved or deleted; renames are not "
    "followed) and is not counted as cleared. `still_flagged` means the same rule still fires.",
)


class PinMismatch(RuntimeError):
    """A fetched dataset or tool does not match its pinned hash."""


# ---------------------------------------------------------------------------------------------
# SARIF


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    start_line: int
    end_line: int
    kind: str  # "detection" | "abstention"
    check: str = ""
    cwe: tuple[int, ...] = ()
    level: str = ""


def normalize_path(uri: str, root: str | None = None) -> str:
    """A repository-relative POSIX path from a SARIF artifact URI (or a label's file name).

    Removes `file://`, an absolute `root` prefix when given, leading `./` and leading `/`, and
    uses `/` separators.
    """
    path = unquote(uri.strip()).replace("\\", "/")
    if path.startswith("file://"):
        path = path[len("file://"):]
    if root:
        prefix = root.replace("\\", "/").rstrip("/") + "/"
        if path.startswith(prefix):
            path = path[len(prefix):]
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def cwe_numbers(values: Iterable[object]) -> tuple[int, ...]:
    """CWE ids as integers from strings such as `CWE-079`, `cwe-79`, `external/cwe/cwe-79` or 79."""
    found: set[int] = set()
    for value in values:
        text = str(value).lower()
        marker = text.rfind("cwe-")
        digits = ""
        if marker >= 0:
            for character in text[marker + 4:]:
                if not character.isdigit():
                    break
                digits += character
        elif text.isdigit():
            digits = text
        if digits:
            found.add(int(digits))
    return tuple(sorted(found))


def display_rule_id(rule_id: str, tool: str) -> str:
    """Semgrep prefixes rule ids with the dotted path of the rule folder; keep only the rule's own part."""
    if tool == "semgrep" and "semgrep-rules." in rule_id:
        return rule_id.split("semgrep-rules.", 1)[1]
    return rule_id


def parse_sarif(document: Mapping[str, Any], *, tool: str, root: str | None = None) -> list[Finding]:
    """Findings from a SARIF 2.1.0 document.

    For Polaris (`tool == "polaris"`), `properties.result` decides: `flagged` is a detection,
    `needs_context` an abstention, anything else is skipped. Every result of another tool is a
    detection. Results without a usable file and line are skipped. `root` is an absolute folder
    removed from the front of absolute artifact URIs.
    """
    findings: list[Finding] = []
    for run in document.get("runs") or ():
        rules = (run.get("tool") or {}).get("driver", {}).get("rules") or []
        rule_tags = {str(rule.get("id")): list((rule.get("properties") or {}).get("tags") or ()) for rule in rules}
        for result in run.get("results") or ():
            properties = result.get("properties") or {}
            if tool == "polaris":
                state = properties.get("result")
                if state == "flagged":
                    kind = "detection"
                elif state == "needs_context":
                    kind = "abstention"
                else:
                    continue
            else:
                kind = "detection"
            if result.get("suppressions"):
                continue
            tags = [*(properties.get("tags") or ()), *rule_tags.get(str(result.get("ruleId")), ()),
                    *([properties["cwe"]] if "cwe" in properties else ())]
            for location in result.get("locations") or ():
                physical = location.get("physicalLocation") or {}
                uri = (physical.get("artifactLocation") or {}).get("uri")
                region = physical.get("region") or {}
                start = region.get("startLine")
                if not isinstance(uri, str) or not isinstance(start, int):
                    continue
                end = region.get("endLine")
                findings.append(Finding(
                    tool=tool, rule_id=display_rule_id(str(result.get("ruleId", "")), tool), path=normalize_path(uri, root),
                    start_line=start, end_line=end if isinstance(end, int) and end >= start else start,
                    kind=kind, check=str(properties.get("check", "")), cwe=cwe_numbers(tags),
                    level=str(result.get("level", "")),
                ))
    return findings


def sarif_tool_version(document: Mapping[str, Any]) -> str:
    for run in document.get("runs") or ():
        driver = (run.get("tool") or {}).get("driver") or {}
        version = driver.get("semanticVersion") or driver.get("version")
        if version:
            return str(version)
    return ""


def analysed_paths(document: Mapping[str, Any]) -> set[str]:
    """Paths Polaris reports as analysed by at least one check (coverage `checked` or `partial`).

    Only Polaris SARIF carries per-file coverage; for other tools the caller must not use this.
    """
    paths: set[str] = set()
    for run in document.get("runs") or ():
        coverage = (run.get("properties") or {}).get("coverage") or {}
        for entry in coverage.get("entries") or ():
            if entry.get("status") in ("checked", "partial") and isinstance(entry.get("path"), str):
                paths.add(normalize_path(entry["path"]))
    return paths


def coverage_summary(document: Mapping[str, Any]) -> dict[str, Any]:
    """Polaris's own statement of what it checked: status, file counts, required rows not checked."""
    for run in document.get("runs") or ():
        properties = run.get("properties") or {}
        coverage = properties.get("coverage") or {}
        gaps = [f"{entry.get('path')}: {entry.get('check_id')} ({entry.get('reason')})"
                for entry in coverage.get("entries") or ()
                if entry.get("required") and entry.get("status") != "checked"]
        return {"status": properties.get("status"), "complete": coverage.get("complete"),
                "files_total": coverage.get("files_total"), "files_analyzed": coverage.get("files_analyzed"),
                "files_not_fully_checked": coverage.get("files_not_fully_checked"),
                "required_rows_not_checked": gaps[:10], "required_rows_not_checked_count": len(gaps)}
    return {}


# ---------------------------------------------------------------------------------------------
# Matching


def location_match(finding: Finding, path: str, line: int, *, window: int = LOCATION_WINDOW) -> bool:
    return (finding.path == normalize_path(path)
            and finding.start_line - window <= line <= finding.end_line + window)


def file_match(finding: Finding, path: str) -> bool:
    return finding.path == normalize_path(path)


@dataclass(frozen=True)
class Weakness:
    file: str
    line: int
    explanation: str = ""


# ---------------------------------------------------------------------------------------------
# Scoring one CVE


@dataclass
class Revision:
    """What a tool reported for one revision: `None` findings mean the run failed."""

    findings: list[Finding] | None
    analysed: set[str] | None = None  # None: the tool does not report coverage
    files_present: set[str] = field(default_factory=set)


def score_vulnerable(revision: Revision, weaknesses: Sequence[Weakness], cwes: Sequence[object] = (),
                     *, window: int = LOCATION_WINDOW) -> dict[str, Any]:
    """Outcome at the vulnerable revision: detected, abstained, missed, not_analyzed or error."""
    if revision.findings is None:
        return {"outcome": "error", "matched_rules": [], "cwe_agrees": False, "file_level_detection": False,
                "flagged_in_labelled_files": 0, "flagged_matching_label": 0, "abstentions_in_labelled_files": 0}
    files = {normalize_path(item.file) for item in weaknesses}
    labelled = [f for f in revision.findings if f.path in files]
    detections = [f for f in labelled if f.kind == "detection"]
    questions = [f for f in labelled if f.kind == "abstention"]
    near = [f for f in detections if any(location_match(f, w.file, w.line, window=window) for w in weaknesses)]
    near_questions = [f for f in questions if any(location_match(f, w.file, w.line, window=window) for w in weaknesses)]
    wanted = set(cwe_numbers(cwes))
    analysed = revision.analysed is None or bool(files & revision.analysed)
    if near:
        outcome = "detected"
    elif near_questions:
        outcome = "abstained"
    elif not analysed:
        outcome = "not_analyzed"
    else:
        outcome = "missed"
    return {
        "outcome": outcome,
        "matched_rules": sorted({f.rule_id for f in near}),
        "cwe_agrees": bool(wanted) and any(set(f.cwe) & wanted for f in near),
        "file_level_detection": bool(detections),
        "flagged_in_labelled_files": len(detections),
        "flagged_matching_label": len(near),
        "abstentions_in_labelled_files": len(questions),
    }


def score_fixed(revision: Revision, weaknesses: Sequence[Weakness], matched_rules: Sequence[str]) -> dict[str, Any]:
    """Whether the matched rules stopped firing in the same files at the fixed revision."""
    files = {normalize_path(item.file) for item in weaknesses}
    if revision.findings is None:
        return {"fix": "error", "flagged_in_labelled_files": 0}
    detections = [f for f in revision.findings if f.path in files and f.kind == "detection"]
    present = files & {normalize_path(p) for p in revision.files_present}
    if not matched_rules:
        return {"fix": "not_applicable", "flagged_in_labelled_files": len(detections)}
    if not present:
        return {"fix": "file_absent", "flagged_in_labelled_files": len(detections)}
    again = sorted({f.rule_id for f in detections} & set(matched_rules))
    return {"fix": "still_flagged" if again else "cleared", "flagged_in_labelled_files": len(detections),
            "still_firing_rules": again}


# ---------------------------------------------------------------------------------------------
# Numbers with denominators


def wilson(numerator: int, denominator: int, z: float = 1.96) -> tuple[float, float] | None:
    """Wilson 95% interval for a proportion; None when the denominator is zero."""
    if denominator <= 0:
        return None
    p = numerator / denominator
    centre = p + z * z / (2 * denominator)
    margin = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator * denominator))
    base = 1 + z * z / denominator
    return round(max(0.0, (centre - margin) / base), 3), round(min(1.0, (centre + margin) / base), 3)


def ratio(numerator: int, denominator: int) -> dict[str, Any]:
    """A rate that always carries its numerator and denominator (and no rate when it is 0/0)."""
    interval = wilson(numerator, denominator)
    return {"numerator": numerator, "denominator": denominator,
            "rate": round(numerator / denominator, 3) if denominator else None,
            "wilson95": list(interval) if interval else None}


def summarize_cves(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate per-CVE results (each has `vulnerable` and optionally `fixed` score dicts)."""
    total = len(results)
    outcomes = Counter(item["vulnerable"]["outcome"] for item in results)
    analysed = total - outcomes["not_analyzed"] - outcomes["error"]
    detected = [item for item in results if item["vulnerable"]["outcome"] == "detected"]
    fixes = Counter(item["fixed"]["fix"] for item in detected if item.get("fixed"))
    flagged = sum(item["vulnerable"]["flagged_in_labelled_files"] for item in results
                  if item["vulnerable"]["outcome"] != "error")
    matching = sum(item["vulnerable"]["flagged_matching_label"] for item in results
                   if item["vulnerable"]["outcome"] != "error")
    return {
        "cves": total,
        "outcomes": {name: outcomes.get(name, 0)
                     for name in ("detected", "abstained", "missed", "not_analyzed", "error")},
        "detected_of_all": ratio(len(detected), total),
        "detected_of_analyzed": ratio(len(detected), analysed),
        "abstained_of_all": ratio(outcomes["abstained"], total),
        "detected_or_abstained_of_all": ratio(len(detected) + outcomes["abstained"], total),
        "cwe_agrees_among_detected": ratio(sum(item["vulnerable"]["cwe_agrees"] for item in detected), len(detected)),
        "file_level_detection_of_all": ratio(
            sum(item["vulnerable"]["file_level_detection"] for item in results
                if item["vulnerable"]["outcome"] != "error"), total - outcomes["error"]),
        "fixed_cleared_of_detected": ratio(fixes["cleared"], len(detected)),
        "fixed_outcomes": {name: fixes.get(name, 0)
                           for name in ("cleared", "still_flagged", "file_absent", "error")},
        "labelled_file_flags": {
            "flagged_in_labelled_files_at_vulnerable": flagged,
            "of_which_matching_a_label": matching,
            "note": "Findings in a labelled file that are not at a label are not necessarily false "
                    "positives (the labels are not exhaustive), so this is not a precision.",
        },
    }


# ---------------------------------------------------------------------------------------------
# Determinism and digests


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def results_digest(document: Mapping[str, Any]) -> str:
    """Digest of what a SARIF run concluded, independent of report ids, timestamps and snapshot ids.

    It covers every result's rule, location, state, check, fingerprints and evidence digest, plus
    whether coverage was complete, so two runs that agree here reached the same conclusions.
    """
    rows: list[object] = []
    complete: list[object] = []
    for run in document.get("runs") or ():
        properties = run.get("properties") or {}
        complete.append((properties.get("coverage") or {}).get("complete"))
        for result in run.get("results") or ():
            props = result.get("properties") or {}
            places = []
            for location in result.get("locations") or ():
                physical = location.get("physicalLocation") or {}
                region = physical.get("region") or {}
                places.append([(physical.get("artifactLocation") or {}).get("uri"),
                               region.get("startLine"), region.get("endLine")])
            rows.append([result.get("ruleId"), result.get("level"), props.get("result"), props.get("check"),
                         props.get("evidenceDigest"), result.get("partialFingerprints"), places])
    rows.sort(key=lambda row: canonical(row))
    return sha256_hex(canonical({"complete": complete, "results": rows}))


def digest_without_report_id(document: Mapping[str, Any]) -> str:
    """Digest of the whole SARIF document except each run's `properties.reportId`.

    Polaris 0.5.0 and earlier computed `reportId` from the whole review including its elapsed
    time, so it changed from run to run even when every result was identical (later versions
    leave elapsed time out). Everything else in the file is kept.
    """
    copy = json.loads(json.dumps(document))
    for run in copy.get("runs") or ():
        (run.get("properties") or {}).pop("reportId", None)
    return sha256_hex(canonical(copy))


def check_determinism(results: Sequence[str], raw: Sequence[str] | None = None,
                      stripped: Sequence[str] | None = None) -> dict[str, Any]:
    """Whether repeated runs produced identical digests.

    `results`: normalised conclusions (see `results_digest`); `raw`: the whole files' sha256;
    `stripped`: whole files without `reportId` (see `digest_without_report_id`).
    """
    verdict: dict[str, Any] = {"runs": len(results), "distinct_result_digests": len(set(results)),
                               "identical_results": len(results) > 1 and len(set(results)) == 1}
    if raw is not None:
        verdict["distinct_raw_digests"] = len(set(raw))
        verdict["identical_raw"] = len(raw) > 1 and len(set(raw)) == 1
    if stripped is not None:
        verdict["distinct_without_report_id"] = len(set(stripped))
        verdict["identical_without_report_id"] = len(stripped) > 1 and len(set(stripped)) == 1
    verdict["comparable"] = len(results) > 1
    return verdict


def summarize_determinism(per_run: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    comparable = [item for item in per_run if item.get("comparable")]
    return {
        "run_groups": len(per_run),
        "comparable_groups": len(comparable),
        "groups_with_identical_results": sum(1 for item in comparable if item["identical_results"]),
        "groups_with_identical_raw_files": sum(1 for item in comparable if item.get("identical_raw")),
        "groups_identical_without_report_id": sum(1 for item in comparable if item.get("identical_without_report_id")),
        "all_identical_results": bool(comparable) and all(item["identical_results"] for item in comparable),
    }


def tree_digest(files: Mapping[str, bytes]) -> str:
    """A content hash over named files: sha256 of sorted `name NUL sha256(content) LF` lines."""
    lines = "".join(f"{name}\0{sha256_hex(content)}\n" for name, content in sorted(files.items()))
    return sha256_hex(lines.encode())


def verify_pin(actual: str, expected: str, what: str) -> None:
    if actual != expected:
        raise PinMismatch(f"{what}: expected {expected}, got {actual}")


# ---------------------------------------------------------------------------------------------
# Report


NOT_SHOWN = (
    "This is a small, deterministic slice of each dataset, not a sample drawn at random. It says "
    "nothing about the whole dataset, about other languages, or about code that is not in it.",
    "A detection is a finding near a label. It does not show the finding explains the "
    "vulnerability, and findings that are not at a label are not counted as false positives "
    "because the labels are not exhaustive. No false-positive rate is measured here.",
    "On the CVE dataset every tool was run on the labelled files only, not on the whole "
    "repository (Polaris could still read the rest of the checkout as context). Whole-repository "
    "precision, noise and speed are not measured here.",
    "Other tools were compared only where this report lists their pinned version, rule set and raw "
    "output. Where it says no comparison was run, none was run and nothing is implied.",
    "Fix results show that the matched rule stopped firing in the same file. They do not show "
    "that the fix is correct, complete or behaviour-preserving, and Polaris did not run any test.",
    "Determinism is measured over the repeats listed, on one machine. It shows identical output "
    "for identical input here, not across machines, versions or inputs.",
    "The labels come from the datasets' maintainers. They can be wrong or incomplete, and a "
    "dataset can overlap with what a tool's rules were written against.",
    "Nothing here is a model-quality result. No AI is used in these runs.",
)


def format_ratio(item: Mapping[str, Any]) -> str:
    """`n/d = rate (95% interval a to b)`; used by the section builders."""
    text = f"{item['numerator']}/{item['denominator']}"
    if item["rate"] is None:
        return f"{text} (no rate)"
    low, high = item["wilson95"]
    return f"{text} = {item['rate']:.0%} (95% interval {low:.0%} to {high:.0%})"


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [f"# Public benchmark, first measured results: Polaris {report['polaris_version']}, {report['date']}", "",
             f"Format `{report['format']}`. Generated {report['generated_at']}. "
             "Polaris-only unless a section says another tool was run.", ""]
    lines += ["## Tools", ""]
    for tool in report["tools"]:
        lines.append(f"- **{tool['name']}** {tool['version']}: {tool['how']}")
    lines += ["", "## Datasets", ""]
    for dataset in report["datasets"]:
        status = dataset["status"]
        lines.append(f"- **{dataset['id']}** ({status}): licence {dataset['licence']}; source {dataset['source']}"
                     + (f" at `{dataset['commit']}`" if dataset.get("commit") else "")
                     + (f"; content digest `{dataset['content_digest']}`" if dataset.get("content_digest") else "")
                     + (f". {dataset['note']}" if dataset.get("note") else ""))
    lines += ["", "## Matching rules", ""] + [f"- {rule}" for rule in report["matching_rules"]]
    for section in report["sections"]:
        lines += ["", f"## {section['title']}", ""]
        lines += section["lines"]
    lines += ["", "## Determinism", ""]
    for name, item in report["determinism"].items():
        lines.append(f"- {name}: {item['groups_with_identical_results']} of {item['comparable_groups']} comparable "
                     f"run groups gave identical normalised results; {item['groups_with_identical_raw_files']} "
                     f"identical as whole raw files, {item['groups_identical_without_report_id']} identical once the "
                     f"run-specific `reportId` is removed (Polaris 0.5.0 and earlier derived it from the whole "
                     f"review including its elapsed time). {item['run_groups']} run groups, {report['repeats']} "
                     "repeats each.")
    lines += ["", "## What this does not show", ""] + [f"- {item}" for item in report["not_shown"]]
    lines += ["", "## Reproduce", ""] + [f"    {command}" for command in report["reproduce"]]
    lines += ["", "## Raw output", "",
              f"Raw SARIF for every run is under `{report['raw_root']}` (outside the repository, not committed); "
              "`report.json` lists each file with its sha256.", ""]
    return "\n".join(lines)

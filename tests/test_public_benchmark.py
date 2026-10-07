"""The public benchmark harness: matching rules, scoring, digests, pins, adapters and reports.

Everything here uses small synthetic data and runs offline. Nothing is fetched; the one test that
runs the real Polaris CLI reviews a tiny project made in a temporary folder. Source in fixtures
is data that is parsed, never executed.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PUBLIC = Path(__file__).resolve().parents[1] / "benchmarks" / "public"
sys.path.insert(0, str(PUBLIC))

import pbench_core as core  # noqa: E402
import pbench_datasets as datasets  # noqa: E402
import pbench_report as reports  # noqa: E402
import pbench_tools as tools  # noqa: E402

GIT_ENV = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def load_runner():
    spec = importlib.util.spec_from_file_location("public_benchmark_run", PUBLIC / "run.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def result(rule="polaris.js.xss.dom_html", path="src/a.js", start=44, end=44, state="flagged", check="xss",
           cwe="CWE-79", **extra):
    return {"ruleId": rule, "level": "note", "partialFingerprints": {"f": rule},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                 "region": {"startLine": start, "endLine": end}}}],
            "properties": {"result": state, "check": check, "cwe": cwe, "evidenceDigest": f"sha256:{rule}{start}"},
            **extra}


def sarif(*results, report_id="sha256:1", complete=True, entries=None, version="0.5.0", rules=None):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Polaris", "semanticVersion": version, "rules": rules or []}},
        "results": list(results),
        "properties": {"reportId": report_id, "status": "complete" if complete else "incomplete",
                       "coverage": {"complete": complete, "files_total": 1, "files_analyzed": 1,
                                    "files_not_fully_checked": 0, "entries": entries if entries is not None else [
                                        {"path": "src/a.js", "check_id": "xss", "status": "checked", "required": True,
                                         "reason": "builtin_rules_completed"}]}}}]}


WEAK = [core.Weakness("src/a.js", 43, "xss")]


# ---- paths, CWE ids and SARIF reading --------------------------------------------------------------


def test_paths_are_compared_without_prefixes_and_separators():
    assert core.normalize_path("./src\\a.js") == "src/a.js"
    assert core.normalize_path("file:///work/repo/src/a.js", "/work/repo") == "src/a.js"
    assert core.normalize_path("/src/a.js") == "src/a.js"
    assert core.normalize_path("src%20x/a.js") == "src x/a.js"


def test_cwe_ids_are_read_from_the_forms_tools_use():
    assert core.cwe_numbers(["CWE-079", "cwe-116", "external/cwe/cwe-22", "79", "OWASP-A03:2021", 89]) == (22, 79, 89, 116)
    assert core.cwe_numbers(["CWE-79: Improper Neutralization", "security"]) == (79,)
    assert core.cwe_numbers([]) == ()


def test_polaris_flagged_is_a_detection_and_needs_context_is_an_abstention():
    document = sarif(result(state="flagged"), result(rule="r2", start=90, state="needs_context"),
                     result(rule="r3", state="passed"))
    found = core.parse_sarif(document, tool="polaris")
    assert [(f.rule_id, f.kind) for f in found] == [("polaris.js.xss.dom_html", "detection"), ("r2", "abstention")]
    assert found[0].cwe == (79,) and found[0].check == "xss"


def test_other_tools_report_only_detections_and_rule_tags_carry_the_cwe():
    rules = [{"id": "x.y.rule", "properties": {"tags": ["CWE-79: Improper Neutralization", "security"]}}]
    document = sarif(result(rule="x.y.rule", state=None, cwe=None), rules=rules)
    document["runs"][0]["results"][0]["properties"] = {}
    found = core.parse_sarif(document, tool="semgrep")
    assert len(found) == 1 and found[0].kind == "detection" and found[0].cwe == (79,)


def test_suppressed_results_and_results_without_a_line_are_ignored():
    suppressed = result()
    suppressed["suppressions"] = [{"kind": "inSource"}]
    no_line = result(rule="r2")
    no_line["locations"][0]["physicalLocation"]["region"] = {}
    assert core.parse_sarif(sarif(suppressed, no_line), tool="polaris") == []


def test_semgrep_rule_ids_drop_the_cache_path_prefix():
    assert core.display_rule_id("a.b.semgrep-rules.javascript.browser.rule", "semgrep") == "javascript.browser.rule"
    assert core.display_rule_id("zizmor/template-injection", "zizmor") == "zizmor/template-injection"


def test_the_polaris_version_and_coverage_come_from_the_report():
    document = sarif(version="9.9.9", complete=False)
    assert core.sarif_tool_version(document) == "9.9.9"
    summary = core.coverage_summary(sarif(entries=[
        {"path": "a.js", "check_id": "xss", "status": "not_checked", "required": True, "reason": "parse_error"},
        {"path": "a.js", "check_id": "api", "status": "not_checked", "required": False, "reason": "policy"}], complete=False))
    assert summary["status"] == "incomplete" and summary["required_rows_not_checked_count"] == 1
    assert core.analysed_paths(sarif()) == {"src/a.js"}


# ---- the matching rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(("start", "end", "line", "expected"), [
    (44, 44, 43, True),     # one line away
    (44, 44, 49, True),     # exactly five lines after the finding
    (44, 44, 50, False),    # six lines after
    (44, 44, 39, True),     # exactly five lines before
    (44, 44, 38, False),
    (44, 60, 62, True),     # within five lines of the end of a multi-line span
    (44, 60, 66, False),
])
def test_location_window_is_five_lines_either_side_of_the_finding_span(start, end, line, expected):
    finding = core.Finding("polaris", "r", "src/a.js", start, end, "detection")
    assert core.location_match(finding, "src/a.js", line) is expected


def test_location_requires_the_same_file_and_file_match_ignores_the_line():
    finding = core.Finding("polaris", "r", "src/a.js", 44, 44, "detection")
    assert not core.location_match(finding, "src/b.js", 44)
    assert core.file_match(finding, "./src/a.js") and not core.file_match(finding, "src/b.js")


# ---- scoring one CVE -------------------------------------------------------------------------------


def revision(*items, analysed=("src/a.js",), present=("src/a.js",)):
    return core.Revision(list(items), set(analysed) if analysed is not None else None, set(present))


def test_a_flagged_finding_at_the_label_is_a_detection():
    found = core.parse_sarif(sarif(result()), tool="polaris")
    score = core.score_vulnerable(revision(*found), WEAK, ["CWE-079", "CWE-116"])
    assert score["outcome"] == "detected" and score["matched_rules"] == ["polaris.js.xss.dom_html"]
    assert score["cwe_agrees"] is True and score["flagged_matching_label"] == 1


def test_a_question_at_the_label_is_an_abstention_and_never_a_detection():
    found = core.parse_sarif(sarif(result(state="needs_context")), tool="polaris")
    score = core.score_vulnerable(revision(*found), WEAK)
    assert score["outcome"] == "abstained" and score["matched_rules"] == []
    assert score["flagged_in_labelled_files"] == 0 and score["abstentions_in_labelled_files"] == 1


def test_a_detection_wins_over_a_question_for_the_same_cve():
    found = core.parse_sarif(sarif(result(), result(rule="r2", start=45, state="needs_context")), tool="polaris")
    assert core.score_vulnerable(revision(*found), WEAK)["outcome"] == "detected"


def test_a_detection_far_from_the_label_is_a_miss_but_counts_at_file_level():
    found = core.parse_sarif(sarif(result(start=200, end=200)), tool="polaris")
    score = core.score_vulnerable(revision(*found), WEAK)
    assert score["outcome"] == "missed" and score["file_level_detection"] is True and score["flagged_matching_label"] == 0


def test_findings_in_other_files_do_not_count():
    found = core.parse_sarif(sarif(result(path="src/other.js")), tool="polaris")
    score = core.score_vulnerable(revision(*found), WEAK)
    assert score["outcome"] == "missed" and score["flagged_in_labelled_files"] == 0


def test_an_unanalysed_file_is_not_analysed_rather_than_a_miss():
    assert core.score_vulnerable(revision(analysed=()), WEAK)["outcome"] == "not_analyzed"
    # A tool that reports no coverage (None) is judged on its findings alone.
    assert core.score_vulnerable(revision(analysed=None), WEAK)["outcome"] == "missed"


def test_a_failed_run_is_an_error_and_not_a_miss():
    assert core.score_vulnerable(core.Revision(None), WEAK)["outcome"] == "error"
    assert core.score_fixed(core.Revision(None), WEAK, ["r"])["fix"] == "error"


def test_any_labelled_weakness_can_make_the_cve_detected():
    two = [core.Weakness("src/a.js", 10), core.Weakness("src/b.js", 300)]
    found = core.parse_sarif(sarif(result(path="src/b.js", start=301, end=301)), tool="polaris")
    assert core.score_vulnerable(revision(*found, analysed=("src/a.js", "src/b.js")), two)["outcome"] == "detected"


def test_the_fix_is_cleared_when_the_matched_rule_stops_firing_in_the_file():
    still = core.parse_sarif(sarif(result(start=60, end=60)), tool="polaris")  # lines moved: line is not compared
    other_rule = core.parse_sarif(sarif(result(rule="another", start=60, end=60)), tool="polaris")
    rules = ["polaris.js.xss.dom_html"]
    assert core.score_fixed(revision(*still), WEAK, rules)["fix"] == "still_flagged"
    assert core.score_fixed(revision(*other_rule), WEAK, rules)["fix"] == "cleared"
    assert core.score_fixed(revision(), WEAK, rules)["fix"] == "cleared"
    assert core.score_fixed(revision(present=()), WEAK, rules)["fix"] == "file_absent"
    assert core.score_fixed(revision(*still), WEAK, [])["fix"] == "not_applicable"


# ---- numbers with denominators ---------------------------------------------------------------------


def test_every_rate_carries_its_denominator_and_zero_over_zero_has_no_rate():
    assert core.ratio(0, 0) == {"numerator": 0, "denominator": 0, "rate": None, "wilson95": None}
    row = core.ratio(2, 20)
    assert (row["numerator"], row["denominator"], row["rate"]) == (2, 20, 0.1)
    low, high = row["wilson95"]
    assert 0.02 < low < 0.1 < high < 0.35
    assert core.wilson(0, 20)[0] == 0.0 and core.wilson(20, 20)[1] == 1.0 and core.wilson(1, 0) is None


def outcome(name, **extra):
    vulnerable = {"outcome": name, "matched_rules": [], "cwe_agrees": False, "file_level_detection": False,
                  "flagged_in_labelled_files": 0, "flagged_matching_label": 0, "abstentions_in_labelled_files": 0}
    return {"vulnerable": vulnerable, **extra}


def test_the_summary_separates_detections_abstentions_misses_and_scope_limits():
    cases = [
        {**outcome("detected"), "fixed": {"fix": "cleared"}},
        {**outcome("detected"), "fixed": {"fix": "still_flagged"}},
        outcome("abstained"), outcome("missed"), outcome("missed"), outcome("not_analyzed"), outcome("error"),
    ]
    cases[0]["vulnerable"]["cwe_agrees"] = True
    summary = core.summarize_cves(cases)
    assert summary["outcomes"] == {"detected": 2, "abstained": 1, "missed": 2, "not_analyzed": 1, "error": 1}
    assert (summary["detected_of_all"]["numerator"], summary["detected_of_all"]["denominator"]) == (2, 7)
    assert summary["detected_of_analyzed"]["denominator"] == 5  # not analysed and errors leave the denominator
    assert (summary["abstained_of_all"]["numerator"], summary["detected_or_abstained_of_all"]["numerator"]) == (1, 3)
    assert summary["fixed_cleared_of_detected"]["numerator"] == 1 and summary["fixed_cleared_of_detected"]["denominator"] == 2
    assert summary["cwe_agrees_among_detected"]["numerator"] == 1
    assert "not a precision" in summary["labelled_file_flags"]["note"]


def test_an_empty_run_has_no_rates_instead_of_a_division_error():
    summary = core.summarize_cves([])
    assert summary["detected_of_all"]["rate"] is None and summary["cves"] == 0


# ---- determinism and digests -----------------------------------------------------------------------


def test_the_results_digest_ignores_report_ids_and_result_order_but_not_conclusions():
    first = sarif(result(), result(rule="r2", start=90), report_id="sha256:aaa")
    reordered = sarif(result(rule="r2", start=90), result(), report_id="sha256:bbb")
    assert core.results_digest(first) == core.results_digest(reordered)
    changed = sarif(result(), result(rule="r2", start=91), report_id="sha256:aaa")
    assert core.results_digest(first) != core.results_digest(changed)
    question = sarif(result(state="needs_context"), result(rule="r2", start=90))
    assert core.results_digest(first) != core.results_digest(question)
    incomplete = sarif(result(), result(rule="r2", start=90), complete=False)
    assert core.results_digest(first) != core.results_digest(incomplete)


def test_the_whole_file_digest_without_report_id_changes_for_any_other_difference():
    first = sarif(result(), report_id="sha256:aaa")
    second = sarif(result(), report_id="sha256:bbb")
    assert core.digest_without_report_id(first) == core.digest_without_report_id(second)
    third = copy.deepcopy(second)
    third["runs"][0]["results"][0]["message"] = {"text": "different"}
    assert core.digest_without_report_id(first) != core.digest_without_report_id(third)
    assert first["runs"][0]["properties"]["reportId"] == "sha256:aaa"  # the input is not modified


def test_determinism_is_identical_only_when_every_repeat_agrees_and_needs_two_runs():
    assert core.check_determinism(["a", "a", "a"], ["x", "y", "z"], ["w", "w", "w"]) == {
        "runs": 3, "distinct_result_digests": 1, "identical_results": True, "distinct_raw_digests": 3,
        "identical_raw": False, "distinct_without_report_id": 1, "identical_without_report_id": True,
        "comparable": True}
    assert core.check_determinism(["a", "b"])["identical_results"] is False
    one = core.check_determinism(["a"])
    assert one["comparable"] is False and one["identical_results"] is False


def test_the_determinism_summary_counts_groups():
    groups = [core.check_determinism(["a", "a"], ["x", "x"], ["x", "x"]),
              core.check_determinism(["a", "b"], ["x", "y"], ["x", "y"]), core.check_determinism(["a"])]
    summary = core.summarize_determinism(groups)
    assert (summary["run_groups"], summary["comparable_groups"], summary["groups_with_identical_results"]) == (3, 2, 1)
    assert summary["all_identical_results"] is False and summary["groups_with_identical_raw_files"] == 1
    assert core.summarize_determinism([])["all_identical_results"] is False


# ---- pins and adapters -----------------------------------------------------------------------------


def test_tree_digest_depends_on_names_and_content_but_not_order():
    base = {"a.json": b"1", "b.json": b"2"}
    assert core.tree_digest(base) == core.tree_digest(dict(reversed(list(base.items()))))
    assert core.tree_digest(base) != core.tree_digest({"a.json": b"1", "b.json": b"3"})
    assert core.tree_digest(base) != core.tree_digest({"a.json": b"1", "c.json": b"2"})


def test_a_pin_mismatch_is_an_error_that_names_both_values():
    core.verify_pin("abc", "abc", "thing")
    with pytest.raises(core.PinMismatch, match="expected def, got abc"):
        core.verify_pin("abc", "def", "thing")


def test_the_cve_labels_must_match_their_pinned_digest(tmp_path, monkeypatch):
    dataset = datasets.OssfCveDataset(tmp_path)
    folder = dataset.labels_dir / "CVEs"
    folder.mkdir(parents=True)
    entry = {"CVE": "CVE-1", "state": "PUBLISHED"}
    (folder / "CVE-1.json").write_text(json.dumps(entry))
    monkeypatch.setattr(datasets, "fetch_commit", lambda *args, **kwargs: None)
    monkeypatch.setattr(datasets, "checkout", lambda *args, **kwargs: None)
    with pytest.raises(core.PinMismatch):
        dataset.fetch_labels()
    digest = core.tree_digest({"CVEs/CVE-1.json": (folder / "CVE-1.json").read_bytes()})
    monkeypatch.setattr(datasets, "OSSF_CVES_DIGEST", digest)
    assert dataset.fetch_labels() == {"CVE-1.json": entry}


def test_the_fixture_dataset_must_match_its_pinned_digest(tmp_path, monkeypatch):
    dataset = datasets.ZizmorFixtures(tmp_path)
    base = dataset.source_dir / datasets.ZIZMOR_FIXTURE_DIR
    base.mkdir(parents=True)
    (base / "a.yml").write_text("on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n")
    monkeypatch.setattr(datasets, "fetch_commit", lambda *args, **kwargs: None)
    monkeypatch.setattr(datasets, "run_git", lambda *args, **kwargs: "")
    monkeypatch.setattr(datasets, "checkout", lambda *args, **kwargs: None)
    with pytest.raises(core.PinMismatch):
        dataset.fetch()


def test_only_full_commit_hashes_on_github_are_fetched(tmp_path):
    with pytest.raises(datasets.DatasetUnavailable, match="github.com"):
        datasets.fetch_commit("https://example.com/x.git", "a" * 40, tmp_path / "r", tmp_path)
    with pytest.raises(ValueError, match="40-character"):
        datasets.fetch_commit("https://github.com/x/y.git", "main", tmp_path / "r", tmp_path)


def test_a_checkout_that_is_not_the_pinned_commit_is_refused(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    env = {**GIT_ENV, "HOME": str(tmp_path)}
    subprocess.run(["/usr/bin/git", "init", "-q", str(root)], check=True, env=env)
    (root / "a.txt").write_text("x")
    subprocess.run(["/usr/bin/git", "-C", str(root), "add", "."], check=True, env=env)
    subprocess.run(["/usr/bin/git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@localhost", "commit", "-q",
                    "-m", "one"], check=True, env=env)
    head = subprocess.run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"], check=True, env=env,
                          capture_output=True, text=True).stdout.strip()
    datasets.checkout(root, head, tmp_path)
    with pytest.raises(datasets.DatasetUnavailable):
        datasets.checkout(root, "0" * 40, tmp_path)


def test_the_cache_folder_defaults_outside_the_repository_and_is_resolved(tmp_path, monkeypatch):
    monkeypatch.delenv(datasets.CACHE_VARIABLE, raising=False)
    assert datasets.cache_root() == Path(datasets.DEFAULT_CACHE).resolve()
    monkeypatch.setenv(datasets.CACHE_VARIABLE, str(tmp_path / "from-env"))
    assert datasets.cache_root() == (tmp_path / "from-env").resolve()
    assert datasets.cache_root(tmp_path / "flag") == (tmp_path / "flag").resolve()
    repository = Path(__file__).resolve().parents[1]
    assert not datasets.cache_root().is_relative_to(repository)


# ---- the CVE labels --------------------------------------------------------------------------------


def entry(cve="CVE-2017-1", **changes):
    value = {"CVE": cve, "state": "PUBLISHED", "repository": f"https://github.com/o/{cve}.git",
             "prePatch": {"commit": "a" * 40, "weaknesses": [
                 {"location": {"file": "src/a.js", "line": 43}, "explanation": "xss"}]},
             "postPatch": {"commit": "b" * 40}, "CWEs": ["CWE-079"]}
    value.update(changes)
    return value


def test_a_complete_label_becomes_a_case():
    case = datasets.parse_cve_entry(entry())
    assert (case.id, case.pre_commit, case.post_commit) == ("CVE-2017-1", "a" * 40, "b" * 40)
    assert case.weaknesses == (core.Weakness("src/a.js", 43, "xss"),) and case.files == ("src/a.js",)


@pytest.mark.parametrize(("changes", "reason"), [
    ({"state": "REJECTED"}, "not PUBLISHED"),
    ({"repository": "https://gitlab.com/o/r.git"}, "github.com"),
    ({"postPatch": {"commit": "main"}}, "postPatch"),
    ({"prePatch": {"commit": "a" * 40, "weaknesses": []}}, "no weakness"),
    ({"prePatch": {"commit": "a" * 40, "weaknesses": [{"location": {"file": "../x.js", "line": 1}}]}}, "no weakness"),
    ({"prePatch": {"commit": "a" * 40, "weaknesses": [{"location": {"file": "/etc/x", "line": 1}}]}}, "no weakness"),
])
def test_unusable_labels_are_refused_with_a_reason(changes, reason):
    with pytest.raises(ValueError, match=reason):
        datasets.parse_cve_entry(entry(**changes))


def test_case_selection_is_the_first_n_in_id_order_that_fetch_and_records_what_it_skipped():
    entries = [("CVE-3.json", entry("CVE-3")), ("CVE-1.json", entry("CVE-1")), ("CVE-2.json", entry("CVE-2")),
               ("CVE-0.json", entry("CVE-0", state="REJECTED")), ("CVE-4.json", entry("CVE-4"))]
    tried: list[str] = []

    def fetch(case):
        tried.append(case.id)
        if case.id == "CVE-2":
            raise datasets.DatasetUnavailable("gone")

    chosen, skipped = datasets.select_cases(entries, 2, fetch)
    assert [case.id for case in chosen] == ["CVE-1", "CVE-3"]
    assert tried == ["CVE-1", "CVE-2", "CVE-3"]  # selection stops once the limit is reached
    assert [(item["id"], item["reason"][:12]) for item in skipped] == [("CVE-0", "unusable lab"), ("CVE-2", "not fetched:")]
    again, _ = datasets.select_cases(list(reversed(entries)), 2, lambda case: None if case.id != "CVE-2" else fetch(case))
    assert [case.id for case in again] == [case.id for case in chosen]


# ---- fixtures --------------------------------------------------------------------------------------

WORKFLOW = "name: x\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"


def test_workflows_are_told_apart_from_other_yaml_and_named_safely():
    assert datasets.looks_like_workflow(WORKFLOW) and datasets.looks_like_workflow('"on": push\njobs: {}\n')
    assert not datasets.looks_like_workflow("name: action\nruns:\n  using: composite\n")
    assert not datasets.looks_like_workflow("  on: nested\n  jobs: nested\n")
    assert datasets.flatten_name("a/b c.yml") == "a__b_c.yml"
    files = {"a/one.yml": WORKFLOW.encode(), "action.yml": b"runs: {}\n", "notes.txt": WORKFLOW.encode(),
             "bad.yml": b"\xff\xfe"}
    assert list(datasets.select_fixtures(files)) == ["a__one.yml"]


def test_the_gpl_dataset_is_a_disabled_stub_that_fetches_nothing(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the stub must not run anything")

    monkeypatch.setattr(subprocess, "run", refuse)
    stub = datasets.OwaspPythonStub()
    assert stub.enabled is False and stub.describe()["status"] == "disabled" and stub.describe()["licence"] == "GPL"
    with pytest.raises(datasets.DatasetUnavailable, match="GPL"):
        stub.fetch()


# ---- fixtures comparison and the report ------------------------------------------------------------


def finding(path, check="", rule="", kind="detection"):
    return core.Finding("t", rule, path, 1, 1, kind, check)


def test_the_fixture_comparison_counts_agreement_and_keeps_questions_apart():
    fixtures = ["a", "b", "c", "d"]
    polaris = [finding("a", "workflow_injection"), finding("b", "workflow_injection"),
               finding("c", "workflow_injection", kind="abstention"), finding("a", "secret_exposure")]
    zizmor = [finding("a", rule="zizmor/template-injection"), finding("c", rule="zizmor/template-injection"),
              finding("d", rule="zizmor/artipacked")]
    result_ = reports.compare_fixtures(polaris, zizmor, fixtures)
    pair = next(item for item in result_["comparison"]["pairs"] if item["zizmor_audit"] == "template-injection")
    assert pair == {"zizmor_audit": "template-injection", "polaris_check": "workflow_injection", "both": 1,
                    "only_polaris": 1, "only_zizmor": 1, "neither": 1, "polaris_asked_where_zizmor_flagged": 1}
    assert result_["polaris_any_detection"] == 2 and result_["polaris_any_abstention"] == 1
    assert result_["comparison"]["zizmor_audits_without_a_paired_polaris_check"] == {"artipacked": 1}
    assert result_["comparison"]["polaris_checks_without_a_paired_zizmor_audit"] == {"secret_exposure": 1}
    assert reports.compare_fixtures(polaris, None, fixtures)["comparison"] == "not run"


def build_sample_report():
    cases = [{"id": "CVE-1", "weaknesses": [{"file": "src/a.js", "line": 43}],
              "polaris": {**outcome("abstained"), "runs": {"vulnerable": {"coverage": {"complete": True}}}}},
             {"id": "CVE-2", "weaknesses": [{"file": "b.js", "line": 1}, {"file": "c.js", "line": 2}],
              "polaris": {**outcome("detected"), "fixed": {"fix": "cleared"}, "runs": {}}}]
    section, lines = reports.cve_section("CVE dataset", cases, [{"id": "CVE-9", "reason": "not fetched: gone"}],
                                         ["polaris"], 3)
    fixtures, fixture_lines = reports.fixtures_section(
        reports.compare_fixtures([], None, ["a"]), core.summarize_determinism([]), 3, "not requested; no comparison was run")
    return reports.build_report(
        date="2026-10-06", generated_at="2026-10-06T00:00:00Z", polaris_version="0.5.0",
        tools=[{"name": "Polaris", "version": "0.5.0", "how": "cli"}, {"name": "zizmor", "version": "not run", "how": "-"}],
        datasets=[datasets.OwaspPythonStub().describe()], sections=[section, fixtures],
        section_lines=[("CVE dataset", lines), ("Fixtures", fixture_lines)],
        determinism={"x": core.summarize_determinism([core.check_determinism(["a", "a"], ["x", "y"], ["z", "z"])])},
        repeats=3, raw_root="/cache/raw", raw_files=[{"path": "p", "sha256": "s"}], reproduce=["run it"])


def test_the_report_states_dates_versions_denominators_abstentions_and_limits():
    text = core.render_markdown(build_sample_report())
    assert "Polaris 0.5.0, 2026-10-06" in text and "## What this does not show" in text
    assert "Detected, of all 2 CVEs: 1/2 = 50%" in text and "Abstained (questions to the user, not detections): 1/2" in text
    assert "| CVE-1 | `src/a.js:43` | abstained |" in text and "| CVE-2 | `b.js:1 (+1)` | detected, fix cleared |" in text
    assert "CVE-9: not fetched: gone" in text and "no comparison was run" in text
    assert "(disabled)" in text and "licence GPL" in text
    assert "1 of 1 comparable run groups gave identical normalised results; 0 identical as whole raw files, 1 identical" in text
    assert "No AI is used" in text and "not a sample drawn at random" in text and "    run it" in text


def test_the_report_files_are_written_once_and_the_json_round_trips(tmp_path):
    report = build_sample_report()
    markdown, document = reports.write_report(report, tmp_path / "out")
    assert json.loads(document.read_text()) == json.loads(json.dumps(report))
    assert markdown.read_text().startswith("# Public benchmark")
    with pytest.raises(FileExistsError):
        reports.write_report(report, tmp_path / "out")


# ---- tools and the command line --------------------------------------------------------------------


def test_subprocess_environments_carry_no_credentials(tmp_path, monkeypatch):
    for name in ("OPENROUTER_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "POLARIS_AI_KEY"):
        monkeypatch.setenv(name, "must-not-leak")
    for env in (tools.clean_environment(tmp_path / "home"), datasets.git_environment(tmp_path / "home")):
        assert not [name for name in env if "KEY" in name or "TOKEN" in name]
        assert "must-not-leak" not in env.values()


def test_a_missing_uv_makes_the_optional_tools_unavailable_instead_of_failing_the_run(tmp_path, monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    with pytest.raises(tools.ToolUnavailable, match="uv is not on PATH"):
        tools.run_zizmor(tmp_path, tmp_path / "out.sarif", tmp_path)


def test_the_command_lists_adapters_without_fetching_anything(tmp_path, capsys):
    runner = load_runner()
    shown: list[str] = []
    assert runner.main(["--list-adapters", "--cache", str(tmp_path / "cache")], out=shown.append) == 0
    described = [json.loads(item) for item in shown]
    assert [item["id"] for item in described] == ["ossf-cve-benchmark", "github-actions-fixtures", "owasp-benchmark-python"]
    assert [item["status"] for item in described] == ["used", "used", "disabled"]
    assert all(len(item.get("commit", "")) in (0, 40) for item in described)
    assert all(item["licence"] for item in described)


def test_the_command_refuses_nonsense_counts(capsys):
    runner = load_runner()
    assert runner.main(["--limit", "0"]) == 2 and "at least 1" in capsys.readouterr().err
    assert runner.main(["--repeats", "0"]) == 2


def test_the_real_cli_reviews_a_project_and_repeats_are_identical(tmp_path):
    root = (tmp_path / "project").resolve()
    root.mkdir()
    env = {**GIT_ENV, "HOME": str(tmp_path)}
    subprocess.run(["/usr/bin/git", "--no-pager", "init", "-q", str(root)], check=True, env=env)
    (root / "db.py").write_text('def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = " + name)\n')
    home = tmp_path / "home"
    runs = [tools.run_polaris(root, ["db.py"], tmp_path / "raw" / f"run-{index}.sarif", home) for index in (1, 2)]
    assert all(run.document is not None and run.exit_code in (0, 1) for run in runs), [run.note for run in runs]
    documents = [run.document for run in runs if run.document is not None]
    found = core.parse_sarif(documents[0], tool="polaris")
    assert found and {item.path for item in found} == {"db.py"}
    assert core.check_determinism([core.results_digest(item) for item in documents],
                                  [run.sarif_sha256 for run in runs],
                                  [core.digest_without_report_id(item) for item in documents])["identical_results"] is True
    score = core.score_vulnerable(core.Revision(found, core.analysed_paths(documents[0]), {"db.py"}),
                                  [core.Weakness("db.py", 2)])
    assert score["outcome"] == "detected" and score["flagged_matching_label"] >= 1

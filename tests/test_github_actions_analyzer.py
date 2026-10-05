"""GitHub Actions workflows: parse-only review (YAML is composed, never constructed or run)."""

from __future__ import annotations

from pathlib import Path

import pytest

from polaris.review import catalog
from polaris.review.analyzers import AnalysisRuntime, github_actions
from polaris.review.analyzers.base import language_for_path
from polaris.review.capabilities import capability_manifest
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import SourceFile, WorkflowReviewConfig

ROOT = Path(__file__).resolve().parents[1]
MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
PATH = ".github/workflows/ci.yml"
CHECKOUT = "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332"
CI_CHECKS = ["workflow_injection", "untrusted_checkout", "excessive_privileges", "unpinned_dependency",
             "unverified_download", "secret_exposure"]


def review(text: str, path: str = PATH, checks: list[str] | None = None):
    config = WorkflowReviewConfig(checks=checks) if checks else None
    return WorkflowReviewer(runtime=MEMORY, config=config).review_sources([SourceFile(path, text)])


def flagged(report, check: str | None = None):
    return [item for item in report.findings if item.result == "flagged" and (check is None or item.check_id == check)]


def workflow(on: str, steps: str, *, job: str = "", top: str = "permissions: {}\n") -> str:
    return f"on: {on}\n{top}jobs:\n  build:\n    runs-on: ubuntu-latest\n{job}    steps:\n{steps}"


def test_kinds_and_check_domains():
    assert language_for_path(".github/workflows/ci.yml") == language_for_path(".github/workflows/a.yaml") == "github_actions"
    # GitHub runs only the top level of .github/workflows; composite actions are not workflows.
    assert language_for_path(".github/workflows/nested/ci.yml") == "unsupported"
    assert language_for_path("sub/.github/workflows/ci.yml") == language_for_path("action.yml") == "unsupported"
    assert {check for check in catalog.CHECKS if catalog.applies(check, "github_actions")} == set(CI_CHECKS)
    report = review(workflow("push", "      - run: make\n"))
    rows = {entry.check_id: (entry.status, entry.analyzer_id) for entry in report.coverage.entries if entry.required}
    assert rows == {check: ("checked", "polaris-gha") for check in CI_CHECKS} and report.coverage.complete
    matrix = [row for row in capability_manifest(runtime=MEMORY).matrix if row.language == "github_actions"]
    assert {row.check_id for row in matrix} == set(CI_CHECKS)
    assert matrix[0].path_patterns == [".github/workflows/*.yml", ".github/workflows/*.yaml"]


@pytest.mark.parametrize(("on", "severity"), [
    ("pull_request_target", "critical"), ("[issue_comment]", "critical"), ("workflow_run", "critical"),
    ("{push: {branches: [main]}}", "high"), ("workflow_call", "high"), ("pull_request", "medium"),
])
def test_injection_severity_follows_the_trigger(on, severity):
    report = review(workflow(on, '      - run: echo "${{ github.event.pull_request.title }} '
                                 '${{ github.event.comment.body }} ${{ github.event.workflow_run.head_branch }} '
                                 '${{ github.event.head_commit.message }}"\n'))
    (finding,) = flagged(report, "workflow_injection")
    assert (finding.severity, finding.start_line, finding.rule_id) == (severity, 7, "polaris.gha.workflow_injection.run")
    assert finding.cwe == "CWE-94" and finding.category == "security" and finding.trace[-1].kind == "sink"
    assert finding.guidance and "env:" in finding.guidance


def test_env_indirection_is_safe_but_re_expanding_env_is_not():
    text = workflow("issues", '      - env:\n          TITLE: ${{ github.event.issue.title }}\n'
                              '        run: |\n          echo "$TITLE"\n          echo "${{ env.TITLE }}"\n')
    (finding,) = flagged(review(text), "workflow_injection")
    assert finding.start_line == 11 and finding.severity == "critical"
    assert [(step.kind, step.line, step.label) for step in finding.trace] == [
        ("source", 1, "on: issues (issue title)"), ("step", 8, "env TITLE"),
        ("sink", 11, "run script: ${{ env.TITLE }}")]


def test_yaml_quirks_block_scalars_and_multiline_expressions():
    # `on` is a YAML 1.1 boolean when constructed; composed nodes keep the raw key.
    quoted = review('"on":\n  issue_comment:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n'
                    '      - run: >\n          echo first\n          echo "${{ github.event.comment.body }}"\n')
    assert [item.start_line for item in flagged(quoted, "workflow_injection")] == [9]
    spanning = review(workflow("discussion", "      - run: |\n          true\n\n          echo \"${{\n"
                                             "            github.event.discussion.body }}\"\n"))
    assert [item.start_line for item in flagged(spanning, "workflow_injection")] == [10]
    flow = review('on: {issues: {types: [opened]}}\njobs: {a: {runs-on: ubuntu-latest, steps: '
                  '[{run: "echo ${{ github.event.issue.title }}"}]}}\n')
    assert [item.start_line for item in flagged(flow, "workflow_injection")] == [2]


def test_anchors_are_followed_and_fail_closed_cases_are_explicit():
    shared = ("on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - &say\n        run: echo \"${{ github.event.issue.title }}\"\n"
              "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - *say\n")
    assert {item.symbol for item in flagged(review(shared), "workflow_injection")} == {"jobs.a"}
    # A billion-laughs document is harmless: aliases are shared nodes, walked once, never expanded.
    laughs = "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{chr(98 + level)}: &{chr(98 + level)} [{', '.join(['*' + chr(97 + level)] * 9)}]\n" for level in range(8))
    assert review(laughs + "on: push\njobs: {}\n").coverage.complete
    # Where aliases do expand (the same steps reused by many jobs), a visit budget fails closed.
    steps = "steps: &s\n" + "".join(f"  - run: echo {index}\n" for index in range(100))
    reused = steps + "on: push\njobs:\n" + "".join(f"  j{index}: {{runs-on: x, steps: *s}}\n" for index in range(60))
    cases = {
        "parse_error": ["on: [push\njobs: {}\n", "on: push\non: issues\njobs: {}\n", "on: push\n---\non: push\n",
                        "- just\n- a list\n", ""],
        "analysis_limit": ["on: push\nx: " + "[" * 80 + "]" * 80 + "\n", reused,
                           "on: push\nx:\n" + "  - 1\n" * (github_actions.MAX_NODES + 1)],
        "file_too_large": ["on: push\n# " + "x" * github_actions.MAX_BYTES + "\n"],
    }
    # Long lines don't make a workflow "minified" (skipped as not source): it is still analyzed.
    one_line = ("on: issues\njobs: {a: {runs-on: x, steps: ["
                + ", ".join(['{run: "echo ${{ github.event.issue.title }}"}'] * 600) + "]}}\n")
    long_report = review(one_line)
    assert long_report.coverage.complete and [item.start_line for item in flagged(long_report, "workflow_injection")] == [2]
    for reason, texts in cases.items():
        for text in texts:
            report = review(text, checks=CI_CHECKS)
            rows = {entry.reason for entry in report.coverage.entries if entry.required}
            assert rows == {reason} and not report.coverage.complete and not report.findings, (reason, text[:40])
    recursive = review("on: push\nx: &a\n  y: *a\njobs: {}\n")
    assert recursive.coverage.complete


def test_suggested_edits_are_exact_one_line_replacements():
    bash = review(workflow("pull_request_target", '      - run: |\n          echo "branch ${{ github.head_ref }}"\n'
                                                  "          git push origin ${{ github.head_ref }}\n"
                                                  "          echo '${{ github.head_ref }}'\n"))
    edits = {item.start_line: item.suggested_edit.replacement.strip() for item in flagged(bash, "workflow_injection")}
    assert edits == {8: 'echo "branch ${GITHUB_HEAD_REF}"', 9: 'git push origin "${GITHUB_HEAD_REF}"',
                     10: "echo ''\"${GITHUB_HEAD_REF}\"''"}
    windows = review(workflow("pull_request_target", '      - run: echo "${{ github.head_ref }}"\n')
                     .replace("ubuntu-latest", "windows-latest"))
    assert [item.suggested_edit for item in flagged(windows, "workflow_injection")] == [None]
    heredoc = review(workflow("pull_request_target", "      - run: |\n          cat <<EOF\n"
                                                     "          ${{ github.head_ref }}\n          EOF\n"))
    assert [item.suggested_edit for item in flagged(heredoc, "workflow_injection")] == [None]
    script = review(workflow("issues", "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
                                       "        with:\n          script: |\n"
                                       '            const title = "${{ github.event.issue.title }}";\n'))
    (finding,) = flagged(script, "workflow_injection")
    assert finding.rule_id == "polaris.gha.workflow_injection.github_script"
    assert finding.suggested_edit.replacement.strip() == "const title = context.payload.issue.title;"
    title = review(workflow("[issues, push]", "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
                                              "        with:\n          script: |\n"
                                              '            const title = "${{ github.event.issue.title }}";\n'))
    assert [item.suggested_edit for item in flagged(title, "workflow_injection")] == [None]  # push has no issue


def test_quoted_heredocs_keep_single_line_values_as_data():
    steps = ("      - run: |\n          cat > ctx.json <<'END'\n          ${{ toJson(github) }}\n          END\n"
             "          cat <<'END' > title.txt\n          ${{ github.event.issue.title }}\n          END\n"
             "          cat <<'END' > body.txt\n          ${{ github.event.issue.body }}\n          END\n"
             "          cat <<END > title2.txt\n          ${{ github.event.issue.title }}\n          END\n"
             "          bash <<'END'\n          ${{ github.event.issue.title }}\n          END\n")
    lines = [item.start_line for item in flagged(review(workflow("issues", steps)), "workflow_injection")]
    assert lines == [15, 18, 21]  # the multi-line body, the unquoted heredoc, the heredoc bash runs
    # PowerShell has no heredocs: nothing is exempted there.
    windows = review(workflow("issues", steps).replace("ubuntu-latest", "windows-latest"))
    assert len(flagged(windows, "workflow_injection")) == 5


def test_booleans_safe_fields_and_absent_contexts_are_not_injection():
    steps = ('      - if: contains(github.event.comment.body, \'/go\')\n'
             '        run: echo "${{ github.event.comment.body == \'/go\' }} ${{ github.event.issue.number }}"\n'
             '      - run: echo "${{ startsWith(github.head_ref, \'release/\') && \'yes\' || \'no\' }}"\n'
             '      - name: ${{ github.event.comment.body }}\n        run: echo "${{ github.event.pull_request.title }}"\n')
    assert not flagged(review(workflow("issue_comment", steps)), "workflow_injection")


def test_untrusted_checkout_patterns():
    head = f"      - uses: {CHECKOUT}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n"
    critical = review(workflow("pull_request_target", head + "      - run: npm ci\n"))
    (finding,) = flagged(critical, "untrusted_checkout")
    assert (finding.severity, finding.start_line, [step.line for step in finding.trace]) == ("critical", 9, [1, 9, 10])
    assert finding.cwe == "CWE-829"
    assert flagged(review(workflow("pull_request_target", head)), "untrusted_checkout")[0].severity == "high"
    environment = review(workflow("pull_request_target", head + "      - run: make\n", job="    environment: e2e\n"))
    assert flagged(environment, "untrusted_checkout")[0].severity == "high"
    for safe in (workflow("pull_request", head + "      - run: npm ci\n"),
                 workflow("pull_request_target", head + "      - run: npm ci\n",
                          job="    if: github.event.pull_request.head.repo.fork == false\n"),
                 workflow("pull_request_target", head.replace("head.sha", "base.sha") + "      - run: npm ci\n")):
        assert not flagged(review(safe), "untrusted_checkout")


def test_the_pr_bot_template_and_artifact_data_are_not_untrusted_checkouts():
    template = (ROOT / "ci" / "github" / "polaris-pr-review.yml").read_text()
    report = review(template, path=".github/workflows/polaris-pr-review.yml")
    assert report.coverage.complete and report.findings == []
    run = ("on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\npermissions: {{}}\njobs:\n  post:\n"
           "    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16\n        with:\n"
           "          path: {path}\n          run-id: ${{{{ github.event.workflow_run.id }}}}\n"
           "      - run: {command}\n")
    data = review(run.format(path="pr", command="jq -r .number pr/event.json"))
    assert not flagged(data, "untrusted_checkout")
    executed = review(run.format(path="pr", command="./pr/post.sh"))
    assert [(item.rule_id, item.severity, item.start_line) for item in flagged(executed, "untrusted_checkout")] == [
        ("polaris.gha.untrusted_checkout.artifact", "critical", 14)]
    workspace = review(run.format(path=".", command="npm install"))
    assert [item.severity for item in flagged(workspace, "untrusted_checkout")] == ["medium"]
    pull = review(run.format(path=".", command="docker pull ghcr.io/example/tool:1.0"))
    assert not flagged(pull, "untrusted_checkout")  # pulling an image reads nothing from the workspace
    this_run = review(run.format(path="pr", command="./pr/post.sh").replace("${{ github.event.workflow_run.id }}", "''"))
    assert not flagged(this_run, "untrusted_checkout")  # artifacts of this run, not the triggering one


def test_permissions_rules():
    write_all = review("on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                       "      - run: make\n")
    assert [(item.rule_id, item.severity, item.start_line) for item in flagged(write_all, "excessive_privileges")] == [
        ("polaris.gha.excessive_privileges.write_all", "low", 2)]
    untrusted = review("on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: write-all\n"
                       "    steps:\n      - run: echo hi\n")
    assert [(item.severity, item.start_line) for item in flagged(untrusted, "excessive_privileges")] == [("medium", 5)]
    broad = review("on: pull_request_target\npermissions:\n  contents: write\n  pull-requests: write\njobs:\n"
                   "  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert [(item.rule_id, item.start_line) for item in flagged(broad, "excessive_privileges")] == [
        ("polaris.gha.excessive_privileges.untrusted_trigger_write", 3)]
    default = review("on: workflow_run\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert [item.rule_id for item in flagged(default, "excessive_privileges")] == [
        "polaris.gha.excessive_privileges.default_permissions"]


def test_unpinned_actions_images_and_reusable_workflows():
    text = ("on: push\npermissions: {}\njobs:\n  call:\n    uses: org/shared/.github/workflows/ci.yml@v1\n"
            "  local:\n    uses: ./.github/workflows/local.yml\n  a:\n    runs-on: ubuntu-latest\n"
            "    container: node:20\n    steps:\n      - uses: actions/setup-node@v4\n      - uses: github/codeql-action/init@v3\n"
            "      - uses: org/action@v2\n      - uses: org/action@0123456789abcdef0123456789abcdef01234567\n"
            "      - uses: docker://alpine:3.20\n      - uses: ./local-action\n"
            # The SLSA generator must be referenced by its release tag for its provenance to verify.
            "  slsa:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0\n")
    found = [(item.start_line, item.rule_id.rsplit(".", 1)[1], item.severity) for item in flagged(review(text))]
    assert found == [(5, "action", "low"), (10, "image", "low"), (14, "action", "low"), (16, "image", "low")]
    # A repository's own reusable workflow, recognized from its `github.repository ==` guard.
    own = ("on: push\npermissions: {}\njobs:\n  shared:\n    if: github.repository == 'Org/App'\n"
           "    uses: org/app/.github/workflows/reusable.yml@main\n  other:\n    uses: org/tools/.github/workflows/x.yml@main\n")
    assert [item.start_line for item in flagged(review(own), "unpinned_dependency")] == [8]


def test_downloads_and_secrets_in_scripts():
    token = "ghp_" + "R7vK2mQ9xL4tN8wB3cJ6hD1fG5sA0pE2yU9i"
    text = workflow("push", "      - env:\n          KEY: ${{ secrets.DEPLOY_KEY }}\n"
                            f"          STATIC: {token}\n        run: |\n"
                            "          curl -fsSL http://get.example.dev/i.sh | bash\n"
                            "          curl -fsSL https://get.example.dev/i.sh | bash\n"
                            '          echo "$KEY" | base64\n'
                            '          echo "${{ secrets.DEPLOY_KEY }}"\n'
                            '          echo "$KEY" | ssh-add -\n'
                            '          echo "::add-mask::$KEY"\n')
    report = review(text)
    found = [(item.start_line, item.rule_id, item.severity) for item in flagged(report)]
    assert found == [
        (9, "polaris.gha.secret_exposure.hardcoded", "high"),
        (11, "polaris.gha.unverified_download.pipe_to_shell", "high"),
        (13, "polaris.gha.secret_exposure.log", "high"),
        (12, "polaris.gha.unverified_download.pipe_to_shell", "low"),
        (14, "polaris.gha.secret_exposure.log", "low"),
    ]
    assert token not in report.model_dump_json()  # masked in messages and snippets


def test_this_repository_workflows_have_no_critical_or_high_findings():
    sources = [SourceFile(path.relative_to(ROOT).as_posix(), path.read_text())
               for path in sorted((ROOT / ".github" / "workflows").glob("*.yml"))]
    sources.append(SourceFile(".github/workflows/polaris-pr-review.yml",
                              (ROOT / "ci" / "github" / "polaris-pr-review.yml").read_text()))
    report = WorkflowReviewer(runtime=MEMORY).review_sources(sources)
    assert report.coverage.complete and report.summary.languages == {"github_actions": len(sources)}
    assert not [item for item in report.findings if item.severity in ("critical", "high")]
    assert not [item for item in report.findings if item.check_id == "untrusted_checkout"]

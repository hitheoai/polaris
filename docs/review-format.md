# Polaris review format

There are separate versioned contracts. The workflow does not silently change the legacy
Python review or experimental classifier:

- `polaris.check/1`: the plain-language result of `polaris check --json`, the MCP
  `polaris_check` tool and the agent hooks, built from a workflow review. It is what agents
  should read; see [polaris check](check.md#for-ai-agents-the-json-result).
- `polaris.workflow/0.1.0`: the CLI/HTTP workflow envelope, with a nested
  `polaris.review/0.2.0` static report.
- `polaris.workflow-summary/0.1.0` and `polaris.workflow-details/0.1.0`: bounded MCP summary
  and historical detail pages.
- `polaris.capabilities/0.2.0`: actual analyzer identities, availability and language/check matrix.
- `polaris.review/0.1.0`: legacy `polaris review`, `polaris scan`, `/v1/review`,
  `review_changes` / `review_code`, and the existing GitHub/GitLab integrations.
- `polaris.assessment/0.1.0`: the separate experimental assessment/model contract.

Expanded static support does not qualify the classifier, and it is not a measure of security
or repair accuracy.

## Agent-native workflow

`polaris workflow review` reviews uncommitted changes by default. Choose one of `--staged`,
`--diff RANGE`, or `--files PATH ...` instead. `--root` chooses a bounded Git worktree.
`--checks`, repeated `--include` / `--exclude`, `--guard-policy`, `--semgrep` and
`--no-external-analyzers` explicitly configure this review. `.polaris.toml` `[workflow]`
sets `auth_guards`, `public_routes`, `exclude` and `honor_suppressions` (range reviews read
it from the base revision, so a change can't loosen its own review); legacy `[review]` policy
prose is not promoted to workflow authority.

Whole available file contents are analyzed, not just added lines. Findings can predate the
change; the report is not a claim that each finding was newly introduced. Related imports,
test candidates and project manifests are bounded context, not whole-program data flow or
evidence that tests ran. Unsupported files, deletions, renames, unavailable baselines,
scope exclusions and exhausted limits must remain visible.

The sixteen default checks are `sql_injection`, `command_injection`, `code_injection`, `xss`,
`ssrf`, `open_redirect`, `path_traversal`, `secret_exposure`, `missing_authorization`,
`insecure_auth_crypto` and `unsafe_security_configuration`, run by the built-in
TypeScript/JavaScript, Python and Rust engines, plus `workflow_injection` and
`untrusted_checkout` (workflows only), `excessive_privileges`, `unpinned_dependency` and
`unverified_download`, run with `secret_exposure` by the built-in GitHub Actions workflow and
Dockerfile engines. `api_authorization` needs caller-trusted guard
requirements and before/after evidence; it only detects supported direct guard-call removal.
Retaining a call proves nothing about actual identity, tenancy or authorization behavior.
Absent guard policy is advisory/not checked unless the check was explicitly requested.
See [analyzers](analyzers.md) for exact syntax, source/sink and sandbox limitations.

### Envelope, coverage and freshness

`WorkflowEnvelope` includes `report_id`, `status`, `summary`, `finding_count`, `snapshot`,
`changes`, `context`, `review`, `tests_status` and `notices`.

- `status` is `complete`, `incomplete`, `stale` or `error`. Complete coverage can still
  contain flagged findings; status is not a security verdict.
- `finding_count` counts only `flagged` findings. Inspect all `review.findings`.
- `review.coverage.entries` contains a row per file/check, with `checked`, `not_checked`
  or `partial`, its reason, analyzer and `required` flag. `coverage.complete` requires
  completed required rows without scope omissions; an empty finding list is insufficient.
- `review.capabilities` reports actual analyzer availability and rule-pack provenance.
  `review.provenance` binds source/baseline, check, policy and capability digests.
- `snapshot` binds the selected review to content/configuration and discloses omitted scope.
  Local kinds are `worktree`, `git_index` and `git_revision`; submitted API content uses
  `submitted_content`, with `fresh=null`, because a server cannot attest a client's worktree.
- `tests_status` is always `not_run`.

Workflow findings extend legacy finding fields with `analyzer_id`, `analyzer_version`,
`rule_id` and `evidence_digest`. Static findings carry fixed explanations and hashes rather
than raw analyzer messages or source excerpts; they do not manufacture calibrated model risk.
Availability and a checked row mean the bounded analysis ran, not that the source is secure.

Freshness binds repository/worktree identity, HEAD/index, tracked and non-ignored untracked
content, known root configuration, actual check/policy/runtime settings and the configured
Semgrep launcher's bytes. Installed dependencies, ignored nested/generated content,
external environment and network state are outside the declared snapshot. Bounds and
omissions are explicit. Re-review after relevant edits; hashes and local receipts are not
signatures or trusted CI attestations. See [freshness details](ide.md#content-bound-freshness).

The default MCP tool for agents is `polaris_check` ([polaris check](check.md)). The advanced
MCP tools below are listed with `polaris mcp --advanced-tools` and stay callable by name.
MCP `review_workflow` returns at most 12 finding summaries by default and a `report_id`.
`review_details(report_id, offset=0, limit=25)` retrieves at most 50 findings per page from
the bounded in-memory cache. Findings and coverage have separate next offsets; follow both
when reading details. Evicted reports require re-review. Historical details never establish
current freshness. Neither tool applies changes or authorizes action.

### Results imported from other tools (SARIF)

`workflow review --import-sarif PATH` (repeatable, up to 16) adds results from other tools'
SARIF 2.1.0 files. Polaris never runs those tools and treats each file as untrusted input. The
nested report carries them separately from Polaris's own results:

- `review.imported`: at most 5,000 results inside the reviewed scope, each with `tool`,
  `tool_version`, `rule_id`, the tool's `level`, `severity` (from `security-severity` when
  the tool gave one, otherwise the level: `error` is medium, `warning` low, `note` info),
  `security_severity`, `category`, repository `path` and lines, `message`, `cwe`,
  `related_check`, `fingerprint`, `sarif_digest`, `corroborates` (the id of a Polaris
  finding at the same place that reports the same weakness) and `verified_by_polaris: false`.
- `review.imports`: one record per file with its digest, `imported` or `rejected` and a fixed
  error code, the tools it named, runs, runs without results or with an unsuccessful
  execution (`failed_runs`), and how many results were imported, corroborate Polaris findings
  or were left out, by reason (`duplicate`, `outside_review_scope`, `outside_repository`,
  `unmapped_path`, `invalid_path`, `no_location`, `suppressed_by_tool`, `not_a_problem`,
  `reserved_tool_name`, `result_limit`, `imported_limit`, `invalid_result`).
- `review.provenance.imported_digests` binds the files' content (never their location) into
  the report. Files are processed in content order, so the same files give the same result in
  any order.

Imported results never change `review.findings`, coverage, summary counts, suppressions,
baselines or exit codes. `--fail-on-imported error|warning|note` opts in. Exit code 1 then
means an imported result is at that level or above. Exit code 2 means a file was rejected,
a tool did not finish, or results went past a limit, so the opt-in gate could not decide. The
text report lists imported results under "Other tools", grouped by tool, and adds "Also reported
by" lines to Polaris findings. SARIF output adds one run per tool, marked
`importedBy: Polaris` and `verifiedByPolaris: false`. If you also upload that tool's own
SARIF to GitHub code scanning, upload only one of the two, or its alerts appear twice. Code
Quality output adds issues described as imported. For pull requests see
[results from your own tools](pr-bot.md#results-from-your-own-tools-sarif).

### Output and gate semantics

`workflow review --format text|json|sarif|codequality` presents the same workflow result.
Keep JSON when full coverage/provenance is needed. `--output` creates a new private file,
never overwrites one and refuses user-created symbolic links in its path (root-owned system
links such as macOS `/tmp` are followed); a failure is reported as `output_unwritable`.
Store outputs outside the worktree being bound.

Use `--require-complete` for required review. Exit 2 covers stale/error review; otherwise
flagged findings return 1, and required incomplete coverage or other unresolved non-OK
results return 2. Exit 0 is only a successful declared gate, never permission. Without
`--require-complete`, incompleteness alone need not produce a nonzero exit code, although
input/runtime errors still fail. This envelope behavior is distinct from the nested static
report's own strict `exit_code()` helper and from legacy `--fail-on`.
See [trusted required CI](ci.md#required-development-workflow-review).

### Proposal, apply, verify and action records

`workflow propose --input candidate.json` / MCP `propose_repair` / HTTP
`/v1/workflow/propose` validate a supplied candidate against freshly observed finding
references. `CandidateRequest` contains one to eight `edits`, `rationale`, optional
`verification_commands` and optional `expected_snapshot_digest`. Each edit supplies
`path`, exact `before_sha256`, complete `replacement` and observed `finding_refs`.
The service derives the diff; it does not invoke a coding model or write source.

`polaris.proposal/0.1.0` binds the repair snapshot, context, candidate, origin and proposed
commands in `proposal_digest`. Proposal JSON includes source/diff and is not a source-free
receipt. Repository/model instructions cannot authenticate policy, finding references or
consent. See [bounded engineering](engineering.md) for separate snapshot, approval,
application, verification, action and optional generation schemas.

Only local CLI/SDK application can replace existing source:
`workflow apply --proposal PATH --approve-proposal DIGEST` requires actual human approval
of that exact immutable proposal and fresh context. It is bounded to existing UTF-8 files,
not create/delete/rename, and is not a multi-file transaction.
`workflow verify --proposal PATH --expected-proposal DIGEST` checks exact post-edit
content and re-runs configured static analysis. Inspect `static_review.status`, original
finding statuses and `additional_findings`; `verified_snapshot` alone is not a clean review.
`no_longer_detected` is not behavioral correctness. `behavioral_tests` remains `not_run`;
there is no runner for the proposed commands. An approved isolated fixture runner is separate.

`workflow action --input action.json [--policy trusted-policy.json]` compares typed
process/filesystem/network proposals with a separate user/application policy.
Results are `within_declared_scope`, `out_of_scope` or `needs_review`, always with
`authorized=false`, `executed=false`, `policy_changed=false`, `scope_only=true`.
HTTP/MCP do not accept policy in tool requests and expose no apply/exec operation.

Inspect canonical schemas with `polaris workflow schema workflow`, `review`, `capabilities`,
`candidate`, `proposal`, `verification`, `action_request` or `action_review`.
CLI failures use a bounded `polaris.workflow-error/0.1.0` envelope, not a source-bearing
exception dump. The optional SDK generation gateway is disabled by default and distinct
from the host-candidate workflow and Preview classifier.

### Caller-recorded workflow experiments

`workflow benchmark --input measurements.json` accepts the schema printed by
`workflow schema benchmark` and returns `polaris.workflow-benchmark/0.1.0`.
Every task needs paired `editor_baseline` and `editor_with_polaris` measurements bound to
one predeclared experiment digest and disjoint declared training/evaluation repositories.
Attempts, retries, failed tasks, elapsed time, human review, false positives/negatives,
regressions, token counts and cost are accounted for; missing measurements remain `null`.

Verified completion requires caller-supplied independent review, completion, a correct
patch when required, passed behavioral tests and zero regressions. The aggregator does not
run or authenticate those activities. Acceptance is `met`, `not_met` or
`insufficient_evidence`; `security_qualified` is always false. It supplies no measured
speed, accuracy or cost advantage by itself.

## Legacy Python review

The remaining sections describe `polaris.review/0.1.0`, not the broader workflow.
Legacy training examples share the input-building pipeline. Changes to its versioned
model input/static notes require compatible model preprocessing and retraining; this does
not make unrelated workflow schema additions into trained-model capabilities.

## Pipeline

```
files / git diff ──► units ──► prefilter ──► static notes ──┬──► rules ───────────────────────────────────────┐
                                   │                              └──► request ──► model (batched) ──┤
                                   │                                                                     ▼
                                   └─ no SQL/process calls: "ok" instantly          findings (engine: hybrid / rules / model)
```

- `hybrid` (default): the rules decide each result; the model's view is attached as
  `second_opinion` and never changes the result, the counts or the exit code. Without an
  installed model, hybrid reviews run the rules alone and say so.
- `model`: the model decides alone (exit code 3 if no model is installed).
- `rules`: static rules only.

Code is parsed into syntax trees, never imported or executed. A local model/rules review
stays local; an explicitly configured [hosted classifier](remote.md) receives candidate
functions, prior versions, labels, static notes and policy context. The hosted path is
not a blanket no-upload guarantee.

## Units

- Every top-level function and method (including methods of nested classes and definitions
  under `if`/`try` guards). Decorators are included because they carry context (for example a
  web route). Nested functions stay inside their parent.
- `<module>`: top-level statements that contain calls (scripts often do their work there).
- For diffs, only units that overlap changed lines are reviewed. When the previous version of
  a unit exists and differs, it is supplied as `code_before`.
- Files that fail to parse are skipped and counted (`parse_error`), never guessed at.

## Prefilter

A unit is only sent to the model if it contains a candidate call:

- SQL: `.execute`, `.executemany`, `.executescript`, `.mogrify`, `.raw`, `.read_sql`,
  `.read_sql_query`, `.exec_driver_sql`, `.execute_sql`, Django `.extra(where=...)`,
  `.query(<string>)`, asyncpg `.fetch/.fetchrow/.fetchval(<string that reads as SQL>)`,
  SQLAlchemy `text(...)`.
- Processes: `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `subprocess.run/call/
  check_call/check_output/Popen/getoutput/getstatusoutput`, `asyncio.create_subprocess_*`,
  `pty.spawn`. Import aliases are resolved (`import subprocess as sp`, `from os import system`).

Units without candidates count as `ok` with reason `no_candidate_calls` and engine `static`.
Checks are only requested for the call families present in a unit.

## Static notes (versioned: `polaris-static-notes/0.1.0`)

Facts, never verdicts: where values come from, how arguments are built, whether a shell is used.
A single forward pass means a later reassignment never changes what an earlier call received.
Function parameters, request data (`request.args`, `request.GET`, ...), `input()`, `sys.argv`,
environment variables and file/network reads are untrusted under the default policy.
`int`, `float`, `bool`, `len`, `abs`, `round`, `shlex.quote`, `pipes.quote` and `uuid.UUID`
are recorded as sanitizing. Example:

```
Static notes from polaris-static-notes/0.1.0 (machine-generated; may be incomplete).
Untrusted sources: request data (flask.request.args) (line 31).
Calls of interest:
- line 32 db.execute: SQL execution. Query: concatenation using term (untrusted). Separate parameters: no.
```

## Request (versioned: `polaris.review-input/0.1.0`)

Each candidate unit becomes one `polaris.assessment/0.1.0` request:

- `evidence`: `before` (`code_before`, only when changed), `after` (`code_after`, with
  `location.path` and `start_line`), and `flow` (`data_flow`, the static notes).
- `trusted_context`: one `scope` item holding the repository policy statements
  (default: parameters, request data, arguments, environment, file and network contents are untrusted).
- `requested_checks`: `sql_injection` and/or `command_injection`, depending on the calls present.
- The model input (`snapshot-json/0.2.0`) excludes integrity digests, which carry no meaning.
  Units above the 2,048-token limit are reported as `too_large`, never truncated.

## Results

| Result | Meaning |
|---|---|
| `flagged` | Assessed, and estimated risk ≥ the flag threshold (the tuned `evaluation_risk_threshold`, or `flag_threshold` from settings). |
| `ok` | Assessed below the threshold, or no relevant calls (`no_candidate_calls`). Not a safety guarantee. |
| `needs_context` | The model (or rules) can't judge from this function alone, for example the value comes from elsewhere. |
| `uncertain` | Enough context, but the model isn't confident. Take a closer look. |
| `unsupported` | The check isn't supported by the loaded model. |
| `too_large` | Over the token limit. Review manually or split the function. |
| `error` | No assessment was produced; the finding says why. |

Findings include file, line range, symbol, check, estimated risk and threshold (when assessed),
a plain message, fixed per-check guidance, and the relevant static facts as `details`.
The legacy classifier does not write explanations or generate patches. In an IDE, the editor's
AI can explain findings and propose fixes within the user's scope and normal approvals.

## Report (`polaris.review/0.1.0`)

`ReviewReport` JSON: `format`, `model` (engine, version, release status, runtime), `checks`,
`policy_source`, `summary` (files reviewed/skipped by reason, units total/assessed/prefiltered,
results by count, cache hits, elapsed time, units per second, and in hybrid reviews
`second_opinion_disagreements`), `findings` (non-`ok` unless `report_ok`; hybrid reviews also
keep `ok` results that the model flags), and `notices` (for example that a Preview model gave
the second opinion).

In hybrid reviews each finding may carry `second_opinion`: `{"result", "risk", "reason"}` from
the model. The text output shows it as "Model second opinion: ..." and lists rule-OK functions
the model flags under "Second opinion only"; SARIF reports those as `note` results.

SARIF 2.1.0 maps `flagged` to `error`, `needs_context`/`uncertain` to `warning`, and the rest to
`note`, with stable `partialFingerprints` so code-scanning alerts track the same function.

Exit codes: `0` no finding in `--fail-on` (default `flagged`), `1` otherwise, `2` input,
settings or git problems, `3` model unavailable (`--engine model` only; see `--no-model`).
`--format codequality` writes a GitLab Code Quality report.

## Settings

`.polaris.toml` (or `[tool.polaris.review]` in `pyproject.toml`):

```toml
[review]
checks = ["sql_injection", "command_injection"]
policy = ["Request handlers receive untrusted HTTP input.", "Admin scripts run with trusted arguments."]
flag_threshold = 0.8
exclude = ["scripts/legacy/**"]   # added to the defaults (migrations, generated protobuf, vendor)
```

Policy statements are trusted context: only repository owners should write them. Scans never
descend into `.git`, virtual environments, `node_modules`, `site-packages`, build outputs,
caches or hidden folders.

## Cache

`.polaris-cache/review.sqlite` (with its own `.gitignore`) stores assessment envelopes keyed by
the full request plus the exact model, calibration and operating-profile identity. Unchanged
functions under the same model are never assessed twice. Delete the folder at any time.

## Python API (for integrations)

```python
from polaris.review import Reviewer, load_backend, load_config, to_sarif, to_text
from polaris.review.git import sources_from_git

config, _ = load_config(repo_root)                    # repository settings (or defaults)
reviewer = Reviewer(load_backend(), config=config, engine="hybrid")   # or engine="model" / Reviewer(engine="rules")
report = reviewer.review_sources(sources_from_git(repo_root))   # uncommitted changes
report = reviewer.review_diff(diff_text)              # a unified diff (hunks only without a root)
report = reviewer.review_snippet(code, path="app/db.py")
report = reviewer.review_paths([repo_root], root=repo_root)     # whole codebase
```

`Reviewer` is safe to reuse across requests; model loading is the slow part, so long-lived
processes (API server, MCP server) should load once. Inference inside one backend is serialized.

## Legacy limitations

Python only. Two default checks. Analysis stays inside one function: a caller passing untrusted data to
a wrapper is not traced. Static notes may be incomplete. Findings are estimates for review, not
authorization or proof of safety.

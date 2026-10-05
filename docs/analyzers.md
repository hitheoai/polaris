# Static workflow analyzers

`polaris.review.engine.WorkflowReviewer` provides the broader static workflow as
`polaris.review/0.2.0`. It does not load a classifier, download weights, invoke a
coding model, install an analyzer, or execute the source being reviewed. The
legacy `Reviewer`, `ReviewConfig`, `polaris.review/0.1.0`, and experimental
assessment/model contracts keep their existing Python/two-default-check domain.

## Entry points

Construct `WorkflowReviewer(*, config=None, runtime=None, guard_policy=None)` and
call `review_sources`, `review_snippet`, `review_paths`, or `review_diff`.
`SourceFile` carries an exact relative path, complete after/before text when
available, changed lines, optional previous path, and explicit skip/context
metadata. Complete supplied files are scanned; a finding is not necessarily
newly introduced on a changed line.

`WorkflowReviewConfig` defaults to sixteen checks: the eleven code checks `sql_injection`,
`command_injection`, `code_injection`, `xss`, `ssrf`, `open_redirect`, `path_traversal`,
`secret_exposure`, `missing_authorization`, `insecure_auth_crypto` and
`unsafe_security_configuration`, and the CI-workflow and container checks
`workflow_injection`, `untrusted_checkout`, `excessive_privileges`, `unpinned_dependency` and
`unverified_download` (`secret_exposure` applies to all three). Its default limits are 2,000
files, 1,000,000 bytes per file, 64,000,000 source bytes, 50,000 Python units, and 1,000
findings; the local CLI raises the file/byte limits for
`--files`, `baseline` and diff reviews. An exhausted limit is incomplete coverage, not a
successful review of omitted input. Documentation, assets and configuration are
`not_applicable` and never make a review incomplete; so are generated or minified files
(by name, or by a bounded sample of an oversized file). Other oversized source stays
visible, unreviewed scope. `.polaris.toml` `[workflow].exclude` globs are listed as
`excluded` rows (not required).

`polaris.review.scope.workflow_sources_from_paths` confines reads to the supplied
root using no-follow directory/file descriptors. Unsupported extensions are
listed without reading their bodies. Symlinks, excluded/pruned paths, missing
files, invalid UTF-8, oversized input, and truncated discovery remain visible.
The Git collector includes changed unsupported files, deletions, and renames;
it disables configured helpers, external diffs, text conversion, filters,
credential helpers, hooks, and network transports. It does not run project code.

## Built-in engines

**TypeScript/JavaScript** (`polaris-ts`, bundled tree-sitter grammars, in process):
function-level data flow with summaries across reviewed and related files (imports
resolved through `tsconfig` paths, importers found by bounded search). Entry points are
Next.js route handlers, pages, middleware and server actions, `pages/api`,
Express/Hono/Fastify registrations and client URL APIs. Large reviews are analyzed in
batches so memory stays bounded; see [parallel analysis](#parallel-analysis). Recognized
validation includes allowlist/prefix/equality
checks with early exits, known sanitizers, constrained zod/valibot schemas, a fixed URL
origin (also when a caller passes it into a fetch wrapper) and calls to SSRF guards named
like `checkFetchUrlSafe`, `isPrivateHostname`, `isDnsResolvedPublic`. Authentication
includes common guard names, configured `auth_guards`, secret comparisons against secret
environment values (also through variables), webhook signature verifiers and OAuth state
consumers. An unauthenticated write in a rate-limited handler is reported as a question
(likely public by design), as are credential-shaped values in test files. Records looked
up by a request id are not treated as the request value.

**Python** (`polaris-python`, `ast`): SQL/command injection (including argument
injection), plus SSRF, open redirect, template XSS, path traversal, secrets, auth and
configuration checks for Flask/FastAPI/Django-style code. HTTP calls include methods of
httpx/requests/aiohttp client objects; pathlib reads and writes are reported when request
input reaches the path in the same function. `secure_filename`/`safe_join`, allowlists and a
`startswith`/`is_relative_to`/`commonpath` check on a `resolve()`d or `realpath` path count as
validation (on an unresolved path these checks are lexical, so `..` passes them); `abort()`
ends a request like `raise`.

**Rust** (`polaris-rust`, tree-sitter): `#[tauri::command]` arguments, generic
axum/actix extractors (`Path<_>`, `Query<_>`, `Json<_>`, `Form<_>`, also destructured as
`Query(params)`) and `std::env::args` reaching `Command::new`, `format!` SQL, filesystem
paths, outbound HTTP, output macros and disabled TLS checks. A plain `std::path::Path`
parameter is not input.

**GitHub Actions workflows** (`polaris-gha`, in process): the files GitHub runs,
`.github/workflows/*.yml` and `*.yaml` at the repository root. The YAML is composed into nodes
with a bounded `SafeLoader` (nesting, node and alias-expansion budgets) and never constructed,
so keys are read as written (an unquoted `on:` stays `on`). Invalid YAML, duplicate keys and
several documents are `parse_error`, never clean. Shell in `run:` steps is tokenized for
commands, pipes, redirections and heredocs, never executed. Severity follows the trigger: an
outsider controls the data of `pull_request_target`, `issues`, `issue_comment`, `discussion`,
`discussion_comment`, `commit_comment`, `gollum` and `workflow_run` runs, which get the
repository's secrets and a token that may write; `push` runs see commit text that arrives through
merged pull requests; `pull_request` runs from forks get a read-only token and no secrets.
`if: github.event_name == '…'` conditions narrow the triggers a job sees.

* `workflow_injection`: untrusted event fields (issue, pull request and discussion titles and
  bodies, comment and review bodies, pull request branch names, commit messages and authors, the
  triggering run's branch and title, wiki page names) expanded by `${{ }}` into a `run:` script
  or an `actions/github-script` script, also through `${{ env.NAME }}`. Expressions are parsed:
  `format`, `join` and `toJSON` carry the value, comparisons and `contains`/`startsWith` yield
  booleans, and a field the workflow's triggers never supply is empty. Critical under the
  privileged triggers, high under `push` and `workflow_call` (unknown caller), medium under
  `pull_request`. Passing the value through `env:` and quoting `"$NAME"` is never reported, nor is
  a value without newlines (a title, a branch name, `toJSON` output) inside a quoted heredoc that
  is only data.
* `untrusted_checkout`: a `pull_request_target`, `workflow_run` or `issue_comment` job that checks
  out the pull request head (`actions/checkout` `ref`/`repository`, `gh pr checkout`, `git
  checkout`/`switch`/`reset` of a fetched pull ref): critical when a later step builds or runs
  workspace code, high otherwise, one level lower behind a label or environment gate; same-
  repository, author-association, merged and push-only guards suppress it. Fetching the change
  as data only (`git fetch`, as `ci/github/polaris-pr-review.yml` does) is not a checkout.
  A `workflow_run` job that runs files from the triggering run's artifacts is critical; one that
  extracts such an artifact over the workspace before build tools run is medium. Reading
  artifacts as data is not reported.
* `excessive_privileges`: `permissions: write-all` (medium on the privileged triggers, low
  otherwise), `contents`, `actions`, `packages`, `deployments`, `id-token`, `pages` or
  `attestations` writes on the privileged triggers, and privileged-trigger workflows without a
  `permissions` block (low).
* `unpinned_dependency`: third-party actions and reusable workflows not pinned to a full commit
  SHA, and `docker://` steps and job containers not pinned by digest (low). GitHub-owned
  `actions/*` and `github/*`, local references, the repository's own workflows (recognized from
  `github.repository == 'owner/name'` guards) and the SLSA generator's release tags (its
  provenance check needs the tag) are not reported.
* `unverified_download`: downloads piped or substituted into an interpreter (`curl … | sh`,
  `sh -c "$(curl …)"`, `bash <(curl …)`, PowerShell `iwr … | iex`), high over plain HTTP and low
  over HTTPS; loopback servers are not reported.
* `secret_exposure`: credential formats and long random literals under secret-named keys (always
  masked in messages and snippets), and secrets printed to the job log: low when GitHub's
  exact-value masking applies, high when the value is transformed (`base64`, `rev`, …) first.
  Output piped to another program, redirected, captured or passed to `::add-mask::` is not
  printed.

Suggested edits are offered only where they are exact: `${{ github.head_ref }}` in a bash `run:`
script becomes `${GITHUB_HEAD_REF}`, quoted for its position, and `"${{ github.event.… }}"` in
`actions/github-script` becomes `context.payload.…` when every trigger supplies the field.
Composite actions (`action.yml`) and workflows called from other repositories are not analyzed.

**Dockerfiles** (`polaris-dockerfile`, in process): `Dockerfile`, `Containerfile`,
`**/Dockerfile.*`, `**/Containerfile.*` and `*.dockerfile`, read as text: parser directives
(`# escape=` backslash or backtick), line continuations with comment lines inside them, heredocs
(unterminated is `parse_error`), multi-stage builds and `FROM <stage>`. Nothing is built or pulled.

* `unverified_download`: `RUN` downloads piped or substituted into an interpreter (shell and exec
  form, heredoc scripts, `ONBUILD`), high over plain HTTP and low over HTTPS, and remote `ADD`
  without `--checksum` (medium over HTTP, low over HTTPS; Git sources are not reported).
* `secret_exposure`: credential formats anywhere in the file (masked), long random literals in
  secret-named `ENV`/`ARG` (medium), secret-named build arguments (medium when their history ships
  in the final image, low in builder stages) and `ENV` copying a build value into a secret-named
  variable (high in the final image, low in builder stages).
* `excessive_privileges`: the final stage's last `USER` is root, or it never sets one and its base
  is known to run as root (operating-system and language images, root distroless images, scratch
  with an entrypoint), low. Images that set their own user, users or images chosen by `ARG`, dev
  containers and files that install a privilege-drop tool (gosu, su-exec, setpriv) are not
  reported.
* `unpinned_dependency`: `FROM` and `COPY --from` images without a digest (low). Stage
  references, `scratch`, `ARG`-parameterized and template images are skipped, never guessed.

Both analyzers fail closed: oversized files, exhausted budgets and parse errors are explicit
coverage gaps (`file_too_large`, `analysis_limit`, `parse_error`), and a long-line workflow or
Dockerfile is never skipped as minified.

The engines report `needs_context` ("to verify") when the answer depends on code or intent
they can't see, with the question to answer. They are not whole-program analysis: unresolved
packages, dynamic dispatch and framework conventions outside the list above can hide flows.

### Parallel analysis

A TypeScript/JavaScript review of 80 or more files is split into up to eight batches by its
size alone. `AnalysisRuntime(parallel_workers=N)` (default 0) analyzes those batches in up to
N spawned worker processes. The local CLI and MCP server set N from the CPU count (at most 8);
the HTTP server and plain library use stay in-process. Because the split never depends on the
machine, findings, coverage and review digests are identical with or without workers, and the
worker count is not part of a review's or approval's identity. If worker processes can't be
used (for example in a frozen executable), the same batches run in-process. An embedding
application that opts in needs the usual `if __name__ == "__main__":` entry-point guard.

## Source kinds, categories and analyzer plugins

Which analyzer reads a file is decided by registered **source kinds**
(`polaris.review.analyzers.base.SourceKind`): a name (the coverage `language`), a domain, and
the extensions, exact file names and path patterns that select it. Patterns are matched first,
then file names, then extensions, so a CI-workflow kind for `.github/workflows/*.yml` wins over
a generic YAML kind. In patterns `*` stays within one directory and `**` spans any number. Two
kinds can never claim the same extension, file name or pattern, so a file never silently
changes analyzer. The built-in kinds are `python`, `javascript`, `typescript` and `rust`
(domain `code`), `github_actions` (domain `ci`) and `dockerfile` (domain `container`); other files
are `unsupported`.

Every check in the catalog has a **category** (`security`, `correctness`, `reliability`,
`performance` or `maintainability`) and the **domains** it applies to. Findings carry their
check's category, always taken from the catalog whichever analyzer reported them; reports count
them in `summary.categories`; SARIF tags each rule with it (only security rules get a
`security-severity`); GitLab Code Quality maps it to its own categories. A check creates
coverage rows only for files of its domains: CI-workflow checks never leave gaps on TypeScript,
and code checks never on a Dockerfile. A file with no applicable requested check is listed as
`not_applicable` (`no_applicable_checks`). Today every check is a security check: twelve apply
to code, six to CI workflows and four to container builds (`secret_exposure` to all three).

Analyzers are registered in `polaris.review.analyzers.registry` with the languages and checks
they complete. An installed third-party analyzer is loaded from the `polaris.analyzers`
entry-point group only when named explicitly, with `--analyzer-plugin NAME` (repeatable) or
`AnalysisRuntime(plugins=("NAME",))`:

```toml
# The plugin package's pyproject.toml
[project.entry-points."polaris.analyzers"]
acme-terraform = "acme_polaris.plugin:plugin"
```

```python
from polaris.review.analyzers.base import SourceKind
from polaris.review.analyzers.registry import AnalyzerPlugin, AnalyzerSpec


def plugin() -> AnalyzerPlugin:
    return AnalyzerPlugin(
        kinds=(SourceKind("terraform", extensions=(".tf",)),),
        analyzer=AnalyzerSpec(
            "acme-terraform", create=lambda runtime, policy: TerraformAnalyzer(),
            capability=lambda runtime, probe: CAPABILITY, checks={"terraform": ("secret_exposure",)},
        ),
    )
```

Loading a plugin runs its code in the Polaris process, the same trust decision as installing
it; nothing is discovered or loaded implicitly. A plugin adds source kinds and an analyzer for
checks the Polaris catalog already defines, so check definitions, severities and guidance stay
in Polaris. One that is missing, fails to load, is malformed or conflicts with a registered
kind or analyzer stops the review with a fixed error code (`invalid_plugin_name`,
`analyzer_plugin_unavailable`, `analyzer_plugin_failed_to_load`, `invalid_analyzer_plugin`,
`analyzer_plugin_conflict`) and leaves nothing registered. Its findings and coverage are kept
only for reviewed files of the languages and checks it declared, so it can't mark another
analyzer's check complete. Loaded plugins are part of the review's runtime identity and
snapshot digest. Pull-request suggestions are re-verified with the built-in analyzers only, so
plugin findings are never offered as one-click fixes. Source kinds a plugin adds stay
registered for the rest of the process.

## Optional Semgrep CE

The original Polaris Semgrep pack is supplementary. It runs only when configured
(`--with-semgrep`, `--semgrep PATH`), and then counts toward completeness. It recognizes
JavaScript `.js`, `.jsx`, `.mjs`, `.cjs` and TypeScript `.ts`, `.tsx`, `.mts`, `.cts`:

* Selected untrusted parameters/request/environment reads flowing to
  `query`/`execute`/`raw`-style SQL text.
* Explicit Node `child_process` imports/requires calling `exec`/`execSync`, or
  `spawn`/`spawnSync` with `shell: true`.
* Secret-named environment values flowing to selected logging/HTTP outputs.
* Selected untrusted paths passed to explicit Node filesystem
  imports/requires or `sendFile`.
* Explicit TLS certificate-verification disabling.

The same pack adds selected Python environment-secret output, `open`/`send_file`
path, and TLS-verification patterns. It is not a general credential scanner,
whole-program analysis, complete sanitizer model, dependency audit, or proof of
safe configuration. Wrappers, dynamic imports, unrecognized sources/sinks, and
interprocedural flows can be missed; conservative source assumptions can also
produce false positives. JSX/TSX file parsing does not imply React-specific
security checks.

## Analyzer installation and data boundary

The managed analyzer contract, frozen with the Theo 0.3.3 macOS release, supplies
the analyzer only through managed macOS ARM64 Homebrew/standalone packages, in an
isolated CPython 3.11.16 environment. The `analysis` extra is retired in both
source and public packages. There is no empty compatibility extra, old-analyzer
fallback or independently published pip derivative. Pip's warning about an
unknown extra does not establish coverage. Plain Python consumers can explicitly
select the same verified managed analyzer with
`AnalysisRuntime(semgrep_executable="/absolute/managed/analyzer/bin/semgrep")`
or `--semgrep`; otherwise dependent checks remain incomplete.

`analyzer-contract.json` pins all 67 wheels and their metadata, including Semgrep
distribution `1.178.0+theovex.1`, upstream runtime/JSON `1.178.0`, Setuptools
`83.0.0` and analyzer MCP `1.29.0`. Application MCP stays separate at `2.2.0`.
The derivative changes dependency metadata, not Semgrep code or native bytes.
Assembly verifies complete hash-locked wheel bytes; runtime identity checks
the exact isolated graph and installed metadata before execution. Untouched
upstream `1.178.0`, duplicate/missing/extra distributions and proprietary core
candidates in the fixed resolution locations are rejected. Metadata checking
is not a full installed-payload integrity check or trust in a hostile executable.

The wheel declares LGPL-2.1-or-later; the exact native source root declares
LGPL-2.1-only. Neither declaration overrides the other without legal review.
The original Polaris pack is Apache-2.0 and contains no Semgrep Registry rules.
The recipient source/notice packet carries actual digest-bound files, the
derivation recipe/patch and missing evidence. It is preparation-only; native
corresponding-source, compiled membership, build/relink and legal obligations
remain separate gates. No public release or redistribution approval is implied.

External analysis writes source copies to a private temporary workspace:
0700 directories, 0600 generated source/rule files, temporary HOME/CWD, and no
repository-controlled target names or configuration. Copies and analyzer logs
are removed on normal cleanup; this is not secure disk erasure, and a process
crash or host-level backup may retain data. The subprocess receives an
allowlisted environment, no inherited credentials, no shell, disabled metrics
and version checks, explicit `--no-trace`, bounded output/time/results, CPU/file-size limits, and CE
memory/per-file timeout settings.

OS-level network denial and write confinement are required through macOS
`sandbox-exec`. The retained Linux `bubblewrap` implementation is not qualification
of this macOS-only artifact graph; other platforms fail closed. If isolation is
unavailable or unusable, required checks do not pass. Runtime/library
reads remain allowed; this is not isolation from a malicious analyzer binary.
Only explicitly supplied source copies are analyzer targets. An operator must
trust the installed executable and its environment.

The supported path is fixed `scan --oss-only` with local original rules and generated
targets, not arbitrary Semgrep arguments. Python CLI startup can import MCP and
OpenTelemetry modules without starting services/exporters. Resource detection
and derived trace-like environment values are not themselves proof of enabled
tracing. Default native dispatch can fall back to Python; ordinary core `-rpc`
is not MCP. MCP service/authentication, enabled tracing and arbitrary legacy
plugins remain shipped and unfixed, outside the supported interface, not
risk-approved. Python diagnostic hooks do not observe native initialization
after exec; keep that evidence limit distinct from OS network denial.

For source payloads that must never be written to temporary files, use
`AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)`
and `review_sources`/`review_snippet`. Python's built-in two checks and supported
guard diffs remain available; Semgrep-dependent coverage is explicitly
`not_checked`. A hosted consumer must not enable transient source storage
without updating its own data-handling contract.

## Caller-trusted authorization guard policy

Pass a `TrustedGuardPolicy` with `policy_id`, `revision`, `requirements`, and
`source="caller"` through the embedding application's authenticated policy
channel. Its `GuardRequirement` entries specify `path`, `symbol`, `guard`, and
optional `require_await=False`, all as keyword arguments.
A JSON `"source": "caller"` label does not
authenticate a policy; repository prose, source comments, and model output
cannot establish or relax requirements.

The guard differ checks only whether an established direct, top-level call
statement in a named function disappears between complete before/after
snapshots. Python uses AST. JavaScript/TypeScript uses a conservative
balanced-token recognizer: arrow handlers, generators, templates, regex/division,
JSX bodies, and complex signatures are unsupported. JavaScript guard statements
must end with a semicolon or be the function's final expression.

Missing policy is `not_checked`, advisory unless authorization was explicitly
requested. Supplying a policy adds the authorization check; unrelated paths
remain advisory. Missing baseline guards, incomplete context, deleted/moved
policy paths, and ambiguous syntax do not pass. Retaining a call proves nothing
about argument correctness, callee binding or implementation, execution order,
identity, tenancy, or actual authorization behavior.

## Capabilities, coverage, and provenance

`polaris.review.capabilities.capability_manifest(runtime=..., probe=False)`
returns `polaris.capabilities/0.2.0` with the exact language/check matrix,
extensions and path patterns, runtime `version`/`expected_version`, distinct `distribution_version`/
`expected_distribution_version`, `identity_digest`, `upstream_artifact_sha256`,
rule-pack digests/provenance/licenses, runtime availability,
and limitations. The default does not execute Semgrep; `probe=True` performs
installed identity checks followed by a sandboxed local version check and can use temporary runtime files.
Availability is not detection accuracy.

Every report includes per-file/check coverage (`checked`, `not_checked`,
`partial`), reasons, required/advisory status, and omissions. `coverage.complete`
requires all required rows to finish without scope omissions. An empty finding
list alone is never a clean-review signal. A checked row means its bounded rules
completed, not that the source is secure.

Findings contain fixed rule descriptions, locations, analyzer/rule identifiers,
and evidence hashes, not raw Semgrep messages, metavariables, or source excerpts.
Provenance binds the supplied sources/baselines, change metadata, configuration,
runtime, policy, and capability digests. It is a snapshot binding, not signed CI
evidence. Review again after any relevant change.

The report's default `exit_code()` is 1 for flagged findings, 2 for incomplete
required coverage, and 0 otherwise. An exit code of 0 is not authorization or a
security proof.

## Measured results

Measured on 2026-10-02 with this source on an Apple Silicon laptop.

* **Labeled corpus** (`benchmarks/workflow_corpus`, run by `tests/test_workflow_corpus.py`):
  development 120/120 code cases, evaluator reconstruction 18/18 (its 16 original cases 16/16).
  The held-out cases were written before tuning and are never edited to pass; a case an
  analyzer change fixes moves to the development split. Held-out results as first measured:
  33/37 (precision 1.00, recall 0.83). Its misses on httpx client objects, pathlib reads and
  axum `Query(params)` destructuring were then fixed (2026-10-04) and moved, so the remaining
  34 cases pass 33; the remaining miss is a placeholder-looking GitHub token, skipped by design.
* **Full scan of a large Next.js/Tauri repository** (15,090 tracked files, read-only): 12,000
  of 12,416 applicable files analyzed (96.6%); not analyzed: 409 shell scripts, 5 Swift and
  1 Kotlin file (no analyzer) and one 2.4 MB generated font file. 145 s wall time, 1.29 GB
  peak memory, complete snapshot (83 s with eight worker processes, measured 2026-10-04).
  Status `incomplete` only because of that unanalyzed scope.
* **Precision on high/critical findings** (manual triage of every finding): 35 of 38 real and
  actionable (92%), mostly SSRF through unrestricted server-side fetches of request URLs,
  Tauri commands that run programs or read paths from the webview, two unauthenticated state
  changes and disabled database TLS. Before the precision fixes in this source, the same scan
  reported 154, of which the same 35 were real (23%). The fixes were derived from that triage
  (each is a general pattern with a corpus regression case), so the 92% is optimistic for
  other repositories.
* **Medium severity** (2026-10-04, fresh full scan with this source: 86 flagged findings and
  296 "to verify" questions; seeded sample stratified by check, triaged by hand). Flagged: 1 of
  42 real (2%, 95% CI 0–12%), a CORS policy that echoes any origin with credentials. 83 of
  the 86 fall into four patterns that were noise here: command-line arguments of scripts and
  CLIs treated as attacker input; same-site navigation and redirects whose fixed prefix is
  lost through a ternary, a helper or `pathname`; `Math.random()` for values whose names look
  security-related (Excalidraw `versionNonce`, an animation `reset`); and OAuth endpoint URLs in
  fields named `tokenUrl`. Questions: 14 of 30 worth asking (47%, 95% CI 30–64%), mostly
  server fetches of caller-supplied URLs (two with provider keys attached) and HTML rendered
  without visible sanitizing; the rest were answered by code the engine doesn't model
  (callbacks, operator flags, fixed API bases, test fixtures).
* **Diff reviews** (CLI wall time, ten latest non-merge commits, measured 2026-10-04 on a
  14-core laptop): 2.7–4.1 s for 2 to 67 changed files, 4.6 s for 178 files and 5.9 s for 572
  files. The two large reviews used worker processes; in-process, the TypeScript analysis of
  the 572-file review takes about 10 s instead of 3.
* **GitHub Actions workflows and Dockerfiles** (2026-10-04). Held-out: 47 cases (27 workflows,
  20 Dockerfiles; 22 vulnerable, 25 safe look-alikes) committed before the two analyzers existed
  pass 47/47 as first measured. The analyzers' author wrote them from the rules' specification,
  so they show consistency with that specification more than real-world recall. The development
  split adds 73 cases (193/193 in all). This repository's four workflows and its pull-request
  template (reviewed as `.github/workflows/polaris-pr-review.yml`) produce no findings;
  `packaging/docker/Dockerfile` has one low (a base image without a digest).
* **Real repositories** (read-only review of every workflow and Dockerfile, 2–3 s each: Apache
  Airflow 56 + 30 files, n8n 111 + 11, PyTorch 158 + 11, Grafana 98 + 32). As first measured,
  7 critical/high findings, 2 real: an example Dockerfile copies AWS credential build arguments
  into `ENV`, so they ship in the image configuration. The 5 false positives were two
  patterns (`${{ toJson(github) }}` in a quoted heredoc written to a file; `docker pull` after an
  artifact was extracted into the workspace), fixed with regression cases; the same scan then
  reports 2 critical/high, both real. That is optimistic for other repositories, because the
  fixes came from this triage. Lower severities are mostly unpinned action and image references,
  accurate by definition but dominated by each project's own organization's actions (PyTorch
  189, Grafana 87).

## Validation

The analysis tests use synthetic positive/negative examples, fake subprocess
responses, temporary homes/repositories, and offline model settings. Real-engine
tests require an explicit absolute `POLARIS_TEST_SEMGREP` pointing at the pinned
isolated executable and never install it. These are software regressions, not an
independently reviewed security-accuracy benchmark. Linux sandbox behavior and
other deployment platforms require their own runtime validation.

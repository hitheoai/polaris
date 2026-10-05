# Polaris pull-request review (GitHub)

Polaris can review every pull request and post the results where reviewers already look:
inline comments on the lines the pull request changed, committable one-click fixes that a static
re-review has confirmed, and one summary comment that also lists what was **not** reviewed. It
runs on your own GitHub Actions runner with the built-in analyzers: no Polaris service, account,
model or API key is involved, and repository content is not sent anywhere.

This is development source, not a published release. Comments are review evidence, not proof
of exploitability or safety, and not approval to merge. Behavioral tests are never run.

To check your code on your own computer before you open a pull request, use
[`polaris check`](check.md).

## What gets posted

- **Inline comments** only on lines the pull request changed (GitHub's own diff decides; a
  comment GitHub can't place moves to the summary). By default only flagged **critical** and
  **high** findings are commented inline: on one large real repository 35 of 38 high/critical
  findings were real, while flagged medium findings were mostly noise (1 of 42 in a sample).
  See [measured results](analyzers.md#measured-results).
- **One-click suggestions** only when Polaris's deterministic suggested edit passes
  re-verification: a control re-review reproduces the finding, and a re-review with the edit
  applied no longer detects it, still completes every required check and reports nothing new.
  Other edits are shown as a plain diff with the reason they were withheld.
- **A collapsible prompt for your coding agent**, built only from Polaris's own catalog text and
  validated identifiers (never the analyzed code). It tells the agent to treat repository text as
  data, make the smallest fix within the pull request's scope, and run `polaris check` again (or
  call the `polaris_check` tool) to confirm the finding is gone.
- **One summary comment**, updated in place on every push: issues in this change, "to verify"
  questions, lower-severity findings, findings already present in touched files outside the
  changed lines, files not reviewed (and why), new `polaris-ignore` suppressions, and anything
  hidden by the base branch's baseline.
- **Resolution**: when a later push makes Polaris stop detecting a finding in a file whose
  required checks all completed, its comment is marked resolved and the conversation collapsed.
  Findings that are still detected anywhere are never marked resolved, and a stale or failed
  review resolves nothing.

Re-running on the same commit posts nothing new: comments carry a hidden marker with the
finding's stable fingerprint, and markers are trusted only when they are the final line of a
comment written by the bot account.

## Set it up

1. Copy [`ci/github/polaris-pr-review.yml`](../ci/github/polaris-pr-review.yml) to
   `.github/workflows/polaris-pr-review.yml` on your default branch.
2. Set the repository variable `POLARIS_PACKAGE` (Settings → Secrets and variables → Actions →
   Variables) to a pinned Polaris requirement that includes `polaris pr`, such as an exact
   released version or a wheel URL with its `#sha256=` hash. The workflow refuses to run without it.
3. Open a pull request. The **analyze** job reviews it; the **publish** job posts the results.

## Security model

- `pull_request_target` runs the workflow file from the **base branch** with the base
  repository's token, so pull requests from forks get reviews too, and a pull request cannot
  change the workflow that reviews it.
- The **analyze** job has a read-only token. It checks out the base branch, fetches the pull
  request's commits as Git objects, verifies the fetched head against the event, and reviews
  `merge-base...head` straight from those objects. Nothing from the pull request is checked
  out, installed, built or executed. Tools are installed in the runner's temporary directory
  with `--no-config`, and Polaris starts with `python -I`, so repository files cannot change
  the installation or shadow its modules. Related context (imports, `tsconfig`) comes from the
  base branch checkout. Project settings and the baseline come from the base revision, so a
  change cannot loosen its own review.
- The **publish** job holds the write token (`pull-requests: write`), never checks out the
  repository, and reads only the plan. `polaris pr publish` validates the plan's schema and
  size, rejects plans containing Polaris markers, and binds it to the repository, pull request
  number and head commit **from the event**, never from the plan. If the pull request has moved
  to a newer commit or closed, nothing is written.
- All repository-derived text in comments is rendered inert: code spans and blocks with
  fences longer than any backtick run, escaped HTML and markdown, no links, autolinks or
  @mentions, and no hidden HTML comments. Bidirectional and invisible control characters are
  replaced, and suggestions are offered only for lines that need no escaping at all.
- The token is read from an environment variable, sent only to the configured GitHub API
  origin (HTTPS, redirects refused), and never printed. Errors are fixed codes without
  exception text.

These comments are **advisory**. A pull request's author controls the code under review, and a
parser bug is always possible. For a required merge gate, use the independent
[agent-native required check](ci.md#required-development-workflow-review).

## Run it yourself

`polaris pr plan` needs no network access or token. Preview what would be posted:

```sh
polaris pr plan --root . --base origin/main --head HEAD --repository owner/name --pr 1 \
  --no-external-analyzers --format markdown
```

| Option | Default | Meaning |
|---|---|---|
| `--min-inline-severity` | `high` | Lowest severity commented inline; the rest are in the summary. |
| `--inline-questions` | off | Also comment inline on "to verify" questions at that severity. |
| `--max-comments` | `25` | Inline comment cap (0 to 100); the rest are in the summary. |
| `--fail-severity` | `high` | Flagged findings on changed lines at or above this fail the gate. |
| `--no-verify-fixes` | off | Skip re-verification; no one-click suggestions are offered. |
| `--import-sarif PATH` | none | Merge another tool's SARIF 2.1.0 results (repeatable, up to 16); see [below](#results-from-your-own-tools-sarif). |
| `--inline-imported` | off | `security` or `errors`: also comment inline on imported results on changed lines. |
| `--fail-on-imported` | off | `error`, `warning` or `note`: imported results on changed lines at that level or above fail the gate. |

`polaris pr publish --plan plan.json --repository owner/name --pr N --head SHA` posts a plan
with the token in `GITHUB_TOKEN` (`--token-env` chooses another variable, `--api-url` a GitHub
Enterprise Server API, `--bot-login` the account whose earlier comments are trusted, for example
a GitHub App). `--dry-run` reads the pull request and reports what would change without
writing. Its JSON receipt contains counts only.

Exit codes of `publish`: `0` published and the gate passed (or `--fail-on never`), or nothing
to do because the pull request moved on or closed; `1` the gate failed (flagged findings at or
above `--fail-severity` on changed lines); `2` an incomplete review with `--fail-on incomplete`,
or an error.

## Results from your own tools (SARIF)

`--import-sarif PATH` adds the results of tools you already run, such as ESLint, Ruff, CodeQL,
Semgrep, Gitleaks or any other SARIF 2.1.0 producer, to the review. Polaris never runs those
tools; it reads the files they wrote. The same option works for `polaris workflow review`.

- **Where they appear:** in the summary, imported results on changed lines are listed in a
  collapsible section grouped by tool. Each one shows the tool's level, rule, location and
  message, and the section is labeled "imported SARIF, not verified by Polaris". A result at
  a Polaris finding's location (within two lines) that reports the same weakness (same CWE,
  or a rule known to check the same thing) is shown with that finding as "also reported by"
  instead. The Polaris finding itself does not change. `workflow review` shows the same
  results in text, JSON, SARIF (one run per tool, marked as imported) and Code Quality output.
- **Off by default:** imported results add no inline comments and leave the gate, exit codes,
  coverage, suppressions and baseline unchanged. `--inline-imported security` comments inline
  on imported security results that the tool itself rated `error`, or high or critical by
  `security-severity`. `--inline-imported errors` adds every other `error`-level result.
  `--fail-on-imported LEVEL` makes imported results on changed lines at that level or above
  fail the gate. With that option, the gate is `incomplete` when a file was rejected, a tool's
  run reported no results or an unsuccessful execution, or results went past a limit.
  Imported comments never get a fix suggestion or an agent prompt. Some tools give every
  result the same level (Ruff reports everything as `error`). With those, these options act
  on every rule you enable, so enable only the rules you want commented on.
- **Severity:** when a tool provides `security-severity`, it sets the severity (9.0 or more is
  critical, 7.0 high, 4.0 medium). Otherwise the tool's level only: `error` is medium,
  `warning` low, `note` info. A level alone never makes a result high.
- **Resolution:** imported comments use their own marker keys (`sarif-<tool>-<fingerprint>`),
  separate from Polaris's. A later push marks one resolved only if that run imported the
  same tool's SARIF completely (nothing rejected, cut at a limit, or from a run without
  results) and the file is still in the pull request, and the tool no longer reports the
  result. A missing or broken SARIF file resolves nothing, and imports never change how
  Polaris's own comments are resolved.

In CI, SARIF is usually produced from the pull request's own code, so Polaris treats it as
untrusted input:

- Each file is limited to 16 MB (64 MB in total), and its JSON structure is counted before
  parsing. Duplicate keys, `NaN` and anything that is not well-formed SARIF 2.1.0 reject the
  whole file with a fixed code (`invalid_sarif`, `sarif_too_large`, `sarif_total_limit`,
  `unsupported_sarif_version`, `sarif_unavailable`). The code is listed in the summary and
  file content is never echoed. A rejected file never stops the Polaris review itself, and
  a run whose tool calls itself Polaris is not imported.
- Locations become repository paths only inside the reviewed change: relative URIs (with
  `uriBaseId`), `file://` URIs under the checkout, or another checkout's paths when every
  result in the run agrees on one root. Anything that climbs out of the repository, uses
  another scheme, contains control characters or is ambiguous is counted and dropped. The
  files a result names are never opened.
- Tool names, rule ids and messages are kept as bounded, printable text: control, invisible
  and bidirectional characters are replaced. Comments render them as escaped text or code
  spans, so they cannot add links, HTML, @mentions or Polaris markers. Snippets, help links
  and the tools' fixes are not used.

### Produce SARIF in CI without giving the tools a write token

Run your tools in a job that has only `contents: read`, gets no secrets, and writes SARIF to
an artifact. Never check out or run anything from the pull request in a
`pull_request_target` workflow, even in a read-only job: that runs a fork's code with the
base repository's identity and lets it poison caches. The job that holds
`pull-requests: write` only downloads the SARIF into `$RUNNER_TEMP` and passes it to
`polaris pr plan`.

**Same-repository pull requests:** one `pull_request` workflow, like this repository's
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml). Its authors can already write to
the repository, so their tools may run their own configuration and plugins (add `npm ci` and
`npx eslint . --format @microsoft/eslint-formatter-sarif --output-file "$RUNNER_TEMP/sarif/eslint.sarif"`
for ESLint).

```yaml
name: Polaris PR review with your tools

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions: {}

jobs:
  sarif:
    name: Your tools (read-only, no secrets)
    if: >-
      github.event.pull_request.head.repo.full_name == github.repository
      && github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false

      - uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
        with:
          enable-cache: false

      - name: Run Ruff and Semgrep (pin the versions you use)
        run: |
          mkdir -p "$RUNNER_TEMP/sarif"
          uvx --no-config ruff@0.6.9 check --exit-zero --output-format sarif \
            --output-file "$RUNNER_TEMP/sarif/ruff.sarif" .
          uvx --no-config semgrep@1.95.0 scan --metrics=off --config p/default \
            --sarif --output "$RUNNER_TEMP/sarif/semgrep.sarif" .

      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: polaris-sarif
          path: ${{ runner.temp }}/sarif/
          if-no-files-found: ignore
          retention-days: 3

  review:
    name: Polaris review and comments
    needs: sarif
    # Runs even when a tool failed: a missing file is reported as a rejected import.
    if: >-
      !cancelled()
      && github.event.pull_request.head.repo.full_name == github.repository
      && github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0

      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        continue-on-error: true
        with:
          name: polaris-sarif
          path: ${{ runner.temp }}/polaris-sarif

      - uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
        with:
          enable-cache: false

      - name: Install Polaris outside the repository
        working-directory: ${{ runner.temp }}
        env:
          POLARIS_PACKAGE: ${{ vars.POLARIS_PACKAGE }}
        run: |
          uv venv --no-config --python 3.12 polaris-env
          uv pip install --no-config --python polaris-env/bin/python "$POLARIS_PACKAGE"

      - name: Review the pull request with the imported SARIF
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPOSITORY: ${{ github.repository }}
        run: |
          "$RUNNER_TEMP/polaris-env/bin/python" -I -m polaris pr plan --root "$GITHUB_WORKSPACE" \
            --base "$BASE_SHA" --head "$HEAD_SHA" --repository "$REPOSITORY" --pr "$PR_NUMBER" \
            --no-external-analyzers \
            --import-sarif "$RUNNER_TEMP/polaris-sarif/ruff.sarif" \
            --import-sarif "$RUNNER_TEMP/polaris-sarif/semgrep.sarif" \
            --output "$RUNNER_TEMP/polaris-plan.json"

      - name: Publish the review
        env:
          GITHUB_TOKEN: ${{ github.token }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPOSITORY: ${{ github.repository }}
        run: |
          "$RUNNER_TEMP/polaris-env/bin/python" -I -m polaris pr publish \
            --plan "$RUNNER_TEMP/polaris-plan.json" --repository "$REPOSITORY" \
            --pr "$PR_NUMBER" --head "$HEAD_SHA"
```

**Pull requests from forks:** produce the SARIF in an ordinary `pull_request` workflow (the
`sarif` job above, without its same-repository condition). For forks it gets a read-only
token and no secrets. Review in a separate workflow triggered by `workflow_run` when that one
completes, and use it instead of `ci/github/polaris-pr-review.yml`, not alongside it. Its
analyze job is the template's: base checkout, data-only fetch of the pull request, Polaris
installed outside the repository, and a publish job that is the only one with
`pull-requests: write`. The differences are that the job needs `actions: read` to download
the triggering run's artifact, treats that artifact as untrusted data, and takes the pull
request from the API only if its head is still the commit the tools analyzed:

```yaml
on:
  workflow_run:
    workflows: [Polaris SARIF]  # the pull_request workflow that uploads polaris-sarif
    types: [completed]

# In the analyze job (permissions: contents: read, actions: read, pull-requests: read):
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        continue-on-error: true
        with:
          name: polaris-sarif
          path: ${{ runner.temp }}/polaris-sarif
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}

      - name: Bind the run to the open pull request whose head it analyzed
        id: pull
        env:
          GH_TOKEN: ${{ github.token }}
          REPOSITORY: ${{ github.repository }}
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
          HEAD_REPOSITORY: ${{ github.event.workflow_run.head_repository.full_name }}
        run: |
          gh api --paginate "repos/$REPOSITORY/pulls?state=open&per_page=100" > "$RUNNER_TEMP/pulls.json"
          jq -r --arg sha "$HEAD_SHA" --arg repo "$HEAD_REPOSITORY" \
            '.[] | select(.head.sha == $sha and .head.repo.full_name == $repo) | "\(.number) \(.base.sha)"' \
            "$RUNNER_TEMP/pulls.json" > "$RUNNER_TEMP/pull.txt"
          test "$(wc -l < "$RUNNER_TEMP/pull.txt")" -eq 1  # moved on or ambiguous: review nothing
          read -r number base < "$RUNNER_TEMP/pull.txt"
          echo "number=$number" >> "$GITHUB_OUTPUT"
          echo "base=$base" >> "$GITHUB_OUTPUT"
```

The remaining steps are the template's, with `steps.pull.outputs.number`,
`steps.pull.outputs.base` and `github.event.workflow_run.head_sha` in place of
`github.event.pull_request.*`, and `--import-sarif` options for the downloaded files. The
publish job binds the plan to the same verified number and head. If the pull request has moved
on, the newer commit's own run reviews it. This variant is a sketch: validate it in your
repository before relying on it.

## Limitations

- GitHub only for now. GitLab merge requests, check-run annotations and `/polaris` commands
  are planned.
- The same analyzer scope as `polaris workflow review`: built-in TypeScript/JavaScript, Python
  and Rust checks; other languages are listed as not reviewed. No model or LLM is used.
- Findings are anchored to changed lines; whole-file analysis can report issues the pull request
  did not introduce, which are listed separately in the summary.
- One-click suggestions are single-line deterministic edits; files with Windows line endings
  never get them. Re-verification is static: it is not a test run.
- Imported SARIF results are other tools' claims, shown as they reported them. Polaris
  verifies none of them and suggests no fix for them. Results without a usable location, or
  on files outside the change, are counted but not listed.

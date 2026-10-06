# Polaris in CI and git hooks

## Advisory pull-request comments

[Pull-request review](pr-bot.md) posts inline comments, re-verified one-click fixes and a
summary on GitHub pull requests, including from forks, using
[`ci/github/polaris-pr-review.yml`](../ci/github/polaris-pr-review.yml). It is advisory:
the pull request's author controls the reviewed code. Use the independent check below where
review is required. To add results from tools you already run (ESLint, Ruff, CodeQL, Semgrep,
Gitleaks), pass their SARIF with `--import-sarif`; produce it in a read-only job as shown in
[results from your own tools](pr-bot.md#results-from-your-own-tools-sarif).

This repository's own [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs lint,
type checks and tests on every pull request and push to `main`, and posts an advisory Polaris
review on same-repository pull requests using the Polaris revision in the pull request (never
a required status). [`.polaris.toml`](../.polaris.toml) excludes the deliberately vulnerable
benchmark corpora, which stay listed as excluded.

## Required development-workflow review

`polaris workflow review` is separate from the legacy Python/two-check integrations below.
It statically reviews declared Python/JavaScript/TypeScript patterns and reports
unavailable, unsupported, partial and stale scope explicitly. It does not run project code,
execute suggested commands, apply patches, or run behavioral tests. Its fixture tests are
not an accuracy claim.

Use the opt-in [agent-native provisioner/launcher guide](../ci/agent-native/README.md),
[GitHub template](../ci/agent-native/github-required-review.yml),
[GitLab template](../ci/agent-native/gitlab-required-review.yml) and
[trusted launcher](../ci/agent-native/required_review.py) for a new required check.
These are development templates, not ready-to-run hosted jobs or hosted-CI validation.
They deliberately contain no checkout/fetch/install/build/test step and require an external
authenticated controller to provision the tools, policy and exact input revisions first.
They do not change the GitLab include or pre-commit definitions.
See [analyzer prerequisites](analyzers.md) and [bounded engineering](engineering.md).

Conceptually, the protected launcher invokes the trusted installation as follows; this
command alone is not a substitute for its provisioner and preflight trust checks:

```sh
/opt/polaris-ci/reviewer/bin/python -I -B -m polaris workflow review \
  --root /var/lib/polaris-ci/input --diff "$TRUSTED_BASE_SHA..$TRUSTED_HEAD_SHA" \
  --semgrep /opt/polaris-ci/semgrep/bin/semgrep \
  --require-complete --format json --output /absolute/private-reports/review.json
```

The controller authenticates exact base/head/repository/run identity. The templates use
`BASE..HEAD` intentionally, not an implicit merge-base or moving branch name. Missing
revisions, analyzers or coverage fail; there is no shallow-checkout fallback. GitHub merge
queues need a separate trusted merge-group configuration; GitLab merged-result and detached
MR pipelines need their actual head bound by the controller. `--staged` reviews an index,
not the revision range required by these jobs.

### Protect the review control plane

A required status is only useful if the contributor cannot replace the code producing it:

- Load the workflow/job definition from a protected trusted source and restrict runner
  assignment. A PR-controlled job or same-name status is not an independent required check.
- Provision immutable, root-owned engine/analyzer/launcher installations outside the checkout.
  The job runs non-root and checks installation-tree digests against protected approval data.
  Never install Polaris, an editable package, or a build script from the candidate.
  Isolated Python startup prevents checkout modules, `PYTHONPATH` or `sitecustomize.py`
  from shadowing the trusted installation.
- Supply a fresh complete worktree and Git metadata on a **kernel-enforced read-only mount**
  owned by the job UID, with exact clean HEAD/index and all required objects already local.
  No remotes, stored credentials, custom helpers, shallow/partial clones or lazy fetching.
  The external controller, not the template, authenticates acquisition and prepares the mount.
- Keep checks, exclusions, limits and guard/action policies in the protected control plane.
  The controller explicitly selects either `authorization: "not_requested"` or
  `"guard_regressions"` with the exact trusted guard-policy digest. The latter adds
  `api_authorization`; a JSON `source="caller"` label alone does not authenticate policy.
- Do not run project tests, package scripts, hooks or proposed commands in this static gate.
  Do not give untrusted source deployment secrets, a Docker socket, writable tooling or
  persistent state from other jobs. Acquisition credentials must be removed before review.
- Enforce the exact independent status through a protected workflow/ruleset or pipeline policy.
  Do not use `continue-on-error`, `allow_failure`, a pipeline hiding the exit code, or report
  upload success as a substitute for the gate. Validate fork permissions and artifact access.

Installation is a trusted preparation step, not something review does. The current
managed graph is macOS ARM64 only: Semgrep distribution `1.178.0+theovex.1`,
runtime `1.178.0`, Setuptools `83.0.0`, separate from application MCP.
The `analysis` extra is removed, and `[all]` installs no analyzer.
The existing Linux runner templates are blocked by this contract, not qualified by
retaining `bubblewrap` code. A separately reviewed platform graph/runner adaptation is
required. Local macOS external analysis requires `sandbox-exec`; never disable isolation
or substitute the old analyzer to obtain a passing job.

The launcher requires fresh complete Git-revision coverage, no unresolved findings and
actual pinned-analyzer availability even for an empty change. It retains full `review.json`
and bounded `status.json` outside the input tree on success or failure. Raw subprocess
stdout/stderr is not uploaded. Artifacts have restricted access and short retention; they
are not signed attestations. SARIF/Code Quality can be separate presentation, not a substitute
for full coverage/status and the strict process exit code. Local receipts, MCP historical
pages, editor rules and earlier developer reviews are not gate evidence.

### Strict local hook

```sh
polaris setup git-hook --required-review --semgrep /absolute/trusted/analysis-env/bin/semgrep
```

This opt-in runs `workflow review --staged --require-complete --format json` independently,
without trusting a prior local receipt. It is not the default legacy hook. Local hooks,
including editor completion hooks, remain bypassable; required CI must run again.
Warp rules are advisory and no verified deterministic Warp completion hook is installed.
Doctor's MCP SDK smoke is not evidence of an actual installed-client invocation.

### Workflow exit codes and evidence

With `--require-complete`, `0` means declared required coverage and snapshot checks
completed with no unresolved non-OK findings; it is not authorization or proof of safety.
`1` means flagged findings. `2` covers stale/error review and other required incompleteness
or unresolved non-OK results. Stale/error takes precedence over findings. Without the
strict flag, incompleteness alone may return 0: do not use that mode for required review.
Review's `tests_status` remains `not_run`; a disappearing static finding is not a passed test.
Any separately approved isolated fixture runner must supply its own actual evidence.

Offline tests in `tests/test_workflow_ci.py` exercise the template/launcher trust contracts,
not real root-owned mounts or enforcement by GitHub/GitLab. Validate the actual controller,
image, sandbox, runner isolation, fork behavior and merge protection before requiring a
production status. Adding these template files enables no hosted job by itself.

## Legacy Python/two-check integrations

Polaris reviews changed Python code for SQL injection and command injection on every pull
request, merge request or commit. It runs on the CI machine or yours. With an API key, the
model's second opinion comes from the [hosted model](remote.md): only functions with SQL or
process calls are sent, and nothing heavy is installed. With a model archive instead, nothing
is sent anywhere.

By default the static rules decide each result and the Polaris model, when available, adds a
second opinion. The job fails only on the results you choose with `fail-on` (default:
`flagged`); second opinions never fail a job.

### GitHub Actions

For pull requests on GitHub, use the `hitheoai/polaris@v1` action ([guide](pr-bot.md#set-it-up)),
or the [workflow template](../ci/github/polaris-pr-review.yml) it is built from. Neither runs
the legacy two-check review described here. To run the legacy review in your own workflow,
install the package in a step and run `polaris review`, as the GitLab template below does. Pass
the hosted model's key as `POLARIS_API_KEY` from a repository secret through the step's `env`,
never by interpolating it into the script.

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/hitheoai/polaris/v0.5.0/ci/gitlab/polaris.gitlab-ci.yml
```

For the hosted model, add a masked CI/CD variable `POLARIS_API_KEY` in the project's settings
(not in the file). To run the model on the runner instead, set `POLARIS_MODEL_URL` (and
`POLARIS_MODEL_SHA256`). The `polaris-review` job runs on merge requests, reports findings in the
merge request's Code Quality widget (`--format codequality`) and fails on `POLARIS_FAIL_ON`
(default `flagged`). Set `POLARIS_ENGINE` to `rules` to skip the model entirely.

### pre-commit

```yaml
repos:
  - repo: https://github.com/hitheoai/polaris
    rev: v0.5.0
    hooks:
      - id: polaris-review          # or polaris-review-rules for static rules only
```

The hooks use the `polaris` already installed on the machine (`install.sh` or pip), so PyTorch
and the model aren't reinstalled for every repository.

### Plain git hook

```sh
polaris setup git-hook
```

Commits with flagged findings stop and show the findings; `git commit --no-verify` skips the
check once. See [the editor guide](ide.md#git-hook) for options.

### Legacy exit codes

`0` nothing in `fail-on`; `1` findings in `fail-on`; `2` input, settings or git problem; `3` no
model, or the hosted model can't be used (only with `--engine model`; `--no-model skip` or
`--no-model rules` changes that).

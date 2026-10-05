# Opt-in independently required static review

These are **development templates**, not a published service, a released reviewer,
or ready-to-run hosted jobs. They intentionally fail without a separately
provisioned trusted installation, explicit protected check selection, and isolated input. They do
not change the legacy Action or GitLab template.

**Current blocker:** the managed analyzer contract (frozen with the Theo 0.3.3
macOS release) covers only macOS ARM64. These Linux runner/provisioner templates
are not runnable with it; the launcher rejects unqualified platforms. Do not
install old upstream Semgrep or disable isolation to obtain a green check. A
separate reviewed Linux graph or separately qualified macOS controller/runner
adaptation is required before enabling this gate.

## Enforcement is outside the candidate repository

A required status is meaningful only when the workflow/pipeline configuration,
runner assignment, control-plane inputs, and installation are protected from the
candidate author. A copied YAML file, an MR-controlled include, a job name, a
mutable local Polaris receipt, or an agent's summary is **not enforcement**.

* GitHub: use a centrally controlled required workflow/ruleset and restrict the
  runner group to that trusted workflow. Require the observed status for the
  actual reviewed revision. A same-name job in candidate-controlled YAML must not
  satisfy the rule. This example handles pull requests, not merge-queue events;
  provision separate exact merge-group metadata and trusted configuration before
  using merge queues.
* GitLab: enforce centrally owned pipeline configuration/pipeline execution
  policy, a protected dedicated runner, and a non-optional merge gate. Do not let
  candidate pipeline configuration or pipeline variables override this job.
  `CI_MERGE_REQUEST_DIFF_BASE_SHA` and `CI_COMMIT_SHA` must match independently
  authenticated control-plane metadata. Detached MR and merged-result pipelines
  have different heads; the controller must bind the actual pipeline head.
* Never use `pull_request_target` to run candidate content. Do not give this runner
  arbitrary candidate jobs, secrets, a Docker socket, host administration rights,
  writable tool volumes, or persistent state from earlier jobs.

Both templates deliberately have **no checkout/fetch/install/build/test step**.
GitLab uses `GIT_STRATEGY=empty` and clears inherited steps, caches, and artifact
dependencies. GitHub uploads reports using the official
`actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` commit
([v4.6.2 tag](https://api.github.com/repos/actions/upload-artifact/git/ref/tags/v4.6.2)).
The review jobs need no repository API credentials. Acquisition and report upload
are outside the offline review subprocess, not exceptions inside it.

## Protected provisioner contract

Before the review job, an authenticated controller must prepare a fresh
disposable Linux runner with root-owned, non-job-writable OS/tool paths. Use an
audited immutable runner image; the system interpreter, standard library, Git,
and bubblewrap are part of that trusted image. Do not install anything from the
candidate repository, including a wheel, requirements, actions, scripts, or an
editable Python package.

Provision these fixed paths. No job parameter or candidate file can override them:

* `/opt/polaris-ci/required_review.py`: an independently audited, pinned copy of
  this launcher template, deployed by the control plane—not executed from a
  candidate checkout.
* `/opt/polaris-ci/reviewer/bin/python`: Python with the explicitly approved
  development Polaris build and dependencies already installed. This build must
  include `workflow review --diff --require-complete`; legacy released versions
  do not qualify merely because their package version is `0.2.0`.
* `/opt/polaris-ci/semgrep/bin/semgrep`: an independently approved exact analyzer
  graph, not an arbitrary pip install. The current managed distribution is
  `1.178.0+theovex.1` (runtime `1.178.0`, Setuptools `83.0.0`), macOS ARM64 only.
  The source/public `analysis` extra is retired; this is not a Linux installation recipe.
* `/etc/polaris-ci/installation.json`, `request.json`, and (when guard regression
  checking is requested) `guard-policy.json`: root-owned, non-link files beneath
  non-job-writable root-owned directories.
* `/var/lib/polaris-ci/input`: a complete, fresh Git worktree and `.git` directory
  on a **read-only mount**, owned by the review job UID to satisfy Git ownership
  checks without enabling global `safe.directory`. HEAD is exactly the requested
  head, with the corresponding clean index/worktree; both exact commits and all
  blobs are already local. No linked worktrees, shallow/partial clones, object
  alternates, grafts, lazy fetching, stored credentials, remotes, include files,
  filters, custom Git configuration, or checkout helpers. Source symlinks and
  unsupported scope remain review failures/omissions, not executable content.

Acquisition must use the authenticated repository/event identity, not arbitrary
URLs from a PR. It must not run checkout hooks, LFS, submodules, filters, builds,
or project code. Any credential used for acquisition must be removed before the
read-only input is handed to the review job. Never mutate these mounts during a
job. The launcher does not implement or authenticate this provisioner.

The review job runs **non-root**. An isolated system-Python standard-library
bootstrap checks launcher ownership, writable parents, and symlinks **before**
executing that launcher; a candidate-writable replacement cannot self-attest.
Tool/policy ownership and complete installation
tree hashes are checked before launching Polaris. Installation trees must contain
regular copied files/directories, not symlinks or editable installs. The complete
tree-digest algorithm in `required_review.py` hashes a canonical sorted list of
relative file paths and SHA-256 values; directories are ownership-checked too.
Prepare digests from the actually audited trees after provisioning, not from the
candidate. Hashing is bounded at 50,000 entries, 2 GB total, 250 MB per file, and
60 seconds per tree; exceeding a bound fails.

`installation.json` has format `polaris.ci-installation/0.1.0`, `approved: true`,
`semgrep_version: "1.178.0"`, `semgrep_distribution_version: "1.178.0+theovex.1"`,
`setuptools_version: "83.0.0"`, `analyzer_contract_digest` matching the independently
reviewed application contract, and the operator's
actual `reviewer_tree_digest`, `semgrep_tree_digest`, and `launcher_digest`, each
`sha256:` plus 64 lowercase hex characters. There are deliberately no sample
release hashes or installer commands: no qualifying release digest is asserted.
The provisioner must verify dependency provenance/licenses and maintain the
approved image/installation pins; a local hash alone does not establish trust.

`request.json` has format `polaris.ci-request/0.1.0`, the independently verified
`provider`, `repository`, `run_id`, full lowercase `base_sha` and `head_sha`,
`issued_at`/`expires_at` Unix seconds with at most one hour validity, and the
`authorization` selection and `guard_policy_digest`. GitHub run identity is `run_id:run_attempt`; GitLab is
`pipeline_id:job_id`. Stale, mismatched, abbreviated, zero, or missing identities
fail. The externally selected policy must match that request's exact digest.
For repositories with no intended guard invariant, the controller explicitly sets
`authorization: "not_requested"` and `guard_policy_digest: null`. The five broader
checks still run, and the report shows authorization as not checked. For intended
guard invariants it sets `authorization: "guard_regressions"` and the exact policy
digest; `api_authorization` and `--guard-policy` are then added. Missing/ambiguous
selection fails. Do not supply an empty invalid requirements list or infer policy
from candidate text.

`guard-policy.json` uses the `TrustedGuardPolicy` schema from
`src/polaris/review/models.py`. The controller/user must authorize exact
requirements; never infer them from repository prose or model output. A
`source: "caller"` label alone does not authenticate policy. The policy only
implements the documented narrow named-function guard regression invariant,
not general authorization correctness.

## What the gate actually does

From an empty private temporary working directory, the launcher clears inherited
credentials/Python/Git overrides and invokes the approved absolute Python with
`-I -B -m polaris workflow review --diff BASE..HEAD --require-complete`, fixed
required checks, the fixed Semgrep executable, and the protected policy when requested.
It uses two dots intentionally: compare those exact commits, not an implicit
merge-base or moving branch ref. Git transports, prompts, replacements, lazy
fetching, global/system config, helpers, and inherited PATH are disabled.

The full workflow JSON is a new private file outside the input tree. The launcher
requires a fresh complete Git-revision snapshot at the expected head, complete
required coverage, zero unresolved findings, and actual pinned Semgrep
availability—even for an empty change. It does not read a receipt. Nonzero
review exit codes are preserved as failure; unavailable/stale/incomplete setup
returns 2. A 300-second subprocess timeout fails and kills the process group.
The job timeout also bounds preflight inventory and artifact handling.

`review.json` and a small `status.json` are retained by the CI artifact mechanism
on success or failure. Missing artifacts fail instead of fabricating a report.
Raw subprocess stdout/stderr is discarded, not uploaded; it can contain source
or credentials. Keep artifact access limited to appropriate repository members
and seven-day retention, or make it stricter. Do not publish local filesystem
paths or treat unsigned artifacts as an independent attestation service.

No project code or behavioral tests run. Semgrep uses private temporary source
copies, with required OS network denial; normal deletion is not secure erasure.
Unsupported languages, absent guards/baselines, missing analyzers, oversized
input, parse errors, and snapshot omissions must not become a clean gate. Explicit
policy paths outside the change remain advisory; the template does not assert
authorization coverage outside caller policy. No templates are enabled or cloud
providers configured by adding these files.

## Validation limits

`tests/test_workflow_ci.py` checks the templates and launcher trust contracts
offline using synthetic metadata and temporary paths. It does not provision
root-owned runtime mounts or prove enforcement in a hosted GitHub/GitLab
installation. Validate the actual controller, immutable image, isolated runner,
fork permissions, artifact ACLs, branch protection/pipeline policy, and network
sandbox before making the status a required production merge gate.

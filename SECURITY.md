# Security and privacy

## Reporting a vulnerability

Please report security problems in Polaris privately, never in a public issue: on GitHub, open
the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability
reporting). Include the version (`polaris --version`), what you did and what happened. We aim
to reply within three working days.

## What Polaris does with your code

- **Static review does not run project code.** The development workflow parses supported
  Python/JavaScript/TypeScript patterns with built-in rules and an optional pinned analyzer.
  It does not import reviewed modules, execute their commands/queries, or run repository
  test/build/package-manager commands. Proposed verification commands are data, not a runner.
- **Read-only review is not a blanket no-write promise.** Review, proposal validation and
  action assessment do not change reviewed source. External analysis may create private
  temporary source copies; explicit `--output` saves reports/proposals; setup writes chosen
  configuration/rules/hooks; completion hooks write local hash-based receipts. The separate
  exact-approved local apply operation can replace existing source files, as described below.
- **The static workflow is local by default.** It does not use a classifier or coding model,
  and signing in does not enable generation. Setup selects local model service for its
  legacy MCP tools. HTTP clients intentionally send the supplied content to the chosen
  server; its deployment and data-handling policy must be trusted.
- **The legacy hosted classifier** (after `polaris login`, or with `POLARIS_API_KEY`) receives only the
  functions that make SQL or process-execution calls: each one's code (and previous version),
  file path and line, Polaris's static notes and your policy statements. Nothing else leaves
  through that classifier request, and each report says when the hosted model was used.
  `--model-source local` keeps this legacy review local. See [the hosted model](docs/remote.md).
- **API keys** are saved by `polaris login` to `~/.polaris/credentials.json` with owner-only
  permissions, sent only over HTTPS (or to this machine), never printed, and never re-sent
  after a redirect.
- **The legacy local cache** (`.polaris-cache/review.sqlite` in your repository) stores assessment
  results keyed by a hash of each function, so unchanged code isn't assessed twice. Delete it at
  any time, or use `--no-cache`. Workflow freshness is separate: snapshots bind content,
  selection, policy and analyzer configuration. Local receipts in the per-worktree Git
  administrative directory are mutable hints, not signatures or required-CI attestations.
- **The API defaults to memory-only analysis.** `/v1/workflow/*` never treats request paths
  as server filesystem locations. It does not persist or log request bodies. An administrator
  may explicitly enable isolated transient source files with `--allow-temporary-analysis`;
  callers cannot enable this in requests. Without it, Semgrep-dependent checks are
  `not_checked`, not clean. Usage logs contain bounded counts/metadata, not source or file
  names; errors do not echo input. Apply an appropriate policy to reverse proxies, host
  monitoring and response storage too. Proposal responses necessarily contain replacement
  source and a diff: do not treat them as source-free receipts.
- **No permitted analyzer network traffic or implicit downloads.** The fixed scan disables
  metrics, version checks and tracing explicitly, with OS network denial. This is not proof
  that shipped native code imports or initializes no telemetry components.
  Explicit network paths include HTTP clients, the configured legacy hosted
  classifier, operator-requested model downloads, and the optional generation gateway below.
  Workflow review, setup and doctor never install dependencies, fetch weights, or start
  paid inference.

## Analyzer and policy trust

The intended analyzer is the exact managed macOS ARM64 67-package graph: Semgrep
distribution `1.178.0+theovex.1` (runtime `1.178.0`), Setuptools `83.0.0` and analyzer
MCP `1.29.0`, separate from application MCP `2.2.0`. The public/source `analysis`
extra is removed; no pip fallback is provided. Assembly binds wheel bytes and runtime
checks installed metadata; a matching version alone cannot identify the derivative.
This is not complete installed-payload integrity or hostile-executable trust.
Polaris ships original rules, not fetched Registry rules. Bare MCP service/authentication,
enabled tracing and arbitrary plugins remain shipped/unfixed but unsupported, not
security-risk accepted. Operators must trust the configured executable and environment,
not take an executable or rule URL from repository text or tool input.

External review uses 0700 temporary directories and 0600 source/rule files, a credential-free
environment, bounded subprocess time/output/resources, and required OS network/write
confinement. Copies are removed on normal cleanup, not securely erased; crashes, backups or
host monitoring may retain them. A missing sandbox or incompatible analyzer fails coverage.
This is not isolation from a malicious analyzer binary. Use `--no-external-analyzers` locally,
or the default memory-only HTTP runtime, when transient source storage is not acceptable.
See [analyzer boundaries](docs/analyzers.md).

Authorization-guard checks require explicit caller-trusted policy and before/after evidence.
Action policy belongs to the application/user, with HTTP policies fixed by the administrator
at startup. Source comments, model output, repository guidance and a JSON `"source": "caller"`
label cannot authenticate or relax policy. Workflow HTTP/MCP inputs accept no trusted policy,
analyzer path or provider endpoint. Legacy classifier policy statements are a separate
context field, not permission to execute or change files.

## Bounded repair, generation and execution

The default proposal path reuses an editor/host candidate, binds it to actual findings and
fresh source/context, and returns an immutable digest. The CLI/SDK local apply operation
requires the human-approved exact proposal and snapshot, checks current limits and content,
and replaces only bounded existing UTF-8 regular files. It cannot create/delete/rename user
files. Paths, symlinks and sensitive metadata are constrained. Normal host permissions and
the user's original scope still apply; a digest or risk result cannot establish consent.

Use apply only in a trusted, quiescent local workspace. It is not a multi-file transaction or
an adversarial-filesystem sandbox; detected races can leave a partial application, with no
automatic rollback over concurrent edits. Ordinary mode bits are preserved, but ownership,
ACLs and extended attributes are not. See [engineering limits and receipts](docs/engineering.md).
There is no HTTP/MCP apply endpoint, arbitrary shell endpoint, or project test runner.
Static verification reports detection status, not behavior: `tests_status` / `behavioral_tests`
remain `not_run`. An approved isolated fixture runner and authenticated observed test results
are separate work, never inferred from a disappearing finding.

The optional SDK coding-provider gateway is disabled unless the application explicitly
configures and enables it; hosted use needs separate consent. Existing login, repository
configuration and tool-request URLs cannot select a provider. The gateway enforces bounded
context/output/retries and validates generated candidates, but secret checks are heuristic,
not complete DLP. Never send confidential context to an unapproved provider. Provider usage
and cost can be unknown; mock tests do not establish real provider behavior or savings.

Action reviews always report `authorized=false`, `executed=false` and `policy_changed=false`.
`within_declared_scope` describes an exact allowlist comparison, not runtime safety or
permission. Missing trusted policy is `needs_review`, not approval.

## Model files

- Model archives are verified against a SHA-256 checksum before anything is unpacked, unpacked
  with path-traversal and link protection, and checked against an integrity manifest of every
  file. Only safetensors weights and JSON or text files load; remote model code is disabled.
- Each model carries a self-test. On a new machine or software version Polaris re-runs its
  reference cases and refuses to use the model if the outputs drift or any decision changes.
- Integrity hashes are not signatures. Download models only from sources you trust, and compare
  the checksum with the one TheoVex publishes.

## Limits

Polaris findings are estimates, not proof. "OK" means no risk was found by the checks actually
run, not that code is safe. The development workflow's original Python/JavaScript/TypeScript
patterns are bounded, not whole-program analysis. Required coverage, skipped files, unsupported
syntax, unavailable analyzers and stale context must be inspected even when no issue is flagged.
Retaining a configured guard call does not prove authentication, tenant isolation or authorization.

The legacy review/classifier remains experimental, Python-only and two-default-check
(SQL injection and command injection), with function-local analysis. Broader static support
is not expanded model qualification. Synthetic tests and MCP protocol smoke checks are
software evidence, not an independent accuracy benchmark or actual installed-client approval.
Editor rules/hooks can be bypassed. Required CI must independently review the actual revision
using protected engine/analyzer/policy configuration, never trust a submitted local receipt;
see [the CI guide](docs/ci.md).

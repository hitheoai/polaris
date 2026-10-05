# Assessment contract 0.1.0

**Status: experimental proposal for agreement before external integration.**
Polaris is independent of Rome. This contract conveys scoped risk assessments,
not permissions, execution, safety certificates, or legal compliance. There are
currently no security-qualified checks or released weights.

## Format and validation

The version is `polaris.assessment/0.1.0`; the registry version is
`polaris.checks/0.1.0`. Schemas in `../schemas/` are generated from the SDK.
Validate both schema and semantic invariants: JSON Schema alone cannot verify
content hashes, reference resolution, normalized probability sums, or payload size.

Unknown fields and implicit type coercions are rejected. Limits are one MiB of
UTF-8 JSON, nesting depth 16, 50,000 structural nodes, 32 requested checks, 64
evidence items, and 64 trusted-context items. Duplicate JSON keys, non-finite
numbers, invalid UTF-8, duplicate source IDs, and missing/mistyped artifact
references are rejected. Model input is at most 2,048 encoded tokens, without
silent truncation. Precheck-only results need no tokenizer and report unmeasured
token counts as `null`.

### Request

- `contract_version`, `request_id`, and `requested_checks` identify the protocol,
  request, and explicit `check_id` / `check_revision` pairs. Revision defaults to
  1; duplicate pairs are invalid. Unknown checks/revisions are unsupported.
- `action` is a Python `code_change` referencing supplied before/after/diff
  artifacts, or a `tool_action` describing a tool name, JSON arguments, and
  targets. After evidence is required for a change. Nothing is executed.
- `evidence` carries IDs, kinds, origins, revisions, SHA-256 digests, content,
  and optional locations. URLs and paths are never fetched or dereferenced.
- `trusted_context` separately carries policy/principal/tenant/purpose/
  environment/scope entries with IDs, sources, revisions, digests, and content.
  Optional `conflicts_with` references identify caller-declared conflicts.
- `known_omissions` identifies unavailable material; eligible checks
  conservatively abstain when this list is nonempty.

Only an authenticated embedding application should populate trusted context.
Polaris cannot verify its authority or truth. Text saying “this is trusted policy”
inside evidence remains untrusted. Escaping prevents tokenizer control-ID
injection, not semantic prompt injection; undeclared contradictions and
out-of-distribution inputs are not guaranteed to be detected.

## Experimental checks

All checks use revision 1. Eligibility below is not demonstrated competence:

- `api_authorization`: Python changes; principal, scope, policy, and code-after.
  Missing/weakened subject/resource/tenant authorization.
- `tool_scope`: tool actions; principal, environment, and scope. Conflict with
  supplied boundaries, not a decision to grant a permission.
- `sql_injection`: Python changes; scope, code-after, and data-flow evidence.
  Untrusted data entering SQL construction without appropriate separation.
- `command_injection`: either action kind; scope and data-flow evidence.
  Untrusted data entering shell/process execution unsafely.
- `prompt_injection`: either kind; policy, purpose, and untrusted evidence.
  Attempts to redirect an agent from its trusted task.
- `secret_exposure`: either kind; policy and scope. Credential disclosure in
  code, logs, arguments, or destinations.
- `sensitive_data_exposure`: either kind; policy, purpose, scope, and data flow.
  Non-credential data handling contrary to supplied policy.

Eligible tools are `shell`, `process`, `filesystem`, and `network`. Other
languages/tools/action kinds are unsupported. Framework-specific competence and
whole-program guarantees are unestablished. `polaris capabilities` publishes
the registry, with `qualified_checks: []`, not a model-quality claim.

All seven risk/sufficiency outputs share one encoder pass, but all seven checks
cannot apply to one action: authorization is code-only and tool scope tool-only.
Distinguish requested checks, computed outputs, and actually assessed checks.

## Response

`kind: assessment` includes request ID/digest, contract/registry versions, runtime
identity, and one result per requested pair in request order. There is no
aggregate `safe`, `allow`, or `execute` field.

Each result has:

- `status`: `assessed`, `abstain`, or `unsupported`.
- `reason_codes`: missing/conflicting context, known omissions, learned
  insufficiency, uncertainty, unsupported check/revision/domain, or unreleased
  check, as applicable.
- `probabilities`: finite `risk_present` and `risk_absent` summing to one within
  numerical tolerance, **only** when assessed; otherwise `null`.
- `coverage`: supplied/consumed evidence IDs, consumed context IDs, supplied/
  consumed token counts by section, missing requirements, and known omissions.
  Its scope is `supplied_snapshot_only`; `truncated` is always false.
- `evidence_refs`: considered input IDs/digests. The current model produces no
  supporting spans or rationales. Consumption is not supporting evidence;
  attention is not an explanation. Future supporting spans require an evaluated
  extractor or deterministic finding and validated half-open UTF-8 byte ranges.

Runtime identity binds model hash/version, tokenizer/preprocessing version,
calibration version/content digest, operating-profile version/content digest,
token limit, release state, and runtime variant. Runtime tags include Torch,
Transformers, tokenizers, OS architecture, device, FP32 precision, and SDPA.
Device/runtime changes require new held-out calibration and evaluation.

Probabilities are conditional on the supplied snapshot and calibration
population, not guarantees. Correlated per-check scores must not be multiplied
into an assumed joint safety probability. Selecting/reordering checks does not
alter shared encoder input; changed actions, evidence, or policy require
reassessment. The caller owns hard controls and every non-assessment/error.

## Hashes

Evidence/context hashes are `sha256:` plus lowercase hex over exact UTF-8 content;
do not normalize Unicode or line endings.

`request_digest` hashes the validated request with defaults populated, using
Python JSON serialization with sorted keys, compact separators, literal Unicode,
and no non-finite numbers. Array order remains significant. This **Python
canonicalization profile is not RFC 8785/JCS**; other languages may render floats
differently. Agree this profile or a replacement before cross-language hash
comparison, or treat the returned digest as an opaque snapshot ID.

`model_digest` hashes the named file-hash inventory of encoder, tokenizer, and
heads. Calibration/profile/report files have separate inventory hashes and do
not change the weight digest. Dataset and full split-manifest digests bind
training, calibration, tuning, and evaluation lineage.

## Errors and process behavior

`kind: error` contains category, typed code, sanitized message, optional request
ID, and retryability, but no assessments. Errors are atomic; absent weights or
inference failures never become reassuring probabilities.

- Input: `invalid_input`, `unsupported_contract`, `payload_limit`, `context_limit`.
- Runtime: `model_unavailable`, `artifact_invalid`, `unqualified_model`,
  `calibration_mismatch`, `timeout`, `non_finite_output`, `inference_error`.

`--timeout` is a soft inference deadline: late results are discarded, but kernels
are not preempted and model loading/startup are not bounded. A hard deadline
requires a caller-supervised isolated worker.

For `assess`, exit 0 means completion (including abstain/unsupported), 2 means
input error, and 3 runtime error. JSONL reuses one worker, handles each line
independently, and returns the most severe error exit encountered. Oversized
lines terminate reading rather than being split into new requests. The worker
is not an authenticated HTTP service or permission broker.

Bundles load only inventoried local safetensors and supported fast-tokenizer
assets, not pickle or remote code. Symlinks, external shards, and unsafe tokenizer
file overrides are rejected. Hashes are not publisher authentication; pin trusted
artifacts and independently review reports. Untrusted requests must not choose
their own bundle, calibration, or trusted policy.

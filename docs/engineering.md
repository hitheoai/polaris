# Bounded engineering services

`polaris.engineering` validates small, host-supplied repair candidates and reviews typed
action scope. It is separate from the experimental `polaris.assessment/0.1.0` classifier;
it does not make the Preview model a code generator or expand its validated checks.
The default workflow reuses the editor agent's candidate. No extra inference is required.

The services do not run repository code, verification commands, package managers, shells,
or deployment tools. Only the optional, explicitly enabled generation gateway can send a
request to an application-configured coding provider. Only `apply_proposal` changes source,
after exact-proposal approval and local prechecks. Do not expose that function as an HTTP
or MCP write tool.

## Contracts and parsing

All models forbid extra fields, enforce strict scalar types, and use frozen models with
immutable tuples. JSON arrays become tuples when parsed as JSON. The public parsers also
revalidate existing model instances, including unvalidated `model_copy` results.
Integers `1`/`0` are not accepted in place of literal boolean approval/result fields.

The formats are independently versioned:

* `polaris.repair-snapshot/0.1.0`: `ReviewedSnapshot`, distinct from review-hook freshness.
* `polaris.proposal/0.1.0`: `PatchProposal`.
* `polaris.proposal-validation/0.1.0`: source-free `ProposalValidation`.
* `polaris.approval/0.1.0`: `ProposalApproval`.
* `polaris.apply-receipt/0.1.0`: source-free `ApplyReceipt`.
* `polaris.verification/0.1.0`: source-free `VerificationRecord`.
* `polaris.action-review/0.1.0`: `ActionRequest` and source-free `ActionReview`.
* `polaris.generation/0.1.0`: `GenerationRequest` and `GenerationResult`.
* `polaris.generation-receipt/0.1.0`: source-free `GenerationReceipt`.

`schema(kind)` returns JSON Schema for `snapshot`, `candidate_edit`, `proposal`,
`proposal_validation`, `approval`, `apply_receipt`, `verification`, `action_request`,
`action_policy`, `action_review`, `generation_request`, `generation_result`, or
`generation_receipt`. `parse_snapshot`, `parse_proposal`, and `parse_action` accept an
existing model, dictionary, JSON string, or bytes. Use these boundary parsers rather than
returning raw Pydantic exceptions: validation errors can carry submitted values in their
structured details. `EngineeringError.as_dict()` contains only a fixed code and message.
The JSON parser rejects duplicate keys, non-finite numbers, excessive nesting and payloads
over 1 MiB. It does not log inputs.

Digests are `sha256:<64 lowercase hexadecimal characters>` over UTF-8 bytes or the
repository's deterministic sorted-key JSON encoding; this is not a claim of RFC 8785
canonicalization. Digests are integrity/freshness bindings, **not signatures, authorization,
or independently trusted CI evidence**.

## Caller-established review and scope

`ReviewContext` contains `review_digest`, `policy_digest`, `analyzer_digest`, and
`capability_digest`. `FindingReference` contains `finding_id`, an exact relative `path`,
and nonempty `evidence_refs`. The embedding application must derive both from the actual
review and trusted policy channel, not accept model/repository claims as authority.

A snapshot contains source/context paths, content hashes, byte counts, finding references,
the context digests, and its own digest. It contains no source code. Worktree snapshots also
bind root path identity, device/inode, and file permission bits. Submitted-content snapshots
have `source_kind="submitted_content"` and `root_digest=null`; they do not describe the
server's filesystem or establish that a user's worktree contains those bytes.

Related files are explicit `context_paths`/`context_sources`. Changes to them invalidate the
snapshot even if the edited file is unchanged. Supply dependency/configuration files and
relevant revision identity through this channel when they affect the review. There is no
automatic repository-wide dependency discovery in this package. Untracked context is not
claimed to be fresh; the embedding workflow must disclose omissions.

### Memory-only API boundary

These functions never resolve supplied paths on the server or create temporary source files:

```python
capture_supplied_snapshot(
    sources: Mapping[str, str], *,
    context: ReviewContext,
    finding_refs: Sequence[FindingReference],
    context_sources: Mapping[str, str] | None = None,
    limits: EngineeringLimits | None = None,
) -> ReviewedSnapshot

propose_supplied_patch(
    sources: Mapping[str, str], snapshot: ReviewedSnapshot,
    edits: Sequence[CandidateEdit], *,
    context: ReviewContext, rationale: str,
    verification_commands: Sequence[ProcessAction] = (),
    context_sources: Mapping[str, str] | None = None,
    limits: EngineeringLimits | None = None,
) -> PatchProposal

validate_supplied_proposal(
    sources: Mapping[str, str], proposal, *,
    expected_proposal_digest: str, context: ReviewContext,
    context_sources: Mapping[str, str] | None = None,
    limits: EngineeringLimits | None = None,
) -> ProposalValidation
```

`verify_supplied_proposal` takes the same supplied **post-edit** source/context mapping,
exact proposal digest and current `ReviewContext`, plus an optional `static_reviewer`.
HTTP adapters must obtain fresh review findings before constructing a proposal. Do not
accept server filesystem roots, provider configuration, or action policy from proposal JSON.

### Local boundary

`capture_snapshot(root: Path, *, paths, context, finding_refs, context_paths=(), limits=None)`
creates a worktree-bound snapshot. The `propose_patch` and `validate_proposal` functions
have the corresponding signatures above, with `root: Path` replacing the source mapping
and no `context_sources` argument. They read existing files only and do not write.

Paths must be exact, normalized, workspace-relative POSIX spellings. Absolute paths,
traversal, backslashes, drive paths, control characters, ambiguous duplicate edits, unrelated
file/finding references, and sensitive metadata/credential files are rejected. The root,
every ancestor directory, and final files are opened without following symlinks. Hard links,
case/normalization aliases to one inode, special files, non-UTF-8 content and special
permission bits are unsupported. Local operations require POSIX directory-descriptor and
no-follow facilities; unsupported platforms fail rather than using an unsafe fallback.

The initial implementation supports replacing **existing UTF-8 regular files only**.
It does not create/delete/rename user files, recursively edit directories, or infer
authorization from a Git branch. Replacement preserves ordinary permission bits only:
ownership, ACLs and extended attributes are **not preserved**. If that metadata matters,
use a different, separately reviewed editing mechanism instead.

## Host candidates and reviewable diffs

`CandidateEdit(path, before_sha256, replacement, finding_refs)` supplies the exact original
content hash and complete replacement text. The service derives a small contextual unified
diff from the actual before/after bytes, checks its limits, rejects no-ops and includes it
in the proposal digest. It never applies a caller-authored patch parser or executes text.
The digest also binds the snapshot, origin, rationale, finding IDs and proposed commands.
Validation recomputes the diff rather than trusting a self-consistent, caller-rehashed diff.

Each edited file must be in the reviewed scope and referenced by its own finding. These are
path-level relevance and size checks, **not proof that every hunk is semantically necessary
or that the repair is correct**. Human review and a fresh analyzer pass are still needed.
Instructions in comments, source, documentation or candidate rationale are data, not policy.

Default `EngineeringLimits`:

* 16 source files and 16 context files; 128 KiB per file; 512 KiB aggregate source/context.
* At most 8 edits, a 64 KiB diff and 200 added-plus-removed lines.
* At most 300 seconds between approval creation and expiry.

The embedding application can lower or adjust limits within the schema's hard maxima.
Every operation uses the current application limits; a proposal cannot carry relaxed limits.

Potential secret output is rejected, not echoed. Guards recognize common credential/token
formats, private key markers, literal password/key assignments, bearer tokens and credential
URLs. The generation gateway additionally rejects its configured credential verbatim in
input/output. This is a conservative heuristic, **not complete DLP**: it can have false
positives and miss unfamiliar/encoded secrets. Never submit confidential context to an
unapproved provider. A pre-existing recognized secret also makes a raw removal diff unsafe
to return, so that repair must use a separately approved redacted/manual workflow.

Proposal objects and generation results necessarily contain replacement source and a diff.
Do not store/log them as receipts. Validation, apply, verification, action and generation
receipts contain bounded metadata/hashes only. The package does not persist receipts itself.

## Approval-only local application

```python
apply_proposal(
    root: Path, proposal, *,
    approval: ProposalApproval | None,
    context: ReviewContext,
    limits: EngineeringLimits | None = None,
) -> ApplyReceipt
```

The host must authenticate a human's approval of the exact displayed immutable proposal.
`ProposalApproval` binds both `proposal_digest` and `snapshot_digest`, requires the actual
boolean `approved=True`, and contains `approved_at_unix` and `expires_at_unix`. JSON alone
cannot prove human consent. Never mint approval from a risk score, a model response, or an
untrusted tool argument.

All source/context hashes, root binding, derived diff, current limits and approval are
checked before staging bytes. After same-directory temporary files are prepared, all files
are rechecked before any source replacement. Preconditions and approval are checked again
between replacements. Each replacement uses `os.replace` through held directory descriptors,
preserves ordinary permission bits, and fsyncs the file/directory.

**This is not a multi-file transaction or an adversarial-filesystem sandbox.** A final
check and a filesystem rename cannot be made into a portable content compare-and-swap;
concurrent changes can still race between them, or change already replaced files afterward.
Use only a caller-controlled, quiescent workspace, not directories writable by an attacker.
Do not use this function as a privileged service across trust boundaries.

Detected races or I/O failures stop further replacements and return `not_applied` or
`partially_applied`, with the exact paths/hashes already replaced and remaining paths.
No automatic rollback overwrites someone else's concurrent work. A process crash or cleanup
failure can leave private temporary files; inspect the workspace rather than assuming
transactional recovery. A malformed proposal fails boundary parsing without a receipt.

Submitted-content proposals cannot be applied locally. First review/capture the actual
worktree and create a new worktree-bound proposal; its new digest requires new approval.

## Static review is not behavioral testing

```python
verify_proposal(
    root: Path, proposal, *,
    expected_proposal_digest: str,
    context: ReviewContext,
    static_reviewer: StaticReviewer | None = None,
    limits: EngineeringLimits | None = None,
) -> VerificationRecord
```

The expected post-edit files and untouched context are rehashed before and after the static
adapter. The adapter is trusted application code with this signature:

```python
def static_reviewer(
    sources: Mapping[str, str], snapshot: ReviewedSnapshot
) -> StaticReviewObservation: ...
```

It must perform static analysis only, not import/run supplied code, fetch models, or invoke
test commands. The mapping is read-only. Return `completed`, `partial`, `unavailable` or
`error`, the actual `review_digest`, `analyzed_paths`, `unreviewed_paths`, and
`remaining_finding_refs`. It must also report non-OK results not mapped to original references
through `additional_findings`, a default-empty tuple of at most 128 `AdditionalFinding`
records. Each contains only `finding_id`, `path`, `check_id`, and the actual non-OK `result`
(`flagged`, `needs_context`, `uncertain`, `unsupported`, `too_large`, or `error`); there are no
source snippets or free-text messages. These are additional observed results, not proof they
were newly introduced. IDs must be unique and distinct from all original references; paths
must belong to the requested source scope and have explicit analyzed/unreviewed coverage.
A partial review can retain observed findings on unreviewed paths. Unavailable/error
observations cannot claim findings. Excess results must yield an explicit partial/error
observation, never silent truncation followed by a clean result.

Remaining references are the **original** finding IDs; the adapter must map
them using actual check/location evidence, not assume post-edit IDs are stable. Every
requested path must have explicit coverage. Invalid coverage or adapter errors are errors.

Per-finding status is `still_detected`, `no_longer_detected`, or `not_reviewed`.
`verified_snapshot` means the expected content/context matched, not that every analyzer
was available. Inspect `static_review.status` and unreviewed scope.
Resolving every original reference is not a clean-review gate when
`static_review.additional_findings` is nonempty. Callers must retain these results and fail
their completion gate on additional non-OK findings rather than only checking original IDs.
`behavioral_tests` is always `not_run`, `behavioral_reason` is
`no_approved_isolated_runner`, and `behavior_proven` is always false in this package.
An approved isolated runner and its authenticated observed results are separate work;
there is no runner, remote shell endpoint, or test-result fabrication here.

## Typed action scope

```python
review_action(action, *, policy: ActionPolicy | None, root: Path | None = None) -> ActionReview
```

`ActionRequest` wraps one of:

* `ProcessAction(action_id, executable, argv=(), cwd=".", filesystem_targets=(), network_targets=())`.
* `FilesystemAction(action_id, operation="read" | "write" | "delete", path)`.
* `NetworkAction(action_id, method, url)`.

Policy is a separate application/user argument, never a request field. `ActionPolicy`
contains a policy ID/revision, `authority="application" | "user"`, and exact process,
filesystem and network allowlists. The host must establish that authority out of band.
Repository policy text cannot broaden it. No policy file is discovered or loaded here.

`ProcessGrant` binds exact executable, argv, cwd and declared targets, not just the name of
a powerful interpreter. `FilesystemGrant` binds an exact path and allowed operations.
`NetworkGrant` binds an exact HTTP(S) URL and methods; wildcards, queries, fragments,
userinfo, redirects and encoded/ambiguous path semantics are not supported. Cleartext
non-loopback network operations need additional review even if declared.

Shell strings and unknown fields fail schema validation. Shell interpreters, PATH-based
executable names and missing actual filesystem scope require further review. Explicit
scope conflicts are `out_of_scope`. A matching invocation is only
`within_declared_scope`; it does not prove a program's actual runtime effects or resolve
every argument's semantics. Recheck in the executing host; this read-only assessment is
not a future filesystem lock.

All responses have `authorized=false`, `executed=false`, `policy_changed=false` and
`scope_only=true`. Missing authority is `needs_review` with unknown risk, not approval.

## Optional coding-provider gateway

```python
gateway = OpenAICompatibleGateway(
    config: GenerationConfig | None = None,
    *,
    transport: GenerationTransport | None = None,
    input_token_counter: Callable[[Sequence[Mapping[str, str]]], int] | None = None,
    clock: Callable[[], float] = time.monotonic,
)
result = gateway.generate(request: GenerationRequest)  # GenerationResult(receipt, proposal)
```

The pseudocode above describes signatures, not automatic registration or inference.
Construction performs no I/O. Default configuration is disabled. `GenerationConfig` is
owned by the application and contains `enabled`, `endpoint`, `model`, `allow_hosted`,
an optional `SecretStr` API credential, `GenerationBudget`, and `EngineeringLimits`.
The credential is excluded from serialization and repr. No environment key, existing
login, repository configuration, provider URL from a request, or model-emitted URL is used.
Non-loopback HTTPS providers additionally require explicit `allow_hosted=True`.

`endpoint` is the complete configured chat-completions URL. HTTPS uses normal certificate
and hostname verification. Cleartext is allowed only for **literal loopback IPs**, not
DNS names such as `localhost`; that avoids DNS-based cleartext scope changes. The standard
library transport uses no proxy environment configuration and follows no redirects, even
same-host redirects. Error/redirect bodies are discarded. Compressed responses are rejected.
DNS lookup, connection/read work and total output are bounded; a timed-out DNS worker can
finish DNS later but has no source, credentials, or ability to send the inference request.
A timeout does not prove that an upstream provider stopped billing/computation.

`GenerationRequest` contains the reviewed snapshot, caller goal, exact
`GenerationSource(path, sha256, content)` source tuple, and an optional context-source tuple.
All paths/hashes must match the snapshot. Repository text is explicitly framed as untrusted
data in the prompt, but framing alone is not a prompt-injection defense: generated JSON
must pass the same scope, digest, diff, size and secret checks as a host candidate.
No tools or provider-selected function calls are enabled or accepted.

Default budget: 64 KiB complete request context, 16,384 input token budget units,
1,024 requested output tokens, 32,768 aggregate reserved tokens, 64 KiB response bytes,
one attempt and 20 seconds total. Nothing is silently truncated. By default, input
reservation uses UTF-8 bytes plus framing allowance as a conservative byte-tokenizer
bound, **not measured token usage or a universal tokenizer guarantee**. Configure a
trusted model-specific counter for other tokenizers/exact accounting. The remote endpoint
must honor `max_tokens`; overruns in reported usage are rejected, not reclassified as success.

Additional attempts require an explicit configured limit (maximum three), with full
input/output reservation per attempt. Only explicit transient HTTP statuses can retry;
ambiguous transport errors/timeouts and invalid candidates do not trigger an automatic
paid second pass. A successful retry after an attempt with unknown usage leaves aggregate
usage unknown, rather than hiding that attempt.

`GenerationResult` carries a validated proposal only on `generated`. Disabled/unconfigured
generation is `unavailable`; input/transport/provider/validation failures are explicit
`error` codes. `GenerationReceipt` contains metadata only. Usage is reported as
`provider_reported` only when complete, validated token counts were returned for every
attempt. Missing token counts and billed cost remain `null`; OpenAI-compatible token
counts do not establish actual cost. Provider error text and credentials are never echoed.
No real provider, model weights, training, latency/cost benchmark, or behavioral patch
quality has been validated by the mock-transport test suite.

## Validation

Focused tests are `tests/test_engineering.py`, `tests/test_engineering_actions.py` and
`tests/test_engineering_generation.py`. They use temporary homes/projects, offline model
settings, blocked real sockets, fake provider responses and bounded transport doubles.
They cover stale context/approval, duplicate/unrelated edits, traversal and symlinks,
secret-bearing output, prompt injection as data, mixed-file prechecks, partial-write
failures, unavailable/failed static review, no execution/authorization, provider budgets,
redirect rejection and unknown cost accounting. One static flow uses the existing local
rules engine to re-review a synthetic command-concatenation repair without executing it.

Run pytest with `PYTHONPATH=src`, `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, a temporary
home and an already-installed environment; no dependency/weight downloads are needed.
Run Ruff over the new package/tests and mypy over `src/polaris/engineering`.

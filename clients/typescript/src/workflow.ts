/** Versioned static workflow, separate from the experimental assessment/model contract. */
import type { FileInput, Finding, ModelInfo, Result } from "./index.js";

export type WorkflowCheck =
  | "sql_injection" | "command_injection" | "code_injection" | "xss" | "ssrf"
  | "open_redirect" | "path_traversal" | "secret_exposure" | "missing_authorization"
  | "insecure_auth_crypto" | "unsafe_security_configuration"
  /** GitHub Actions workflows (and Dockerfiles for the last three). */
  | "workflow_injection" | "untrusted_checkout" | "excessive_privileges" | "unpinned_dependency"
  | "unverified_download" | "api_authorization";
/** Registered source kinds; plugins can add more. */
export type WorkflowLanguage =
  | "python" | "javascript" | "typescript" | "rust" | "github_actions" | "dockerfile" | "unsupported"
  | (string & {});
/** What a check protects; every check belongs to exactly one category. */
export type Category = "security" | "correctness" | "reliability" | "performance" | "maintainability";
export type AnalyzerAvailability =
  | "available" | "not_probed" | "unavailable" | "disabled"
  | "version_mismatch" | "sandbox_unavailable" | "error";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

/** Repository review settings (`.polaris.toml` [workflow]); advisory, never trusted policy. */
export interface ProjectSettings {
  auth_guards?: string[];
  public_routes?: string[];
  honor_suppressions?: boolean;
  /** Generated/vendored paths; reported as excluded, never silently dropped. */
  exclude?: string[];
}

/** No executable, generator URL, or trusted policy can be supplied through a request. */
export interface WorkflowSettings {
  checks?: WorkflowCheck[];
  include?: string[];
  exclude?: string[];
  max_files?: number;
  max_file_bytes?: number;
  max_total_bytes?: number;
  max_units?: number;
  max_findings?: number;
  /** "redacted" omits source snippets from findings; traces keep line numbers. */
  evidence?: "full" | "redacted";
  project?: ProjectSettings;
}

export interface WorkflowInput {
  files: FileInput[];
  config?: WorkflowSettings | null;
}

export interface AnalyzerCapability {
  analyzer_id: string;
  availability: AnalyzerAvailability;
  version: string | null;
  expected_version: string;
  distribution_version?: string | null;
  expected_distribution_version?: string | null;
  identity_digest?: string | null;
  upstream_artifact_sha256?: string | null;
  rule_pack_version: string;
  rule_pack_digest: string;
  languages: WorkflowLanguage[];
  checks: string[];
  provenance: string;
  license: string;
  reason: string;
  limitations: string[];
}

export interface CheckCapability {
  language: WorkflowLanguage;
  extensions: string[];
  /** File names and path patterns that also select this language. */
  path_patterns: string[];
  check_id: string;
  analyzer_id: string;
  availability: AnalyzerAvailability;
  requires_trusted_policy: boolean;
  /** Opt-in analyzers (Semgrep CE) that add findings beyond the built-in rules. */
  supplementary: boolean;
  limitations: string[];
}

export interface WorkflowCapabilities {
  format: "polaris.capabilities/0.2.0";
  workflow_format: "polaris.review/0.2.0";
  default_checks: string[];
  analyzers: AnalyzerCapability[];
  matrix: CheckCapability[];
  limitations: string[];
}

export interface CheckCoverage {
  path: string;
  language: WorkflowLanguage;
  check_id: string;
  analyzer_id: string | null;
  /** not_applicable: documentation, assets, deleted or generated files (never a gap). */
  status: "checked" | "not_checked" | "partial" | "not_applicable";
  reason: string;
  required: boolean;
}

export interface WorkflowCoverage {
  files_total: number;
  files_analyzed: number;
  files_not_fully_checked: number;
  checks_total: number;
  checks_completed: number;
  complete: boolean;
  statuses: Record<string, number>;
  entries: CheckCoverage[];
  omissions: string[];
}

/** One hop from an untrusted source to the sink. */
export interface TraceStep {
  kind: "source" | "step" | "call" | "sink";
  line: number;
  label: string;
  /** Set when the hop is in another file than the finding. */
  path: string | null;
}

/** A deterministic, rule-generated replacement for one line. Review before applying. */
export interface SuggestedEdit {
  line: number;
  original: string;
  replacement: string;
  note: string;
}

export interface WorkflowFinding extends Finding {
  analyzer_id: string;
  analyzer_version: string;
  rule_id: string;
  evidence_digest: string;
  severity: Severity | null;
  confidence: Confidence | null;
  cwe: string | null;
  category: Category | null;
  /** Stable across unrelated edits; used by `.polaris/baseline.json`. */
  fingerprint: string | null;
  /** Absent when the review ran with evidence: "redacted". */
  snippet: string | null;
  snippet_start_line: number | null;
  trace: TraceStep[];
  suggested_edit: SuggestedEdit | null;
  /** For needs_context findings: the question to answer before deciding. */
  verify: string | null;
  call_sites: string[];
  suppression: string | null;
}

/** The tool's own SARIF level for an imported result. */
export type ImportedLevel = "error" | "warning" | "note" | "none";

/** A result another tool reported in an imported SARIF file (`--import-sarif`). Polaris did not
 * verify it; it never changes Polaris results, coverage or exit codes unless the caller opts in. */
export interface ImportedFinding {
  import_id: string;
  tool: string;
  tool_version: string | null;
  rule_id: string | null;
  level: ImportedLevel;
  /** From the tool's security-severity when given, otherwise from its level (error: medium). */
  severity: Severity;
  security_severity: number | null;
  category: Category;
  path: string;
  /** null for results the tool reported for a whole file. */
  start_line: number | null;
  end_line: number | null;
  message: string;
  cwe: string[];
  /** The Polaris check this kind of result relates to (from its CWE or a curated rule map). */
  related_check: WorkflowCheck | null;
  fingerprint: string;
  sarif_digest: string;
  /** Id of the Polaris finding at the same place that reports the same weakness. */
  corroborates: string | null;
  verified_by_polaris: false;
}

/** One imported SARIF file: what was kept from it, or the fixed code it was rejected with. */
export interface SarifImport {
  name: string;
  digest: string | null;
  status: "imported" | "rejected";
  error:
    | "sarif_unavailable" | "sarif_too_large" | "sarif_total_limit" | "invalid_sarif"
    | "unsupported_sarif_version" | null;
  tools: string[];
  runs: number;
  /** Runs without results or with an unsuccessful execution: the tool may not have finished. */
  failed_runs: number;
  results: number;
  imported: number;
  corroborating: number;
  /** Results left out, by fixed reason (duplicate, outside_review_scope, invalid_path, ...). */
  dropped: Record<string, number>;
}

/** A data read or write an entry point reaches. */
export interface SurfaceOperation {
  line: number;
  /** A short code label (for example "db.user.delete"). */
  label: string;
}

/** One request handler, route or server action, its auth guard (or none), and what it reaches.
 * Evidence for review, not an access-control model: `guarded` means a recognized guard call was
 * seen, not that authorization is correct. */
export interface EntryPoint {
  path: string;
  line: number;
  end_line: number;
  kind: "route_handler" | "pages_api" | "server_action" | "express_handler" | "middleware" | "page";
  /** "GET", "POST /users", a server action's name... */
  name: string;
  method: string | null;
  guarded: boolean;
  guards: string[];
  /** The file matches the configured `[workflow].public_routes`. */
  public: boolean;
  rate_limited: boolean;
  writes: SurfaceOperation[];
  reads: SurfaceOperation[];
  /** Dangerous calls the handler reaches, tainted or not. */
  sinks: number;
  /** Ids of reported findings inside the handler. */
  findings: string[];
  analyzer_id: string;
}

export interface WorkflowReviewReport {
  format: "polaris.review/0.2.0";
  model: ModelInfo;
  checks: string[];
  summary: {
    files_reviewed: number;
    files_skipped: Record<string, number>;
    findings_total: number;
    results: Partial<Record<Result, number>>;
    elapsed_ms: number;
    files_not_applicable: number;
    languages: Record<string, number>;
    severities: Partial<Record<Severity, number>>;
    categories: Partial<Record<Category, number>>;
    suppressed: number;
    suppressions_added: number;
    baselined: number;
  };
  findings: WorkflowFinding[];
  coverage: WorkflowCoverage;
  capabilities: WorkflowCapabilities;
  provenance: {
    source_digests: Record<string, string | null>;
    before_digests: Record<string, string | null>;
    checks_digest: string;
    guard_policy_digest: string | null;
    capability_digest: string;
    snapshot_digest: string;
    context_digests: Record<string, string>;
    /** Content digests of imported SARIF files (never their location). */
    imported_digests: string[];
  };
  notices: string[];
  /** Moved out by inline polaris-ignore comments or the baseline; never counted. */
  suppressed: WorkflowFinding[];
  baselined: WorkflowFinding[];
  /** Other tools' results from imported SARIF, within the reviewed scope; never counted. */
  imported: ImportedFinding[];
  imports: SarifImport[];
  /** Entry points in reviewed files (TypeScript/JavaScript today); descriptive, never counted. */
  surface: EntryPoint[];
}

export interface WorkflowSnapshot {
  format: string;
  kind: "worktree" | "git_index" | "git_revision" | "submitted_content";
  digest: string;
  repository_id: string | null;
  worktree_id: string | null;
  head: string | null;
  index_digest: string | null;
  provenance_digest: string | null;
  complete: boolean;
  /** null for submitted content: a server cannot assert freshness of a client's worktree. */
  fresh: boolean | null;
  files_count: number;
  omissions: Record<string, string>[];
  omitted_scope: string[];
}

export interface RelatedFile {
  path: string;
  digest: string;
  bytes: number;
  reason:
    | "relative_import" | "alias_import" | "importer" | "tsconfig" | "python_import"
    | "test_candidate" | "project_manifest";
  /** True when flows through this file were followed (it is not itself reviewed). */
  used_for_analysis: boolean;
}

export interface WorkflowReport {
  format: "polaris.workflow/0.1.0";
  report_id: string;
  status: "complete" | "incomplete" | "stale" | "error";
  summary: string;
  finding_count: number;
  snapshot: WorkflowSnapshot;
  changes: {
    path: string;
    previous_path: string | null;
    kind: "added" | "modified" | "renamed" | "deleted" | "unreadable" | "supplied";
    before_digest: string | null;
    after_digest: string | null;
    changed_lines: number | null;
  }[];
  context: { files: RelatedFile[]; omissions: string[]; bytes_read: number; scope: string };
  review: WorkflowReviewReport;
  tests_status: "not_run";
  notices: string[];
}

export interface CandidateEdit {
  path: string;
  before_sha256: string;
  replacement: string;
  finding_refs: string[];
}

/** A proposal only. Its argv and declared effects are never executed by the API. */
export interface ProcessAction {
  kind?: "process";
  action_id: string;
  executable: string;
  argv?: string[];
  cwd?: string;
  filesystem_targets?: string[];
  network_targets?: string[];
}

export interface CandidateRequest {
  edits: CandidateEdit[];
  rationale: string;
  verification_commands?: ProcessAction[];
  expected_snapshot_digest?: string | null;
}

export interface WorkflowRepairInput extends WorkflowInput {
  candidate: CandidateRequest;
}

export interface ReviewContext {
  review_digest: string;
  policy_digest: string;
  analyzer_digest: string;
  capability_digest: string;
}

export interface RepairFileState {
  path: string;
  sha256: string;
  size_bytes: number;
  mode: number | null;
}

export interface RepairSnapshot {
  format: "polaris.repair-snapshot/0.1.0";
  source_kind: "worktree" | "submitted_content";
  root_digest: string | null;
  files: RepairFileState[];
  context_files: RepairFileState[];
  context: ReviewContext;
  finding_refs: { finding_id: string; path: string; evidence_refs: string[] }[];
  snapshot_digest: string;
}

export interface PatchProposal {
  format: "polaris.proposal/0.1.0";
  snapshot: RepairSnapshot;
  origin: "host_candidate" | "configured_generator";
  edits: CandidateEdit[];
  rationale: string;
  verification_commands: Required<ProcessAction>[];
  diff: string;
  changed_lines: number;
  proposal_digest: string;
}

export type EngineeringAction =
  | (ProcessAction & { kind: "process" })
  | { kind: "filesystem"; action_id: string; operation: "read" | "write" | "delete"; path: string }
  | { kind: "network"; action_id: string; method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"; url: string };

export interface ActionRequest {
  format?: "polaris.action-review/0.1.0";
  action: EngineeringAction;
}

export interface ActionReview {
  format: "polaris.action-review/0.1.0";
  action_digest: string;
  policy_digest: string | null;
  status: "within_declared_scope" | "out_of_scope" | "needs_review";
  risk: "low" | "elevated" | "unknown";
  reasons: { code: string; message: string }[];
  safer_alternative: string | null;
  authorized: false;
  executed: false;
  policy_changed: false;
  scope_only: true;
}

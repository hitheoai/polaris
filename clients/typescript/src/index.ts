/**
 * Typed fetch client for the Polaris REST API (`polaris serve`).
 *
 *   import { PolarisClient } from "@theovex/polaris";
 *   const polaris = new PolarisClient({ baseUrl: "http://127.0.0.1:8780" });
 *   const report = await polaris.reviewCode("def f(db, n):\n    db.execute('SELECT ' + n)\n", { engine: "rules" });
 *   for (const finding of report.findings) console.log(finding.result, finding.path, finding.message);
 *
 * The types mirror the server's OpenAPI description, shipped as openapi.json in this package.
 * Findings estimate risk; they never approve, block or authorize anything.
 */
import type {
  ActionRequest, ActionReview, PatchProposal, WorkflowCapabilities,
  WorkflowInput, WorkflowRepairInput, WorkflowReport,
} from "./workflow.js";
export * from "./workflow.js";

/** hybrid (default): static rules decide and the model adds a second opinion; model: the model alone. */
export type Engine = "hybrid" | "model" | "rules";
export type Result = "flagged" | "ok" | "needs_context" | "uncertain" | "unsupported" | "too_large" | "error";

/** The model's view in a hybrid review. It never changes the finding's result. */
export interface SecondOpinion {
  result: Result;
  risk: number | null;
  reason: string;
}

export interface Finding {
  finding_id: string;
  path: string;
  start_line: number;
  end_line: number;
  symbol: string;
  check_id: string;
  title: string;
  result: Result;
  engine: "model" | "rules" | "static";
  risk: number | null;
  threshold: number | null;
  reason: string;
  message: string;
  guidance: string | null;
  details: string[];
  request_digest: string | null;
  second_opinion: SecondOpinion | null;
}

export interface ModelInfo {
  engine: Engine;
  model_version: string | null;
  release_status: string;
  runtime_variant: string | null;
  calibration_version: string | null;
}

export interface ReviewSummary {
  files_reviewed: number;
  files_skipped: Record<string, number>;
  units_total: number;
  units_assessed: number;
  units_prefiltered: number;
  results: Partial<Record<Result, number>>;
  cache_hits: number;
  elapsed_ms: number;
  units_per_second: number | null;
  second_opinion_disagreements: number;
}

export interface ReviewReport {
  format: "polaris.review/0.1.0";
  model: ModelInfo;
  checks: string[];
  policy_source: string;
  summary: ReviewSummary;
  findings: Finding[];
  notices: string[];
}

/** A whole file. `path` only labels findings; the server never reads its own disk. */
export interface FileInput {
  path: string;
  content: string;
  before?: string | null;
}

/** Per-request settings. Policy statements are trusted context about your own code. */
export interface ReviewSettings {
  checks?: string[];
  policy?: string[];
  flag_threshold?: number;
}

export interface ReviewOptions {
  engine?: Engine;
  config?: ReviewSettings;
}

export type ReviewInput = { diff: string } | { files: FileInput[] } | { code: string; path?: string };

export type ApiErrorCode =
  | "unauthorized"
  | "invalid_host"
  | "not_found"
  | "method_not_allowed"
  | "unsupported_media_type"
  | "payload_too_large"
  | "too_many_files"
  | "invalid_json"
  | "invalid_request"
  | "rate_limited"
  | "queue_full"
  | "model_unavailable"
  | "internal_error";

export interface ApiErrorBody {
  kind: "api_error";
  code: ApiErrorCode;
  message: string;
  retryable: boolean;
  fields: string[];
}

export interface HealthResponse {
  status: "ok";
  version: string;
  model_loaded: boolean;
  api_keys_required: boolean;
}

export interface ModelStatus {
  loaded: boolean;
  status: string;
  message: string;
  model_version: string | null;
  release_status: string | null;
  runtime_variant: string | null;
  calibration_version: string | null;
  max_input_tokens: number | null;
  supported_checks: string[];
  /** "local": the model runs on this server; "remote": it is forwarded to the Polaris API. */
  source: "local" | "remote" | null;
  /** Estimated risk at or above which each check is flagged. */
  flag_thresholds: Record<string, number>;
  identity: RuntimeIdentity | null;
}

export interface ModelsResponse {
  model: ModelStatus;
  engines: { engine: Engine; available: boolean; message: string }[];
}

export interface UsageResponse {
  key_id: string;
  since: string;
  usage: {
    requests: number;
    reviews: number;
    assessments: number;
    files_reviewed: number;
    functions_total: number;
    functions_assessed: number;
    rejected: number;
  };
}

/** A polaris.assessment/0.1.0 request; see openapi.json#/components/schemas/AssessmentRequest. */
export interface AssessmentRequest {
  contract_version: "polaris.assessment/0.1.0";
  request_id: string;
  requested_checks: { check_id: string; check_revision?: number }[];
  action: Record<string, unknown>;
  evidence: Record<string, unknown>[];
  trusted_context: Record<string, unknown>[];
  known_omissions?: string[];
}

export interface RuntimeIdentity {
  model_version: string | null;
  model_digest: string | null;
  tokenizer_version: string | null;
  preprocessing_version: string;
  calibration_version: string | null;
  calibration_digest: string | null;
  operating_profile_version: string | null;
  operating_profile_digest: string | null;
  max_input_tokens: number | null;
  runtime_variant: string | null;
  release_status: "not_loaded" | "experimental" | "qualified";
}

export interface CheckResult {
  check_id: string;
  check_revision: number;
  status: "assessed" | "abstain" | "unsupported";
  reason_codes: string[];
  probabilities: { risk_present: number; risk_absent: number } | null;
  coverage: Record<string, unknown>;
  evidence_refs: Record<string, unknown>[];
}

export interface AssessmentResponse {
  kind: "assessment";
  contract_version: "polaris.assessment/0.1.0";
  registry_version: string;
  request_id: string;
  request_digest: string;
  runtime: RuntimeIdentity;
  results: CheckResult[];
}

/** A contract error envelope from /v1/assess: returned, not thrown. */
export interface ContractError {
  kind: "error";
  contract_version: "polaris.assessment/0.1.0";
  request_id: string | null;
  category: "input" | "runtime";
  code: string;
  message: string;
  retryable: boolean;
}

export class PolarisApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;
  readonly retryAfterSeconds: number | null;
  readonly fields: string[];

  constructor(status: number, code: string, message: string, retryable = false,
              retryAfterSeconds: number | null = null, fields: string[] = []) {
    super(`${code} (${status}): ${message}`);
    this.name = "PolarisApiError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.retryAfterSeconds = retryAfterSeconds;
    this.fields = fields;
  }
}

export interface ClientOptions {
  /** Default http://127.0.0.1:8780. */
  baseUrl?: string;
  /** Sent as `Authorization: Bearer <key>`; only over https or to this machine. */
  apiKey?: string;
  /** Per-request timeout in milliseconds (default 120000). */
  timeoutMs?: number;
  /** A fetch implementation (default: the global fetch). */
  fetch?: typeof fetch;
}

function isLoopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host === "::1" || /^127(\.\d{1,3}){3}$/.test(host);
}

export class PolarisClient {
  readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetcher: typeof fetch;

  constructor(options: ClientOptions = {}) {
    const url = new URL(options.baseUrl ?? "http://127.0.0.1:8780");
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("baseUrl must be an http:// or https:// address.");
    }
    if (options.apiKey && url.protocol === "http:" && !isLoopback(url.hostname)) {
      throw new Error("Use https:// to send an API key to another machine.");
    }
    this.baseUrl = url.toString().replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 120_000;
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  health(): Promise<HealthResponse> {
    return this.call<HealthResponse>("GET", "/health");
  }

  models(): Promise<ModelsResponse> {
    return this.call<ModelsResponse>("GET", "/v1/models");
  }

  capabilities(): Promise<Record<string, unknown>> {
    return this.call<Record<string, unknown>>("GET", "/v1/capabilities");
  }
  /** Actual static-analyzer availability; unsupported or unavailable is not clean. */
  workflowCapabilities(): Promise<WorkflowCapabilities> {
    return this.call<WorkflowCapabilities>("GET", "/v1/workflow/capabilities");
  }

  /** Review submitted snapshots; never resolves labels as server filesystem paths. */
  reviewWorkflow(input: WorkflowInput): Promise<WorkflowReport> {
    return this.call<WorkflowReport>("POST", "/v1/workflow/review", input);
  }

  /** Validate a host candidate against observed findings, without applying it or calling a model. */
  proposeRepair(input: WorkflowRepairInput): Promise<PatchProposal> {
    return this.call<PatchProposal>("POST", "/v1/workflow/propose", input);
  }

  /** Policy is administrator-owned. Results never grant permission or execute an operation. */
  reviewAction(input: ActionRequest): Promise<ActionReview> {
    return this.call<ActionReview>("POST", "/v1/workflow/action", input);
  }

  usage(): Promise<UsageResponse> {
    return this.call<UsageResponse>("GET", "/v1/usage");
  }

  /** Review a diff, whole files or a snippet. */
  review(input: ReviewInput, options: ReviewOptions = {}): Promise<ReviewReport> {
    return this.call<ReviewReport>("POST", "/v1/review", { ...input, ...options, format: "json" });
  }

  reviewCode(code: string, options: ReviewOptions & { path?: string } = {}): Promise<ReviewReport> {
    const { path, ...rest } = options;
    return this.review(path ? { code, path } : { code }, rest);
  }

  /** Reviewed from the diff's hunks only; send whole files for full function context. */
  reviewDiff(diff: string, options: ReviewOptions = {}): Promise<ReviewReport> {
    return this.review({ diff }, options);
  }

  reviewFiles(files: FileInput[], options: ReviewOptions = {}): Promise<ReviewReport> {
    return this.review({ files }, options);
  }

  /** The same review as SARIF 2.1.0, for code-scanning tools. */
  sarif(input: ReviewInput, options: ReviewOptions = {}): Promise<Record<string, unknown>> {
    return this.call<Record<string, unknown>>("POST", "/v1/review", { ...input, ...options, format: "sarif" });
  }

  /** The assessment contract. Contract error envelopes are returned, not thrown. */
  async assess(request: AssessmentRequest): Promise<AssessmentResponse | ContractError> {
    const { status, body, headers } = await this.send("POST", "/v1/assess", request);
    if (isObject(body) && (body.kind === "assessment" || body.kind === "error")) {
      return body as unknown as AssessmentResponse | ContractError;
    }
    throw toError(status, body, headers);
  }

  /** Up to 64 independent requests in one call; one envelope per request, in order. */
  async assessBatch(requests: AssessmentRequest[]): Promise<(AssessmentResponse | ContractError)[]> {
    const body = await this.call<{ results: (AssessmentResponse | ContractError)[] }>(
      "POST", "/v1/assess/batch", { requests });
    return body.results;
  }

  private async call<T>(method: string, path: string, payload?: unknown): Promise<T> {
    const { status, body, headers } = await this.send(method, path, payload);
    if (status >= 400) {
      throw toError(status, body, headers);
    }
    return body as T;
  }

  private async send(method: string, path: string, payload?: unknown):
      Promise<{ status: number; body: unknown; headers: Headers }> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.apiKey) {
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    let response: Response;
    try {
      response = await this.fetcher(this.baseUrl + path, {
        method,
        headers,
        body: payload === undefined ? undefined : JSON.stringify(payload),
        // Refuse redirects so an API key is never re-sent to another address.
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new PolarisApiError(0, "connection_failed", `Couldn't reach Polaris at ${this.baseUrl} (${reason}).`, true);
    }
    const text = await response.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    return { status: response.status, body, headers: response.headers };
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toError(status: number, body: unknown, headers: Headers): PolarisApiError {
  const data: Record<string, unknown> = isObject(body) ? body : {};
  const retryAfter = headers.get("retry-after");
  return new PolarisApiError(
    status,
    typeof data.code === "string" ? data.code : "http_error",
    typeof data.message === "string" ? data.message : `The server answered with status ${status}.`,
    data.retryable === true,
    retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null,
    Array.isArray(data.fields) ? data.fields.filter((field): field is string => typeof field === "string") : [],
  );
}

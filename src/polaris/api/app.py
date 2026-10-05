"""The Polaris REST API: versioned, local-only by default, and it never keeps submitted code.

Every request passes one guard before any endpoint runs: host check (local servers only), API
key, per-key rate limit, JSON content type, body size limit and strict JSON parsing. Errors are
typed envelopes without stack traces, and request bodies are never logged.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ValidationError
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from polaris import __version__
from polaris.api.models import (
    ApiError,
    ApiErrorCode,
    AssessBatchRequest,
    AssessBatchResponse,
    EngineInfo,
    HealthResponse,
    ModelsResponse,
    ReviewRequest,
    UsageCounts,
    UsageResponse,
)
from polaris.api.security import ApiKey, KeyStore, QueueFull, RateLimiter, UsageTracker, WorkQueue
from polaris.contract import AssessmentRequest, AssessmentResponse, ErrorResponse
from polaris.errors import PolarisError
from polaris.integrations import ModelUnavailable, ReviewService, request_config, settings_problem
from polaris.jsonio import load_json
from polaris.review import ReviewConfig, Reviewer, ReviewReport, SourceFile, to_sarif

if TYPE_CHECKING:
    from polaris.engineering import ActionPolicy
    from polaris.review.analyzers import AnalysisRuntime
    from polaris.review.models import TrustedGuardPolicy

LOG = logging.getLogger("polaris.api")
WORK = "polaris.work"
KEY_ID = "polaris.key_id"
ENDPOINTS = frozenset({"/v1/review", "/v1/assess", "/v1/assess/batch", "/v1/models", "/v1/capabilities",
                       "/v1/usage", "/v1/workflow/review", "/v1/workflow/propose",
                       "/v1/workflow/action", "/v1/workflow/capabilities"})
DOC_PATHS = ("/docs", "/redoc")
SECURITY_HEADERS = (
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("x-frame-options", "DENY"),
)
CSP = "default-src 'none'; frame-ancestors 'none'"
REMOTE_NEEDS_KEYS = (
    "Serving other machines requires API keys. Create one with "
    "`polaris serve keys create --file keys.json`, then start with --api-keys keys.json "
    "(or set POLARIS_API_KEYS)."
)
RUNTIME_UNAVAILABLE = frozenset({"model_unavailable", "artifact_invalid", "unqualified_model",
                                 "calibration_mismatch"})
DESCRIPTION = """\
Versioned security review and bounded engineering proposals. Legacy Python/model contracts remain separate.

* `POST /v1/review` takes a diff, whole files or a snippet and returns findings (JSON or SARIF).
* `POST /v1/assess` runs the `polaris.assessment/0.1.0` contract; `POST /v1/assess/batch` runs
  up to 64 of them at once (the hosted-model client uses it).
* Findings estimate risk; they never approve, block or authorize anything.
* `/v1/workflow/review` adds explicit coverage and content binding; `/v1/workflow/propose`
  validates host candidates. `/v1/workflow/action` assesses configured scope without execution.
* Project code is parsed, never run. The workflow API defaults to memory-only analysis.
  An administrator may explicitly enable isolated transient source files for external analyzers.
  Request bodies are not logged or persistently stored; proposal responses contain scoped edits.
  No remote apply or arbitrary shell endpoint exists.

Send `Authorization: Bearer <key>` when the server was started with API keys.
"""


@dataclass(frozen=True)
class ApiSettings:
    """Limits and switches for one API server. Defaults are safe for local use."""

    host: str = "127.0.0.1"
    port: int = 8780
    max_body_bytes: int = 5 * 1024 * 1024
    max_files: int = 500
    rate_per_minute: float = 0.0
    burst: int = 30
    workers: int = 1
    queue_depth: int = 16
    cors_origins: tuple[str, ...] = ()
    docs: bool = False
    usage_log: Path | None = None

    def limits(self) -> dict[str, int]:
        return {"max_body_bytes": self.max_body_bytes, "max_files": self.max_files,
                "max_file_bytes": ReviewConfig().max_file_bytes,
                "rate_per_minute": math.ceil(self.rate_per_minute)}


def is_loopback(host: str) -> bool:
    name = host.strip().strip("[]").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def local_hosts(port: int) -> frozenset[str]:
    names = ("127.0.0.1", "localhost", "[::1]")
    return frozenset({*names, *(f"{name}:{port}" for name in names)})


def error_response(status: int, code: ApiErrorCode, message: str, *, retryable: bool = False,
                   fields: list[str] | None = None,
                   headers: dict[str, str] | None = None) -> JSONResponse:
    body = ApiError(code=code, message=message, retryable=retryable, fields=fields or [])
    return JSONResponse(body.model_dump(mode="json"), status_code=status, headers=headers)


def busy() -> JSONResponse:
    return error_response(429, "queue_full", "The server is busy with other reviews. Try again shortly.",
                          retryable=True, headers={"Retry-After": "1"})


def ok(model: BaseModel) -> JSONResponse:
    return JSONResponse(model.model_dump(mode="json"))


class Reject(Exception):
    """Stop a request in the guard with a typed error envelope."""

    def __init__(self, status: int, code: ApiErrorCode, message: str, *,
                 retry_after: int | None = None, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.headers = dict(headers or {})
        if retry_after is not None:
            self.headers["Retry-After"] = str(retry_after)

    def response(self) -> JSONResponse:
        return error_response(self.status, self.code, self.message,
                              retryable=self.status in (429, 503), headers=self.headers)


class ClientDisconnected(Exception):
    pass


@dataclass
class ApiContext:
    settings: ApiSettings
    keys: KeyStore | None
    limiter: RateLimiter
    usage: UsageTracker
    queue: WorkQueue
    allowed_hosts: frozenset[str] | None

    def authenticate(self, headers: Headers) -> ApiKey | None:
        if self.keys is None:
            return None
        scheme, _, token = headers.get("authorization", "").partition(" ")
        record = self.keys.verify(token.strip()) if scheme.lower() == "bearer" else None
        if record is None:
            raise Reject(401, "unauthorized",
                         "This server needs an API key: send the header 'Authorization: Bearer <key>'.",
                         headers={"WWW-Authenticate": "Bearer"})
        return record

    async def read_body(self, headers: Headers, receive: Receive) -> Receive:
        """Read at most the body limit, parse it strictly, and hand the same bytes onward."""
        media = headers.get("content-type", "").split(";")[0].strip().lower()
        if media != "application/json":
            raise Reject(415, "unsupported_media_type",
                         "Send JSON with the header 'Content-Type: application/json'.")
        limit = self.settings.max_body_bytes
        too_large = f"Requests are limited to {limit:,} bytes."
        declared = headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            raise Reject(413, "payload_too_large", too_large)
        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise ClientDisconnected
            body.extend(message.get("body", b""))
            if len(body) > limit:
                raise Reject(413, "payload_too_large", too_large)
            more = bool(message.get("more_body", False))
        try:
            load_json(bytes(body), max_bytes=limit)
        except PolarisError as exc:
            if exc.code == "payload_limit":
                raise Reject(413, "payload_too_large",
                             "The JSON is too deeply nested or has too many items.") from None
            raise Reject(400, "invalid_json", "The request body isn't valid JSON. Duplicate keys, "
                         "NaN and Infinity aren't allowed.") from None
        data = bytes(body)
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": data, "more_body": False}
            return await receive()

        return replay


class Guard:
    """Pure ASGI middleware applied to every request before routing."""

    def __init__(self, app: ASGIApp, *, context: ApiContext) -> None:
        self.app = app
        self.context = context

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        context = self.context
        started = time.perf_counter()
        path: str = scope["path"]
        method: str = scope["method"]
        headers = Headers(scope=scope)
        versioned = path.startswith("/v1/")
        work: dict[str, Any] = {}
        scope[WORK] = work
        status = 500
        responded = False
        key_id: str | None = None

        async def reply(message: Message) -> None:
            nonlocal status, responded
            if message["type"] == "http.response.start":
                status, responded = message["status"], True
                extra = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    if name not in extra:
                        extra[name] = value
                if not path.startswith(DOC_PATHS) and "content-security-policy" not in extra:
                    extra["content-security-policy"] = CSP
            await send(message)

        try:
            try:
                host = headers.get("host", "").lower()
                if context.allowed_hosts is not None and host not in context.allowed_hosts:
                    raise Reject(400, "invalid_host",
                                 "This server only answers requests sent to its local address.")
                if versioned:
                    record = context.authenticate(headers)
                    key_id = record.key_id if record is not None else "local"
                    scope[KEY_ID] = key_id
                    wait = context.limiter.acquire(key_id, record.rate_per_minute if record else None)
                    if wait > 0:
                        seconds = max(1, math.ceil(wait))
                        raise Reject(429, "rate_limited",
                                     f"Too many requests for this key. Try again in {seconds} s.",
                                     retry_after=seconds)
                if method == "POST":
                    receive = await context.read_body(headers, receive)
            except Reject as exc:
                await exc.response()(scope, receive, reply)
                return
            except ClientDisconnected:
                status = 499
                return
            try:
                await self.app(scope, receive, reply)
            except Exception as exc:
                # Only the exception type is logged: messages can quote submitted input.
                LOG.error("Polaris API: internal error in %s %s (%s)", method,
                          path if path in ENDPOINTS else "other", type(exc).__name__)
                if not responded:
                    await error_response(500, "internal_error",
                                         "Something went wrong on the server. Please try again.",
                                         retryable=True)(scope, receive, reply)
        finally:
            if versioned:
                context.usage.record(key_id or "anonymous", method=method,
                                     endpoint=path if path in ENDPOINTS else "other", status=status,
                                     elapsed_ms=(time.perf_counter() - started) * 1000, work=work)


def _review(reviewer: Reviewer, payload: ReviewRequest) -> ReviewReport:
    if payload.diff is not None:
        return reviewer.review_diff(payload.diff)
    if payload.files is not None:
        return reviewer.review_sources(
            [SourceFile(item.path, item.content, item.before) for item in payload.files]
        )
    assert payload.code is not None
    return reviewer.review_snippet(payload.code, path=payload.path or "snippet.py")


def _contract_status(envelope: AssessmentResponse | ErrorResponse) -> int:
    if isinstance(envelope, AssessmentResponse):
        return 200
    if envelope.code == "payload_limit":
        return 413
    if envelope.category == "input":
        return 400
    if envelope.code in RUNTIME_UNAVAILABLE:
        return 503
    return 504 if envelope.code == "timeout" else 500


def _fields(errors: list[Any], *, under: str = "") -> list[str]:
    """Field names from validation errors (never their values), optionally below `under`."""
    names = []
    for error in errors:
        name = ".".join(str(part) for part in error.get("loc", ()) if part != "body")
        names.append(".".join(part for part in (under, name) if part) or "body")
    return list(dict.fromkeys(names))[:20]


ERRORS: dict[int | str, dict[str, Any]] = {
    status: {"model": ApiError, "description": description}
    for status, description in (
        (400, "Invalid JSON or host."),
        (401, "Missing or invalid API key."),
        (413, "Request too large."),
        (415, "Not JSON."),
        (422, "The JSON doesn't match this endpoint."),
        (429, "Rate limited or server busy; see Retry-After."),
        (503, "No model is loaded (engine \"model\")."),
    )
}


def create_app(service: ReviewService, *, settings: ApiSettings | None = None,
               keys: KeyStore | None = None, analysis_runtime: AnalysisRuntime | None = None,
               guard_policy: TrustedGuardPolicy | None = None,
               action_policy: ActionPolicy | None = None) -> FastAPI:
    """Build the API around one loaded model. Refuses to serve other machines without keys."""
    settings = settings or ApiSettings()
    if keys is not None and len(keys) == 0:
        raise ValueError("The key file has no keys. Create one with `polaris serve keys create`.")
    if keys is None and not is_loopback(settings.host):
        raise ValueError(REMOTE_NEEDS_KEYS)
    context = ApiContext(
        settings=settings,
        keys=keys,
        limiter=RateLimiter(settings.rate_per_minute, settings.burst),
        usage=UsageTracker(settings.usage_log),
        queue=WorkQueue(settings.workers, settings.queue_depth),
        allowed_hosts=local_hosts(settings.port) if is_loopback(settings.host) else None,
    )
    app = FastAPI(
        title="Polaris API",
        summary="Polaris by TheoVex: security review and bounded engineering proposals.",
        description=DESCRIPTION,
        version=__version__,
        docs_url="/docs" if settings.docs else None,
        redoc_url="/redoc" if settings.docs else None,
        openapi_url="/openapi.json",
    )
    app.state.context = context
    bearer = HTTPBearer(auto_error=False, description=(
        "An API key from `polaris serve keys create`. Required when the server was started with keys."
    ))
    secured = [Depends(bearer)]

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> Response:
        errors = list(exc.errors())
        names = _fields(errors)
        reasons = [str(error.get("msg", "invalid")).removeprefix("Value error, ") for error in errors]
        message = "The request doesn't match this endpoint: " + "; ".join(
            f"{name}: {reason}" for name, reason in zip(names, reasons, strict=False)
        )
        return error_response(422, "invalid_request", message, fields=names)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if exc.status_code == 404:
            return error_response(404, "not_found", "Nothing here. The API is described at /openapi.json.")
        if exc.status_code == 405:
            return error_response(405, "method_not_allowed", "This address doesn't accept that method.",
                                  headers=dict(exc.headers or {}))
        return error_response(exc.status_code, "invalid_request", "The request couldn't be handled.")

    @app.get("/health", response_model=HealthResponse, tags=["service"],
             summary="Whether the server is up and a model is loaded")
    async def health() -> Response:
        return ok(HealthResponse(version=__version__, model_loaded=service.backend is not None,
                                 api_keys_required=keys is not None))

    @app.get("/v1/models", response_model=ModelsResponse, dependencies=secured, responses=ERRORS,
             tags=["service"], summary="The loaded model and which engines work")
    async def models() -> Response:
        status = service.model_status()
        return ok(ModelsResponse(model=status, engines=[
            EngineInfo(**item) for item in service.capabilities()["engines"]
        ]))

    @app.get("/v1/capabilities", response_model=dict[str, Any], dependencies=secured,
             responses=ERRORS, tags=["service"], summary="Languages, checks, engines and limits")
    async def capabilities() -> Response:
        return JSONResponse(service.capabilities(limits=settings.limits()))

    @app.get("/v1/usage", response_model=UsageResponse, dependencies=secured, responses=ERRORS,
             tags=["service"], summary="Usage counts for the calling key")
    async def usage(request: Request) -> Response:
        key_id = str(request.scope.get(KEY_ID, "local"))
        counts = context.usage.usage(key_id)
        return ok(UsageResponse(key_id=key_id, since=context.usage.started,
                                usage=UsageCounts(**vars(counts))))

    @app.post(
        "/v1/review", dependencies=secured, tags=["review"],
        summary="Review Python code for SQL and command injection risk",
        responses={200: {"model": ReviewReport, "description": "A review report, or SARIF 2.1.0 "
                         "when format is sarif.", "content": {"application/sarif+json": {}}}, **ERRORS},
    )
    async def review(request: Request, payload: ReviewRequest) -> Response:
        if payload.files is not None and len(payload.files) > settings.max_files:
            return error_response(413, "too_many_files",
                                  f"Send at most {settings.max_files} files per request.")
        config = None
        if payload.config is not None:
            try:
                config = request_config(checks=payload.config.checks, policy=payload.config.policy,
                                        flag_threshold=payload.config.flag_threshold)
            except ValidationError as exc:
                return error_response(422, "invalid_request", settings_problem(exc),
                                      fields=_fields(list(exc.errors()), under="config"))
        try:
            reviewer = service.reviewer(payload.engine, config)
        except ModelUnavailable as exc:
            return error_response(503, "model_unavailable", str(exc))
        try:
            report = await context.queue.run(
                lambda: service.run(payload.engine, lambda: _review(reviewer, payload))
            )
        except QueueFull:
            return busy()
        work = request.scope.get(WORK, {})
        work.update(reviews=1, engine=payload.engine, files_reviewed=report.summary.files_reviewed,
                    functions_total=report.summary.units_total,
                    functions_assessed=report.summary.units_assessed)
        if payload.format == "sarif":
            return JSONResponse(to_sarif(report), media_type="application/sarif+json")
        return ok(report)

    @app.post(
        "/v1/assess", dependencies=secured, tags=["assessment"],
        summary="Assess one polaris.assessment/0.1.0 request",
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/AssessmentRequest"}}}}},
        responses={200: {"model": AssessmentResponse, "description": "An assessment."},
                   400: {"model": ErrorResponse, "description": "An input error envelope."},
                   503: {"model": ErrorResponse, "description": "No usable model is loaded."},
                   **{status: value for status, value in ERRORS.items() if status not in (400, 503)}},
    )
    async def assess(request: Request) -> Response:
        body = await request.body()
        try:
            envelope = await context.queue.run(lambda: service.assess(body))
        except QueueFull:
            return busy()
        request.scope.get(WORK, {}).update(assessments=1)
        return JSONResponse(envelope.model_dump(mode="json"), status_code=_contract_status(envelope))

    @app.post(
        "/v1/assess/batch", response_model=AssessBatchResponse, dependencies=secured, tags=["assessment"],
        summary="Assess up to 64 polaris.assessment/0.1.0 requests at once",
        responses={503: {"model": ApiError, "description": "No usable model is loaded."},
                   **{status: value for status, value in ERRORS.items() if status != 503}},
    )
    async def assess_batch(request: Request, payload: AssessBatchRequest) -> Response:
        if service.backend is None:
            return error_response(503, "model_unavailable", service.model_status().message,
                                  retryable=service.problem == "loading")
        try:
            results = await context.queue.run(lambda: service.assess_batch(payload.requests))
        except QueueFull:
            return busy()
        request.scope.get(WORK, {}).update(assessments=len(payload.requests))
        return ok(AssessBatchResponse(results=results))
    from polaris.workflow.api import action_request_schema, register_workflow_routes

    register_workflow_routes(
        app, context=context, secured=secured, runtime=analysis_runtime,
        guard_policy=guard_policy, action_policy=action_policy,
    )

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            schema = get_openapi(title=app.title, version=app.version, summary=app.summary,
                                 description=app.description, routes=app.routes)
            components = schema.setdefault("components", {}).setdefault("schemas", {})
            request_schema = AssessmentRequest.model_json_schema(
                ref_template="#/components/schemas/{model}"
            )
            for name, definition in request_schema.pop("$defs", {}).items():
                components.setdefault(name, definition)
            components["AssessmentRequest"] = request_schema
            action_schema = action_request_schema()
            for name, definition in action_schema.pop("$defs", {}).items():
                components.setdefault(name, definition)
            components["ActionRequest"] = action_schema
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
    app.add_middleware(Guard, context=context)
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                           allow_methods=["GET", "POST"],
                           allow_headers=["authorization", "content-type"], max_age=600)
    return app


def openapi_document() -> dict[str, Any]:
    """The published OpenAPI description; it is the same for every server."""
    return create_app(ReviewService()).openapi()

"""A small typed client for the Polaris REST API, using only the standard library.

    from polaris.client import PolarisClient

    client = PolarisClient("http://127.0.0.1:8780")
    report = client.review_code("def f(db, n):\\n    db.execute('SELECT ' + n)\\n")
    for finding in report.findings:
        print(finding.result, finding.path, finding.start_line, finding.message)

It talks only to the server you give it. API keys are sent only over HTTPS, or to this machine.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal, get_args
from urllib.parse import urlsplit

from polaris.api.models import (
    ApiErrorCode,
    AssessBatchResponse,
    HealthResponse,
    ModelsResponse,
    UsageResponse,
)
from polaris.contract import AssessmentRequest, AssessmentResponse, ErrorResponse
from polaris.review import ReviewReport

if TYPE_CHECKING:
    from polaris.engineering import ActionRequest, ActionReview, PatchProposal
    from polaris.review.models import CapabilityManifest
    from polaris.workflow.models import WorkflowEnvelope
    from polaris.workflow.requests import WorkflowRepairRequest, WorkflowReviewRequest

Engine = Literal["hybrid", "model", "rules"]
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ACCOUNT_RESPONSE_BYTES = 64 * 1024
ACCOUNT_PATHS = frozenset({"/health", "/v1/models", "/v1/usage"})
ERROR_MESSAGES = {
    "unauthorized": "The Polaris API did not accept the API key.",
    "invalid_host": "The Polaris API rejected the request host.",
    "not_found": "The requested Polaris API endpoint is unavailable.",
    "method_not_allowed": "The Polaris API does not support this request method.",
    "unsupported_media_type": "The Polaris API requires a supported request format.",
    "payload_too_large": "The request exceeds the Polaris API's size limit.",
    "too_many_files": "The request exceeds the Polaris API's file limit.",
    "invalid_json": "The Polaris API could not read the request JSON.",
    "invalid_request": "The Polaris API rejected the request. Check its supported contract.",
    "rate_limited": "The Polaris API rate limit was reached. Try again shortly.",
    "queue_full": "The Polaris API is busy. Try again shortly.",
    "model_unavailable": "The hosted Polaris model is unavailable.",
    "internal_error": "The Polaris API could not complete the request.",
}


class PolarisAPIError(Exception):
    """An error envelope from the server (or a connection problem, with status 0)."""

    def __init__(self, status: int, code: str, message: str, *, retryable: bool = False,
                 retry_after: float | None = None) -> None:
        super().__init__(f"{code} ({status}): {message}")
        self.status = status
        self.code = code
        self.message = message
        self.retryable = retryable
        self.retry_after = retry_after


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Redirects are refused so an API key is never re-sent to another address."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class PolarisClient:
    """Calls `polaris serve`. Review methods return `ReviewReport` models."""

    def __init__(self, base_url: str = "http://127.0.0.1:8780", *, api_key: str | None = None,
                 timeout: float = 120.0) -> None:
        try:
            parts = urlsplit(base_url)
            valid = (
                bool(base_url) and not any(character.isspace() or ord(character) < 32
                                          or ord(character) == 127 for character in base_url)
                and not any(character in base_url for character in ("\\", "?", "#"))
                and parts.scheme in ("http", "https") and bool(parts.hostname)
                and parts.username is None and parts.password is None
                and (parts.port is None or 0 < parts.port <= 65535)
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("base_url must be an http:// or https:// address without credentials, "
                             "query parameters, fragments or control characters.")
        assert parts.hostname is not None
        if api_key and parts.scheme == "http" and not _loopback(parts.hostname):
            raise ValueError("Use https:// to send an API key to another machine.")
        if api_key and (len(api_key) > 4096 or not api_key.isascii() or not api_key.isprintable()
                        or any(character.isspace() for character in api_key)):
            raise ValueError("The API key must be a bounded printable token without whitespace.")
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("timeout must be between zero and 600 seconds.")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        handlers: list[urllib.request.BaseHandler] = [_NoRedirects()]
        if _loopback(parts.hostname):
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    # ---- service ---------------------------------------------------------------------------

    def health(self) -> HealthResponse:
        return HealthResponse.model_validate_json(self._call("GET", "/health"))

    def models(self) -> ModelsResponse:
        return ModelsResponse.model_validate_json(self._call("GET", "/v1/models"))

    def capabilities(self) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(self._call("GET", "/v1/capabilities"))
        return value

    def usage(self) -> UsageResponse:
        return UsageResponse.model_validate_json(self._call("GET", "/v1/usage"))

    # ---- agent-native workflow --------------------------------------------------------------

    def workflow_capabilities(self) -> CapabilityManifest:
        """Probe the server's actual static-analyzer availability, not model coverage."""
        from polaris.review.models import CapabilityManifest

        return CapabilityManifest.model_validate_json(self._call("GET", "/v1/workflow/capabilities"))

    def review_workflow(self, request: WorkflowReviewRequest | Mapping[str, Any]) -> WorkflowEnvelope:
        """Review supplied content; labels never select server filesystem paths."""
        from polaris.workflow.models import WorkflowEnvelope
        from polaris.workflow.requests import WorkflowReviewRequest

        body = request.model_dump(mode="json") if isinstance(request, WorkflowReviewRequest) else dict(request)
        return WorkflowEnvelope.model_validate_json(self._call("POST", "/v1/workflow/review", body))

    def propose_repair(self, request: WorkflowRepairRequest | Mapping[str, Any]) -> PatchProposal:
        """Validate a host candidate without applying it or calling a generator."""
        from polaris.engineering import parse_proposal
        from polaris.workflow.requests import WorkflowRepairRequest

        body = request.model_dump(mode="json") if isinstance(request, WorkflowRepairRequest) else dict(request)
        return parse_proposal(self._call("POST", "/v1/workflow/propose", body))

    def review_action(self, request: ActionRequest | Mapping[str, Any]) -> ActionReview:
        """Assess administrator-established scope without execution or authorization."""
        from polaris.engineering import ActionRequest, ActionReview

        body = request.model_dump(mode="json") if isinstance(request, ActionRequest) else dict(request)
        return ActionReview.model_validate_json(self._call("POST", "/v1/workflow/action", body))

    # ---- review ----------------------------------------------------------------------------

    def review_code(self, code: str, *, path: str | None = None, engine: Engine = "hybrid",
                    checks: Sequence[str] | None = None, policy: Sequence[str] | None = None,
                    flag_threshold: float | None = None) -> ReviewReport:
        payload: dict[str, Any] = {"code": code, **({"path": path} if path else {})}
        return self._review(payload, engine, checks, policy, flag_threshold)

    def review_diff(self, diff: str, *, engine: Engine = "hybrid", checks: Sequence[str] | None = None,
                    policy: Sequence[str] | None = None,
                    flag_threshold: float | None = None) -> ReviewReport:
        """Reviewed from the diff's hunks only; send whole files for full function context."""
        return self._review({"diff": diff}, engine, checks, policy, flag_threshold)

    def review_files(self, files: Mapping[str, str], *, before: Mapping[str, str] | None = None,
                     engine: Engine = "hybrid", checks: Sequence[str] | None = None,
                     policy: Sequence[str] | None = None,
                     flag_threshold: float | None = None) -> ReviewReport:
        """`files` maps path labels to contents; `before` holds previous versions of changed files."""
        entries = [{"path": path, "content": content,
                    **({"before": before[path]} if before and path in before else {})}
                   for path, content in files.items()]
        return self._review({"files": entries}, engine, checks, policy, flag_threshold)

    def sarif(self, *, code: str | None = None, diff: str | None = None,
              files: Mapping[str, str] | None = None, engine: Engine = "hybrid") -> dict[str, Any]:
        """The same review as SARIF 2.1.0, for code-scanning tools."""
        payload: dict[str, Any] = {"engine": engine, "format": "sarif"}
        if code is not None:
            payload["code"] = code
        if diff is not None:
            payload["diff"] = diff
        if files is not None:
            payload["files"] = [{"path": path, "content": content} for path, content in files.items()]
        value: dict[str, Any] = json.loads(self._call("POST", "/v1/review", payload))
        return value

    def assess(self, request: AssessmentRequest | Mapping[str, Any]) -> AssessmentResponse | ErrorResponse:
        """The assessment contract; contract error envelopes are returned, not raised."""
        body = (request.model_dump(mode="json") if isinstance(request, AssessmentRequest)
                else dict(request))
        status, raw, headers = self._send("POST", "/v1/assess", body)
        try:
            kind = json.loads(raw).get("kind")
        except (ValueError, AttributeError):
            kind = None
        if kind == "assessment":
            return AssessmentResponse.model_validate_json(raw)
        if kind == "error":
            return ErrorResponse.model_validate_json(raw)
        raise self._error(status, raw, headers)

    def assess_batch(self, requests: Sequence[AssessmentRequest | Mapping[str, Any]]
                     ) -> list[AssessmentResponse | ErrorResponse]:
        """Up to 64 independent requests in one call; one envelope per request, in order."""
        body = {"requests": [item.model_dump(mode="json") if isinstance(item, AssessmentRequest) else dict(item)
                             for item in requests]}
        return list(AssessBatchResponse.model_validate_json(self._call("POST", "/v1/assess/batch", body)).results)

    # ---- transport -------------------------------------------------------------------------

    def _review(self, payload: dict[str, Any], engine: Engine, checks: Sequence[str] | None,
                policy: Sequence[str] | None, flag_threshold: float | None) -> ReviewReport:
        config: dict[str, Any] = {}
        if checks is not None:
            config["checks"] = list(checks)
        if policy is not None:
            config["policy"] = list(policy)
        if flag_threshold is not None:
            config["flag_threshold"] = flag_threshold
        payload = {**payload, "engine": engine, **({"config": config} if config else {})}
        return ReviewReport.model_validate_json(self._call("POST", "/v1/review", payload))

    def _call(self, method: str, path: str, payload: Any = None) -> bytes:
        status, raw, headers = self._send(method, path, payload)
        if not 200 <= status < 300:
            raise self._error(status, raw, headers)
        return raw

    def _send(self, method: str, path: str, payload: Any = None) -> tuple[int, bytes, Mapping[str, str]]:
        limit = MAX_ACCOUNT_RESPONSE_BYTES if path in ACCOUNT_PATHS else MAX_RESPONSE_BYTES

        def read_response(stream: Any) -> bytes:
            body: bytes = stream.read(limit + 1)
            if len(body) > limit:
                raise PolarisAPIError(0, "response_too_large",
                                      "The Polaris API response exceeded the allowed size.")
            return body
        data = None if payload is None else json.dumps(payload, allow_nan=False).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.api_key:
            request.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    return response.status, read_response(response), dict(response.headers)
            except urllib.error.HTTPError as exc:
                with exc:
                    return exc.code, read_response(exc), dict(exc.headers or {})
        except (urllib.error.URLError, http.client.HTTPException, OSError):
            raise PolarisAPIError(0, "connection_failed",
                                  "Couldn't reach the configured Polaris API. Check its address "
                                  "and your network connection.") from None

    @staticmethod
    def _error(status: int, raw: bytes, headers: Mapping[str, str]) -> PolarisAPIError:
        if 300 <= status < 400:
            return PolarisAPIError(status, "redirect_refused",
                                   "The Polaris API redirected the request. Use its final trusted "
                                   "address; credentials were not forwarded.")
        try:
            body = json.loads(raw)
        except (ValueError, RecursionError):
            body = {}
        if not isinstance(body, dict):
            body = {}
        retry = next((value for name, value in headers.items() if name.lower() == "retry-after"), None)
        code = body.get("code")
        if not isinstance(code, str) or code not in get_args(ApiErrorCode):
            code = "http_error"
        # Error bodies and transport reasons may reflect an Authorization header. Never echo
        # them into CLI output, MCP logs, or exceptions, even for a recognized error code.
        message = ERROR_MESSAGES.get(code, f"The Polaris API answered with status {status}.")
        retry_after = min(float(retry), 60.0) if retry and retry.isascii() and retry.isdigit() and len(retry) <= 6 else None
        return PolarisAPIError(
            status, code, message,
            retryable=body.get("retryable") is True and status in (429, 502, 503, 504),
            retry_after=retry_after,
        )

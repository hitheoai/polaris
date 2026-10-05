"""Workflow HTTP routes. Request labels never become server filesystem paths."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from polaris.engineering import (
    ActionPolicy,
    ActionRequest,
    ActionReview,
    PatchProposal,
    parse_action,
)
from polaris.engineering import review_action as assess_action
from polaris.engineering.errors import EngineeringError
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.capabilities import capability_manifest
from polaris.review.models import CapabilityManifest, SourceFile, TrustedGuardPolicy
from polaris.workflow.models import WorkflowEnvelope
from polaris.workflow.repair import propose_supplied
from polaris.workflow.requests import WorkflowRepairRequest, WorkflowReviewRequest
from polaris.workflow.service import review_supplied

WORKFLOW_ENDPOINTS = frozenset({
    "/v1/workflow/review", "/v1/workflow/propose", "/v1/workflow/action",
    "/v1/workflow/capabilities",
})


def register_workflow_routes(
    app: FastAPI, *, context: Any, secured: list[Any], runtime: AnalysisRuntime | None = None,
    guard_policy: TrustedGuardPolicy | None = None, action_policy: ActionPolicy | None = None,
) -> None:
    from polaris.api.app import ERRORS, WORK, busy, error_response, ok
    from polaris.api.security import QueueFull

    active = runtime or AnalysisRuntime(
        allow_external_analyzers=False, allow_temporary_source_files=False,
    )

    def files(payload: WorkflowReviewRequest) -> list[SourceFile]:
        return [SourceFile(item.path, item.content, item.before) for item in payload.files]

    @app.get(
        "/v1/workflow/capabilities", response_model=CapabilityManifest, dependencies=secured,
        responses=ERRORS, tags=["workflow"], summary="Actual workflow analyzer availability and limits",
    )
    async def capabilities() -> Response:
        try:
            manifest = await context.queue.run(lambda: capability_manifest(runtime=active, probe=True))
        except QueueFull:
            return busy()
        return ok(manifest)

    @app.post(
        "/v1/workflow/review", response_model=WorkflowEnvelope, dependencies=secured,
        responses=ERRORS, tags=["workflow"], summary="Review submitted content; no server paths or project execution",
    )
    async def review(request: Request, payload: WorkflowReviewRequest) -> Response:
        if len(payload.files) > context.settings.max_files:
            return error_response(413, "too_many_files", "Too many submitted files.")
        try:
            report = await context.queue.run(lambda: review_supplied(
                files(payload), config=payload.config, runtime=active, guard_policy=guard_policy,
            ))
        except QueueFull:
            return busy()
        request.scope.get(WORK, {}).update(
            reviews=1, engine="rules", files_reviewed=report.review.summary.files_reviewed,
        )
        return ok(report)

    @app.post(
        "/v1/workflow/propose", response_model=PatchProposal, dependencies=secured,
        responses=ERRORS, tags=["workflow"], summary="Validate supplied candidate edits; never apply or execute",
    )
    async def propose(request: Request, payload: WorkflowRepairRequest) -> Response:
        if len(payload.files) > min(context.settings.max_files, 64):
            return error_response(413, "too_many_files", "Too many submitted repair-context files.")
        try:
            proposal = await context.queue.run(lambda: propose_supplied(
                files(payload), payload.candidate, config=payload.config,
                runtime=active, guard_policy=guard_policy,
            ))
        except QueueFull:
            return busy()
        except EngineeringError:
            return error_response(422, "invalid_request",
                                  "The candidate could not be bound to fresh, scoped review evidence.")
        request.scope.get(WORK, {}).update(reviews=1, engine="rules")
        return ok(proposal)

    @app.post(
        "/v1/workflow/action", response_model=ActionReview, dependencies=secured,
        responses=ERRORS, tags=["workflow"], summary="Assess an action using application-owned policy; no execution",
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/ActionRequest"},
        }}}},
    )
    async def action(request: Request) -> Response:
        try:
            parsed = parse_action(await request.body())
            result = await context.queue.run(
                lambda: assess_action(parsed.action, policy=action_policy, root=None),
            )
        except QueueFull:
            return busy()
        except EngineeringError:
            return error_response(422, "invalid_request", "A bounded typed action request is required.")
        return JSONResponse(result.model_dump(mode="json"))


def action_request_schema() -> dict[str, Any]:
    return ActionRequest.model_json_schema(ref_template="#/components/schemas/{model}")

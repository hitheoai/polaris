"""Agent-native CLI operations; no project commands or paid generation run implicitly."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any


def _analysis_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--root", type=Path, help="Git worktree to review (default current repository).")
    command.add_argument("--checks", help="Comma-separated required checks; defaults to the declared static workflow.")
    command.add_argument("--include", action="append", help="Explicit scope glob; repeat for multiple patterns.")
    command.add_argument("--exclude", action="append", help="Explicit excluded scope; exclusions remain visible.")
    command.add_argument("--guard-policy", type=Path, help="Explicit caller-approved guard policy JSON, never inferred from code.")
    command.add_argument("--semgrep", type=Path,
                         help="Also run Semgrep CE from this trusted absolute path (optional; built-in analyzers cover all checks).")
    command.add_argument("--with-semgrep", action="store_true",
                         help="Also run the Semgrep CE installed by `theo setup` (optional, slower).")
    command.add_argument("--no-external-analyzers", action="store_true", help="Forbid external analyzers and temporary source files.")
    command.add_argument("--analyzer-plugin", action="append", metavar="NAME",
                         help="Load this installed `polaris.analyzers` entry point (repeatable). Loading a plugin "
                              "runs its code in this process; none are loaded unless named.")


def _output_option(command: argparse.ArgumentParser) -> None:
    command.add_argument("--output", type=Path, help="Create a new private report file; never overwrite an existing file.")


def _import_options(command: argparse.ArgumentParser, *, gate: str) -> None:
    """Results from other tools' SARIF files: shared by `workflow review` and `pr plan`."""
    command.add_argument(
        "--import-sarif", action="append", type=Path, metavar="PATH",
        help="Merge results from another tool's SARIF 2.1.0 file (repeatable, up to 16). Polaris never runs that "
             "tool; its results are untrusted data, labeled as not verified by Polaris, and change no Polaris result, "
             "coverage or exit code unless --fail-on-imported is set.")
    command.add_argument("--fail-on-imported", choices=("error", "warning", "note"), metavar="LEVEL",
                         help=f"Opt in: imported results at or above this SARIF level (error, warning, note) {gate}.")


def sarif_inputs(paths: list[Path] | None) -> list[Any]:
    """Read `--import-sarif` files: bounded, regular, not symbolic links. A file that cannot be read
    becomes a rejected input with a fixed code, never an exception, so the review still runs."""
    from polaris.integrations._safe import IntegrationProblem, read_bytes
    from polaris.review.models import MAX_SARIF_IMPORTS
    from polaris.review.sarif_import import (
        MAX_SARIF_BYTES,
        MAX_TOTAL_SARIF_BYTES,
        SarifInput,
        SarifProblem,
        input_name,
    )

    chosen = list(paths or ())
    if len(chosen) > MAX_SARIF_IMPORTS:
        raise SarifProblem("too_many_sarif_files")
    inputs: list[SarifInput] = []
    total = 0
    for path in chosen:
        name = input_name(path)
        location = _system_resolved(path.absolute())
        try:
            info = os.lstat(location)
        except OSError:
            inputs.append(SarifInput(name, error="sarif_unavailable"))
            continue
        if not stat.S_ISREG(info.st_mode):
            inputs.append(SarifInput(name, error="sarif_unavailable"))
        elif info.st_size > MAX_SARIF_BYTES:
            inputs.append(SarifInput(name, error="sarif_too_large"))
        elif total + info.st_size > MAX_TOTAL_SARIF_BYTES:
            inputs.append(SarifInput(name, error="sarif_total_limit"))
        else:
            try:
                data = read_bytes(location, limit=MAX_SARIF_BYTES)
            except (IntegrationProblem, OSError):
                data = None
            if data is None:
                inputs.append(SarifInput(name, error="sarif_unavailable"))
            else:
                total += len(data)
                inputs.append(SarifInput(name, data=data))
    return inputs


def add_workflow_parsers(commands: Any) -> None:
    workflow = commands.add_parser("workflow", help="Review, propose bounded repairs, re-check, and assess actions.")
    actions = workflow.add_subparsers(dest="workflow_command", required=True)
    review = actions.add_parser("review", help="Fresh multi-language review; missing coverage is explicit.")
    choice = review.add_mutually_exclusive_group()
    choice.add_argument("--staged", action="store_true")
    choice.add_argument("--diff", metavar="RANGE", help="Independently review this actual Git revision range.")
    choice.add_argument("--files", type=Path, nargs="+")
    review.add_argument("--require-complete", action="store_true",
                        help="Fail on incomplete/stale analysis and unresolved findings; never trust a local receipt.")
    review.add_argument("--format", choices=("text", "json", "sarif", "codequality"), default="text")
    _analysis_options(review)
    _import_options(review, gate="exit 1 (2 if an import was rejected or went past a limit)")
    _output_option(review)
    baseline = actions.add_parser(
        "baseline", help="Record current findings in .polaris/baseline.json so later reviews report only new issues.")
    baseline.add_argument("--files", type=Path, nargs="+", help="Paths to baseline (default: the whole repository).")
    baseline.add_argument("--format", choices=("text", "json"), default="text")
    _analysis_options(baseline)
    _output_option(baseline)
    caps = actions.add_parser("capabilities", help="Probe real analyzer availability without installing anything.")
    _analysis_options(caps)
    _output_option(caps)
    propose = actions.add_parser("propose", help="Validate host candidate edits against fresh observed findings; no writes.")
    propose.add_argument("--input", default="-", help="Candidate JSON file, or stdin.")
    _analysis_options(propose)
    _output_option(propose)
    apply = actions.add_parser("apply", help="Apply an exact user-approved proposal locally; normal host permissions still apply.")
    apply.add_argument("--proposal", type=Path, required=True)
    apply.add_argument("--approve-proposal", required=True,
                       help="Exact proposal digest explicitly approved by the user; never synthesize approval from a risk score.")
    _analysis_options(apply)
    _output_option(apply)
    verify = actions.add_parser("verify", help="Verify exact post-edit content and static findings; behavioral tests are not run.")
    verify.add_argument("--proposal", type=Path, required=True)
    verify.add_argument("--expected-proposal", required=True)
    _analysis_options(verify)
    _output_option(verify)
    action = actions.add_parser("action", help="Assess a typed proposal against explicit caller policy; never execute it.")
    action.add_argument("--input", default="-")
    action.add_argument("--policy", type=Path, help="User/application-owned action policy JSON; absence requires further review.")
    action.add_argument("--root", type=Path, help="Explicit filesystem scope, when applicable.")
    _output_option(action)
    benchmark = actions.add_parser("benchmark", help="Aggregate paired, caller-recorded complete-task measurements.")
    benchmark.add_argument("--input", default="-")
    _output_option(benchmark)
    schema = actions.add_parser("schema", help="Print a versioned workflow/engineering JSON Schema.")
    schema.add_argument("kind", choices=(
        "workflow", "review", "capabilities", "candidate", "snapshot", "proposal", "proposal_validation",
        "approval", "apply_receipt", "verification", "action_request", "action_policy", "action_review",
        "generation_request", "generation_result", "generation_receipt", "benchmark",
    ))
    _output_option(schema)


def read_input(path: str | Path, *, limit: int = 2_097_152) -> bytes:
    from polaris.integrations._safe import read_bytes

    if str(path) == "-":
        data = sys.stdin.buffer.read(limit + 1)
    else:
        data = read_bytes(Path(path).expanduser().absolute(), limit=limit)
        if data is None:
            raise ValueError("input file unavailable")
    if len(data) > limit:
        raise ValueError("input byte limit exceeded")
    return data


def _system_resolved(path: Path) -> Path:
    """Resolve root-owned links among the parent directories (macOS /tmp -> /private/tmp, /var).

    Links created by users are left in place, so no_symlinks still refuses them.
    """
    path = Path(os.path.abspath(path.expanduser()))
    resolved = Path(path.anchor)
    for part in path.parent.parts[1:]:
        candidate = resolved / part
        try:
            info = candidate.lstat()
        except OSError:
            resolved = candidate
            continue
        resolved = candidate.resolve() if stat.S_ISLNK(info.st_mode) and info.st_uid == 0 else candidate
    return resolved / path.name


def _emit(value: Any, output: Path | None, *, text: bool = False) -> None:
    rendered = value if text else json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2)
    content = (str(rendered).rstrip("\n") + "\n").encode("utf-8")
    if output is None:
        sys.stdout.write(content.decode("utf-8"))
        return
    from polaris.integrations._safe import no_symlinks, parent_descriptor

    # A caller chooses the destination explicitly. Refuse existing files and user-created links.
    destination = no_symlinks(_system_resolved(output.absolute()))
    with parent_descriptor(destination) as parent:
        descriptor = os.open(
            destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)


def analysis_settings(args: argparse.Namespace) -> tuple[Any, Any, Any]:
    from polaris.jsonio import load_json
    from polaris.review.analyzers import AnalysisRuntime
    from polaris.review.analyzers.base import local_workers
    from polaris.review.models import TrustedGuardPolicy, WorkflowReviewConfig

    config_values: dict[str, Any] = {}
    if args.checks is not None:
        config_values["checks"] = [item.strip() for item in args.checks.split(",") if item.strip()]
    for name in ("include", "exclude"):
        if getattr(args, name, None) is not None:
            config_values[name] = getattr(args, name)
    if getattr(args, "workflow_command", None) in ("review", "baseline"):
        # A local review can afford far larger scopes than the bounded MCP/HTTP defaults.
        # (Repair commands keep the shared defaults: the config is part of an approval.)
        whole = getattr(args, "files", None) is not None or args.workflow_command == "baseline"
        config_values.setdefault("max_files", 50_000 if whole else 5_000)
        config_values.setdefault("max_total_bytes", 512_000_000 if whole else 128_000_000)
        config_values.setdefault("max_units", 500_000 if whole else 100_000)
        config_values.setdefault("max_findings", 10_000)
    config = WorkflowReviewConfig.model_validate(config_values)
    semgrep = args.semgrep
    # Semgrep is opt-in: the built-in analyzers cover every default check on their own.
    if semgrep is None and getattr(args, "with_semgrep", False) and not args.no_external_analyzers:
        from polaris.onboarding.installation import analyzer

        semgrep = analyzer()
        if semgrep is None:
            raise ValueError("--with-semgrep requires the analyzer installed by `theo setup`")
    plugins = tuple(dict.fromkeys(getattr(args, "analyzer_plugin", None) or ()))
    if plugins:
        from polaris.review.analyzers.registry import load_plugins

        load_plugins(plugins)  # fail early, with a fixed code, before any review work
    runtime = AnalysisRuntime(
        allow_external_analyzers=not args.no_external_analyzers,
        allow_temporary_source_files=not args.no_external_analyzers,
        semgrep_executable=str(semgrep) if semgrep else None,
        parallel_workers=local_workers(),
        plugins=plugins,
    )
    policy = (
        TrustedGuardPolicy.model_validate(load_json(read_input(args.guard_policy, limit=256_000)))
        if args.guard_policy else None
    )
    return config, runtime, policy


def _root(args: argparse.Namespace) -> Path:
    from polaris.integrations.freshness import repository_identity

    return repository_identity(args.root or Path.cwd()).root


def _paths(root: Path, files: list[Path] | None) -> list[Path] | None:
    """Relative --files resolve against the working directory when that is inside the repository."""
    if files is None:
        return None
    resolved = []
    for item in files:
        here = Path.cwd() / item
        inside = not item.is_absolute() and here.exists() and here.resolve().is_relative_to(root)
        resolved.append(here.resolve() if inside else item)
    return resolved


def run(args: argparse.Namespace) -> int:
    from pydantic import BaseModel, ValidationError

    from polaris.engineering.errors import EngineeringError
    from polaris.errors import PolarisError
    from polaris.integrations._safe import IntegrationProblem
    from polaris.jsonio import digest_json, load_json
    from polaris.onboarding.errors import OnboardingProblem
    from polaris.review.analyzers.registry import PLUGIN_ERRORS, PluginProblem
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS
    from polaris.review.sarif_import import SarifProblem
    from polaris.workflow.service import review_policy

    try:
        command = args.workflow_command
        code = 0
        text = False
        value: Any
        if command == "benchmark":
            from polaris.workflow.benchmark import ExperimentMeasurements, benchmark_report

            report = benchmark_report(ExperimentMeasurements.model_validate(load_json(read_input(args.input))))
            value = report.model_dump(mode="json")
            code = 0 if report.acceptance == "met" else 2
        elif command == "schema":
            from polaris.engineering import schema
            from polaris.review.models import CapabilityManifest, WorkflowReviewReport
            from polaris.workflow.benchmark import ExperimentMeasurements
            from polaris.workflow.models import WorkflowEnvelope
            from polaris.workflow.requests import CandidateRequest

            models: dict[str, type[BaseModel]] = {
                "workflow": WorkflowEnvelope, "review": WorkflowReviewReport,
                "capabilities": CapabilityManifest, "candidate": CandidateRequest,
                "benchmark": ExperimentMeasurements,
            }
            value = models[args.kind].model_json_schema() if args.kind in models else schema(args.kind)
        elif command == "action":
            from polaris.engineering import ActionPolicy, parse_action, review_action
            from polaris.engineering.models import parse_model

            request = parse_action(read_input(args.input))
            policy = parse_model(ActionPolicy, read_input(args.policy, limit=256_000)) if args.policy else None
            result = review_action(request.action, policy=policy, root=args.root)
            value = result.model_dump(mode="json")
            code = 0 if result.status == "within_declared_scope" else 1
        else:
            config, runtime, policy = analysis_settings(args)
            settings_digest = digest_json(review_policy(config, policy, runtime))
            if command == "capabilities":
                from polaris.review.capabilities import capability_manifest

                value = capability_manifest(runtime=runtime, probe=True).model_dump(mode="json")
            elif command == "review":
                from polaris.workflow.output import to_codequality, to_sarif
                from polaris.workflow.service import (
                    imported_exit_code,
                    render_workflow,
                    review_workspace,
                )

                imports = sarif_inputs(args.import_sarif)
                root = _root(args)
                reviewed = review_workspace(
                    root, staged=args.staged, revision_range=args.diff, paths=_paths(root, args.files),
                    config=config, runtime=runtime, guard_policy=policy, imports=imports,
                )
                text = args.format == "text"
                if args.format == "sarif":
                    value = to_sarif(reviewed)
                elif args.format == "codequality":
                    value = to_codequality(reviewed)
                else:
                    value = render_workflow(reviewed) if text else reviewed.model_dump(mode="json")
                code = reviewed.exit_code(require_complete=args.require_complete)
                if args.fail_on_imported is not None:
                    code = imported_exit_code(reviewed, args.fail_on_imported, code)
            elif command == "baseline":
                from polaris.review.project import BASELINE_PATH, write_baseline
                from polaris.workflow.service import review_workspace

                root = _root(args)
                reviewed = review_workspace(
                    root, paths=_paths(root, args.files) or [root], config=config, runtime=runtime,
                    guard_policy=policy, use_baseline=False,
                )
                if reviewed.status == "stale":
                    raise EngineeringError("stale_context")
                _, entries = write_baseline(root, reviewed.review.findings)
                text = args.format == "text"
                value = (
                    f"Recorded {entries} existing finding(s) in {BASELINE_PATH} (review {reviewed.status}). "
                    "Later reviews list these as baselined and report only new issues; commit the file to share it."
                    if text else {"format": "polaris.baseline-result/0.1.0", "path": BASELINE_PATH,
                                  "entries": entries, "status": reviewed.status}
                )
                code = 0 if reviewed.status == "complete" else 2
            elif command == "propose":
                from polaris.workflow.repair import propose_local
                from polaris.workflow.requests import CandidateRequest

                candidate = CandidateRequest.model_validate(load_json(read_input(args.input)))
                proposal = propose_local(_root(args), candidate, config=config, runtime=runtime, guard_policy=policy)
                value = proposal.model_dump(mode="json")
            else:
                from polaris.engineering import (
                    ProposalApproval,
                    apply_proposal,
                    parse_proposal,
                    verify_proposal,
                )
                from polaris.workflow.repair import active_context, static_adapter

                proposal = parse_proposal(read_input(args.proposal))
                root = _root(args)
                context = active_context(
                    root, proposal, config=config, runtime=runtime, guard_policy=policy,
                    post_edit=command == "verify",
                )
                if command == "apply":
                    if args.approve_proposal != proposal.proposal_digest:
                        raise EngineeringError("proposal_mismatch")
                    now = int(time.time())
                    approval = ProposalApproval(
                        proposal_digest=args.approve_proposal,
                        snapshot_digest=proposal.snapshot.snapshot_digest,
                        approved=True, approved_at_unix=now, expires_at_unix=now + 60,
                    )
                    receipt = apply_proposal(root, proposal, approval=approval, context=context)
                    value = receipt.model_dump(mode="json")
                    code = 0 if receipt.status == "applied" else 2
                else:
                    verification = verify_proposal(
                        root, proposal, expected_proposal_digest=args.expected_proposal, context=context,
                        static_reviewer=static_adapter(config=config, runtime=runtime, guard_policy=policy, root=root),
                    )
                    current_config, current_runtime, current_policy = analysis_settings(args)
                    if active_context(
                        root, proposal, config=current_config, runtime=current_runtime,
                        guard_policy=current_policy, post_edit=True,
                    ) != context:
                        raise EngineeringError("stale_context")
                    value = verification.model_dump(mode="json")
                    code = 0 if (
                        verification.status == "verified_snapshot"
                        and verification.static_review.status == "completed"
                        and not verification.static_review.additional_findings
                        and all(item.status == "no_longer_detected" for item in verification.findings)
                    ) else 2
            if command in ("review", "baseline", "propose", "capabilities"):
                current_config, current_runtime, current_policy = analysis_settings(args)
                if digest_json(review_policy(current_config, current_policy, current_runtime)) != settings_digest:
                    raise EngineeringError("stale_context")
        try:
            _emit(value, args.output, text=text)
        except (IntegrationProblem, OSError):
            _emit({"format": "polaris.workflow-error/0.1.0", "code": "output_unwritable",
                   "message": "The command finished, but --output could not be written: choose a new file "
                              "(existing files and user-created symbolic links are refused)."}, None)
            return 2
        return code
    except EngineeringError as exc:
        _emit({"format": "polaris.workflow-error/0.1.0", "code": exc.code,
               "message": "The bounded operation could not be completed; no execution permission was granted."}, None)
        return 2
    except PluginProblem as problem:
        reason = str(problem) if str(problem) in PLUGIN_ERRORS else "invalid_analyzer_plugin"
        _emit({"format": "polaris.workflow-error/0.1.0", "code": reason, "message": PLUGIN_ERRORS[reason]}, None)
        return 2
    except SarifProblem as problem:
        reason = problem.code if problem.code in SARIF_ERRORS else "invalid_sarif"
        _emit({"format": "polaris.workflow-error/0.1.0", "code": reason, "message": SARIF_ERRORS[reason]}, None)
        return 2
    except (PolarisError, IntegrationProblem, OnboardingProblem, ValidationError, OSError, ValueError, RuntimeError):
        # Do not print exception messages: JSON/parser/path errors may contain source or credentials.
        _emit({"format": "polaris.workflow-error/0.1.0", "code": "workflow_unavailable",
               "message": "Invalid, unavailable or stale input/context; review did not complete."}, None)
        return 2

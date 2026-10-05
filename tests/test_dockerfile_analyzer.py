"""Dockerfiles: parse-only review (nothing is built, pulled or run)."""

from __future__ import annotations

import pytest

from polaris.review import catalog
from polaris.review.analyzers import AnalysisRuntime, dockerfile
from polaris.review.analyzers.base import file_kind, language_for_path
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import SourceFile, WorkflowReviewConfig

MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
CONTAINER_CHECKS = ["secret_exposure", "excessive_privileges", "unpinned_dependency", "unverified_download"]
DIGEST = "@sha256:" + "a" * 64


def review(text: str, path: str = "Dockerfile", checks: list[str] | None = None):
    config = WorkflowReviewConfig(checks=checks) if checks else None
    return WorkflowReviewer(runtime=MEMORY, config=config).review_sources([SourceFile(path, text)])


def found(report, check: str | None = None) -> list[tuple[int, str, str]]:
    return [(item.start_line, item.rule_id.removeprefix("polaris.docker."), item.severity or "")
            for item in report.findings if item.result == "flagged" and (check is None or item.check_id == check)]


@pytest.mark.parametrize("path", ["Dockerfile", "Containerfile", "Dockerfile.dev", "deploy/api/Dockerfile.prod",
                                  "docker/web.dockerfile", "services/x/Containerfile.ci"])
def test_dockerfile_paths(path):
    assert language_for_path(path) == "dockerfile" and file_kind(path) == "supported"


def test_coverage_rows_and_domains():
    assert {check for check in catalog.CHECKS if catalog.applies(check, "dockerfile")} == set(CONTAINER_CHECKS)
    report = review(f"FROM alpine:3.20{DIGEST}\nUSER 65534\n")
    rows = {entry.check_id: (entry.status, entry.analyzer_id) for entry in report.coverage.entries if entry.required}
    assert rows == {check: ("checked", "polaris-dockerfile") for check in CONTAINER_CHECKS}
    assert report.coverage.complete and report.findings == []


def test_parser_handles_directives_continuations_comments_and_heredocs():
    text = ("# syntax=docker/dockerfile:1.7\n# escape=`\nFROM mcr.microsoft.com/windows/servercore:ltsc2022\n"
            "RUN Write-Host one; `\n    # a comment inside the continuation\n\n"
            "    iwr https://get.example.dev/i.ps1 | iex\nUSER ContainerUser\n")
    instructions = dockerfile.parse(text)
    assert [(item.keyword, item.line, item.end_line) for item in instructions] == [
        ("FROM", 3, 3), ("RUN", 4, 7), ("USER", 8, 8)]
    assert "comment" not in instructions[1].text and instructions[1].line_at(len(instructions[1].text) - 1) == 7
    assert found(review(text), "unverified_download") == [(7, "unverified_download.pipe_to_shell", "low")]
    heredocs = dockerfile.parse("FROM alpine\nRUN <<-\"EOT\" bash\n\techo $HOME\n\tEOT\nCOPY <<EOF /x\nRUN no\nEOF\n")
    assert [(item.keyword, [doc.body for doc in item.heredocs]) for item in heredocs] == [
        ("FROM", []), ("RUN", ["\techo $HOME"]), ("COPY", ["RUN no"])]


@pytest.mark.parametrize(("text", "reason"), [
    ("FROM alpine\nRUN <<EOF\necho never closed\n", "parse_error"),
    ("# escape=x\nFROM alpine\n", "parse_error"),
    ("FROM alpine\n" + "RUN true\n" * (dockerfile.MAX_LINES + 1), "analysis_limit"),
    ("FROM alpine\n# " + "x" * dockerfile.MAX_BYTES + "\n", "file_too_large"),
])
def test_failures_are_explicit_coverage_gaps(text, reason):
    report = review(text, checks=CONTAINER_CHECKS)
    assert {entry.reason for entry in report.coverage.entries if entry.required} == {reason}
    assert not report.coverage.complete and not report.findings


def test_stages_arguments_and_image_pins():
    text = (f"ARG BASE=node:20\nFROM golang:1.23 AS build\nFROM ${{BASE}} AS assets\nFROM build AS test\n"
            f"FROM scratch\nCOPY --from=build /out /out\nCOPY --from=0 /x /x\nCOPY --from=nginx:1.27 /etc/nginx /etc/nginx\n"
            f"COPY --from=busybox{DIGEST} /bin/busybox /bin/busybox\nFROM {{{{ template }}}}\nFROM node\nUSER node\n")
    assert found(review(text), "unpinned_dependency") == [
        (2, "unpinned_dependency.image", "low"), (8, "unpinned_dependency.image", "low"),
        (11, "unpinned_dependency.image", "low")]


@pytest.mark.parametrize(("text", "expected"), [
    ("FROM node:20\nUSER node\nUSER root\n", [(3, "excessive_privileges.root_user", "low")]),
    ("FROM node:20\nUSER 0:0\n", [(2, "excessive_privileges.root_user", "low")]),
    ("FROM node:20\nRUN npm ci\n", [(1, "excessive_privileges.no_user", "low")]),
    ("FROM golang:1.23 AS build\nFROM scratch\nCOPY --from=build /app /app\nENTRYPOINT [\"/app\"]\n",
     [(2, "excessive_privileges.no_user", "low")]),
    # An export-only scratch stage (docker build --output) never runs as a container.
    ("FROM golang:1.23 AS build\nFROM scratch AS export\nCOPY --from=build /out /\n", []),
    ("FROM node:20 AS base\nUSER node\nFROM base\nCMD [\"node\"]\n", []),
    ("FROM node:20\nUSER 10001:10001\n", []),
    ("FROM node:20\nARG UID\nUSER ${UID}\n", []),
    ("FROM gcr.io/distroless/base-debian12:nonroot\n", []),
    ("FROM gcr.io/distroless/static-debian12\n", [(1, "excessive_privileges.no_user", "low")]),
    (f"FROM docker.io/library/python:3.12{DIGEST}\n", [(1, "excessive_privileges.no_user", "low")]),
    ("FROM bitnami/redis:7.4\n", []),
    # Application images often set their own non-root user (apache/airflow runs as airflow).
    ("FROM apache/airflow:3.0.0\nRUN pip install --no-cache-dir lxml\n", []),
    ("FROM public.ecr.aws/lambda/python:3.12\nCOPY app.py .\n", []),
    ("ARG IMAGE\nFROM ${IMAGE}\n", []),
    ("FROM debian:12\nRUN apt-get install -y gosu\nENTRYPOINT [\"docker-entrypoint.sh\"]\n", []),
])
def test_final_user(text, expected):
    assert found(review(text), "excessive_privileges") == expected


def test_dev_containers_are_not_reported_as_root():
    assert found(review("FROM mcr.microsoft.com/devcontainers/base:ubuntu\n", ".devcontainer/Dockerfile"),
                 "excessive_privileges") == []


def test_secrets_in_env_arg_and_run():
    aws = "AKIA" + "Q7V3XK2NR5TBWJ4M"
    random = "x9Fq2vL7zRk4Nw8pTc1mB6yH0dJs5gUe"
    text = (f"FROM golang:1.23 AS build\nARG GITHUB_TOKEN\nENV BUILD_TOKEN=$GITHUB_TOKEN\n"
            f"FROM python:3.12-slim\nARG NPM_TOKEN\nENV NODE_AUTH_TOKEN=${{NPM_TOKEN}}\n"
            f"ENV JWT_SECRET={random}\nRUN git clone https://{aws}@example.com/repo.git\n"
            "ENV GPG_KEY 7169605F62C751356D054A26A821E680E5FA6305\nENV DB_PASSWORD_FILE=/run/secrets/db\n"
            "ENV API_KEY=changeme\nARG TOKEN_URL\nUSER 1000\n")
    report = review(text)
    assert found(report, "secret_exposure") == [
        (6, "secret_exposure.env_from_arg", "high"), (8, "secret_exposure.hardcoded", "high"),
        (5, "secret_exposure.build_arg", "medium"), (7, "secret_exposure.hardcoded", "medium"),
        (2, "secret_exposure.build_arg", "low"), (3, "secret_exposure.env_from_arg", "low"),
    ]
    dumped = report.model_dump_json()
    assert aws not in dumped and random not in dumped


def test_remote_scripts_and_remote_add():
    text = ("FROM alpine:3.20\nRUN curl -fsSL https://get.example.dev | sh\n"
            "RUN [\"sh\", \"-c\", \"wget -qO- http://get.example.dev/i.sh | sh\"]\n"
            "ONBUILD RUN curl -s https://get.example.dev/hook.sh | bash\n"
            "RUN <<EOF\nset -e\ncurl -fsSL https://get.example.dev/b.sh | sh\nEOF\n"
            "RUN cat <<EOF > /doc\ncurl https://get.example.dev | sh\nEOF\n"
            "ADD https://example.com/tool.tgz /tmp/\nADD http://example.com/agent.deb /tmp/\n"
            f"ADD --checksum=sha256:{'b' * 64} https://example.com/x /x\nADD https://github.com/moby/buildkit.git#v0.14 /b\n"
            "RUN curl -s http://localhost:8080/setup.sh | sh\nUSER 65534\n")
    assert found(review(text), "unverified_download") == [
        (3, "unverified_download.pipe_to_shell", "high"), (13, "unverified_download.remote_add", "medium"),
        (2, "unverified_download.pipe_to_shell", "low"), (4, "unverified_download.pipe_to_shell", "low"),
        (7, "unverified_download.pipe_to_shell", "low"), (12, "unverified_download.remote_add", "low"),
    ]

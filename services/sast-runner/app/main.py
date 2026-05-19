"""SAST Runner 서비스 — FastAPI 앱."""

from __future__ import annotations

import logging
import os
import sys
import time as _time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pythonjsonlogger.json import JsonFormatter


# Python logging level → pino numeric level
_LEVEL_TO_PINO = {
    logging.DEBUG: 20,
    logging.INFO: 30,
    logging.WARNING: 40,
    logging.ERROR: 50,
    logging.CRITICAL: 60,
}


class _EpochMsFormatter(JsonFormatter):
    """timestamp를 epoch ms, level을 pino 숫자로 출력하는 JSON 포매터."""

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["time"] = int(record.created * 1000)
        log_record.pop("timestamp", None)
        # level을 pino 숫자 표준으로 변환
        log_record["level"] = _LEVEL_TO_PINO.get(record.levelno, 30)

from fastapi.responses import JSONResponse

from app.config import SERVICE_VERSION, settings
from app.context import RequestIdFilter, get_request_id, set_request_id
from app.errors import SastRunnerError
from app.routers.scan import router as scan_router
from app.scanner.orchestrator import ScanOrchestrator, sanitize_tool_availability_map


REQUEST_VALIDATION_ERROR_MESSAGE = "request validation failed"
REQUEST_VALIDATION_ERROR_CODE = "REQUEST_VALIDATION_FAILED"
SAFE_VALIDATION_LOC_PARTS = {
    "body",
    "query",
    "path",
    "headers",
    "files",
    "content",
    "scanId",
    "scan_id",
    "projectId",
    "project_id",
    "projectPath",
    "project_path",
    "compileCommands",
    "compile_commands",
    "buildProfile",
    "build_profile",
    "sdkId",
    "sdk_id",
    "sdkResolutionMode",
    "sdk_resolution_mode",
    "sdkDescriptor",
    "sdk_descriptor",
    "sdkRootPath",
    "sdk_root_path",
    "setupScript",
    "setup_script",
    "sysroot",
    "toolchainTriplet",
    "toolchain_triplet",
    "compilerPath",
    "compiler_path",
    "compilerVersion",
    "compiler_version",
    "targetArch",
    "target_arch",
    "languageStandard",
    "language_standard",
    "headerLanguage",
    "header_language",
    "includePaths",
    "include_paths",
    "defines",
    "environment",
    "compiler",
    "flags",
    "provenance",
    "buildSnapshotId",
    "build_snapshot_id",
    "buildUnitId",
    "build_unit_id",
    "snapshotSchemaVersion",
    "snapshot_schema_version",
    "rulesets",
    "thirdPartyPaths",
    "third_party_paths",
    "options",
    "timeoutSeconds",
    "timeout_seconds",
    "tools",
    "buildCommand",
    "build_command",
    "buildEnvironment",
    "build_environment",
    "wrapWithBear",
    "wrap_with_bear",
    "scanProfile",
    "scan_profile",
}
MAPPING_VALIDATION_LOC_PARTS = {
    "buildEnvironment",
    "build_environment",
    "defines",
    "environment",
}


def _setup_logging() -> None:
    """JSON structured logging 설정 (observability.md 준수)."""
    handler = logging.StreamHandler(sys.stdout)
    formatter = _EpochMsFormatter(
        fmt="%(levelname)s %(message)s",
        rename_fields={"levelname": "level", "message": "msg"},
        static_fields={"service": "s4-sast"},
    )
    handler.setFormatter(formatter)

    # 파일 핸들러 (JSONL)
    log_dir = settings.log_dir or str(Path(__file__).resolve().parents[3] / "logs")
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path / "s4-sast-runner.jsonl", mode="a")
    file_handler.setFormatter(formatter)

    logger = logging.getLogger("aegis-sast-runner")
    logger.setLevel(logging.INFO)
    logger.addFilter(RequestIdFilter())
    logger.addHandler(handler)
    logger.addHandler(file_handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱 시작/종료 시 실행."""
    _setup_logging()
    logger = logging.getLogger("aegis-sast-runner")
    hot_reload = os.getenv("SAST_HOT_RELOAD", "").lower() in {"1", "true", "yes", "on"}
    logger.info(
        "SAST Runner runtime configuration",
        extra={
            "port": settings.port,
            "serviceVersion": SERVICE_VERSION,
            "hotReload": hot_reload,
            "reloadDir": "app" if hot_reload else None,
            "maxConcurrentScans": settings.max_concurrent_scans,
            "scanTimeout": settings.scan_timeout,
            "defaultRulesets": settings.default_rulesets,
            "sdkRootConfigured": bool(settings.sdk_root),
            "logDirConfigured": bool(settings.log_dir),
            "logDirSource": "configured" if settings.log_dir else "default",
        },
    )

    orch = ScanOrchestrator()
    tools = sanitize_tool_availability_map(await orch.check_tools(force=True))
    for name, info in tools.items():
        if info["available"]:
            logger.info("Tool %s available: v%s", name, info["version"])
        else:
            logger.warning(
                "Tool %s not found",
                name,
                extra={
                    "probeReason": info.get("probeReason"),
                    "expectedExecutablePathStatus": info.get("expectedExecutablePathStatus"),
                },
            )

    policy = orch.build_health_policy(tools)
    if policy["policyStatus"] != "ok":
        logger.warning(
            "Tool availability degraded",
            extra={
                "policyStatus": policy["policyStatus"],
                "policyReasons": policy["policyReasons"],
                "unavailableTools": policy["unavailableTools"],
                "allowedSkipReasons": policy["allowedSkipReasons"],
            },
        )

    logger.info(
        "SAST Runner ready for traffic",
        extra={
            "port": settings.port,
            "serviceVersion": SERVICE_VERSION,
            "hotReload": hot_reload,
            "policyStatus": policy["policyStatus"],
            "policyReasons": policy["policyReasons"],
            "unavailableTools": policy["unavailableTools"],
            "allowedSkipReasons": policy["allowedSkipReasons"],
            "defaultRulesets": settings.default_rulesets,
        },
    )

    yield

    logger.info("SAST Runner shutting down")


app = FastAPI(
    title="AEGIS SAST Runner",
    version=SERVICE_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)


def _safe_validation_loc_part(part: Any) -> str | int:
    """Return structural validation location metadata without caller values."""
    if isinstance(part, int):
        return part
    if isinstance(part, str) and part in SAFE_VALIDATION_LOC_PARTS:
        return part
    return "<field>"


def _sanitize_validation_loc(loc: list[Any] | tuple[Any, ...]) -> list[str | int]:
    sanitized: list[str | int] = []
    previous_raw_part: Any = None
    for part in loc:
        if isinstance(part, str) and previous_raw_part in MAPPING_VALIDATION_LOC_PARTS:
            sanitized.append("<field>")
        else:
            sanitized.append(_safe_validation_loc_part(part))
        previous_raw_part = part
    return sanitized


def _sanitize_validation_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for error in errors:
        loc = error.get("loc") or []
        if not isinstance(loc, (list, tuple)):
            loc = ["<field>"]
        error_type = error.get("type")
        if not isinstance(error_type, str) or not error_type:
            error_type = "validation_error"
        sanitized.append(
            {
                "type": error_type,
                "loc": _sanitize_validation_loc(loc),
                "msg": "Invalid request field",
            },
        )
    return sanitized


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(request, exc: RequestValidationError):
    """Return value-free 422 validation errors without FastAPI raw `input` echo."""
    request_id = request.headers.get("X-Request-Id") or get_request_id() or "unknown"
    set_request_id(request_id)
    validation_errors = _sanitize_validation_errors(exc.errors())

    logger = logging.getLogger("aegis-sast-runner")
    logger.warning(
        "Request validation failed",
        extra={
            "requestId": request_id,
            "code": REQUEST_VALIDATION_ERROR_CODE,
            "validationErrorCount": len(validation_errors),
            "validationErrorLocations": [item["loc"] for item in validation_errors],
        },
    )

    return JSONResponse(
        status_code=422,
        headers={"X-Request-Id": request_id},
        content={
            "success": False,
            "error": REQUEST_VALIDATION_ERROR_MESSAGE,
            "errorDetail": {
                "code": REQUEST_VALIDATION_ERROR_CODE,
                "message": REQUEST_VALIDATION_ERROR_MESSAGE,
                "requestId": request_id,
                "retryable": False,
            },
            "validationErrors": validation_errors,
        },
    )


@app.exception_handler(SastRunnerError)
async def sast_runner_error_handler(request, exc: SastRunnerError):
    """SastRunnerError를 observability.md 형식으로 변환."""
    request_id = request.headers.get("X-Request-Id") or get_request_id() or "unknown"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.message,
            "errorDetail": {
                "code": exc.code,
                "message": exc.message,
                "requestId": request_id,
                "retryable": exc.retryable,
            },
        },
    )

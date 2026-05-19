"""Startup logging contract tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI

from app import main as main_module


class _HealthyOrchestrator:
    async def check_tools(self, *, force: bool = False):
        return {
            "semgrep": {
                "available": True,
                "version": "1.0.0",
                "probeReason": None,
            },
        }

    def build_health_policy(self, tools):
        return {
            "policyStatus": "ok",
            "policyReasons": [],
            "unavailableTools": [],
            "allowedSkipReasons": ["operator-requested-subset", "profile-not-applicable"],
        }


@pytest.mark.asyncio
async def test_startup_runtime_configuration_log_redacts_log_dir(caplog, monkeypatch):
    secret_log_dir = "/tmp/SECRET_STARTUP_LOG_DIR_SHOULD_NOT_LEAK"
    monkeypatch.setattr(main_module.settings, "log_dir", secret_log_dir)
    caplog.set_level("INFO", logger="aegis-sast-runner")

    with patch.object(main_module, "_setup_logging", lambda: None), patch.object(
        main_module,
        "ScanOrchestrator",
        return_value=_HealthyOrchestrator(),
    ):
        async with main_module.lifespan(FastAPI()):
            pass

    config_record = next(
        record for record in caplog.records
        if record.getMessage() == "SAST Runner runtime configuration"
    )
    assert config_record.logDirConfigured is True
    assert config_record.logDirSource == "configured"
    assert not hasattr(config_record, "logDir")
    assert secret_log_dir not in caplog.text


@pytest.mark.asyncio
async def test_startup_degraded_tool_log_redacts_expected_executable_path(caplog):
    secret_path = "/svc/SECRET_STARTUP_TOOL_PATH_SHOULD_NOT_LEAK/semgrep"

    class _FakeOrchestrator:
        async def check_tools(self, *, force: bool = False):
            return {
                "semgrep": {
                    "available": False,
                    "version": None,
                    "probeReason": "environment-drift",
                    "expectedExecutablePath": secret_path,
                },
            }

        def build_health_policy(self, tools):
            return {
                "policyStatus": "degraded",
                "policyReasons": ["environment-drift"],
                "unavailableTools": ["semgrep"],
                "allowedSkipReasons": ["operator-requested-subset", "profile-not-applicable"],
            }

    caplog.set_level("WARNING", logger="aegis-sast-runner")
    with patch.object(main_module, "_setup_logging", lambda: None), patch.object(
        main_module,
        "ScanOrchestrator",
        return_value=_FakeOrchestrator(),
    ):
        async with main_module.lifespan(FastAPI()):
            pass

    tool_record = next(
        record for record in caplog.records
        if record.getMessage() == "Tool semgrep not found"
    )
    assert tool_record.expectedExecutablePathStatus == "configured"
    assert not hasattr(tool_record, "expectedExecutablePath")
    assert secret_path not in caplog.text

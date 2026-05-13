"""Phase1Executor 단위 테스트 — 결정론적 도구 실행 + KB 연동."""
import json

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.core.phase_one import Phase1Executor, Phase1Result, build_phase2_prompt
from app.agent_runtime.schemas.agent import ToolResult


# ───────────────────────────────────────────────
# _extract_cwe_ids
# ───────────────────────────────────────────────

class TestExtractCweIds:
    def test_from_rule_id(self):
        findings = [{"ruleId": "flawfinder:CWE-78", "message": ""}]
        assert Phase1Executor._extract_cwe_ids(findings) == {"CWE-78"}

    def test_from_message(self):
        findings = [{"ruleId": "", "message": "race condition (CWE-362, CWE-20)"}]
        result = Phase1Executor._extract_cwe_ids(findings)
        assert "CWE-362" in result
        assert "CWE-20" in result

    def test_dedup(self):
        findings = [
            {"ruleId": "CWE-78", "message": "CWE-78 injection"},
            {"ruleId": "", "message": "also CWE-78"},
        ]
        assert Phase1Executor._extract_cwe_ids(findings) == {"CWE-78"}

    def test_empty(self):
        assert Phase1Executor._extract_cwe_ids([]) == set()

    def test_from_metadata_cwe(self):
        """metadata.cwe 배열에서 CWE를 추출한다 (S4 v0.4.0+)."""
        findings = [{"ruleId": "", "message": "", "metadata": {"cwe": ["CWE-476"]}}]
        assert Phase1Executor._extract_cwe_ids(findings) == {"CWE-476"}

    def test_metadata_cwe_combined(self):
        """ruleId + metadata.cwe에서 중복 없이 추출한다."""
        findings = [{"ruleId": "CWE-78", "message": "", "metadata": {"cwe": ["CWE-78", "CWE-77"]}}]
        result = Phase1Executor._extract_cwe_ids(findings)
        assert result == {"CWE-78", "CWE-77"}

    def test_no_cwe(self):
        findings = [{"ruleId": "bugprone-easily-swappable", "message": "parameters swapped"}]
        assert Phase1Executor._extract_cwe_ids(findings) == set()


# ───────────────────────────────────────────────
# _extract_dangerous_funcs
# ───────────────────────────────────────────────

class TestExtractDangerousFuncs:
    def test_matches_known_funcs(self):
        findings = [
            {"message": "popen() is dangerous"},
            {"message": "getenv() untrustable input"},
        ]
        result = Phase1Executor._extract_dangerous_funcs(findings)
        assert "popen" in result
        assert "getenv" in result

    def test_no_match(self):
        findings = [{"message": "variable is unused"}]
        assert Phase1Executor._extract_dangerous_funcs(findings) == set()

    def test_case_insensitive(self):
        findings = [{"message": "POPEN used in code"}]
        result = Phase1Executor._extract_dangerous_funcs(findings)
        assert "popen" in result


# ───────────────────────────────────────────────
# _run_threat_query
# ───────────────────────────────────────────────

class TestRunThreatQuery:
    @pytest.mark.asyncio
    async def test_success(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sast_findings=[{"ruleId": "CWE-78", "message": "command injection"}],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "results": [
                {"query": "CWE-78", "hits": [{"id": "CWE-78", "source": "CWE", "title": "OS Command Injection"}]},
            ],
        }
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        result = await executor._run_threat_query(result)

        assert len(result.threat_context) == 1
        assert result.threat_context[0]["id"] == "CWE-78"
        assert result.threat_query_duration_ms >= 0
        # 배치 API 호출 확인
        call_args = executor._kb_client.post.call_args
        assert "/v1/search/batch" in str(call_args)
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_kb_down_graceful(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sast_findings=[{"ruleId": "CWE-78", "message": "injection"}],
        )

        executor._kb_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        result = await executor._run_threat_query(result)

        assert result.threat_context == []
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_kb_not_ready_flagged(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sast_findings=[{"ruleId": "CWE-78", "message": "injection"}],
        )

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.json.return_value = {"errorDetail": {"code": "KB_NOT_READY"}}
        executor._kb_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError("kb not ready", request=MagicMock(), response=mock_response)
        )

        result = await executor._run_threat_query(result)

        assert result.threat_context == []
        assert result.kb_not_ready is True
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_kb_timeout_flagged(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sast_findings=[{"ruleId": "CWE-78", "message": "injection"}],
        )

        mock_response = MagicMock()
        mock_response.status_code = 408
        mock_response.json.return_value = {"errorDetail": {"code": "TIMEOUT"}}
        executor._kb_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError("timeout", request=MagicMock(), response=mock_response)
        )

        result = await executor._run_threat_query(result)

        assert result.threat_context == []
        assert result.kb_timed_out is True
        await executor.aclose()


# ───────────────────────────────────────────────
# _run_cve_lookup
# ───────────────────────────────────────────────

class TestRunCveLookup:
    @pytest.mark.asyncio
    async def test_success(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sca_libraries=[
                {"name": "mosquitto", "version": "2.0.22", "repoUrl": "https://github.com/eclipse/mosquitto.git"},
            ],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "results": [{
                "library": "mosquitto",
                "version": "2.0.22",
                "cves": [
                    {"id": "CVE-2021-34434", "version_match": True, "severity": 7.5},
                    {"id": "CVE-2023-99999", "version_match": False, "severity": 5.0},
                ],
            }],
        }
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        result = await executor._run_cve_lookup(result)

        assert len(result.cve_lookup) == 2
        matched = [c for c in result.cve_lookup if c.get("version_match") is True]
        assert len(matched) == 1
        assert matched[0]["id"] == "CVE-2021-34434"
        assert matched[0]["_library"] == "mosquitto"
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_partitions_s4_enriched_libraries_before_s5_lookup(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sca_libraries=[
                {
                    "name": "openssl",
                    "version": "1.1.1",
                    "repoUrl": "https://github.com/openssl/openssl.git",
                    "cveLookupEligible": True,
                    "versionStatus": "known",
                    "diagnostics": [],
                },
                {
                    "name": "zlib",
                    "version": None,
                    "repoUrl": "https://github.com/madler/zlib.git",
                    "cveLookupEligible": False,
                    "versionStatus": "unknown",
                    "diagnostics": [{"code": "VERSION_UNKNOWN"}],
                },
                {
                    "name": "ambiguous-lib",
                    "version": "1.0.0",
                    "cveLookupEligible": False,
                    "versionStatus": "ambiguous",
                    "diagnostics": [{"code": "VERSION_AMBIGUOUS"}],
                },
            ],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "results": [{"library": "openssl", "version": "1.1.1", "cves": []}],
        }
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        result = await executor._run_cve_lookup(result)

        request_body = executor._kb_client.post.await_args.kwargs["json"]
        assert request_body == {
            "libraries": [{
                "name": "openssl",
                "version": "1.1.1",
                "repoUrl": "https://github.com/openssl/openssl.git",
            }],
        }
        assert result.cve_lookup_attempted is True
        assert result.cve_lookup_completed is True
        assert result.cve_lookup_eligible_count == 1
        assert result.cve_lookup_attempted_libraries == request_body["libraries"]
        assert [skip["name"] for skip in result.cve_lookup_skipped_libraries] == ["zlib", "ambiguous-lib"]
        assert {skip["reason"] for skip in result.cve_lookup_skipped_libraries} == {
            "VERSION_UNKNOWN",
            "CVE_LOOKUP_INELIGIBLE",
        }
        assert all("version" in lib for lib in request_body["libraries"])
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_all_ineligible_s4_libraries_skip_s5_call(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sca_libraries=[
                {
                    "name": "versionless",
                    "version": None,
                    "cveLookupEligible": False,
                    "versionStatus": "unknown",
                    "diagnostics": [{"code": "VERSION_UNKNOWN"}],
                },
            ],
        )
        executor._kb_client.post = AsyncMock()

        result = await executor._run_cve_lookup(result)

        executor._kb_client.post.assert_not_called()
        assert result.cve_lookup_attempted is False
        assert result.cve_lookup_completed is False
        assert result.cve_lookup_eligible_count == 0
        assert result.cve_lookup == []
        assert result.cve_lookup_skipped_libraries == [{
            "name": "versionless",
            "version": None,
            "path": None,
            "reason": "VERSION_UNKNOWN",
            "versionStatus": "unknown",
            "diagnostics": [{"code": "VERSION_UNKNOWN"}],
        }]
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_legacy_name_version_library_remains_lookup_eligible(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(sca_libraries=[{"name": "legacy-lib", "version": "2.4.6"}])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"results": []}
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        result = await executor._run_cve_lookup(result)

        assert executor._kb_client.post.await_args.kwargs["json"] == {
            "libraries": [{"name": "legacy-lib", "version": "2.4.6"}],
        }
        assert result.cve_lookup_attempted is True
        assert result.cve_lookup_completed is True
        assert result.cve_lookup_skipped_libraries == []
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_truncated_eligible_libraries_record_unqueried_count(self, monkeypatch):
        monkeypatch.setattr("app.core.phase_one_kb.settings.phase1_max_cve_libraries", 1)
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sca_libraries=[
                {"name": "lib-a", "version": "1.0.0"},
                {"name": "lib-b", "version": "2.0.0"},
            ],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"results": []}
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        result = await executor._run_cve_lookup(result)

        assert executor._kb_client.post.await_args.kwargs["json"] == {
            "libraries": [{"name": "lib-a", "version": "1.0.0"}],
        }
        assert result.cve_lookup_eligible_count == 2
        assert result.cve_lookup_attempted_libraries == [{"name": "lib-a", "version": "1.0.0"}]
        assert result.cve_lookup_truncated is True
        assert result.cve_lookup_unqueried_eligible_count == 1
        assert result.cve_lookup_completed is True
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_kb_down_graceful(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sca_libraries=[{"name": "openssl", "version": "1.1.1"}],
        )

        executor._kb_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        result = await executor._run_cve_lookup(result)

        assert result.cve_lookup == []
        assert result.cve_lookup_attempted is True
        assert result.cve_lookup_completed is False
        assert result.cve_lookup_error
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_timeout_flagged(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sca_libraries=[{"name": "openssl", "version": "1.1.1"}],
        )

        mock_response = MagicMock()
        mock_response.status_code = 408
        mock_response.json.return_value = {"errorDetail": {"code": "TIMEOUT"}}
        executor._kb_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError("timeout", request=MagicMock(), response=mock_response)
        )

        result = await executor._run_cve_lookup(result)

        assert result.cve_lookup == []
        assert result.cve_lookup_timed_out is True
        assert result.cve_lookup_attempted is True
        assert result.cve_lookup_completed is False
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_no_libraries_skips(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(sca_libraries=[])

        result = await executor._run_cve_lookup(result)

        assert result.cve_lookup == []
        await executor.aclose()


# ───────────────────────────────────────────────
# _run_dangerous_callers
# ───────────────────────────────────────────────

class TestRunDangerousCallers:
    @pytest.mark.asyncio
    async def test_success(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sast_findings=[{"ruleId": "", "message": "popen() used for command execution"}],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "results": [
                {"name": "postJson", "file": "src/http_client.cpp", "line": 8, "dangerous_calls": ["popen"]},
            ],
        }
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        result = await executor._run_dangerous_callers(result, "test-project")

        assert len(result.dangerous_callers) == 1
        assert result.dangerous_callers[0]["name"] == "postJson"
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_timeout_flagged(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            sast_findings=[{"ruleId": "", "message": "popen() used for command execution"}],
        )

        mock_response = MagicMock()
        mock_response.status_code = 408
        mock_response.json.return_value = {"errorDetail": {"code": "TIMEOUT"}}
        executor._kb_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError("timeout", request=MagicMock(), response=mock_response)
        )

        result = await executor._run_dangerous_callers(result, "test-project")

        assert result.dangerous_callers == []
        assert result.dangerous_callers_timed_out is True
        await executor.aclose()


class TestIngestCodeGraph:
    @pytest.mark.asyncio
    async def test_consumes_ingest_readiness_contract(self):
        executor = Phase1Executor(kb_endpoint="http://localhost:8002")
        result = Phase1Result(
            code_functions=[
                {"name": "postJson", "file": "src/http_client.cpp", "line": 8, "calls": ["popen"]},
            ],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "status": "partial",
            "readiness": {
                "neo4jGraph": True,
                "vectorIndex": False,
                "graphRag": False,
            },
            "warnings": ["VECTOR_INDEX_INCOMPLETE"],
            "nodeCount": 1,
            "edgeCount": 0,
        }
        executor._kb_client.post = AsyncMock(return_value=mock_resp)

        await executor._ingest_code_graph(result, "proj-1", "req-1")

        assert result.code_graph_status == "partial"
        assert result.code_graph_neo4j_ready is True
        assert result.code_graph_vector_ready is False
        assert result.code_graph_graph_rag_ready is False
        assert result.code_graph_warnings == ["VECTOR_INDEX_INCOMPLETE"]
        await executor.aclose()


# ───────────────────────────────────────────────
# build_phase2_prompt
# ───────────────────────────────────────────────

class TestBuildPhase2Prompt:
    def test_mission_structure(self):
        """시스템 프롬프트에 임무 중심 4단계 구조가 포함된다."""
        result = Phase1Result()
        system, user = build_phase2_prompt(result, {"objective": "test"})

        assert "당신의 임무" in system
        assert "보고서 스키마" in system
        assert "규칙" in system
        # "JSON만 출력하라"가 임무 설명보다 앞에 오지 않음
        mission_pos = system.index("당신의 임무")
        schema_pos = system.index("보고서 스키마")
        assert mission_pos < schema_pos
        assert "계획만 쓰고 종료하지 마라" in system
        assert "caveats에 어떤 finding을 왜 dismiss했는지" in system
        assert "빈 배열로 둘 수는 있지만" in system
        assert "low-confidence claim" in system
        assert "Exploitability is plausible but not fully confirmed from the available evidence." in system
        assert "low_confidence_claim_present" in system
        assert "CWE/CVE 또는 exploitability grounding이 약한데도" in system
        assert "이 약한 grounding 보강 경로에서는 `build.metadata`를 사용하지 마라" in system

    def test_includes_threat_context(self):
        """위협 지식이 프롬프트에 포함된다."""
        result = Phase1Result(
            threat_context=[
                {"id": "CWE-78", "source": "CWE", "title": "OS Command Injection", "threat_category": "Injection"},
            ],
        )
        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "위협 지식" in user
        assert "CWE-78" in user
        assert "OS Command Injection" in user

    def test_includes_version_matched_cves(self):
        """version_match가 true인 CVE만 프롬프트에 포함된다."""
        result = Phase1Result(
            cve_lookup=[
                {"id": "CVE-2021-001", "version_match": True, "_library": "curl", "_version": "7.68", "title": "vuln1", "severity": 9.8},
                {"id": "CVE-2023-999", "version_match": False, "_library": "curl", "_version": "7.68", "title": "vuln2"},
            ],
        )
        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "CVE-2021-001" in user
        assert "CVE-2023-999" not in user
        assert "버전 매칭 완료" in user

    def test_epss_kev_critical_cve_section(self):
        """risk_score 높은 CVE가 고위험 섹션으로 분류된다."""
        result = Phase1Result(
            cve_lookup=[
                {"id": "CVE-2021-001", "version_match": True, "_library": "curl", "_version": "7.68",
                 "title": "critical vuln", "severity": 9.8, "kev": True, "epss_score": 0.92,
                 "risk_score": 0.85},
                {"id": "CVE-2021-002", "version_match": True, "_library": "curl", "_version": "7.68",
                 "title": "normal vuln", "severity": 5.0, "kev": False, "epss_score": 0.1,
                 "risk_score": 0.15},
            ],
        )
        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "고위험 CVE" in user
        assert "CISA KEV" in user
        assert "risk=0.85" in user
        assert "일반 CVE" in user

    def test_includes_dangerous_callers(self):
        """위험 함수 호출자가 프롬프트에 포함된다."""
        result = Phase1Result(
            dangerous_callers=[
                {"name": "postJson", "file": "src/http_client.cpp", "line": 8, "dangerous_calls": ["popen"]},
            ],
        )
        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "위험 함수 호출자" in user
        assert "postJson" in user
        assert "popen" in user

    def test_mentions_kb_timeouts_as_caveats(self):
        result = Phase1Result(
            kb_timed_out=True,
            cve_lookup_timed_out=True,
            dangerous_callers_timed_out=True,
        )

        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "KB timeout" in user
        assert "CVE lookup timeout" in user
        assert "dangerous-callers timeout" in user

    def test_sca_prompt_preserves_unknown_version_and_diff_uncertainty(self):
        result = Phase1Result(
            sca_libraries=[
                {
                    "name": "zlib",
                    "version": None,
                    "path": "third_party/zlib",
                    "versionStatus": "unknown",
                    "versionConfidence": "none",
                    "cveLookupEligible": False,
                    "diagnostics": [{"code": "VERSION_UNKNOWN"}, {"code": "DIFF_NOT_COMPUTED"}],
                    "diffAvailable": False,
                    "modificationStatus": "unknown",
                    "diffSummary": None,
                },
            ],
            cve_lookup_skipped_libraries=[
                {
                    "name": "zlib",
                    "version": None,
                    "path": "third_party/zlib",
                    "reason": "VERSION_UNKNOWN",
                    "versionStatus": "unknown",
                    "diagnostics": [{"code": "VERSION_UNKNOWN"}, {"code": "DIFF_NOT_COMPUTED"}],
                },
            ],
        )

        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "VERSION_UNKNOWN" in user
        assert "DIFF_NOT_COMPUTED" in user
        assert "CVE lookup skipped" in user
        assert "수정 여부 미확인" in user
        assert "원본 그대로" not in user

    def test_mentions_code_graph_not_ready(self):
        result = Phase1Result(
            code_graph_neo4j_ready=False,
        )

        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "code graph not ready" in user
        assert "code_graph.callers" in user
        assert "unavailable in this session" in user

    def test_mentions_code_graph_semantic_search_not_ready(self):
        result = Phase1Result(
            code_graph_neo4j_ready=True,
            code_graph_graph_rag_ready=False,
            code_graph_warnings=["VECTOR_INDEX_INCOMPLETE"],
        )

        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "code graph semantic search not ready" in user
        assert "VECTOR_INDEX_INCOMPLETE" in user
        assert "code_graph.search` is unavailable" in user

    def test_mentions_knowledge_search_unavailable_when_kb_not_ready(self):
        result = Phase1Result(kb_not_ready=True)

        _, user = build_phase2_prompt(result, {"objective": "test"})

        assert "KB not ready" in user
        assert "knowledge.search` is unavailable" in user

    def test_phase_a_is_not_accepted_as_final_output(self):
        """Phase A 계획만 출력하고 종료하면 안 된다는 규칙이 포함된다."""
        result = Phase1Result()
        system, _ = build_phase2_prompt(result, {"objective": "test"})

        assert "계획만 쓰고 종료하지 마라" in system
        assert "최종 JSON" in system
        assert "caveats에 어떤 finding을 왜 dismiss했는지" in system


# ───────────────────────────────────────────────
# targetPath 지원
# ───────────────────────────────────────────────

class TestTargetPath:
    @pytest.mark.asyncio
    async def test_target_path_combines_with_project_path(self):
        """targetPath가 지정되면 projectPath/targetPath를 분석 루트로 사용한다."""
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-target",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "targetPath": "gateway/",
                    "projectId": "proj-1",
                    "buildCommand": "bash build.sh",
                    "buildProfile": {"sdkId": "nxp-s32g2"},
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        # build-and-analyze를 mock하여 전달된 project_path를 캡처
        captured_path = {}

        async def mock_ba(result, project_id, project_path, build_command, build_profile, request_id, **kwargs):
            captured_path["path"] = project_path
            return result

        executor._run_build_and_analyze = mock_ba

        await executor.execute(session)

        assert captured_path["path"] == "/uploads/project/gateway"
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_no_target_path_uses_project_path(self):
        """targetPath가 없으면 projectPath를 그대로 사용한다."""
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-no-target",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "buildCommand": "bash build.sh",
                    "buildProfile": {"sdkId": "nxp-s32g2"},
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        captured_path = {}

        async def mock_ba(result, project_id, project_path, build_command, build_profile, request_id, **kwargs):
            captured_path["path"] = project_path
            return result

        executor._run_build_and_analyze = mock_ba

        await executor.execute(session)

        assert captured_path["path"] == "/uploads/project"
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_target_path_traversal_blocked(self):
        """targetPath에 ../가 포함되면 projectPath로 fallback한다."""
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-traversal",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "targetPath": "../../etc/",
                    "projectId": "proj-1",
                    "buildCommand": "bash build.sh",
                    "buildProfile": {"sdkId": "nxp-s32g2"},
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        captured_path = {}

        async def mock_ba(result, project_id, project_path, build_command, build_profile, request_id, **kwargs):
            captured_path["path"] = project_path
            return result

        executor._run_build_and_analyze = mock_ba

        await executor.execute(session)

        # traversal이 차단되어 projectPath로 fallback
        assert captured_path["path"] == "/uploads/project"
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_build_preparation_bundle_drives_build_and_analyze(self):
        """명시적 buildPreparation 번들이 있으면 top-level buildCommand 없이도 build-and-analyze를 탄다."""
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-build-preparation",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "buildPreparation": {
                        "buildCommand": "bash build-aegis/run.sh",
                        "buildEnvironment": {"CC": "arm-none-linux-gnueabihf-gcc"},
                        "buildProfile": {"sdkId": "nxp-s32g2"},
                        "provenance": {"buildSnapshotId": "bsnap-1"},
                    },
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        captured = {}

        async def mock_ba(result, project_id, project_path, build_command, build_profile, request_id, **kwargs):
            captured["project_id"] = project_id
            captured["project_path"] = project_path
            captured["build_command"] = build_command
            captured["build_profile"] = build_profile
            captured["build_environment"] = kwargs.get("build_environment")
            captured["provenance"] = kwargs.get("provenance")
            return result

        executor._run_build_and_analyze = mock_ba

        await executor.execute(session)

        assert captured["project_id"] == "proj-1"
        assert captured["project_path"] == "/uploads/project"
        assert captured["build_command"] == "bash build-aegis/run.sh"
        assert captured["build_profile"] == {"sdkId": "nxp-s32g2"}
        assert captured["build_environment"] == {"CC": "arm-none-linux-gnueabihf-gcc"}
        assert captured["provenance"] == {"buildSnapshotId": "bsnap-1"}
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_quick_context_precomputed_results_skip_tool_execution(self):
        """명시적 quickContext findings/libraries가 있으면 결정론적 재실행을 건너뛴다."""
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-quick-context",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "quickContext": {
                        "sastFindings": [{
                            "ruleId": "CWE-78",
                            "message": "command injection",
                            "metadata": {
                                "evidenceResolution": {
                                    "schemaVersion": "s4-evidence-v1",
                                    "kind": "sast-finding",
                                    "diagnostics": ["CWE_UNKNOWN"],
                                },
                            },
                        }],
                        "scaLibraries": [{
                            "name": "openssl",
                            "version": "1.1.1",
                            "versionStatus": "known",
                            "cveLookupEligible": True,
                            "diffAvailable": False,
                            "diagnostics": [{"code": "DIFF_NOT_COMPUTED"}],
                        }],
                    },
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        executor._run_build_and_analyze = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_individual_tools = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_cve_lookup = AsyncMock(side_effect=lambda result: result)
        executor._run_threat_query = AsyncMock(side_effect=lambda result: result)
        executor._run_dangerous_callers = AsyncMock(side_effect=lambda result, *_args, **_kwargs: result)

        result = await executor.execute(session)

        assert result.sast_findings[0]["metadata"]["evidenceResolution"]["schemaVersion"] == "s4-evidence-v1"
        assert result.sca_libraries[0]["versionStatus"] == "known"
        assert result.sca_libraries[0]["diagnostics"] == [{"code": "DIFF_NOT_COMPUTED"}]
        executor._run_build_and_analyze.assert_not_called()
        executor._run_individual_tools.assert_not_called()
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_quick_context_degraded_static_contract_is_not_clean_no_findings(self):
        """precomputed S4 evidence still honors staticEvidenceContract readiness."""
        from app.core.agent_session import AgentSession
        from app.core.evidence_catalog import EvidenceCatalog
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-quick-context-degraded-static-contract",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "quickContext": {
                        "sastFindings": [],
                        "staticEvidenceContract": {
                            "gates": {
                                "systemStability": {"status": "degraded", "reasonCodes": ["TOOL_PARTIAL:scan-build"]},
                                "evidenceReadiness": {"status": "partial", "reasonCodes": ["LOCAL_EVIDENCE_PARTIAL"]},
                                "claimSupportReadiness": {"status": "partial", "reasonCodes": ["LOCAL_ARTIFACT_DEGRADED"]},
                            },
                            "claimBoundaryMatrix": [],
                            "toolEvidenceMatrix": [{"toolId": "scan-build", "status": "partial"}],
                        },
                    },
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        executor._run_build_and_analyze = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_individual_tools = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_cve_lookup = AsyncMock(side_effect=lambda result: result)
        executor._run_threat_query = AsyncMock(side_effect=lambda result: result)
        executor._run_dangerous_callers = AsyncMock(side_effect=lambda result, *_args, **_kwargs: result)

        result = await executor.execute(session)

        assert result.sast_scan_completed is True
        assert result.sast_static_evidence_ready is False
        catalog = EvidenceCatalog()
        catalog.ingest_phase1_result(result)
        assert catalog.negative_ref_ids() == set()
        operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
        assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
        executor._run_build_and_analyze.assert_not_called()
        executor._run_individual_tools.assert_not_called()
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_quick_context_missing_static_contract_suppresses_no_findings(self):
        """precomputed S4 findings without current contract are not clean evidence."""
        from app.core.agent_session import AgentSession
        from app.core.evidence_catalog import EvidenceCatalog
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-quick-context-missing-static-contract",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "quickContext": {
                        "sastFindings": [],
                    },
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        executor._run_build_and_analyze = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_individual_tools = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_cve_lookup = AsyncMock(side_effect=lambda result: result)
        executor._run_threat_query = AsyncMock(side_effect=lambda result: result)
        executor._run_dangerous_callers = AsyncMock(side_effect=lambda result, *_args, **_kwargs: result)

        result = await executor.execute(session)

        assert result.sast_scan_completed is True
        assert result.sast_static_evidence_ready is False
        assert "STATIC_EVIDENCE_CONTRACT_MISSING" in result.sast_static_evidence_diagnostics["reasonCodes"]
        catalog = EvidenceCatalog()
        catalog.ingest_phase1_result(result)
        assert catalog.negative_ref_ids() == set()
        operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
        assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
        executor._run_build_and_analyze.assert_not_called()
        executor._run_individual_tools.assert_not_called()
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_graph_context_not_ready_skips_dangerous_callers(self):
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-graph-context-not-ready",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "quickContext": {
                        "sastFindings": [{"ruleId": "CWE-78", "message": "command injection"}],
                    },
                    "graphContext": {
                        "status": "partial",
                        "readiness": {
                            "neo4jGraph": False,
                            "graphRag": False,
                        },
                    },
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        executor._run_build_and_analyze = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_individual_tools = AsyncMock(side_effect=AssertionError("should not run"))
        executor._run_cve_lookup = AsyncMock(side_effect=lambda result: result)
        executor._run_threat_query = AsyncMock(side_effect=lambda result: result)
        executor._run_dangerous_callers = AsyncMock(side_effect=lambda result, *_args, **_kwargs: result)

        result = await executor.execute(session)

        assert result.code_graph_status == "partial"
        assert result.code_graph_neo4j_ready is False
        executor._run_dangerous_callers.assert_not_called()
        await executor.aclose()


class TestBuildAndAnalyzeFallback:
    @pytest.mark.asyncio
    async def test_execute_passes_preserved_compile_commands_to_fallback(self):
        from app.core.agent_session import AgentSession
        from app.schemas.request import TaskRequest

        request = TaskRequest.model_validate({
            "taskType": "deep-analyze",
            "taskId": "test-ba-fallback",
            "context": {
                "trusted": {
                    "objective": "test",
                    "projectPath": "/uploads/project",
                    "projectId": "proj-1",
                    "buildCommand": "bash build.sh",
                }
            },
        })
        from app.agent_runtime.schemas.agent import BudgetState
        budget = BudgetState(max_steps=1, max_completion_tokens=100)
        session = AgentSession(request, budget)

        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )

        async def mock_ba(result, *args, **kwargs):
            result.build_compile_commands_path = "/tmp/compile_commands.json"
            return None

        captured = {}

        async def mock_individual(result, files, project_id, project_path, build_profile, request_id, **kwargs):
            captured["compile_commands_path"] = kwargs.get("compile_commands_path")
            return result

        executor._run_build_and_analyze = mock_ba
        executor._run_individual_tools = mock_individual

        await executor.execute(session)

        assert captured["compile_commands_path"] == "/tmp/compile_commands.json"
        await executor.aclose()

    @pytest.mark.asyncio
    async def test_build_and_analyze_http_failure_preserves_build_evidence(self):
        executor = Phase1Executor(
            sast_endpoint="http://localhost:9000",
            kb_endpoint="http://localhost:8002",
        )
        result = Phase1Result()

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.json.return_value = {
            "success": False,
            "status": "failed",
            "build": {
                "success": True,
                "buildEvidence": {
                    "compileCommandsPath": "/tmp/compile_commands.json",
                    "entries": 7,
                },
            },
            "failureDetail": {
                "code": "DISALLOWED_TOOL_OMISSION",
                "message": "tool omission policy violation",
            },
        }
        executor._sast_client.post = AsyncMock(return_value=mock_resp)

        ba_result = await executor._run_build_and_analyze(
            result,
            "proj-1",
            "/uploads/project",
            "bash build.sh",
            None,
            "req-1",
        )

        assert ba_result is None
        assert result.build_compile_commands_path == "/tmp/compile_commands.json"
        assert result.build_failure_detail["code"] == "DISALLOWED_TOOL_OMISSION"


@pytest.mark.asyncio
async def test_phase1_sast_invoked_exactly_once_per_request_individual_path():
    from app.core.agent_session import AgentSession
    from app.schemas.request import Context, TaskRequest
    from app.agent_runtime.schemas.agent import BudgetState

    request = TaskRequest(
        taskType="deep-analyze",
        taskId="phase1-exactly-once-individual",
        context=Context(trusted={
            "files": [{"path": "src/http_client.cpp", "content": "int f(){ return popen(url, \"r\") != 0; }"}],
        }),
    )
    session = AgentSession(request, BudgetState())
    executor = Phase1Executor(kb_endpoint="http://localhost:8002")
    individual_calls = {"count": 0}

    async def fake_individual(result, *args, **kwargs):
        individual_calls["count"] += 1
        result.sast_findings = [{"ruleId": "CWE-78", "message": "popen"}]
        return result

    executor._fetch_project_memory = AsyncMock(return_value=[])
    executor._run_build_and_analyze = AsyncMock(side_effect=AssertionError("build path should not run"))
    executor._run_individual_tools = fake_individual
    executor._run_threat_query = AsyncMock(side_effect=lambda result: result)
    executor._run_dangerous_callers = AsyncMock(side_effect=lambda result, *_args, **_kwargs: result)

    await executor.execute(session)

    assert individual_calls["count"] == 1
    executor._run_build_and_analyze.assert_not_called()
    await executor.aclose()


@pytest.mark.asyncio
async def test_phase1_sast_invoked_exactly_once_per_request_build_path():
    from app.core.agent_session import AgentSession
    from app.schemas.request import Context, TaskRequest
    from app.agent_runtime.schemas.agent import BudgetState

    request = TaskRequest(
        taskType="deep-analyze",
        taskId="phase1-exactly-once-build",
        context=Context(trusted={
            "projectPath": "/uploads/project",
            "buildCommand": "bash build.sh",
        }),
    )
    session = AgentSession(request, BudgetState())
    executor = Phase1Executor(kb_endpoint="http://localhost:8002")
    build_calls = {"count": 0}

    async def fake_build(result, *args, **kwargs):
        build_calls["count"] += 1
        result.sast_findings = [{"ruleId": "CWE-78", "message": "popen"}]
        return result

    executor._fetch_project_memory = AsyncMock(return_value=[])
    executor._run_build_and_analyze = fake_build
    executor._run_individual_tools = AsyncMock(side_effect=AssertionError("fallback should not run"))
    executor._run_threat_query = AsyncMock(side_effect=lambda result: result)
    executor._run_dangerous_callers = AsyncMock(side_effect=lambda result, *_args, **_kwargs: result)

    await executor.execute(session)

    assert build_calls["count"] == 1
    executor._run_individual_tools.assert_not_called()
    await executor.aclose()


# ───────────────────────────────────────────────
# _format_origin_label
# ───────────────────────────────────────────────

class TestFormatOriginLabel:
    def test_modified_third_party(self):
        from app.core.phase_one import _format_origin_label
        func = {"origin": "modified-third-party", "original_lib": "libcurl", "original_version": "7.68.0"}
        assert _format_origin_label(func) == " [수정된 서드파티: libcurl v7.68.0]"

    def test_third_party(self):
        from app.core.phase_one import _format_origin_label
        func = {"origin": "third-party", "originalLib": "rapidjson"}  # camelCase
        assert _format_origin_label(func) == " [서드파티: rapidjson]"

    def test_user_code(self):
        from app.core.phase_one import _format_origin_label
        func = {"name": "main", "file": "src/main.cpp"}
        assert _format_origin_label(func) == ""

    def test_null_origin(self):
        from app.core.phase_one import _format_origin_label
        func = {"origin": None}
        assert _format_origin_label(func) == ""


def test_s4_build_profile_strips_custom_sdkid_for_native_profile():
    from app.core.phase_one_exec import _s4_build_profile

    assert _s4_build_profile({
        "sdkId": "custom",
        "compiler": "g++",
        "targetArch": "x86_64",
    }) == {
        "compiler": "g++",
        "targetArch": "x86_64",
    }


def test_s4_build_profile_preserves_real_sdkid():
    from app.core.phase_one_exec import _s4_build_profile

    assert _s4_build_profile({
        "sdkId": "ti-am335x",
        "compiler": "arm-none-linux-gnueabihf-gcc",
    }) == {
        "sdkId": "ti-am335x",
        "compiler": "arm-none-linux-gnueabihf-gcc",
    }


def test_s4_build_profile_converts_resolved_sdk_environment_to_non_registered_descriptor():
    from app.core.phase_one_exec import _s4_build_profile

    assert _s4_build_profile(
        {
            "sdkId": "ti-am335x-08.02.00.24",
            "compiler": "arm-linux-gnueabihf-gcc",
            "targetArch": "armv7",
            "includePaths": ["project/include"],
        },
        build_environment={
            "AEGIS_SDK_ROOT": "/uploads/sdk/ti",
            "AEGIS_SDK_SETUP_SCRIPT": "/uploads/sdk/ti/environment-setup-armv7",
            "AEGIS_SDK_SYSROOT": "/uploads/sdk/ti/sysroots/armv7",
            "AEGIS_TOOLCHAIN_TRIPLET": "arm-linux-gnueabihf",
        },
    ) == {
        "sdkResolutionMode": "non-registered",
        "sdkDescriptor": {
            "sdkRootPath": "/uploads/sdk/ti",
            "setupScript": "/uploads/sdk/ti/environment-setup-armv7",
            "sysroot": "/uploads/sdk/ti/sysroots/armv7",
            "toolchainTriplet": "arm-linux-gnueabihf",
        },
        "compiler": "arm-linux-gnueabihf-gcc",
        "targetArch": "armv7",
        "includePaths": ["project/include"],
    }


def test_s4_build_profile_preserves_explicit_non_registered_descriptor():
    from app.core.phase_one_exec import _s4_build_profile

    assert _s4_build_profile({
        "sdkId": "legacy-label",
        "sdkResolutionMode": "non-registered",
        "sdkDescriptor": {
            "sdkRootPath": "/uploads/sdk/custom",
            "sysroot": "/uploads/sdk/custom/sysroot",
        },
        "compiler": "clang",
    }) == {
        "sdkResolutionMode": "non-registered",
        "sdkDescriptor": {
            "sdkRootPath": "/uploads/sdk/custom",
            "sysroot": "/uploads/sdk/custom/sysroot",
        },
        "compiler": "clang",
    }


@pytest.mark.asyncio
async def test_build_and_analyze_uses_durable_ownership_and_fetches_result(monkeypatch):
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")
    submit = MagicMock(status_code=202)
    submit.json.return_value = {
        "requestId": "req-ba-owned",
        "statusUrl": "/v1/requests/req-ba-owned",
        "resultUrl": "/v1/requests/req-ba-owned/result",
    }
    running = MagicMock(status_code=200)
    running.json.return_value = {
        "requestId": "req-ba-owned",
        "state": "running",
        "localAckState": "transport-only",
        "blockedReason": None,
        "resultReady": False,
    }
    completed = MagicMock(status_code=200)
    completed.json.return_value = {"requestId": "req-ba-owned", "state": "completed", "resultReady": True}
    final = MagicMock(status_code=200)
    final.json.return_value = {
        "requestId": "req-ba-owned",
        "result": {
            "success": True,
            "build": {"success": True, "buildEvidence": {"compileCommandsPath": "/tmp/cc.json"}},
            "scan": {
                "success": True,
                "findings": [{"ruleId": "CWE-78", "location": {"file": "main.c"}}],
                "stats": {"findingsTotal": 1},
                "execution": {"toolResults": {}},
            },
            "codeGraph": {"functions": [{"name": "main"}]},
            "libraries": [{
                "name": "libx",
                "version": None,
                "versionStatus": "unknown",
                "cveLookupEligible": False,
                "diagnostics": [{"code": "VERSION_UNKNOWN"}],
                "diffAvailable": False,
                "modificationStatus": "unknown",
            }],
        },
    }
    executor._sast_client.post = AsyncMock(return_value=submit)
    executor._sast_client.get = AsyncMock(side_effect=[running, completed, final])
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    result = Phase1Result()
    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash build.sh",
        None,
        "req-root",
    )

    assert actual is result
    assert result.build_compile_commands_path == "/tmp/cc.json"
    assert result.sast_findings[0]["ruleId"] == "CWE-78"
    assert result.code_functions[0]["name"] == "main"
    assert result.sca_libraries[0]["name"] == "libx"
    assert result.sca_libraries[0]["versionStatus"] == "unknown"
    assert result.sca_libraries[0]["diagnostics"] == [{"code": "VERSION_UNKNOWN"}]
    headers = executor._sast_client.post.await_args.kwargs["headers"]
    assert headers["Prefer"] == "respond-async"
    assert headers["X-Request-Id"].startswith("req-root:s4:v1-build-and-analyze:phase1_build_and_analyze:")
    await executor.aclose()


@pytest.mark.asyncio
async def test_build_and_analyze_forwards_non_registered_sdk_descriptor(monkeypatch):
    from types import SimpleNamespace

    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    captured = {}

    async def fake_post_and_wait(*args, **kwargs):
        captured["payload"] = kwargs["payload"]
        return SimpleNamespace(payload={
            "success": True,
            "build": {"success": True, "buildEvidence": {}},
            "scan": {
                "success": True,
                "findings": [],
                "stats": {"findingsTotal": 0},
                "execution": {"toolResults": {}},
            },
            "codeGraph": {"functions": []},
            "libraries": [],
        })

    monkeypatch.setattr(
        "app.core.phase_one_exec.post_and_wait_s4_ownership",
        fake_post_and_wait,
    )
    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")

    result = Phase1Result()
    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash scripts/build.sh",
        {"sdkId": "ti-am335x-08.02.00.24", "compiler": "arm-linux-gnueabihf-gcc"},
        "req-root",
        build_environment={
            "AEGIS_SDK_ROOT": "/uploads/project/.aegis/sdks/ti",
            "SDKTARGETSYSROOT": "/uploads/project/.aegis/sdks/ti/sysroots/armv7",
        },
    )

    assert actual is result
    scan_profile = captured["payload"]["scanProfile"]
    assert scan_profile["sdkResolutionMode"] == "non-registered"
    assert scan_profile["sdkDescriptor"] == {
        "sdkRootPath": "/uploads/project/.aegis/sdks/ti",
        "sysroot": "/uploads/project/.aegis/sdks/ti/sysroots/armv7",
    }
    assert "sdkId" not in scan_profile
    assert scan_profile["compiler"] == "arm-linux-gnueabihf-gcc"
    await executor.aclose()


@pytest.mark.asyncio
async def test_build_and_analyze_durable_ack_break_returns_none(monkeypatch):
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")
    submit = MagicMock(status_code=202)
    submit.json.return_value = {
        "requestId": "req-ba-blocked",
        "statusUrl": "/v1/requests/req-ba-blocked",
        "resultUrl": "/v1/requests/req-ba-blocked/result",
    }
    blocked = MagicMock(status_code=200)
    blocked.json.return_value = {
        "requestId": "req-ba-blocked",
        "state": "failed",
        "localAckState": "ack-break",
        "blockedReason": "build_failed",
        "resultReady": False,
    }
    executor._sast_client.post = AsyncMock(return_value=submit)
    executor._sast_client.get = AsyncMock(return_value=blocked)

    result = Phase1Result()
    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash build.sh",
        None,
        "req-root",
    )

    assert actual is None
    await executor.aclose()


@pytest.mark.asyncio
async def test_build_and_analyze_records_s4_contract_failure(monkeypatch):
    from app.clients.s4_ownership import S4OwnershipError
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    async def fake_post_and_wait(*args, **kwargs):
        raise S4OwnershipError(
            "S4 submit failed with HTTP 400",
            status_code=400,
            payload={
                "success": False,
                "failureDetail": {
                    "code": "SDK_NOT_FOUND",
                    "message": "SDK profile not registered",
                },
            },
        )

    monkeypatch.setattr(
        "app.core.phase_one_exec.post_and_wait_s4_ownership",
        fake_post_and_wait,
    )
    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")

    result = Phase1Result()
    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash build.sh",
        {"sdkId": "unknown-sdk"},
        "req-root",
    )

    assert actual is None
    assert result.sast_scan_attempted is True
    assert result.sast_scan_completed is False
    assert result.sast_failure_detail["code"] == "SDK_NOT_FOUND"
    assert result.sast_failure_detail["statusCode"] == 400
    assert result.sast_failure_detail["message"] == "SDK profile not registered"
    await executor.aclose()


@pytest.mark.asyncio
async def test_run_sast_records_tool_failure_detail():
    from app.agent_runtime.schemas.agent import ToolResult
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    class FailingSastTool:
        async def execute(self, arguments):
            return ToolResult(
                tool_call_id="sast-1",
                name="sast.scan",
                success=False,
                content='{"failureDetail":{"code":"SDK_PROFILE_INVALID","message":"invalid profile"}}',
                error="invalid profile",
            )

    executor = Phase1Executor(
        sast_tool=FailingSastTool(),
        sast_endpoint="http://localhost:9000",
        kb_endpoint="http://localhost:8002",
    )

    result = await executor._run_sast(
        Phase1Result(),
        [],
        "proj-1",
        {"sdkResolutionMode": "none"},
        "req-root",
        project_path="/uploads/project",
    )

    assert result.sast_scan_attempted is True
    assert result.sast_scan_completed is False
    assert result.sast_failure_detail["code"] == "SDK_PROFILE_INVALID"
    assert result.sast_failure_detail["message"] == "invalid profile"
    await executor.aclose()


@pytest.mark.asyncio
async def test_run_sast_records_required_tool_system_stability_failure_without_no_findings():
    from app.agent_runtime.schemas.agent import ToolResult
    from app.core.evidence_catalog import EvidenceCatalog
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    class RequiredToolIncompleteSastTool:
        async def execute(self, arguments):
            return ToolResult(
                tool_call_id="sast-1",
                name="sast.scan",
                success=False,
                content=json.dumps({
                    "success": False,
                    "statusCode": 503,
                    "errorDetail": {
                        "code": "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
                        "message": "required tool scan-build did not complete",
                    },
                    "findings": [],
                    "stats": {},
                    "staticEvidenceContract": {
                        "gates": {
                            "systemStability": {"status": "fail"},
                            "evidenceReadiness": {"status": "not_ready"},
                            "claimSupportReadiness": {"status": "fail"},
                        }
                    },
                }),
                error="REQUIRED_TOOL_EXECUTION_INCOMPLETE: required tool scan-build did not complete",
            )

    executor = Phase1Executor(
        sast_tool=RequiredToolIncompleteSastTool(),
        sast_endpoint="http://localhost:9000",
        kb_endpoint="http://localhost:8002",
    )

    result = await executor._run_sast(
        Phase1Result(),
        [],
        "proj-1",
        {"sdkResolutionMode": "none"},
        "req-root",
        project_path="/uploads/project",
    )

    assert result.sast_scan_attempted is True
    assert result.sast_scan_completed is False
    assert result.sast_failure_detail["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert result.sast_failure_detail["statusCode"] == 503

    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(result)
    assert catalog.negative_ref_ids() == set()
    operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
    assert len(operational) == 2
    assert any("sast_scan_failed" in entry.roles for entry in operational if entry)
    assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
    assert all("sast_contract_failure" not in entry.roles for entry in operational if entry)
    await executor.aclose()


@pytest.mark.asyncio
async def test_run_sast_success_with_degraded_static_contract_is_not_clean_no_findings():
    from app.agent_runtime.schemas.agent import ToolResult
    from app.core.evidence_catalog import EvidenceCatalog
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    class DegradedContractSastTool:
        async def execute(self, arguments):
            return ToolResult(
                tool_call_id="sast-1",
                name="sast.scan",
                success=True,
                content=json.dumps({
                    "success": True,
                    "findings": [],
                    "stats": {},
                    "execution": {"toolResults": {"scan-build": {"status": "partial"}}},
                    "staticEvidenceContract": {
                        "gates": {
                            "systemStability": {"status": "degraded", "reasonCodes": ["TOOL_PARTIAL:scan-build"]},
                            "evidenceReadiness": {"status": "partial", "reasonCodes": ["LOCAL_EVIDENCE_PARTIAL"]},
                            "claimSupportReadiness": {"status": "partial", "reasonCodes": ["LOCAL_ARTIFACT_DEGRADED"]},
                        },
                        "claimBoundaryMatrix": [],
                        "toolEvidenceMatrix": [{"toolId": "scan-build", "status": "partial"}],
                    },
                }),
            )

    executor = Phase1Executor(
        sast_tool=DegradedContractSastTool(),
        sast_endpoint="http://localhost:9000",
        kb_endpoint="http://localhost:8002",
    )

    result = await executor._run_sast(
        Phase1Result(),
        [],
        "proj-1",
        {"sdkResolutionMode": "none"},
        "req-root",
        project_path="/uploads/project",
    )

    assert result.sast_scan_attempted is True
    assert result.sast_scan_completed is True
    assert result.sast_static_evidence_ready is False
    assert result.sast_static_evidence_diagnostics["systemStability"] == "degraded"
    assert result.sast_static_evidence_diagnostics["evidenceReadiness"] == "partial"
    assert result.sast_static_evidence_diagnostics["claimSupportReadiness"] == "partial"

    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(result)
    assert catalog.negative_ref_ids() == set()
    operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
    assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
    await executor.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("static_contract", [None, {}, []])
async def test_run_sast_success_missing_or_malformed_static_contract_is_not_clean_no_findings(static_contract):
    from app.agent_runtime.schemas.agent import ToolResult
    from app.core.evidence_catalog import EvidenceCatalog
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    class MissingContractSastTool:
        async def execute(self, arguments):
            payload = {
                "success": True,
                "findings": [],
                "stats": {},
                "execution": {"toolResults": {}},
            }
            if static_contract is not None:
                payload["staticEvidenceContract"] = static_contract
            return ToolResult(
                tool_call_id="sast-1",
                name="sast.scan",
                success=True,
                content=json.dumps(payload),
            )

    executor = Phase1Executor(
        sast_tool=MissingContractSastTool(),
        sast_endpoint="http://localhost:9000",
        kb_endpoint="http://localhost:8002",
    )

    result = await executor._run_sast(
        Phase1Result(),
        [],
        "proj-1",
        {"sdkResolutionMode": "none"},
        "req-root",
        project_path="/uploads/project",
    )

    assert result.sast_scan_completed is True
    assert result.sast_static_evidence_ready is False
    assert "STATIC_EVIDENCE_CONTRACT_MISSING" in result.sast_static_evidence_diagnostics["reasonCodes"]

    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(result)
    assert catalog.negative_ref_ids() == set()
    operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
    assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
    await executor.aclose()


@pytest.mark.asyncio
async def test_build_and_analyze_success_with_degraded_static_contract_is_not_clean_no_findings(monkeypatch):
    from app.clients.s4_ownership import S4OwnershipResult
    from app.core.evidence_catalog import EvidenceCatalog
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    async def fake_post_and_wait(*args, **kwargs):
        return S4OwnershipResult(
            request_id="req-ba",
            payload={
                "success": True,
                "build": {
                    "success": True,
                    "buildEvidence": {"compileCommandsPath": "/uploads/project/compile_commands.json"},
                    "readiness": {"status": "ready", "compileCommandsReady": True, "quickEligible": True},
                },
                "scan": {
                    "success": True,
                    "findings": [],
                    "stats": {},
                    "execution": {"toolResults": {"scan-build": {"status": "partial"}}},
                    "staticEvidenceContract": {
                        "gates": {
                            "systemStability": {"status": "degraded", "reasonCodes": ["TOOL_PARTIAL:scan-build"]},
                            "evidenceReadiness": {"status": "partial", "reasonCodes": ["LOCAL_EVIDENCE_PARTIAL"]},
                            "claimSupportReadiness": {"status": "partial", "reasonCodes": ["LOCAL_ARTIFACT_DEGRADED"]},
                        },
                        "claimBoundaryMatrix": [],
                        "toolEvidenceMatrix": [{"toolId": "scan-build", "status": "partial"}],
                    },
                },
                "codeGraph": {"functions": []},
                "libraries": [],
            },
            raw={},
        )

    monkeypatch.setattr(
        "app.core.phase_one_exec.post_and_wait_s4_ownership",
        fake_post_and_wait,
    )
    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")
    result = Phase1Result()

    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash build.sh",
        {"sdkResolutionMode": "none"},
        "req-root",
    )

    assert actual is result
    assert result.sast_scan_completed is True
    assert result.sast_static_evidence_ready is False
    assert result.build_compile_commands_path == "/uploads/project/compile_commands.json"

    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(result)
    assert catalog.negative_ref_ids() == set()
    operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
    assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
    await executor.aclose()


@pytest.mark.asyncio
async def test_build_and_analyze_success_missing_static_contract_suppresses_no_findings(monkeypatch):
    from app.clients.s4_ownership import S4OwnershipResult
    from app.core.evidence_catalog import EvidenceCatalog
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    async def fake_post_and_wait(*args, **kwargs):
        return S4OwnershipResult(
            request_id="req-ba",
            payload={
                "success": True,
                "build": {
                    "success": True,
                    "buildEvidence": {"compileCommandsPath": "/uploads/project/compile_commands.json"},
                    "readiness": {"status": "ready", "compileCommandsReady": True, "quickEligible": True},
                },
                "scan": {
                    "success": True,
                    "findings": [],
                    "stats": {},
                    "execution": {"toolResults": {}},
                },
                "codeGraph": {"functions": []},
                "libraries": [],
            },
            raw={},
        )

    monkeypatch.setattr(
        "app.core.phase_one_exec.post_and_wait_s4_ownership",
        fake_post_and_wait,
    )
    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")
    result = Phase1Result()

    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash build.sh",
        {"sdkResolutionMode": "none"},
        "req-root",
    )

    assert actual is result
    assert result.sast_scan_completed is True
    assert result.sast_static_evidence_ready is False

    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(result)
    assert catalog.negative_ref_ids() == set()
    operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
    assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
    await executor.aclose()


@pytest.mark.asyncio
async def test_build_and_analyze_success_false_records_static_contract_not_ready(monkeypatch):
    from app.clients.s4_ownership import S4OwnershipResult
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    async def fake_post_and_wait(*args, **kwargs):
        return S4OwnershipResult(
            request_id="req-ba",
            payload={
                "success": False,
                "errorDetail": {
                    "code": "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
                    "message": "required tool did not complete",
                },
                "scan": {
                    "success": False,
                    "findings": [],
                    "staticEvidenceContract": {
                        "gates": {
                            "systemStability": {"status": "fail", "reasonCodes": ["REQUIRED_TOOL_EXECUTION_INCOMPLETE"]},
                            "evidenceReadiness": {"status": "not_ready", "reasonCodes": ["ARTIFACT_FAILED"]},
                            "claimSupportReadiness": {"status": "fail", "reasonCodes": ["LOCAL_ARTIFACT_FAILED"]},
                        },
                        "claimBoundaryMatrix": [],
                        "toolEvidenceMatrix": [],
                    },
                },
            },
            raw={},
        )

    monkeypatch.setattr(
        "app.core.phase_one_exec.post_and_wait_s4_ownership",
        fake_post_and_wait,
    )
    executor = Phase1Executor(sast_endpoint="http://localhost:9000", kb_endpoint="http://localhost:8002")
    result = Phase1Result()

    actual = await executor._run_build_and_analyze(
        result,
        "proj-1",
        "/uploads/project",
        "bash build.sh",
        {"sdkResolutionMode": "none"},
        "req-root",
    )

    assert actual is None
    assert result.sast_scan_completed is False
    assert result.sast_static_evidence_ready is False
    assert result.sast_static_evidence_diagnostics["systemStability"] == "fail"
    assert result.sast_failure_detail["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    await executor.aclose()


@pytest.mark.asyncio
async def test_run_sast_records_success_false_payload_as_failure():
    from app.agent_runtime.schemas.agent import ToolResult
    from app.core.evidence_catalog import EvidenceCatalog
    from app.core.phase_one import Phase1Executor
    from app.core.phase_one_types import Phase1Result

    class FailedPayloadSastTool:
        async def execute(self, arguments):
            return ToolResult(
                tool_call_id="sast-1",
                name="sast.scan",
                success=True,
                content=json.dumps({
                    "success": False,
                    "failureDetail": {
                        "code": "SDK_NOT_FOUND",
                        "message": "SDK profile not registered",
                    },
                    "findings": [],
                    "stats": {},
                }),
            )

    executor = Phase1Executor(
        sast_tool=FailedPayloadSastTool(),
        sast_endpoint="http://localhost:9000",
        kb_endpoint="http://localhost:8002",
    )

    result = await executor._run_sast(
        Phase1Result(),
        [],
        "proj-1",
        {"sdkId": "missing-sdk"},
        "req-root",
        project_path="/uploads/project",
    )

    assert result.sast_scan_attempted is True
    assert result.sast_scan_completed is False
    assert result.sast_failure_detail["code"] == "SDK_NOT_FOUND"

    catalog = EvidenceCatalog()
    catalog.ingest_phase1_result(result)
    assert catalog.negative_ref_ids() == set()
    operational = [catalog.get(ref) for ref in catalog.operational_ref_ids()]
    assert len(operational) == 2
    assert any("sast_scan_failed" in entry.roles for entry in operational if entry)
    assert any("sast_contract_failure" in entry.roles for entry in operational if entry)
    assert any("sast_static_evidence_not_ready" in entry.roles for entry in operational if entry)
    await executor.aclose()


def test_sast_failure_detail_unwraps_ownership_error_detail_payload():
    from app.core.phase_one_exec import _sast_failure_detail

    detail = _sast_failure_detail({
        "error": "S4 submit failed with HTTP 400",
        "statusCode": 400,
        "detail": {
            "success": False,
            "failureDetail": {
                "code": "SDK_NOT_FOUND",
                "message": "SDK profile not registered",
            },
        },
    })

    assert detail["code"] == "SDK_NOT_FOUND"
    assert detail["message"] == "SDK profile not registered"
    assert detail["statusCode"] == 400

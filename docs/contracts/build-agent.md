# Build Agent 계약

Build Agent는 `build-resolve`와 `sdk-analyze`만 처리한다. 기계 스키마의 정본은 `services/build-agent/app/schemas/{request,response}.py`, 계약 정규화는 `app/validators/build_request_contract.py`다.

| 메서드 | 경로 | 의미 |
|---|---|---|
| POST | `/v1/tasks` | 빌드 해결 또는 SDK 분석 |
| GET | `/v1/health` | 설정, task schema와 요청 요약 |

공통 요청은 `taskType`, `taskId`, `context`, `evidenceRefs`, `constraints`, `metadata`다. `build-resolve-v1`/`strictMode=true`에서는 `context.trusted.projectPath`와 명시적 빌드 자료를 요구한다. SDK 모드는 `sdkId`와 `setupScript`, `buildEnvironment`, `scriptHintPath` 중 하나 이상의 materialization source가 필요하다. 네이티브 모드에는 SDK 전용 필드를 보내지 않는다. 인라인 build script hint는 지원하지 않는다.

성공 응답은 `schemaVersion=build-v1.1`, `validation`, `result`, `audit`를 포함한다. 빌드 판단은 `buildOutcome.outcome`, `taskCompleted`, `cleanPass`, `reasons`와 `buildDiagnostics`를 함께 본다. `status=completed`는 유효한 결과 envelope가 생성됐다는 뜻이며 artifact 일치나 빌드 성공을 대신하지 않는다. `expectedArtifacts`, `producedArtifacts`, `missingArtifacts`를 보존한다.

실패 envelope는 `failureCode`, `failureDetail`, `retryable`, `failureContext`를 제공한다. 대표 계약 오류는 `MISSING_BUILD_MATERIALS`, `SDK_MISMATCH`, `BUILD_SCRIPT_SYNTHESIS_FAILED`, `COMPILE_FAILED`, `EXPECTED_ARTIFACTS_MISMATCH`다. transport status와 본문 상태를 모두 확인하고 timeout 뒤 자동 재시도는 `retryable` 및 작업의 부작용을 검토한 뒤 수행한다.

관련 문서: [공유 모델](shared-models.md), [런북](../runbook.md), [문제 해결](../troubleshooting/sdk.md).

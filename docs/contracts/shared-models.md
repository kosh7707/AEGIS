# 공유 모델 계약

이 문서는 서비스 사이에서 사람이 확인해야 할 공통 의미만 요약한다. 전체 TypeScript 정의의 정본은 `services/shared/src/models.ts`, `services/shared/src/dto.ts`, `services/shared/src/llm-sampling.ts`다. 필드 추가·변경 시 문서보다 해당 타입과 계약 테스트를 우선한다.

## 공통 응답과 오류

S2 REST 응답은 보통 `{ success, data?, error?, errorDetail? }` 형태다. 구조화된 오류의 공통 필드는 `code`, `message`, `requestId`, `retryable`이며 엔드포인트별 메타데이터가 추가될 수 있다. HTTP 성공 여부와 도메인 성공 여부를 함께 확인한다.

`AnalysisStatus`는 `pending | running | completed | failed | aborted`다. `completed`는 전송과 작업이 끝났다는 뜻이며, 보안상 깨끗함을 뜻하지 않는다. 분석 결과는 `analysisOutcome`, `qualityOutcome`, `pocOutcome`, `needsHumanReview`, `claimDiagnostics`, `evidenceDiagnostics`를 함께 판정한다. 자세한 경계는 [불변 규칙](../invariants.md)을 따른다.

`BuildTargetStatus`와 SDK 상태의 전체 열거형은 `services/shared/src/models.ts`를 사용한다. UI나 호출자는 알 수 없는 추가 값을 표시 가능한 fallback으로 처리하고, 임의로 성공으로 승격하지 않는다.

## 증거와 진단

- `AnalysisResult.vulnerabilities`와 S3 `claims`는 최종 수용된 결과만 담는다.
- 거부·보류·증거 부족 후보는 `claimDiagnostics.nonAcceptedClaims`에 남는다.
- 실패하거나 결과가 없었던 증거 취득 시도는 `evidenceDiagnostics`에 남는다.
- `warnings`, `caveats`, `fileCoverage`, `analyzedFileIds`는 부분 성공과 누락 범위를 설명하므로 버리면 안 된다.
- 빈 배열이나 검색 결과 없음은 안전 판정이 아니다.

## WebSocket

공통 메시지는 `{ type, payload, meta? }`다. `meta`에는 `channel`, `projectId?`, epoch ms `timestamp`, 단조 증가 `seq?`가 들어간다. 이전 발신자는 `meta`를 생략할 수 있으므로 소비자는 이를 허용한다.

활성 채널은 `/ws/dynamic-analysis`, `/ws/dynamic-test`, `/ws/analysis`, `/ws/upload`, `/ws/pipeline`, `/ws/sdk`, `/ws/notifications`다. WS는 진행 알림이며 재접속 후 정본 상태는 각 REST 조회 API에서 복구한다. 모든 채널은 `heartbeat`를 받을 수 있다.

## LLM 생성 제어

S7 task 호출자는 `enableThinking`, `maxTokens`, `temperature`, `topP`, `topK`, `minP`, `presencePenalty`, `repetitionPenalty`를 명시한다. 기본값은 `services/shared/src/llm-sampling.ts`에 있으며 서비스별 복제값을 만들지 않는다.

관련 문서: [개요](../overview.md), [런북](../runbook.md), [제약](../limitations.md).

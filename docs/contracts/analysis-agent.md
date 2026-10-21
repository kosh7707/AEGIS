# Analysis Agent 계약

S3는 증거 기반 심층 분석과 PoC 판단을 동기식 task API로 제공한다. 전체 스키마는 `services/analysis-agent/app/schemas/{request,response}.py`, 상태·오류 열거형은 `app/types.py`가 정본이다.

## 활성 API

| 메서드 | 경로 | 의미 |
|---|---|---|
| POST | `/v1/tasks` | `deep-analyze`, `generate-poc` 실행 |
| GET | `/v1/health` | 설정, 활성 스키마, RAG/S7 상태와 요청 요약 |
| GET | `/v1/models` | 모델 프로필 목록 |
| GET | `/v1/prompts` | 프롬프트 목록 |

요청의 필수 뼈대는 `taskType`, `taskId`, `context`, `constraints`이며 `evidenceRefs`, `metadata`를 추가할 수 있다. `context.trusted`에는 호출자가 검증한 자료만 넣고 외부·사용자 텍스트는 신뢰 등급을 낮춰 전달한다. `X-Request-Id`는 추적을 위해 전달·응답된다.

성공 envelope는 `status=completed`, `schemaVersion=agent-v1.1`, `validation`, `result`, `audit`를 포함한다. `result.claims`는 수용된 claim만 포함하며 `analysisOutcome`, `qualityOutcome`, `pocOutcome`, `cleanPass`, `recoveryTrace`, `claimDiagnostics`, `evidenceDiagnostics`로 결과 의미를 판정한다. `completed`나 HTTP 200만으로 clean pass를 만들지 않는다.

terminal 실패는 HTTP 상태로도 드러난다: 미지원 task는 400, 검증·grounding·증거·unsafe 계열은 422, 입력/토큰/step budget은 413, timeout은 504, model unavailable/overload는 503, 그 밖은 500이다. 본문 `status`, `failureCode`, `failureDetail`, `retryable`, `audit`도 반드시 보존한다. 호출 취소 API는 없으며 caller timeout이 서버 작업 취소를 보장하지 않는다.

## 실험적 paper 표면

`/v1/paper/analysis-cases`의 생성·목록·상세, `/{case_id}/start`, `/{case_id}/artifacts`는 저장소 내부의 실험 경로다. 스키마 정본은 `services/analysis-agent/app/paper/models.py`, 구현은 `app/paper/api.py`다. 이 경로는 별도 paper 저장소에 의존하지 않으며 일반 제품 API의 안정성 보장을 확장하지 않는다.

관련 문서: [공유 모델](shared-models.md), [SAST](sast-runner.md), [Knowledge Base](knowledge-base.md), [불변 규칙](../invariants.md).

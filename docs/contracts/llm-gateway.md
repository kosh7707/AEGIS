# LLM Gateway 계약

S7은 모델 호출의 단일 관문이다. 스키마 정본은 `services/llm-gateway/app/schemas/`, 상태·오류 열거형은 `app/types.py`, 라우트 정본은 `app/routers/tasks.py`다.

## API

| 메서드 | 경로 | 의미 |
|---|---|---|
| POST | `/v1/tasks` | 구조화된 레거시 task 실행 |
| POST | `/v1/async-chat-requests` | 비동기 chat 제출 |
| GET | `/v1/async-chat-requests/{id}` | 상태 조회 |
| GET | `/v1/async-chat-requests/{id}/result` | 결과 조회 |
| DELETE | `/v1/async-chat-requests/{id}` | 취소 |
| POST | `/v1/chat` | 동기 OpenAI 호환 chat |
| GET | `/v1/health`, `/v1/usage`, `/v1/models`, `/v1/prompts` | 상태와 운영 정보 |
| GET | `/metrics` | Prometheus 메트릭 |

`/v1/tasks` 요청은 `taskType`, `taskId`, 등급화된 `context`, `evidenceRefs`, 모든 생성 제어를 담은 `constraints`가 필요하다. 지원 task는 `static-explain`, `static-cluster`, `dynamic-annotate`, `test-plan-propose`, `report-draft`다. S3/S6 전용 task를 이 API로 보내지 않는다.

비동기 chat 제출은 `messages`와 `max_tokens`, `temperature`, `top_p`, `top_k`, `min_p`, `presence_penalty`, `repetition_penalty`, `chat_template_kwargs.enable_thinking`을 명시한다. accepted 응답의 `requestId`, `statusUrl`, `resultUrl`, `cancelUrl`, `expiresAt`를 저장한다.

상태의 `state`, `resultReady`, `degraded`, `degradeReasons`, `blockedReason`, `retryable`, `expiresAt`를 함께 본다. `queued`/`running`은 계속 poll하고 terminal이어도 `resultReady=true`일 때만 결과를 읽는다. `failed`, `cancelled`, `expired`는 성공 결과가 아니다. DELETE 성공은 취소 요청의 처리 결과이며 이미 끝난 backend 실행을 되돌리지 않는다.

`/v1/health`의 `status=ok`만으로 실제 모델 사용 가능성을 판정하지 않는다. `llmMode`, `ready`, `llmReady`, backend 상태를 함께 확인한다. 제한과 복구 절차는 [런북](../runbook.md)을 따른다.

# Backend 계약

S2는 프로젝트와 분석 실행의 진실원이며 Express router가 실제 REST 표면의 정본이다. 전체 DTO는 `services/shared/src/`, mount 지점은 `services/backend/src/router-setup.ts`, 각 필드는 `src/controllers/*.controller.ts`를 따른다.

## REST 라우트 목록

아래는 mount prefix와 그 아래 활성 suffix다. 메서드·입력 필드의 정본은 대응 controller다.

| prefix | 활성 suffix |
|---|---|
| `/api/projects` | `POST|GET /`, `GET|PUT|DELETE /:id`, `GET /:id/overview` |
| `/api/projects/:pid/source` | `POST /upload`, `GET /upload-status/:uploadId`, `POST /clone`, `GET /files`, `GET /file`, `DELETE /` |
| `/api` | `GET /projects/:projectId/files`, `GET /files/:fileId/content`, `GET /files/:fileId/download`, `DELETE /projects/:projectId/files/:fileId` |
| `/api/projects/:pid/targets` | `GET|POST /`, `PUT|DELETE /:id`, `GET /:id/build-log`, `POST /discover` |
| `/api/projects/:pid/targets/:tid/libraries` | `GET|PATCH /` |
| `/api/projects/:pid/sdk` | `GET|POST /`, `GET /quota`, `GET /metrics`, `GET|DELETE /:id`, `GET /:id/log`, `POST /:id/retry` |
| `/api/projects/:pid/pipeline` | `POST /run`, `POST /prepare`, `POST /run/:targetId`, `POST /prepare/:targetId`, `GET /status` |
| `/api/analysis` | `POST /quick`, `POST /deep`, `GET /status`, `GET /status/:analysisId`, `POST /abort/:analysisId`, `GET /results`, `GET|DELETE /results/:analysisId`, `GET /summary`, `POST /poc` |
| `/api/dynamic-analysis` | `POST|GET /sessions`, `GET|DELETE /sessions/:id`, `POST /sessions/:id/start`, `GET /scenarios`, `POST /sessions/:id/inject`, `POST /sessions/:id/inject-scenario`, `GET /sessions/:id/injections` |
| `/api/dynamic-test` | `POST /run`, `GET /results`, `GET|DELETE /results/:testId` |
| `/api/projects/:pid/findings` | `GET /`, `GET /summary`, `GET /groups`, `PATCH /bulk-status`, `GET /:id/history`, `GET /:id`, `PATCH /:id/status` |
| `/api/projects/:pid/gates` | `GET /`, `GET /runs/:runId`; `/api/gates`: `GET /:id`, `POST /:id/override` |
| `/api/projects/:pid/approvals` | `GET /count`, `GET /`; `/api/approvals`: `GET /:id`, `POST /:id/decide` |
| `/api/projects/:pid/report` | `GET /`, `GET /static`, `GET /dynamic`, `GET /test`, `POST /custom` |
| `/api/projects/:pid/runs` | `GET /`; `/api/projects/:pid/activity`: `GET /` |
| `/api/projects/:pid/notifications` | `GET /count`, `PATCH /read-all`, `GET /` |
| global detail | `GET /api/runs/:id`; `GET /api/findings/:id`, `PATCH /api/findings/:id/status`; `GET /api/gates/:id`, `POST /api/gates/:id/override`; `GET /api/approvals/:id`, `POST /api/approvals/:id/decide`; `GET /api/notifications/:id`, `PATCH /api/notifications/:id/read` |
| project configuration | `/api/projects/:pid/adapters` CRUD + `/:id/connect|disconnect`; `GET|PUT /api/projects/:pid/settings` |
| profiles | `GET /api/sdk-profiles`, `GET /api/sdk-profiles/:id`, `GET /api/gate-profiles`, `GET /api/gate-profiles/:id` |
| auth | `/api/auth/login`, `/logout`, `/me`, `/users`, `/orgs/:code/verify`, `/register`, `/registrations/lookup/:lookupToken`, `/registration-requests[/:id]`, `/:id/approve`, `/:id/reject`, `/password-reset/request`, `/password-reset/confirm`, `/dev/password-reset/latest` |
| health | `GET /health` |

Quick 요청은 `{ projectId, buildTargetId }`, Deep 요청은 `{ projectId, buildTargetId, executionId }`를 요구한다. `mode`, `targetIds`, `quickAnalysisId`는 거부된다. 두 API는 202와 `{ analysisId, buildTargetId, executionId, status: "running" }`를 먼저 반환한다. 결과와 진행 이벤트의 `buildTargetId`, `analysisExecutionId`를 보존한다. abort 응답은 중단 요청 수락을 뜻하며 이미 terminal인 작업과 race할 수 있다. 상태 복구는 `/api/analysis/status*`와 결과 API를 기준으로 한다.

모든 오류는 가능한 경우 `error`와 `errorDetail { code, message, requestId, retryable }`를 함께 반환한다. 모든 응답의 `X-Request-Id`를 로그·하위 서비스 호출까지 전파한다. `CONFLICT` 또는 삭제 `blockers`는 재시도 전에 사용자가 해결할 조건이다. `*_TIMEOUT`, `*_UNAVAILABLE`, `*_HTTP_ERROR`를 같은 실패로 합치지 않는다.

WS 표면은 `/ws/analysis`, `/ws/pipeline`, `/ws/upload`, `/ws/sdk`, `/ws/notifications`, `/ws/dynamic-analysis`, `/ws/dynamic-test`다. 진행 메시지는 보조 신호이며 REST/DB 상태가 authoritative하다. health는 각 하위 서비스의 생존·준비 정보를 포함하지만 실제 분석 준비 여부는 S7 LLM, S4 도구, S5 ready 등 세부 상태를 함께 본다.

전체 모델과 판정 경계는 [공유 모델](shared-models.md), 운영 순서는 [런북](../runbook.md), SDK 오류는 [문제 해결](../troubleshooting/sdk.md)을 따른다.

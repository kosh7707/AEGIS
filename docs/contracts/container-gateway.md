# Container Gateway 계약

S8은 프로젝트별 workspace materialization, 격리 컨테이너 빌드와 제한된 명령 실행을 담당한다. 정본은 `services/container-gateway/src/contracts/`와 `src/routes/`다.

| 메서드 | 경로 | 필수 입력/결과 |
|---|---|---|
| GET | `/health` | 프로세스 상태 |
| POST | `/api/projects/:projectId/upload` | multipart `file` 최대 200개; workspace summary |
| GET | `/api/projects/:projectId/container` | container 상태 |
| POST | `/api/projects/:projectId/compile` | `workspaceId`, `profile.{language, entryFile, outputName}` |
| GET | `/api/projects/:projectId/exec/allowed-commands` | 실행 allowlist |
| POST | `/api/projects/:projectId/exec` | `workspaceId`, `command`, 선택 `args`, `cwd`, `timeoutMs` |
| DELETE | `/api/projects/:projectId/runtime` | workspace와 container teardown |

업로드 결과의 `uploadId`, `workspaceId`, `workspaceVersion`을 후속 요청에 전달한다. compile/exec는 성공 시 HTTP 200, 도구 실행 실패(`data.success=false`) 시 HTTP 422를 반환한다. HTTP 상태와 내부 `data.success`, `exitCode`, `stderr`를 함께 확인하고, compile 산출물 경로는 `artifactPaths`로 읽는다. exec는 읽기/빌드 중심 allowlist만 허용하며 거부는 `COMMAND_NOT_ALLOWED`, 런타임 부재는 `CONTAINER_RUNTIME_UNAVAILABLE`로 구분된다.

컨테이너 상태는 `not_found | creating | running | exited | error | tearing_down | teardown_failed | deleted`다. runtime 삭제는 workspace를 먼저 quarantine하고 container teardown 성공 후 확정한다. teardown 실패 시 workspace를 복원하므로 `teardown_failed`를 terminal 삭제로 취급하지 않는다.

관련 문서: [런북](../runbook.md), [제약](../limitations.md).

# SAST Runner 계약

S4는 C/C++ 정적 분석, 빌드 보조, 요청 수명주기를 제공한다. 요청·응답 정본은 `services/sast-runner/app/schemas/`, 라우트 정본은 `app/routers/scan.py`다.

## 활성 API

- `POST /v1/scan`: 멀티 도구 분석
- `POST /v1/functions`, `/v1/includes`, `/v1/metadata`, `/v1/libraries`: 코드/빌드 메타데이터 추출
- `POST /v1/build`, `/v1/build-and-analyze`, `/v1/discover-targets`: 빌드와 타깃 탐색
- `GET /v1/requests/{request_id}`: 요청 상태
- `GET /v1/requests/{request_id}/result`: 준비된 결과
- `DELETE /v1/requests/{request_id}`: 취소 요청
- `GET /v1/health`: 도구 가용성과 서비스 상태

요청별 세부 필드와 상한은 Pydantic 스키마를 따른다. 결과의 `findings`, `executionReport`, 도구별 상태, warnings 및 증거 locator를 함께 보존한다. 도구 미가용·profile 부적합·operator subset은 서로 다른 상태다. 일부 도구 성공을 전체 커버리지로 해석하지 않는다.

비동기 요청 상태는 `idle | queued | running | completed | failed | cancelled`이며 보관 기한이 지나면 내부 ownership record가 `expired`가 될 수 있다. 상태 조회와 결과 조회는 분리되어 있으므로 `resultReady`를 확인한다. `queued`/`running` 중 결과 조회는 준비되지 않은 응답이고, 취소 결과는 `cancelled` 상태의 결과 payload다. 취소 요청 수락과 실제 하위 프로세스 종료 시점은 다를 수 있다. timeout·partial 결과는 누락 범위를 함께 전달한다. S4 finding은 결정론적 증거이며 최종 취약 판정이 아니다.

## 실험적 paper 표면

`POST /v1/paper/static-evidence`는 정규화된 정적 증거 bundle을 만드는 내부 실험 API다. `schemaVersion=s4-paper-static-evidence-bundle-v1` 계약은 `app/schemas/request.py`, `app/schemas/response.py`, `app/scanner/paper_static_evidence.py`가 정본이다. 별도 paper 저장소에 의존하지 않으며 일반 `/v1/scan` 계약을 대체하지 않는다.

도구 구성 변경 규칙은 [SAST 도구 거버넌스](sast-tool-governance.md), 공통 판정 경계는 [불변 규칙](../invariants.md)을 따른다.

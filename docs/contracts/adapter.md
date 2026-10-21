# Adapter 계약

Adapter는 ECU WebSocket과 S2 backend WebSocket 사이에서 CAN 프레임과 주입 요청을 중계한다. 정본 타입은 `services/adapter/src/protocol.ts`, 연결 동작은 `src/relay.ts`다.

| 표면 | 의미 |
|---|---|
| `GET /health` | ECU 연결 여부, ECU 메타데이터, backend 연결 수 |
| `WS /ws/ecu` | ECU simulator 연결 |
| `WS /ws/backend` | S2 backend 연결; 복수 consumer 허용 |

`CanFrame`은 `timestamp`, `id`, `dlc`, `data`를 가진다. ECU→Adapter 메시지는 `can-frame`, `inject-response`, `ecu-info`; Adapter→ECU는 `inject-request`; backend→Adapter는 `inject-request`; Adapter→backend는 `can-frame`, `inject-response`, `ecu-status`, `ecu-info`다. 주입 상관관계는 `requestId`로 유지한다.

`GET /health`의 `status=ok`는 relay 프로세스가 살아 있다는 뜻이다. 실제 동적 분석 준비에는 `ecu.connected=true`와 S2의 adapter 연결 상태가 필요하다. ECU disconnect, malformed/reset/delayed 응답, backend reconnect를 정상적인 상태 전이로 처리하며 메시지 유실 가능성을 REST 저장 상태와 함께 판단한다.

관련 문서: [Backend](backend.md), [공유 모델](shared-models.md), [제약](../limitations.md).

# AEGIS 문서

이 디렉터리는 **현재 구현을 이해하고, 새 환경에서 설치·검증하고, 변경하기 위한 문서**다.
과거 세션·작업요청·로드맵을 보존하는 기록 저장소가 아니다.

## 읽는 순서

1. [전체 개요](overview.md): 서비스 구성, 제품 흐름, 독립 실행·실험 기능의 경계.
2. [운영 및 복원 절차](runbook.md): 환경, 의존성, 설정, 실행·종료, 검증, 데이터 보관.
3. [핵심 불변조건](invariants.md): 상태 전이, health, 취소·타임아웃, 증거 해석.
4. [현재 한계](limitations.md): 지원 범위와 추가 검증이 필요한 기능.
5. [SDK 문제 해결](troubleshooting/sdk.md): 오류 코드별 진단과 복구.

<a id="contracts"></a>
## 서비스 계약

| 계약 | 구현 위치 |
|---|---|
| [공유 모델](contracts/shared-models.md) | `services/shared/src` |
| [Backend](contracts/backend.md) | `services/backend/src` |
| [Analysis Agent](contracts/analysis-agent.md) | `services/analysis-agent/app` |
| [Build Agent](contracts/build-agent.md) | `services/build-agent/app` |
| [SAST Runner](contracts/sast-runner.md) | `services/sast-runner/app` |
| [SAST 도구 정책](contracts/sast-tool-governance.md) | `services/sast-runner/benchmark` |
| [Knowledge Base](contracts/knowledge-base.md) | `services/knowledge-base/app` |
| [LLM Gateway](contracts/llm-gateway.md) | `services/llm-gateway/app` |
| [Adapter](contracts/adapter.md) | `services/adapter/src` |
| [Container Gateway](contracts/container-gateway.md) | `services/container-gateway/src` |

계약 문서는 중요한 필드·상태·오류 의미와 실제 스키마의 위치를 설명한다.
전체 타입과 검증 규칙은 연결된 코드가 기준이며, 계약 변경 시 문서와 관련 회귀 테스트도 함께 갱신한다.

## 문서 유지 기준

- 현재 동작과 재현에 필요한 조건을 기록한다. 예정 기능은 현재 지원 기능과 구분한다.
- 경로는 저장소 기준 상대경로를 사용하고, 실제 키·토큰·개인별 서버 설정을 적지 않는다.
- 기동 성공, mock 결과, 실제 도구 실행, 실제 LLM 추론의 검증 수준을 구분한다.
- 소스·문서의 동일 커밋을 복원 기준으로 삼는다. Git에서 제외된 데이터는 별도 아카이브와 출처·체크섬이 필요하다.
- 테스트 결과를 기록할 때는 실행 명령, 대상 커밋, 환경, pass/fail/skip과 미검증 범위를 함께 남긴다.

# AEGIS 현재 구조

AEGIS(Automotive Embedded Governance & Inspection System)는 자동차 임베디드 C/C++ 소프트웨어를 대상으로 빌드 준비, 정적 분석, 지식 검색, LLM 보조 판정, CAN 기반 동적 분석을 연결하는 플랫폼이다. 이 문서는 현재 저장소에서 복원 가능한 구현 범위를 설명한다. 세부 요청·응답 형식은 [`contracts/`](contracts/)를 따른다.

## 설계 기준

- S2 Backend가 사용자 프로젝트, 실행 상태, 결과와 증적을 소유하는 오케스트레이터다. Frontend는 Backend만 호출한다.
- 도구 실행·필터링·정규화는 결정론적으로 처리하고, LLM은 분석을 보조한다.
- Finding은 추적 가능한 증적을 가져야 한다. 빈 결과, 서비스 생존, LLM 응답만으로 안전을 확정하지 않는다.
- 장시간 작업은 request ID, 상태 조회, 명시적 취소를 사용한다. 자세한 판정 규칙은 [`invariants.md`](invariants.md)를 따른다.

## 서비스 지도

| 영역 | 구현 경로 | 기본 포트 | 현재 역할 |
|---|---|---:|---|
| S1 Frontend | `services/frontend` | 5173 | 프로젝트·빌드 대상·Quick/Deep 결과와 운영 상태 UI |
| S2 Backend | `services/backend` | 3000 | REST/WebSocket, SQLite 영속화, 분석·빌드 파이프라인 오케스트레이션 |
| 공유 모델 | `services/shared` | — | Frontend와 Backend의 TypeScript 모델·DTO |
| S3 Analysis Agent | `services/analysis-agent` | 8001 | S4/S5 증적 수집과 S7을 통한 Deep 분석 |
| S3 Build Agent | `services/build-agent` | 8003 | 빌드 명령·프로파일 후보 해석과 빌드 준비 보조 |
| Python 공용 런타임 | `services/shared-py` | — | 두 S3 서비스가 심볼릭 링크로 공유하는 에이전트 런타임 |
| S4 SAST Runner | `services/sast-runner` | 9000 | 빌드·정적 분석·SCA·코드 구조 증적 생성 |
| S5 Knowledge Base | `services/knowledge-base` | 8002 | 로컬 벡터 검색, Neo4j 그래프, CVE/위협 지식과 코드 그래프 |
| S6 Adapter | `services/adapter` | 4000 | ECU와 Backend 사이 CAN WebSocket 중계 |
| S6 ECU Simulator | `services/ecu-simulator` | — | CAN 시나리오 발생기 |
| S7 LLM Gateway | `services/llm-gateway` | 8000 | mock/real 모드, LLM 단일 관문, 요청 상태·취소·회로 차단 |
| S8 Container Gateway | `services/container-gateway` | 4010 | Docker 기반 프로젝트별 업로드·컴파일·제한된 실행 실험면 |

S2는 S3, S4, S5, S6, S7을 호출한다. Deep 분석을 위임받은 S3는 S4, S5, S7을 직접 호출할 수 있다. 실제 LLM 엔진에는 S7만 접근한다. S8은 독립 서비스이며 `scripts/start.sh`의 기본 기동 대상이나 주 분석 경로에 포함되지 않는다.

## 정적 분석 흐름

현재 공개 실행 단위는 하나의 `BuildTarget`이다.

1. 소스와 필요 SDK를 프로젝트에 등록한다.
2. 빌드 준비가 빌드 명령과 프로파일을 해석하고 `compile_commands.json`을 만든다.
3. 사용자가 Quick을 요청하면 S2가 준비 상태를 확인한 뒤 S4의 결정론적 분석을 실행한다. 현재 기본 도구 묶음은 `semgrep`, `cppcheck`, `flawfinder`, `clang-tidy`, `scan-build`, `gcc-fanalyzer`다.
4. S2는 Quick 결과를 정규화하고 S5에 코드 그래프를 적재한다. 빌드 증적과 GraphRAG 문맥이 준비되어야 실행 문맥이 Deep 입력으로 승격된다.
5. 사용자가 같은 `BuildTarget`과 앞선 `executionId`로 Deep을 명시적으로 요청한다. S3가 Quick·그래프 문맥을 소비하고 S7을 통해 LLM 판정을 보강한다.

Quick 완료가 Deep 자동 시작을 뜻하지 않는다. Deep의 성공 또한 모든 Finding이 확정 취약점이거나 대상이 안전하다는 뜻이 아니다.

## 동적 분석과 S8 경계

S6의 Adapter, ECU Simulator, Backend 동적 분석·동적 테스트 API와 Frontend 구현은 저장소에 남아 있다. 이 면은 CAN 프레임 중계, 룰 평가, 퍼징/침투 입력을 지원하지만 현재 주 복원 기준은 정적 Quick/Deep 흐름이다. 실제 ECU·QEMU·타깃 연결 없이 UI나 API 존재만 확인한 결과를 동적 분석 성공으로 기록하지 않는다.

S8은 프로젝트별 컨테이너와 워크스페이스 버전을 관리하는 실험적 실행 plane이다. Docker 이미지와 데몬이 별도로 필요하고 기본 전체 기동에서 제외된다. S8을 사용할 때는 [`contracts/container-gateway.md`](contracts/container-gateway.md)와 [`runbook.md`](runbook.md)를 함께 따른다.

## 실험 API

메인 저장소에 남아 있는 `paper` 경로와 TraceAudit 관련 API·테스트는 실험 기능이다. 별도 과거 실험 저장소는 빌드, 실행, 복원에 필요하지 않다. 실험 API의 존재를 현재 제품 경로의 준비 완료나 지원 보장으로 해석하지 않는다.

## 문서 탐색

- 설치·기동·백업·복구: [`runbook.md`](runbook.md)
- 상태와 증적의 안전 규칙: [`invariants.md`](invariants.md)
- 현재 제약: [`limitations.md`](limitations.md)
- 서비스별 계약: [`contracts/`](contracts/)
- SDK 문제 해결: [`troubleshooting/sdk.md`](troubleshooting/sdk.md)

주요 구현 근거: `scripts/start.sh`, `services/backend/src/controllers/analysis.controller.ts`, `services/backend/src/services/analysis-orchestrator.ts`, `services/sast-runner/app/scanner/orchestrator.py`, `services/llm-gateway/app/config.py`.

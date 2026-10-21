# 핵심 불변조건

이 규칙은 API 응답, UI 표시, 자동화와 운영 판정을 해석할 때 유지해야 하는 안전 경계다. 세부 필드와 오류 코드는 [`contracts/`](contracts/)를 따른다.

## 오케스트레이션과 접근 경계

- Frontend는 Backend를 사용자 요청의 단일 진입점으로 사용한다.
- Backend가 프로젝트·실행·결과의 정본을 소유한다. 하위 서비스 응답만으로 사용자 상태를 확정하지 않는다.
- 위임받은 Analysis Agent는 S4/S5/S7을 호출할 수 있지만, LLM 엔진 직접 호출은 금지한다. 모든 LLM 접근은 S7을 경유한다.
- 경로와 프로젝트 ID는 신뢰 경계다. 작업 경로는 허용된 프로젝트 루트 안에서 해석하고 사용자 입력을 셸 문자열로 직접 실행하지 않는다.

## 실행 상태

- HTTP 접수 성공(`202`)은 작업 완료가 아니다. 반환된 `analysisId`, `executionId`, `requestId`로 소유권과 상태를 추적한다.
- 포트 LISTEN과 프로세스 생존은 시작 신호일 뿐 준비 완료가 아니다. 서비스 health, 외부 의존성 준비, 요청 결과를 단계별로 확인한다.
- `completed`는 응답 envelope가 만들어졌다는 뜻일 수 있다. `cleanPass`, build outcome, readiness gate, 증적 품질 같은 결과 필드를 별도로 확인한다.
- 같은 프로젝트/BuildTarget에서 중복 실행 방지, 취소, 재시도와 terminal 상태는 기존 실행 ID를 보존해야 한다. 재시도를 새 성공처럼 덮어쓰지 않는다.
- WebSocket은 진행 알림이다. 재연결·탐색 후 상태 복구는 REST 상태/결과 endpoint와 영속 데이터로 한다.

장시간 작업은 서비스가 노출하는 제어 신호를 따른다.

- `queued` 또는 `running`이며 `localAckState`가 `phase-advancing`/`transport-only`이고 `blockedReason`이 없으면 경과 시간만으로 중단하지 않는다.
- `failed`, `ack-break`, 명시적 `blockedReason`, 확인된 취소, 회복할 수 없는 소유권 상실은 중단 신호다.
- `degraded`는 자동 성공도 자동 실패도 아니다. 이유와 해당 기능의 준비 gate를 확인한다.
- 취소는 가능한 한 하위 요청 체인에 전달하고, 이미 끝난 작업의 결과와 취소 응답을 혼동하지 않는다.

## Build Agent 결과

- Build Agent의 `status="completed"`는 스키마에 맞는 결과 envelope를 만들었다는 뜻이다. 깨끗한 빌드 성공에는 `result.cleanPass=true`와 `result.buildOutcome.cleanPass=true`가 함께 필요하다.
- `compile_failed`, `missing_materials`, `sdk_mismatch`, `artifact_mismatch`, `inconclusive`는 유효한 요청을 처리한 결과로 반환될 수 있다. 이를 task-level 성공이나 Quick-ready로 승격하지 않는다.
- `cleanPass=true`에는 S4 빌드 성공 증적, 예상 artifact 충족, 안전한 요청별 생성 스크립트가 필요하다. 추론한 명령, compile database 존재, LLM 주장은 충분하지 않다.
- 업로드되거나 `scriptHintPath`로 제공된 스크립트는 참고 자료다. 직접 실행하지 않고 프로젝트 루트 안에서 검증한 뒤 요청별 작업 영역의 생성 스크립트로 실행한다.

## Quick와 Deep

- Quick는 정확히 하나의 준비된 `BuildTarget`을 대상으로 한다. 빌드 준비가 `compile_commands.json`을 만들지 못하면 Quick-ready가 아니다.
- Quick 결과와 S5 코드 그래프가 같은 실행 문맥에서 준비되어야 Deep을 요청할 수 있다.
- Deep은 사용자의 명시적 요청이며 Quick 뒤에 자동 실행하지 않는다. 동일 `BuildTarget`과 앞선 `executionId`를 사용한다.
- mock Deep은 계약과 상태 전이를 검증할 수 있지만 실제 모델 기반 보안 판단의 증거가 아니다.

## 증적과 판정

- Finding과 claim은 원본 파일·라인, 도구 결과, 빌드 산출물, 검색 결과 등 재확인 가능한 `EvidenceRef`로 연결한다.
- `findings=[]`, 검색 결과 없음, SAST 도구 성공, LLM의 부정 응답은 취약점 부재의 증거가 아니다.
- 도구가 생성하는 로컬 증적과 최종 보안 판정을 구분한다. S4는 로컬 정적 증적을 제공하며 exploitability, 전체 그래프 완전성, 런타임 안전, 최종 verdict를 확정하지 않는다.
- 요구 도구의 missing/failed/partial/skipped/degraded 상태를 숨기지 않는다. 해당 상태에서는 빈 Finding을 깨끗한 결과로 승격하지 않는다.
- 시스템 안정성, 증적 준비, 보안 품질은 별도 gate다. 요청이 기술적으로 끝나도 증적이 불완전할 수 있고, 도구가 안정적으로 실행돼도 대상이 안전하다고 결론 낼 수 없다.
- S5 미준비, timeout, 외부 CVE 데이터 부재는 지식 부재다. 이를 대상의 취약점 부재로 변환하지 않는다.
- LLM 출력은 분석가 보조 정보다. 정규화·중복 제거·품질 gate와 인간 검토를 통과하기 전에 authoritative verdict로 표시하지 않는다.

<a id="knowledge-base"></a>

## Knowledge Base

- S5 검색·그래프 응답의 `evidenceRefs`는 이 경계를 따라 해석한다. 검색 결과는 어떤 corpus, graph scope, scoring profile과 readiness에서 만들어졌는지 추적할 수 있어야 한다.
- `ready`는 요청된 S5 surface의 준비 상태다. 위협 지식 전체, 코드 그래프 전체 또는 대상 안전성의 완전성을 보장하지 않는다.
- 빈 검색 결과, 미적재 collection, Neo4j/Qdrant degradation, CVE 소스 timeout을 부정 증적으로 사용하지 않는다.
- S5가 반환하는 위협 관계와 후보는 분석 입력이다. 최종 affectedness·exploitability·Finding 상태는 S2의 증적·품질 흐름에서 별도로 판정한다.

## 데이터와 삭제

- DB 레코드, `uploads`의 소스·산출물, S5 적재 데이터는 함께 연결된 상태다. 백업과 복구는 동일 시점의 집합을 사용한다.
- 프로젝트 삭제는 격리 후 하위 자원과 산출물을 정리하는 흐름을 보존한다. 일부 삭제 실패를 전체 삭제 성공으로 숨기지 않는다.
- 비밀값, 실제 엔진 주소, 자격 증명, 사용자 업로드는 Git과 문서 예제에 넣지 않는다.
- 실험 `paper` API의 artifact와 제품 Quick/Deep artifact를 같은 준비 상태나 지원 약속으로 합치지 않는다.

## 변경 시 확인할 계약

- 공유 모델: [`contracts/shared-models.md`](contracts/shared-models.md)
- Backend: [`contracts/backend.md`](contracts/backend.md)
- Analysis/Build Agent: [`contracts/analysis-agent.md`](contracts/analysis-agent.md), [`contracts/build-agent.md`](contracts/build-agent.md)
- SAST/KB/LLM: [`contracts/sast-runner.md`](contracts/sast-runner.md), [`contracts/knowledge-base.md`](contracts/knowledge-base.md), [`contracts/llm-gateway.md`](contracts/llm-gateway.md)
- S6/S8: [`contracts/adapter.md`](contracts/adapter.md), [`contracts/container-gateway.md`](contracts/container-gateway.md)

주요 구현 근거: `services/backend/src/controllers/analysis.controller.ts`, `services/backend/src/controllers/health.controller.ts`, `services/backend/src/services/analysis-orchestrator.ts`, `services/backend/src/services/pipeline-orchestrator.ts`, `services/sast-runner/app/scanner/static_evidence_contract.py`.

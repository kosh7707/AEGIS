# 현재 제약

이 문서는 현재 checkout에서 확인되는 범위와 복원 시 기대치를 제한한다. 해결 여부를 확인하지 않은 과거 계획이나 세션 기록은 포함하지 않는다.

## 설치와 재현성

- Node lockfile은 존재하지만 Python은 직접 의존성만 `==`로 고정되어 있다. 전이 의존성, OS 패키지와 외부 도구까지 동일하게 재현되지는 않는다.
- 문서화된 Node/Python 조합 외의 버전은 별도 검증이 필요하다. 네이티브 모듈은 OS·컴파일러 차이에 영향을 받는다.
- S3 공용 런타임은 Git 심볼릭 링크를 사용한다. 심볼릭 링크를 보존하지 않는 checkout에서는 Analysis/Build Agent import가 깨진다.
- `scripts/start.sh`는 개발용 watch/reload 프로세스를 시작하며 배포용 supervisor나 production hardening을 제공하지 않는다.
- 통합 시작 검사는 대부분 포트 LISTEN을 기준으로 한다. 외부 시스템과 실제 기능의 readiness는 별도 확인이 필요하다.

## 분석 범위

- 주 제품 흐름은 C/C++ `BuildTarget`의 빌드 준비 → Quick → 명시적 Deep이다. 다른 언어와 빌드 체계의 지원은 도구별·프로젝트별이다.
- Quick 전체 증적은 SAST 실행 파일과 유효한 컴파일 데이터베이스에 의존한다. 도구 부재나 불완전한 `compile_commands.json`은 coverage를 낮춘다.
- 정적 분석은 런타임 동작, 전체 call graph 완전성, exploitability, 외부 취약점 affectedness를 단독 확정하지 못한다.
- 실제 Deep은 별도 LLM 엔진, 모델, 네트워크와 자원에 의존한다. 기본 mock 모드는 실제 분석 품질을 대표하지 않는다.
- S5는 로컬 Qdrant를 사용할 수 있지만 완전한 그래프·외부 위협 지식에는 Neo4j, 데이터 적재, 네트워크 기반 CVE/EPSS/KEV 소스가 필요하다. 일부 의존성 없이도 서비스가 degraded 상태로 기동될 수 있다.

## 동적 분석과 컨테이너

- S6 API와 UI는 남아 있으나 실제 차량 ECU, CAN 하드웨어, QEMU 타깃과의 종단 검증은 환경별로 수행해야 한다.
- 부채널, 물리 결함 주입과 실제 하드웨어 레지스터 동작 검증은 소프트웨어 중심 환경의 범위를 벗어난다.
- S8은 기본 기동에 포함되지 않는 실험 서비스다. Docker 데몬과 별도 toolchain 이미지가 필요하며, 프로젝트별 실행이 production sandbox 보장을 뜻하지 않는다.
- S8과 QEMU 산출물은 호스트 커널, Docker, 아키텍처와 이미지 버전에 영향을 받는다. 이미지 digest와 외부 SDK를 별도 기록해야 재현성이 높아진다.

## 상태와 사용자 경험

- 서비스 health가 `ok`여도 특정 요청의 하위 dependency, 도구 coverage 또는 실제 LLM이 준비되지 않았을 수 있다.
- 장시간 요청의 상태·결과 회수 방식은 서비스별 계약을 따른다. 네트워크 단절 뒤 자동 재개가 모든 endpoint에서 보장되는 것은 아니다.
- WebSocket 진행 이벤트는 영속 이력이 아니다. 재연결 후에는 REST 상태와 저장 결과를 다시 조회해야 한다.
- Frontend에는 많은 테스트 placeholder와 실험/보조 화면이 남아 있을 수 있다. 화면이나 route의 존재를 지원 완료 판정으로 사용하지 않는다.

## 데이터와 외부 자산

- `uploads/`, SQLite DB, S5 데이터, 로그, `.env`, 모델, Neo4j 데이터, Docker/QEMU 이미지와 데이터셋은 Git에 포함되지 않는다. 저장소 clone만으로 기존 분석 상태를 복구할 수 없다.
- 현재 로컬의 대규모 업로드/실험 자료는 출처·라이선스·필요성을 선별한 뒤 별도 아카이브해야 한다. `uploads`를 그대로 GitHub에 올리는 복원 전략은 지원하지 않는다.
- DB와 업로드 디렉터리를 다른 시점에 백업하면 메타데이터와 실제 파일이 불일치할 수 있다.
- 실제 `.env`와 자격 증명은 문서 예제, Git 이력, 일반 데이터 아카이브에서 제외해야 한다.

## 실험 및 비정본 경로

- 메인 저장소의 `paper`/TraceAudit API와 테스트는 실험 기능으로 유지된다. 과거 실험 저장소와 기록은 복원 의존성이 아니며 이 문서 집합은 그것을 재구성하지 않는다.
- 현재 계약은 이 저장소의 `docs/`와 코드가 함께 소유한다.
- 이 런북 작성 과정에서는 새 환경 전체 설치, 실제 LLM, 실제 ECU/QEMU, Docker S8의 종단 실행을 새로 증명하지 않았다. 실행 증거는 환경별 검증 기록으로 별도 남긴다.

복원과 검증 절차는 [`runbook.md`](runbook.md), 안전한 판정 규칙은 [`invariants.md`](invariants.md), 서비스별 현재 계약은 [`contracts/`](contracts/)를 참고한다.

주요 구현 근거: `.gitignore`, `scripts/start.sh`, `scripts/test-all.sh`, 각 서비스 requirements/package 파일, `services/llm-gateway/app/config.py`, `services/knowledge-base/app/config.py`, `services/container-gateway/src/config.ts`.

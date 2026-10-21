# AEGIS — Automotive Embedded Governance & Inspection System

자동차 임베디드 소프트웨어의 보안 취약점을 정적 분석, LLM 분석, 동적 분석으로 검증하는 플랫폼이다.
React 프론트엔드, Express/SQLite 백엔드, Python 분석·빌드 에이전트와 SAST·지식·LLM 서비스를 포함한다.

## 문서

**현재 코드의 문서는 이 저장소의 [`docs/`](docs/README.md)가 정본이다.** 별도 문서 저장소나 MCP 없이 읽고 개발할 수 있다.

| 목적 | 문서 |
|---|---|
| 구성과 주요 사용자 흐름 | [전체 개요](docs/overview.md) |
| 설치·실행·검증·데이터 복원 | [운영 및 복원 절차](docs/runbook.md) |
| 서비스 API와 공유 데이터 모델 | [계약 목록](docs/README.md#contracts) |
| 상태·타임아웃·증거 해석 규칙 | [핵심 불변조건](docs/invariants.md) |
| 지원 범위와 알려진 제약 | [현재 한계](docs/limitations.md) |
| SDK 업로드·빌드 준비 오류 | [SDK 문제 해결](docs/troubleshooting/sdk.md) |

## 시작하기

기준 환경은 Linux/WSL2, Node.js **22.23.2**, npm **12.0.2**, Python **3.12.3**이다.
설치할 시스템 도구와 Python 가상환경, 독립 Node 서비스의 의존성은 [설치 절차](docs/runbook.md)에 정리되어 있다.

```bash
git clone https://github.com/kosh7707/AEGIS.git
cd AEGIS
# docs/runbook.md의 설치·설정 단계를 완료한 뒤 실행한다.
./scripts/start.sh
```

Frontend는 `http://localhost:5173`, Backend는 `http://localhost:3000`이다.
새 checkout의 LLM 설정 기본값은 mock이므로, 실제 추론은 모델 서버와 서비스별 설정을 별도로 준비해야 한다.
Container Gateway는 통합 시작 스크립트에 포함되지 않는 선택 서비스다.

```bash
./scripts/start-container-gateway.sh  # Container Gateway가 필요한 경우
./scripts/stop.sh
```

## 검증

```bash
npm test
./scripts/test-all.sh backend analysis-agent  # 필요한 서비스만 선택
```

전체 명령은 TypeScript 6개와 Python 5개, 총 11개 스위트를 실행한다.
의존성이 없는 서비스는 SKIP하고, 실행된 스위트가 하나도 없으면 실패한다.
PASS만으로 모든 도구·실데이터·실제 LLM을 검증했다고 해석하지 말고 [검증 프로필과 제약](docs/runbook.md)을 확인한다.

## 보관 범위

소스·문서·lockfile·추적되는 fixture는 Git에 보관한다. 실제 `.env`, 업로드한 프로젝트·SDK,
운영 DB, 모델과 생성 로그는 Git 보관 대상이 아니다. 필요한 작업 데이터는
[복원 절차](docs/runbook.md)에 따라 출처·버전·변경분·체크섬과 함께 별도로 보관한다.
